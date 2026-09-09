use std::collections::{BTreeMap, BTreeSet};

use kitrove_adapter_api::InstructionTargetPolicy;
use kitrove_instructions::{InstructionLimits, hash_instruction_document, remove_managed_region};
use kitrove_model::{AssetId, ContentHash, EnvironmentManifest, LocalState};

use crate::instruction_apply_batch::{
    CoalescedInstructionApplyError, CoalescedInstructionApplyPlan, CoalescedInstructionDocument,
    CoalescedInstructionRegion, InstructionReceiptTransition, MAX_INSTRUCTION_PROJECTIONS,
    RenderedCoalescedInstructionDocument, batch_digest, document_digest, error, matching_receipt,
    projection_invalid, state_invalid,
};
use crate::{ApplyDisposition, InstructionDocumentObservation, ReceiptIndex};

/// One exact compiled consumer of a receipt-backed managed region selected for removal.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionRemovalProjection {
    policy: InstructionTargetPolicy,
    observation: InstructionDocumentObservation,
}

/// One receipt-backed instruction region selected for reference-aware pack removal.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionRemovalSelection {
    asset_id: AssetId,
    projections: Vec<InstructionRemovalProjection>,
    retained: bool,
}

impl InstructionRemovalSelection {
    #[must_use]
    pub fn remove(asset_id: AssetId, projections: Vec<InstructionRemovalProjection>) -> Self {
        Self {
            asset_id,
            projections,
            retained: false,
        }
    }

    #[must_use]
    pub fn retain(asset_id: AssetId, projections: Vec<InstructionRemovalProjection>) -> Self {
        Self {
            asset_id,
            projections,
            retained: true,
        }
    }
}

impl InstructionRemovalProjection {
    #[must_use]
    pub fn new(
        policy: InstructionTargetPolicy,
        observation: InstructionDocumentObservation,
    ) -> Self {
        Self {
            policy,
            observation,
        }
    }
}

/// Plans removal of one exact receipt-backed managed region without deleting portable authority.
pub fn plan_coalesced_instruction_removal(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    projections: Vec<InstructionRemovalProjection>,
    local_state_text: &str,
    limits: InstructionLimits,
) -> Result<CoalescedInstructionApplyPlan, CoalescedInstructionApplyError> {
    plan_instruction_removal_selections(
        manifest,
        vec![InstructionRemovalSelection::remove(
            asset_id.clone(),
            projections,
        )],
        local_state_text,
        limits,
        false,
    )
}

/// Coalesces mixed retained and removed instruction regions by physical document.
pub fn plan_coalesced_instruction_removal_selection(
    manifest: &EnvironmentManifest,
    selections: Vec<InstructionRemovalSelection>,
    local_state_text: &str,
    limits: InstructionLimits,
) -> Result<CoalescedInstructionApplyPlan, CoalescedInstructionApplyError> {
    plan_instruction_removal_selections(manifest, selections, local_state_text, limits, true)
}

fn plan_instruction_removal_selections(
    manifest: &EnvironmentManifest,
    selections: Vec<InstructionRemovalSelection>,
    local_state_text: &str,
    limits: InstructionLimits,
    preserve_active_profile: bool,
) -> Result<CoalescedInstructionApplyPlan, CoalescedInstructionApplyError> {
    let projection_count = selections
        .iter()
        .try_fold(0usize, |count, selection| {
            count.checked_add(selection.projections.len())
        })
        .ok_or_else(projection_invalid)?;
    if selections.is_empty()
        || projection_count == 0
        || projection_count > MAX_INSTRUCTION_PROJECTIONS
    {
        return Err(error(
            "instruction_remove.projection_invalid",
            "instruction removal requires a bounded non-empty consumer set",
        ));
    }
    manifest.validate().map_err(|_| projection_invalid())?;
    let manifest_revision =
        crate::derive_manifest_revision(manifest).map_err(|_| projection_invalid())?;
    let inspection = ReceiptIndex::inspect_json(local_state_text).map_err(|_| state_invalid())?;
    if !inspection.invalid.is_empty() {
        return Err(state_invalid());
    }
    let initial_state = LocalState::from_json(local_state_text).map_err(|_| state_invalid())?;
    let mut proposed_state = initial_state.clone();
    let mut groups = BTreeMap::new();
    for mut selection in selections {
        if manifest
            .assets
            .get(&selection.asset_id)
            .is_none_or(|asset| asset.kind != kitrove_model::AssetKind::Instruction)
        {
            return Err(projection_invalid());
        }
        if selection.projections.is_empty() {
            return Err(projection_invalid());
        }
        selection
            .projections
            .sort_by(|left, right| left.policy.harness.cmp(&right.policy.harness));
        validate_projection_set(&selection.projections)?;
        groups
            .entry(selection.projections[0].observation.destination().clone())
            .or_insert_with(Vec::new)
            .push(selection);
    }
    let mut documents = Vec::with_capacity(groups.len());
    for selections in groups.into_values() {
        documents.push(plan_removal_document(
            &initial_state,
            &mut proposed_state,
            selections,
            limits,
        )?);
    }
    let active_profile = preserve_active_profile
        .then(|| initial_state.machine.active_profile.clone())
        .flatten();
    proposed_state.machine.active_profile = active_profile.clone();
    let proposed_local_state_text = proposed_state.to_json().map_err(|_| state_invalid())?;
    let target_anchors = documents
        .iter()
        .map(|document| document.target_anchor.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let digest = batch_digest(
        &documents,
        &manifest_revision,
        local_state_text,
        &proposed_local_state_text,
        active_profile.as_ref(),
    );
    Ok(CoalescedInstructionApplyPlan {
        documents,
        target_anchors,
        manifest_revision,
        observed_local_state_text: local_state_text.to_owned(),
        proposed_local_state: proposed_state,
        proposed_local_state_text,
        active_profile,
        digest,
    })
}

fn plan_removal_document(
    initial_state: &LocalState,
    proposed_state: &mut LocalState,
    mut selections: Vec<InstructionRemovalSelection>,
    limits: InstructionLimits,
) -> Result<CoalescedInstructionDocument, CoalescedInstructionApplyError> {
    selections.sort_by(|left, right| left.asset_id.cmp(&right.asset_id));
    if selections
        .windows(2)
        .any(|pair| pair[0].asset_id == pair[1].asset_id)
    {
        return Err(projection_invalid());
    }
    let first = &selections[0].projections[0];
    let document_observation = first.observation.clone();
    let document_policy = first.policy.clone();
    let target_anchor = document_observation
        .destination()
        .anchor_for(&document_policy.relative_document)
        .map_err(|_| projection_invalid())?;
    if selections
        .iter()
        .flat_map(|selection| &selection.projections)
        .any(|projection| {
            !projection
                .observation
                .has_same_physical_authority(&first.observation)
                || projection.policy.scope != first.policy.scope
                || projection.policy.relative_document != first.policy.relative_document
                || projection
                    .observation
                    .destination()
                    .anchor_for(&projection.policy.relative_document)
                    .ok()
                    .as_ref()
                    != Some(&target_anchor)
        })
    {
        return Err(projection_invalid());
    }
    let mut rendered_bytes = document_observation
        .document_bytes()
        .ok_or_else(projection_invalid)?
        .to_vec();
    let mut regions = Vec::with_capacity(selections.len());
    for selection in selections {
        let first_projection = &selection.projections[0];
        let receipt = matching_receipt(
            initial_state,
            &selection.asset_id,
            first_projection.policy.scope,
            first_projection.observation.destination(),
        )?
        .cloned()
        .ok_or_else(|| {
            error(
                "instruction_remove.receipt_missing",
                "instruction removal requires exact receipt ownership",
            )
        })?;
        let consumers = selection
            .projections
            .iter()
            .map(|projection| projection.policy.harness.clone())
            .collect::<BTreeSet<_>>();
        if receipt.consumers().cloned().collect::<BTreeSet<_>>() != consumers
            || selection.projections.iter().any(|projection| {
                receipt.adapter_version_for(&projection.policy.harness)
                    != Some(projection.policy.adapter_version)
            })
        {
            return Err(error(
                "instruction_remove.receipt_stale",
                "instruction removal consumer authority is stale",
            ));
        }
        let region = first_projection
            .observation
            .region(&selection.asset_id)
            .ok_or_else(|| {
                error(
                    "instruction_remove.region_missing",
                    "the receipt-backed instruction region is missing",
                )
            })?;
        if region.exact_region_hash() != &receipt.rendered_hash {
            return Err(error(
                "instruction_remove.region_modified",
                "the receipt-backed instruction region was modified",
            ));
        }
        let transition = if selection.retained {
            InstructionReceiptTransition::Upsert {
                observed: Some(Box::new(receipt.clone())),
                proposed: Box::new(receipt),
            }
        } else {
            rendered_bytes = remove_managed_region(&rendered_bytes, &selection.asset_id, limits)
                .map_err(|_| projection_invalid())?
                .ok_or_else(projection_invalid)?;
            let receipt_id = receipt.receipt_id().map_err(|_| state_invalid())?;
            if proposed_state.receipts.remove(&receipt_id).as_ref() != Some(&receipt) {
                return Err(state_invalid());
            }
            InstructionReceiptTransition::Remove {
                observed: Box::new(receipt),
            }
        };
        regions.push(CoalescedInstructionRegion {
            asset_id: selection.asset_id,
            disposition: if selection.retained {
                ApplyDisposition::NoOp
            } else {
                ApplyDisposition::Remove
            },
            receipt_transition: transition,
            policies: selection
                .projections
                .into_iter()
                .map(|projection| projection.policy)
                .collect(),
        });
    }
    let rendered = RenderedCoalescedInstructionDocument {
        document_hash: hash_instruction_document(&rendered_bytes),
        mode: document_observation.mode(),
        bytes: rendered_bytes,
    };
    let disposition = if document_observation.document_bytes() == Some(rendered.bytes.as_slice()) {
        ApplyDisposition::NoOp
    } else {
        ApplyDisposition::ManagedUpdate
    };
    let mut document = CoalescedInstructionDocument {
        destination: document_observation.destination().clone(),
        target_anchor,
        relative_destination: document_policy.relative_document,
        observation: document_observation,
        rendered,
        disposition,
        regions,
        digest: ContentHash::digest(b"pending"),
    };
    document.digest = document_digest(&document);
    Ok(document)
}

fn validate_projection_set(
    projections: &[InstructionRemovalProjection],
) -> Result<(), CoalescedInstructionApplyError> {
    let first = &projections[0];
    let mut consumers = BTreeSet::new();
    if projections.iter().any(|projection| {
        projection.policy.validate().is_err()
            || projection.observation.policy() != &projection.policy
            || projection.policy.scope != first.policy.scope
            || !projection
                .observation
                .has_same_physical_authority(&first.observation)
            || !consumers.insert(projection.policy.harness.clone())
    }) {
        return Err(projection_invalid());
    }
    Ok(())
}
