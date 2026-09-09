use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::InstructionTargetPolicy;
use kitrove_instructions::{
    InstructionLimits, StoredInstruction, hash_instruction_document, render_managed_region,
    upsert_managed_region,
};
use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, EnvironmentManifest, HarnessId, HarnessScope,
    LocalState, NormalizedDestination, ProfileId, ReceiptTarget, Revision,
};

use crate::instruction_materialization::validate_instruction_source;
use crate::materialization::write_digest_record;
use crate::read_only_fs::RegularFileMode;
use crate::{ApplyDisposition, InstructionDocumentObservation, ReceiptIndex};

pub(crate) const MAX_INSTRUCTION_PROJECTIONS: usize = 4096;

/// One logical instruction projection selected for atomic profile application.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionProjection {
    asset_id: AssetId,
    object: StoredInstruction,
    policy: InstructionTargetPolicy,
    observation: InstructionDocumentObservation,
}

impl InstructionProjection {
    #[must_use]
    pub fn new(
        asset_id: AssetId,
        object: StoredInstruction,
        policy: InstructionTargetPolicy,
        observation: InstructionDocumentObservation,
    ) -> Self {
        Self {
            asset_id,
            object,
            policy,
            observation,
        }
    }

    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn policy(&self) -> &InstructionTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn observation(&self) -> &InstructionDocumentObservation {
        &self.observation
    }
}

impl Debug for InstructionProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionProjection")
            .field("asset_id", &self.asset_id)
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("destination", self.observation.destination())
            .finish()
    }
}

/// One logical managed region within a coalesced physical-document participant.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedInstructionRegion {
    pub(crate) asset_id: AssetId,
    pub(crate) disposition: ApplyDisposition,
    pub(crate) receipt_transition: InstructionReceiptTransition,
    pub(crate) policies: Vec<InstructionTargetPolicy>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum InstructionReceiptTransition {
    Upsert {
        observed: Option<Box<DeploymentReceipt>>,
        proposed: Box<DeploymentReceipt>,
    },
    Remove {
        observed: Box<DeploymentReceipt>,
    },
}

impl CoalescedInstructionRegion {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub fn observed_receipt(&self) -> Option<&DeploymentReceipt> {
        match &self.receipt_transition {
            InstructionReceiptTransition::Upsert { observed, .. } => observed.as_deref(),
            InstructionReceiptTransition::Remove { observed } => Some(observed.as_ref()),
        }
    }

    #[must_use]
    pub fn proposed_receipt(&self) -> Option<&DeploymentReceipt> {
        match &self.receipt_transition {
            InstructionReceiptTransition::Upsert { proposed, .. } => Some(proposed.as_ref()),
            InstructionReceiptTransition::Remove { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_removal(&self) -> bool {
        matches!(
            self.receipt_transition,
            InstructionReceiptTransition::Remove { .. }
        )
    }

    #[must_use]
    pub fn policies(&self) -> &[InstructionTargetPolicy] {
        &self.policies
    }
}

impl Debug for CoalescedInstructionRegion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedInstructionRegion")
            .field("asset_id", &self.asset_id)
            .field("disposition", &self.disposition)
            .field("consumer_count", &self.policies.len())
            .finish()
    }
}

/// One physical co-owned document staged exactly once by an atomic instruction batch.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedInstructionDocument {
    pub(crate) destination: NormalizedDestination,
    pub(crate) target_anchor: NormalizedDestination,
    pub(crate) relative_destination: kitrove_model::PortablePath,
    pub(crate) observation: InstructionDocumentObservation,
    pub(crate) rendered: RenderedCoalescedInstructionDocument,
    pub(crate) disposition: ApplyDisposition,
    pub(crate) regions: Vec<CoalescedInstructionRegion>,
    pub(crate) digest: ContentHash,
}

impl CoalescedInstructionDocument {
    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    #[must_use]
    pub const fn target_anchor(&self) -> &NormalizedDestination {
        &self.target_anchor
    }

    #[must_use]
    pub const fn relative_destination(&self) -> &kitrove_model::PortablePath {
        &self.relative_destination
    }

    #[must_use]
    pub const fn observation(&self) -> &InstructionDocumentObservation {
        &self.observation
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedCoalescedInstructionDocument {
        &self.rendered
    }

    #[must_use]
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub fn regions(&self) -> &[CoalescedInstructionRegion] {
        &self.regions
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

/// Exact complete output for one coalesced co-owned instruction document.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedCoalescedInstructionDocument {
    pub(crate) bytes: Vec<u8>,
    pub(crate) document_hash: ContentHash,
    pub(crate) mode: RegularFileMode,
}

impl RenderedCoalescedInstructionDocument {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn document_hash(&self) -> &ContentHash {
        &self.document_hash
    }

    #[allow(dead_code)]
    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }
}

impl Debug for RenderedCoalescedInstructionDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedCoalescedInstructionDocument")
            .field("byte_count", &self.bytes.len())
            .field("document_hash", &self.document_hash)
            .finish()
    }
}

impl Debug for CoalescedInstructionDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedInstructionDocument")
            .field("destination", &self.destination)
            .field("disposition", &self.disposition)
            .field("region_count", &self.regions.len())
            .field("rendered", &self.rendered)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Complete pure plan for all selected instruction projections and final receipt state.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedInstructionApplyPlan {
    pub(crate) documents: Vec<CoalescedInstructionDocument>,
    pub(crate) target_anchors: Vec<NormalizedDestination>,
    pub(crate) manifest_revision: Revision,
    pub(crate) observed_local_state_text: String,
    pub(crate) proposed_local_state: LocalState,
    pub(crate) proposed_local_state_text: String,
    pub(crate) active_profile: Option<ProfileId>,
    pub(crate) digest: ContentHash,
}

impl CoalescedInstructionApplyPlan {
    #[must_use]
    pub fn documents(&self) -> &[CoalescedInstructionDocument] {
        &self.documents
    }

    #[must_use]
    pub fn target_anchors(&self) -> &[NormalizedDestination] {
        &self.target_anchors
    }

    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub fn observed_local_state_text(&self) -> &str {
        &self.observed_local_state_text
    }

    #[must_use]
    pub const fn proposed_local_state(&self) -> &LocalState {
        &self.proposed_local_state
    }

    #[must_use]
    pub fn proposed_local_state_text(&self) -> &str {
        &self.proposed_local_state_text
    }

    #[must_use]
    pub const fn active_profile(&self) -> Option<&ProfileId> {
        self.active_profile.as_ref()
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for CoalescedInstructionApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedInstructionApplyPlan")
            .field("document_count", &self.documents.len())
            .field("target_anchor_count", &self.target_anchors.len())
            .field("manifest_revision", &self.manifest_revision)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Stable, content- and path-redacted coalesced instruction planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct CoalescedInstructionApplyError {
    code: &'static str,
    message: &'static str,
}

impl CoalescedInstructionApplyError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for CoalescedInstructionApplyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoalescedInstructionApplyError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for CoalescedInstructionApplyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for CoalescedInstructionApplyError {}

/// Coalesces logical instruction projections by physical destination before any mutation occurs.
pub fn plan_coalesced_instruction_apply(
    manifest: &EnvironmentManifest,
    projections: Vec<InstructionProjection>,
    local_state_text: &str,
    active_profile: Option<ProfileId>,
    limits: InstructionLimits,
) -> Result<CoalescedInstructionApplyPlan, CoalescedInstructionApplyError> {
    if projections.is_empty() {
        return Err(error(
            "instruction_batch.empty",
            "an instruction apply batch requires at least one projection",
        ));
    }
    if projections.len() > MAX_INSTRUCTION_PROJECTIONS {
        return Err(error(
            "instruction_batch.limit",
            "the instruction projection count exceeds the compiled limit",
        ));
    }
    let inspection = ReceiptIndex::inspect_json(local_state_text).map_err(|_| state_invalid())?;
    if !inspection.invalid.is_empty() {
        return Err(state_invalid());
    }
    let initial_state = LocalState::from_json(local_state_text).map_err(|_| state_invalid())?;
    let mut groups = BTreeMap::<NormalizedDestination, Vec<InstructionProjection>>::new();
    let mut manifest_revision = None;
    for projection in projections {
        let validated = validate_instruction_source(
            manifest,
            &projection.asset_id,
            &projection.object,
            &projection.policy,
            &projection.observation,
        )
        .map_err(|_| projection_invalid())?;
        match &manifest_revision {
            Some(revision) if revision != &validated.manifest_revision => {
                return Err(projection_invalid());
            }
            None => manifest_revision = Some(validated.manifest_revision),
            _ => {}
        }
        groups
            .entry(projection.observation.destination().clone())
            .or_default()
            .push(projection);
    }
    let manifest_revision = manifest_revision.expect("a non-empty projection set has a revision");
    let mut state = initial_state.clone();
    let mut documents = Vec::with_capacity(groups.len());
    for projections in groups.into_values() {
        documents.push(plan_document(
            manifest,
            &initial_state,
            &mut state,
            &manifest_revision,
            projections,
            limits,
        )?);
    }
    state.machine.active_profile = active_profile.clone();
    let proposed_local_state_text = state.to_json().map_err(|_| state_invalid())?;
    let target_anchors = documents
        .iter()
        .map(|document| document.target_anchor.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
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
        proposed_local_state: state,
        proposed_local_state_text,
        active_profile,
        digest,
    })
}

fn plan_document(
    manifest: &EnvironmentManifest,
    initial_state: &LocalState,
    state: &mut LocalState,
    manifest_revision: &Revision,
    mut projections: Vec<InstructionProjection>,
    limits: InstructionLimits,
) -> Result<CoalescedInstructionDocument, CoalescedInstructionApplyError> {
    projections.sort_by(|left, right| {
        left.asset_id
            .cmp(&right.asset_id)
            .then_with(|| left.policy.harness.cmp(&right.policy.harness))
    });
    let first = &projections[0];
    if projections.iter().any(|projection| {
        projection.policy.scope != first.policy.scope
            || !projection
                .observation
                .has_same_physical_authority(&first.observation)
    }) {
        return Err(error(
            "instruction_batch.document_authority_mismatch",
            "projections for one physical instruction document disagree on observed authority",
        ));
    }
    let target_anchor = first
        .observation
        .destination()
        .anchor_for(&first.policy.relative_document)
        .map_err(|_| projection_invalid())?;
    if projections.iter().any(|projection| {
        projection
            .observation
            .destination()
            .anchor_for(&projection.policy.relative_document)
            .ok()
            .as_ref()
            != Some(&target_anchor)
    }) {
        return Err(error(
            "instruction_batch.target_anchor_mismatch",
            "shared physical instruction projections require one canonical target anchor",
        ));
    }
    if initial_state.receipts.values().any(|receipt| {
        receipt.destination == *first.observation.destination()
            && receipt.target == ReceiptTarget::WholeTarget
    }) {
        return Err(error(
            "instruction_batch.destination_owned_whole",
            "a whole-target receipt owns the selected instruction document",
        ));
    }

    let document_observation = first.observation.clone();
    let relative_destination = first.policy.relative_document.clone();

    let mut rendered_bytes = document_observation
        .document_bytes()
        .unwrap_or_default()
        .to_vec();
    let mut regions = Vec::new();
    for (asset_id, asset_projections) in group_assets(projections) {
        let first_projection = &asset_projections[0];
        if asset_projections.iter().any(|projection| {
            projection.object != first_projection.object
                || projection.policy.scope != first_projection.policy.scope
        }) {
            return Err(error(
                "instruction_batch.region_conflict",
                "one managed instruction region has conflicting projection authority",
            ));
        }
        let mut policy_versions = BTreeMap::<HarnessId, String>::new();
        for projection in &asset_projections {
            if policy_versions
                .insert(
                    projection.policy.harness.clone(),
                    projection.policy.adapter_version.to_owned(),
                )
                .is_some()
            {
                return Err(error(
                    "instruction_batch.projection_duplicate",
                    "one logical instruction consumer was selected more than once",
                ));
            }
        }
        let existing = matching_receipt(
            initial_state,
            &asset_id,
            first_projection.policy.scope,
            first_projection.observation.destination(),
        )?;
        let observed_region = first_projection.observation.region(&asset_id);
        let (_, region_hash) = render_managed_region(&asset_id, first_projection.object.body())
            .map_err(|_| projection_invalid())?;
        let consumers_match = existing.is_some_and(|receipt| {
            receipt.consumers().cloned().collect::<BTreeSet<_>>()
                == policy_versions.keys().cloned().collect()
                && policy_versions.iter().all(|(harness, version)| {
                    receipt.adapter_version_for(harness) == Some(version.as_str())
                })
        });
        let (disposition, prior_hash) = match (existing, observed_region) {
            (None, None) => (ApplyDisposition::Install, None),
            (None, Some(_)) => {
                return Err(error(
                    "instruction_batch.region_unmanaged",
                    "an unmanaged instruction region is never claimed or overwritten",
                ));
            }
            (Some(receipt), None) => (ApplyDisposition::Restore, receipt.prior_hash.clone()),
            (Some(receipt), Some(region)) => {
                if region.exact_region_hash() != &receipt.rendered_hash {
                    return Err(error(
                        "instruction_batch.region_modified",
                        "a managed instruction region changed after materialization",
                    ));
                }
                let asset = manifest
                    .assets
                    .get(&asset_id)
                    .ok_or_else(projection_invalid)?;
                if receipt.source_hash == asset.content_hash
                    && receipt.rendered_hash == region_hash
                    && receipt.environment_revision == *manifest_revision
                    && consumers_match
                {
                    (ApplyDisposition::NoOp, receipt.prior_hash.clone())
                } else {
                    (
                        ApplyDisposition::ManagedUpdate,
                        Some(receipt.rendered_hash.clone()),
                    )
                }
            }
        };
        rendered_bytes = upsert_managed_region(
            &rendered_bytes,
            &asset_id,
            first_projection.object.body(),
            limits,
        )
        .map_err(|_| projection_invalid())?;
        let (primary, adapter_version) = policy_versions
            .first_key_value()
            .expect("one asset group contains a consumer");
        let shared_with = policy_versions
            .keys()
            .filter(|harness| *harness != primary)
            .cloned()
            .collect();
        let shared_adapter_versions = policy_versions
            .iter()
            .filter(|(harness, _)| *harness != primary)
            .map(|(harness, version)| (harness.clone(), version.clone()))
            .collect();
        let asset = manifest
            .assets
            .get(&asset_id)
            .ok_or_else(projection_invalid)?;
        let proposed_receipt = DeploymentReceipt {
            asset_id: asset_id.clone(),
            harness: primary.clone(),
            scope: first_projection.policy.scope,
            destination: first_projection.observation.destination().clone(),
            target: ReceiptTarget::ManagedInstructionRegion,
            logical_key: None,
            shared_with,
            shared_adapter_versions,
            source_hash: asset.content_hash.clone(),
            rendered_hash: region_hash,
            document_hash: None,
            prior_hash,
            adapter_version: adapter_version.clone(),
            environment_revision: manifest_revision.clone(),
        };
        let receipt_id = proposed_receipt.receipt_id().map_err(|_| state_invalid())?;
        if let Some(receipt) = existing {
            let old_id = receipt.receipt_id().map_err(|_| state_invalid())?;
            state.receipts.remove(&old_id);
        }
        if state
            .receipts
            .insert(receipt_id, proposed_receipt.clone())
            .is_some()
        {
            return Err(state_invalid());
        }
        regions.push(CoalescedInstructionRegion {
            asset_id,
            disposition,
            receipt_transition: InstructionReceiptTransition::Upsert {
                observed: existing.cloned().map(Box::new),
                proposed: Box::new(proposed_receipt),
            },
            policies: asset_projections
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
    let disposition = if document_observation.document_bytes() == Some(rendered.bytes()) {
        ApplyDisposition::NoOp
    } else if document_observation.is_present() {
        ApplyDisposition::ManagedUpdate
    } else {
        ApplyDisposition::Install
    };
    let mut document = CoalescedInstructionDocument {
        destination: document_observation.destination().clone(),
        target_anchor,
        relative_destination,
        observation: document_observation,
        rendered,
        disposition,
        regions,
        digest: ContentHash::digest(b"pending"),
    };
    document.digest = document_digest(&document);
    Ok(document)
}

fn group_assets(
    projections: Vec<InstructionProjection>,
) -> BTreeMap<AssetId, Vec<InstructionProjection>> {
    let mut grouped = BTreeMap::new();
    for projection in projections {
        grouped
            .entry(projection.asset_id.clone())
            .or_insert_with(Vec::new)
            .push(projection);
    }
    grouped
}

pub(crate) fn matching_receipt<'a>(
    state: &'a LocalState,
    asset_id: &AssetId,
    scope: HarnessScope,
    destination: &NormalizedDestination,
) -> Result<Option<&'a DeploymentReceipt>, CoalescedInstructionApplyError> {
    let mut matching = state.receipts.values().filter(|receipt| {
        receipt.asset_id == *asset_id
            && receipt.scope == scope
            && receipt.destination == *destination
            && receipt.target == ReceiptTarget::ManagedInstructionRegion
    });
    let first = matching.next();
    if matching.next().is_some() {
        return Err(state_invalid());
    }
    Ok(first)
}

pub(crate) fn batch_digest(
    documents: &[CoalescedInstructionDocument],
    manifest_revision: &Revision,
    observed_state: &str,
    proposed_state: &str,
    active_profile: Option<&ProfileId>,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-coalesced-instruction-apply-plan-v1\0");
    let observed_state_hash = ContentHash::digest(observed_state.as_bytes());
    let proposed_state_hash = ContentHash::digest(proposed_state.as_bytes());
    for value in [
        manifest_revision.as_str(),
        observed_state_hash.as_str(),
        proposed_state_hash.as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    match active_profile {
        Some(profile) => {
            hasher.update(&[1]);
            write_digest_record(&mut hasher, profile.as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&(documents.len() as u64).to_be_bytes());
    for document in documents {
        write_digest_record(&mut hasher, document.digest.as_str());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

pub(crate) fn document_digest(document: &CoalescedInstructionDocument) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-coalesced-instruction-document-plan-v1\0");
    write_document_authority(&mut hasher, document);
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

fn write_document_authority(hasher: &mut blake3::Hasher, document: &CoalescedInstructionDocument) {
    for value in [
        document.destination.as_str(),
        document.target_anchor.as_str(),
        document.relative_destination.as_str(),
        document.rendered.document_hash().as_str(),
    ] {
        write_digest_record(hasher, value);
    }
    write_optional_hash(hasher, document.observation.document_hash());
    match document.rendered.mode().unix_mode() {
        Some(mode) => {
            hasher.update(&[1]);
            hasher.update(&mode.to_be_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&[u8::from(document.rendered.mode().readonly())]);
    hasher.update(&[disposition_tag(document.disposition)]);
    hasher.update(&(document.regions.len() as u64).to_be_bytes());
    for region in &document.regions {
        write_digest_record(hasher, region.asset_id.as_str());
        write_optional_receipt_authority(hasher, region.observed_receipt());
        write_optional_receipt_authority(hasher, region.proposed_receipt());
        hasher.update(&[disposition_tag(region.disposition)]);
        hasher.update(&(region.policies.len() as u64).to_be_bytes());
        for policy in &region.policies {
            hasher.update(&[match policy.anchor {
                kitrove_adapter_api::InstructionTargetAnchor::Scope => 0,
                kitrove_adapter_api::InstructionTargetAnchor::HarnessConfiguration => 1,
            }]);
            for value in [
                policy.harness.as_str(),
                policy.scope.as_str(),
                policy.policy_line.as_str(),
                policy.relative_document.as_str(),
                policy.adapter_version,
                policy.evidence.as_str(),
            ] {
                write_digest_record(hasher, value);
            }
        }
    }
}

fn write_optional_receipt_authority(
    hasher: &mut blake3::Hasher,
    receipt: Option<&DeploymentReceipt>,
) {
    match receipt {
        Some(receipt) => {
            hasher.update(&[1]);
            let receipt_id = receipt
                .receipt_id()
                .expect("planned receipt identity was validated");
            for value in [
                receipt_id.as_str(),
                receipt.source_hash.as_str(),
                receipt.rendered_hash.as_str(),
            ] {
                write_digest_record(hasher, value);
            }
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn write_optional_hash(hasher: &mut blake3::Hasher, hash: Option<&ContentHash>) {
    match hash {
        Some(hash) => {
            hasher.update(&[1]);
            write_digest_record(hasher, hash.as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

const fn disposition_tag(disposition: ApplyDisposition) -> u8 {
    match disposition {
        ApplyDisposition::Install => 0,
        ApplyDisposition::NoOp => 1,
        ApplyDisposition::Restore => 2,
        ApplyDisposition::ManagedUpdate => 3,
        ApplyDisposition::Remove => 4,
    }
}

pub(crate) const fn error(
    code: &'static str,
    message: &'static str,
) -> CoalescedInstructionApplyError {
    CoalescedInstructionApplyError { code, message }
}

pub(crate) const fn projection_invalid() -> CoalescedInstructionApplyError {
    error(
        "instruction_batch.projection_invalid",
        "an instruction projection is not authorized by portable and adapter policy",
    )
}

pub(crate) const fn state_invalid() -> CoalescedInstructionApplyError {
    error(
        "instruction_batch.local_state_invalid",
        "machine-local receipt authority is invalid",
    )
}

#[cfg(test)]
#[path = "instruction_apply_batch_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) use tests::AtomicInstructionFixture;
