use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kitrove_adapter_api::TargetAnchor;
use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    AtomicApplyBatchCommitOutcome, AtomicApplyBatchPlan, AtomicApplyItem,
    InstructionRemovalProjection, InstructionRemovalSelection, McpProjection, McpRemovalSelection,
    commit_atomic_apply_batch, load_native_extension_object, load_portable_agent_object,
    load_portable_mcp_object, load_portable_prompt_command_object, load_portable_skill_object,
    observe_agent_receipt_destination, observe_extension_destination, observe_instruction_document,
    observe_mcp_document, observe_prompt_command_receipt_destination, observe_skill_destination,
    pi_extension_removal_policy, plan_agent_apply, plan_agent_removal,
    plan_coalesced_instruction_removal, plan_coalesced_instruction_removal_selection,
    plan_coalesced_mcp_removal, plan_coalesced_mcp_removal_selection, plan_extension_removal,
    plan_extension_retention, plan_prompt_command_apply, plan_prompt_command_removal,
    plan_skill_apply, plan_skill_removal, render_native_extension, render_portable_skill,
    resolve_extension_destination, resolve_target_destination,
};
use kitrove_model::{
    AssetKind, DeploymentReceipt, EnvironmentManifest, LocalState, ReceiptId, ReceiptTarget,
};
use serde_json::json;

use crate::adapters::{
    receipt_agent_target_policy, receipt_instruction_target_policy, receipt_mcp_target_policy,
    receipt_prompt_command_target_policy, target_policy,
};
use crate::args::{CliError, PackRemoveArgs, RemoveArgs};
use crate::batch_recovery::recover_pending_batch;
use crate::portable::CompletedCommand;
use crate::scan::{
    read_portable_text, resolve_materialization_anchor, resolve_required_environment_root,
    resolve_required_state_root,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn run_remove(
    arguments: RemoveArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    recover_pending(&arguments)?;
    let first = build_removal(&arguments)?;
    let output = render_plan(&first.batch, arguments.json)?;
    if !confirm(&output) {
        return Err(CliError::new(
            "remove.confirmation_required",
            "the removal plan was not confirmed; no changes were made",
        ));
    }
    recover_pending(&arguments)?;
    let refreshed = build_removal(&arguments)?;
    if refreshed.batch.digest() != first.batch.digest() {
        return Err(CliError::new(
            "remove.plan_stale",
            "removal authority changed after confirmation",
        ));
    }
    let outcome = commit_atomic_apply_batch(
        &refreshed.batch,
        &refreshed.environment_root,
        &refreshed.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_result(&refreshed.batch, outcome, arguments.json)?,
        status: 0,
    })
}

pub(crate) fn run_pack_remove(
    arguments: PackRemoveArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    recover_pending_batch(arguments.environment.as_deref())?;
    let first = build_pack_removal(&arguments)?;
    let output = render_pack_removal_plan(&arguments, &first.batch)?;
    if !confirm(&output) {
        return Err(CliError::new(
            "pack_remove.confirmation_required",
            "the pack removal plan was not confirmed; no changes were made",
        ));
    }
    recover_pending_batch(arguments.environment.as_deref())?;
    let refreshed = build_pack_removal(&arguments)?;
    if refreshed.batch.digest() != first.batch.digest() {
        return Err(CliError::new(
            "pack_remove.plan_stale",
            "pack removal authority changed after confirmation",
        ));
    }
    let outcome = commit_atomic_apply_batch(
        &refreshed.batch,
        &refreshed.environment_root,
        &refreshed.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_removal_result(&arguments, &refreshed.batch, outcome)?,
        status: 0,
    })
}

struct PlannedRemoval {
    batch: AtomicApplyBatchPlan,
    environment_root: std::path::PathBuf,
    state_root: std::path::PathBuf,
}

fn build_pack_removal(arguments: &PackRemoveArgs) -> Result<PlannedRemoval, CliError> {
    let environment_root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let state_root = resolve_required_state_root()?;
    let manifest_text = read_portable_text(&environment_root, "kitrove.toml", MAX_CONTROL_BYTES)?
        .ok_or_else(|| {
        CliError::new(
            "cli.environment_manifest_missing",
            "the selected environment does not contain kitrove.toml",
        )
    })?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| {
        CliError::new(
            "cli.environment_manifest_invalid",
            "the selected environment manifest is invalid",
        )
    })?;
    let state_text =
        read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?.ok_or_else(|| {
            CliError::new(
                "pack_remove.local_state_missing",
                "pack removal requires machine-local application authority",
            )
        })?;
    let state = LocalState::from_json(&state_text).map_err(|_| {
        CliError::new(
            "pack_remove.local_state_invalid",
            "machine-local pack application authority is invalid",
        )
    })?;
    let selected_claims = state
        .pack_applications
        .values()
        .filter(|claim| claim.pack_id == arguments.pack_id)
        .collect::<Vec<_>>();
    if selected_claims.is_empty()
        || selected_claims
            .iter()
            .any(|claim| claim.pack_revision != arguments.expected_prior)
    {
        return Err(CliError::new(
            "pack_remove.application_unavailable",
            "the exact pack revision has no unambiguous local application",
        ));
    }
    let mut receipt_anchors = BTreeMap::<ReceiptId, _>::new();
    for claim in selected_claims {
        for receipt_id in &claim.receipts {
            if let Some(anchor) = receipt_anchors.get(receipt_id) {
                if anchor != &claim.target_anchor {
                    return Err(CliError::new(
                        "pack_remove.application_ambiguous",
                        "one pack-owned receipt has conflicting target authority",
                    ));
                }
            } else {
                receipt_anchors.insert(receipt_id.clone(), claim.target_anchor.clone());
            }
        }
    }
    let retained_receipts = state
        .pack_applications
        .values()
        .filter(|claim| claim.pack_id != arguments.pack_id)
        .flat_map(|claim| claim.receipts.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut items = Vec::new();
    let mut instruction_selections = Vec::new();
    let mut mcp_selections = Vec::new();
    for (receipt_id, target_anchor) in receipt_anchors {
        let receipt = state.receipts.get(&receipt_id).ok_or_else(|| {
            CliError::new(
                "pack_remove.application_invalid",
                "pack application authority references a missing receipt",
            )
        })?;
        let asset = manifest.assets.get(&receipt.asset_id).ok_or_else(|| {
            CliError::new(
                "pack_remove.asset_missing",
                "a pack-owned asset is not present in the environment",
            )
        })?;
        let retained = retained_receipts.contains(&receipt_id);
        match asset.kind {
            AssetKind::Skill => items.push(build_pack_skill_transition(
                &manifest,
                &environment_root,
                &state_text,
                receipt,
                &target_anchor,
                retained,
            )?),
            AssetKind::Command => items.push(build_pack_command_transition(
                &manifest,
                &environment_root,
                &state_text,
                receipt,
                &target_anchor,
                retained,
            )?),
            AssetKind::Agent => items.push(build_pack_agent_transition(
                &manifest,
                &environment_root,
                &state_text,
                receipt,
                &target_anchor,
                retained,
            )?),
            AssetKind::Instruction => instruction_selections.push(
                build_pack_instruction_selection(receipt, &target_anchor, retained)?,
            ),
            AssetKind::Mcp => mcp_selections.push(build_pack_mcp_selection(
                &manifest,
                &environment_root,
                receipt,
                &target_anchor,
                retained,
            )?),
            AssetKind::Extension => items.push(build_pack_extension_transition(
                &manifest,
                &environment_root,
                &state_text,
                receipt,
                &target_anchor,
                retained,
            )?),
            _ => {
                return Err(CliError::new(
                    "pack_remove.asset_unsupported",
                    "this pack removal unit does not yet support one selected asset kind",
                ));
            }
        }
    }
    let instructions = (!instruction_selections.is_empty())
        .then(|| {
            plan_coalesced_instruction_removal_selection(
                &manifest,
                instruction_selections,
                &state_text,
                Default::default(),
            )
            .map_err(|error| CliError::new(error.code(), error.message()))
        })
        .transpose()?;
    let mcp = (!mcp_selections.is_empty())
        .then(|| {
            plan_coalesced_mcp_removal_selection(
                &manifest,
                mcp_selections,
                &state_text,
                Default::default(),
            )
            .map_err(|error| CliError::new(error.code(), error.message()))
        })
        .transpose()?;
    let batch = if instructions.is_none() && mcp.is_none() {
        AtomicApplyBatchPlan::new(items, state.machine.active_profile.clone())
    } else {
        AtomicApplyBatchPlan::with_shared_documents(items, instructions, mcp)
    }
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let batch = batch
        .with_pack_application_removal(&manifest, &arguments.pack_id, &arguments.expected_prior)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(PlannedRemoval {
        batch,
        environment_root,
        state_root,
    })
}

fn build_pack_extension_transition(
    manifest: &EnvironmentManifest,
    environment_root: &Path,
    state_text: &str,
    receipt: &kitrove_model::DeploymentReceipt,
    target_anchor: &kitrove_model::NormalizedDestination,
    retained: bool,
) -> Result<AtomicApplyItem, CliError> {
    let policy = pi_extension_removal_policy(receipt.scope)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let object = load_native_extension_object(
        manifest,
        &receipt.asset_id,
        &kitrove_model::HarnessId::Pi,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let rendered = render_native_extension(&object, &policy)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let destination =
        resolve_extension_destination(Path::new(target_anchor.as_str()), &policy, &rendered)
            .map_err(|error| CliError::new(error.code(), error.message()))?;
    if destination != receipt.destination {
        return Err(pack_destination_mismatch());
    }
    let observation = observe_extension_destination(
        Path::new(destination.as_str()),
        &object,
        CaptureLimits::default(),
    );
    let plan = if retained {
        plan_extension_retention(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            Path::new(target_anchor.as_str()),
            state_text,
            observation,
        )
    } else {
        plan_extension_removal(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            Path::new(target_anchor.as_str()),
            state_text,
            observation,
        )
    }
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(AtomicApplyItem::Extension(plan))
}

fn build_pack_instruction_selection(
    receipt: &kitrove_model::DeploymentReceipt,
    target_anchor: &kitrove_model::NormalizedDestination,
    retained: bool,
) -> Result<InstructionRemovalSelection, CliError> {
    let mut projections = Vec::new();
    for consumer in receipt.consumers() {
        let policy = receipt_instruction_target_policy(consumer, receipt.scope)?;
        let observation = observe_instruction_document(
            Path::new(target_anchor.as_str()),
            &policy,
            Default::default(),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        if observation.destination() != &receipt.destination {
            return Err(pack_destination_mismatch());
        }
        projections.push(InstructionRemovalProjection::new(policy, observation));
    }
    Ok(if retained {
        InstructionRemovalSelection::retain(receipt.asset_id.clone(), projections)
    } else {
        InstructionRemovalSelection::remove(receipt.asset_id.clone(), projections)
    })
}

fn build_pack_mcp_selection(
    manifest: &EnvironmentManifest,
    environment_root: &Path,
    receipt: &kitrove_model::DeploymentReceipt,
    target_anchor: &kitrove_model::NormalizedDestination,
    retained: bool,
) -> Result<McpRemovalSelection, CliError> {
    let policy = receipt_mcp_target_policy(&receipt.harness, receipt.scope)?;
    let object = load_portable_mcp_object(
        manifest,
        &receipt.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_mcp_document(
        Path::new(target_anchor.as_str()),
        &policy,
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    if observation.destination() != &receipt.destination {
        return Err(pack_destination_mismatch());
    }
    let projection = McpProjection::new(receipt.asset_id.clone(), object, policy, observation);
    Ok(if retained {
        McpRemovalSelection::retain(projection)
    } else {
        McpRemovalSelection::remove(projection)
    })
}

fn build_pack_skill_transition(
    manifest: &EnvironmentManifest,
    environment_root: &Path,
    state_text: &str,
    receipt: &kitrove_model::DeploymentReceipt,
    target_anchor: &kitrove_model::NormalizedDestination,
    retained: bool,
) -> Result<AtomicApplyItem, CliError> {
    let policy = target_policy(&receipt.harness, receipt.scope)?;
    let object = load_portable_skill_object(
        manifest,
        &receipt.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let rendered = render_portable_skill(&object, &policy)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let destination = resolve_target_destination(
        Path::new(target_anchor.as_str()),
        &policy,
        rendered.package_name(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    if destination != receipt.destination {
        return Err(pack_destination_mismatch());
    }
    let observation =
        observe_skill_destination(Path::new(destination.as_str()), CaptureLimits::default());
    let plan = if retained {
        plan_skill_apply(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            Path::new(target_anchor.as_str()),
            state_text,
            observation,
        )
    } else {
        plan_skill_removal(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            Path::new(target_anchor.as_str()),
            state_text,
            observation,
        )
    }
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(AtomicApplyItem::Skill(plan))
}

fn build_pack_command_transition(
    manifest: &EnvironmentManifest,
    environment_root: &Path,
    state_text: &str,
    receipt: &kitrove_model::DeploymentReceipt,
    target_anchor: &kitrove_model::NormalizedDestination,
    retained: bool,
) -> Result<AtomicApplyItem, CliError> {
    let policy = receipt_prompt_command_target_policy(&receipt.harness, receipt.scope)?;
    let object = load_portable_prompt_command_object(
        manifest,
        &receipt.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_prompt_command_receipt_destination(
        Path::new(target_anchor.as_str()),
        &policy,
        receipt,
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    if retained {
        plan_prompt_command_apply(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            &observation,
            state_text,
        )
        .map(AtomicApplyItem::PromptCommand)
    } else {
        plan_prompt_command_removal(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            &observation,
            state_text,
        )
        .map(AtomicApplyItem::PromptCommandRemoval)
    }
    .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_pack_agent_transition(
    manifest: &EnvironmentManifest,
    environment_root: &Path,
    state_text: &str,
    receipt: &kitrove_model::DeploymentReceipt,
    target_anchor: &kitrove_model::NormalizedDestination,
    retained: bool,
) -> Result<AtomicApplyItem, CliError> {
    let policy = receipt_agent_target_policy(&receipt.harness, receipt.scope)?;
    let object = load_portable_agent_object(
        manifest,
        &receipt.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_agent_receipt_destination(
        Path::new(target_anchor.as_str()),
        &policy,
        receipt,
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    if retained {
        plan_agent_apply(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            &observation,
            state_text,
        )
        .map(AtomicApplyItem::Agent)
    } else {
        plan_agent_removal(
            manifest,
            &receipt.asset_id,
            &object,
            &policy,
            &observation,
            state_text,
        )
        .map(AtomicApplyItem::AgentRemoval)
    }
    .map_err(|error| CliError::new(error.code(), error.message()))
}

const fn pack_destination_mismatch() -> CliError {
    CliError::new(
        "pack_remove.destination_mismatch",
        "a pack-owned receipt is outside its exact target authority",
    )
}

fn build_removal(arguments: &RemoveArgs) -> Result<PlannedRemoval, CliError> {
    let environment_root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let state_root = resolve_required_state_root()?;
    let manifest_text = read_portable_text(&environment_root, "kitrove.toml", MAX_CONTROL_BYTES)?
        .ok_or_else(|| {
        CliError::new(
            "cli.environment_manifest_missing",
            "the selected environment does not contain kitrove.toml",
        )
    })?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| {
        CliError::new(
            "cli.environment_manifest_invalid",
            "the selected environment manifest is invalid",
        )
    })?;
    let state_text =
        read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?.ok_or_else(|| {
            CliError::new(
                "remove.local_state_missing",
                "removal requires existing machine-local receipt authority",
            )
        })?;
    let state = LocalState::from_json(&state_text).map_err(|_| {
        CliError::new(
            "remove.local_state_invalid",
            "machine-local receipt authority is invalid",
        )
    })?;
    let asset = manifest.assets.get(&arguments.asset_id).ok_or_else(|| {
        CliError::new(
            "remove.asset_missing",
            "the selected asset is not present in the environment",
        )
    })?;
    let base_anchor =
        resolve_materialization_anchor(arguments.scope, arguments.project_root.as_deref())?;
    let anchor = removal_policy_anchor(arguments, base_anchor);
    let batch = match asset.kind {
        AssetKind::Instruction => {
            build_instruction_removal(arguments, &manifest, &state, &state_text, &anchor)?
        }
        AssetKind::Command => build_prompt_command_removal(
            arguments,
            &manifest,
            &state,
            &state_text,
            &environment_root,
            &anchor,
        )?,
        AssetKind::Agent => build_agent_removal(
            arguments,
            &manifest,
            &state,
            &state_text,
            &environment_root,
            &anchor,
        )?,
        AssetKind::Mcp => build_mcp_removal(
            arguments,
            &manifest,
            &state,
            &state_text,
            &environment_root,
            &anchor,
        )?,
        _ => {
            return Err(CliError::new(
                "remove.asset_unsupported",
                "the selected asset kind has no receipt-backed removal workflow",
            ));
        }
    };
    Ok(PlannedRemoval {
        batch,
        environment_root,
        state_root,
    })
}

fn build_mcp_removal(
    arguments: &RemoveArgs,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    state_text: &str,
    environment_root: &std::path::Path,
    anchor: &std::path::Path,
) -> Result<AtomicApplyBatchPlan, CliError> {
    let policy = receipt_mcp_target_policy(&arguments.target, arguments.scope)?;
    require_resolved_anchor(&arguments.target, policy.anchor)?;
    let object = load_portable_mcp_object(
        manifest,
        &arguments.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_mcp_document(anchor, &policy, Default::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let native_name = object.server().name().as_str();
    let matching = state
        .receipts
        .values()
        .filter(|receipt| {
            receipt.asset_id == arguments.asset_id
                && receipt.harness == arguments.target
                && receipt.scope == arguments.scope
                && receipt.destination == *observation.destination()
                && receipt.target == ReceiptTarget::ManagedMcpEntry
                && receipt.logical_key.as_deref() == Some(native_name)
                && receipt.shared_with.is_empty()
        })
        .count();
    if matching != 1 {
        return Err(CliError::new(
            "remove.receipt_unavailable",
            "the selected target does not have one exact managed MCP receipt",
        ));
    }
    let removal = plan_coalesced_mcp_removal(
        manifest,
        vec![McpProjection::new(
            arguments.asset_id.clone(),
            object,
            policy,
            observation,
        )],
        state_text,
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    AtomicApplyBatchPlan::with_mcp(Vec::new(), removal)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_instruction_removal(
    arguments: &RemoveArgs,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    state_text: &str,
    anchor: &std::path::Path,
) -> Result<AtomicApplyBatchPlan, CliError> {
    let selected_policy = receipt_instruction_target_policy(&arguments.target, arguments.scope)?;
    let selected_observation =
        observe_instruction_document(anchor, &selected_policy, Default::default())
            .map_err(|error| CliError::new(error.code(), error.message()))?;
    let matching = state
        .receipts
        .values()
        .filter(|receipt| {
            receipt.asset_id == arguments.asset_id
                && receipt.scope == arguments.scope
                && receipt.destination == *selected_observation.destination()
                && receipt.target == ReceiptTarget::ManagedInstructionRegion
                && receipt
                    .consumers()
                    .any(|consumer| consumer == &arguments.target)
        })
        .collect::<Vec<_>>();
    let [receipt] = matching.as_slice() else {
        return Err(CliError::new(
            "remove.receipt_unavailable",
            "the selected target does not have one exact managed instruction receipt",
        ));
    };
    let mut projections = Vec::new();
    for consumer in receipt.consumers() {
        let policy = receipt_instruction_target_policy(consumer, arguments.scope)?;
        let observation = observe_instruction_document(anchor, &policy, Default::default())
            .map_err(|error| CliError::new(error.code(), error.message()))?;
        projections.push(InstructionRemovalProjection::new(policy, observation));
    }
    let instructions = plan_coalesced_instruction_removal(
        manifest,
        &arguments.asset_id,
        projections,
        state_text,
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    AtomicApplyBatchPlan::with_instructions(Vec::new(), instructions)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_prompt_command_removal(
    arguments: &RemoveArgs,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    state_text: &str,
    environment_root: &std::path::Path,
    anchor: &std::path::Path,
) -> Result<AtomicApplyBatchPlan, CliError> {
    let policy = receipt_prompt_command_target_policy(&arguments.target, arguments.scope)?;
    require_resolved_anchor(&arguments.target, policy.anchor)?;
    let object = load_portable_prompt_command_object(
        manifest,
        &arguments.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let receipt = select_whole_target_receipt(
        state,
        arguments,
        "the selected target does not have one exact managed prompt-command receipt",
    )?;
    let observation =
        observe_prompt_command_receipt_destination(anchor, &policy, receipt, Default::default())
            .map_err(|error| CliError::new(error.code(), error.message()))?;
    let plan = plan_prompt_command_removal(
        manifest,
        &arguments.asset_id,
        &object,
        &policy,
        &observation,
        state_text,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    AtomicApplyBatchPlan::new(vec![AtomicApplyItem::PromptCommandRemoval(plan)], None)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_agent_removal(
    arguments: &RemoveArgs,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    state_text: &str,
    environment_root: &std::path::Path,
    anchor: &std::path::Path,
) -> Result<AtomicApplyBatchPlan, CliError> {
    let policy = receipt_agent_target_policy(&arguments.target, arguments.scope)?;
    require_resolved_anchor(&arguments.target, policy.anchor)?;
    let object = load_portable_agent_object(
        manifest,
        &arguments.asset_id,
        environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let receipt = select_whole_target_receipt(
        state,
        arguments,
        "the selected target does not have one exact managed agent receipt",
    )?;
    let observation =
        observe_agent_receipt_destination(anchor, &policy, receipt, Default::default())
            .map_err(|error| CliError::new(error.code(), error.message()))?;
    let plan = plan_agent_removal(
        manifest,
        &arguments.asset_id,
        &object,
        &policy,
        &observation,
        state_text,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    AtomicApplyBatchPlan::new(vec![AtomicApplyItem::AgentRemoval(plan)], None)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

fn select_whole_target_receipt<'a>(
    state: &'a LocalState,
    arguments: &RemoveArgs,
    unavailable_message: &'static str,
) -> Result<&'a DeploymentReceipt, CliError> {
    let matching = state
        .receipts
        .values()
        .filter(|receipt| {
            receipt.asset_id == arguments.asset_id
                && receipt.harness == arguments.target
                && receipt.scope == arguments.scope
                && receipt.target == ReceiptTarget::WholeTarget
                && receipt.shared_with.is_empty()
        })
        .collect::<Vec<_>>();
    let [receipt] = matching.as_slice() else {
        return Err(CliError::new(
            "remove.receipt_unavailable",
            unavailable_message,
        ));
    };
    Ok(receipt)
}

fn removal_policy_anchor(arguments: &RemoveArgs, base: std::path::PathBuf) -> std::path::PathBuf {
    if arguments.target == kitrove_model::HarnessId::OpenCode
        && arguments.scope == kitrove_model::HarnessScope::User
    {
        base.join(".config/opencode")
    } else {
        base
    }
}

fn require_resolved_anchor(
    harness: &kitrove_model::HarnessId,
    anchor: TargetAnchor,
) -> Result<(), CliError> {
    if anchor == TargetAnchor::Scope
        || (harness == &kitrove_model::HarnessId::OpenCode
            && anchor == TargetAnchor::HarnessConfiguration)
    {
        return Ok(());
    }
    Err(CliError::new(
        "remove.harness_configuration_anchor_unavailable",
        "the selected harness configuration root has not been verified locally",
    ))
}

fn recover_pending(arguments: &RemoveArgs) -> Result<(), CliError> {
    recover_pending_batch(arguments.environment.as_deref())
}

fn render_pack_removal_plan(
    arguments: &PackRemoveArgs,
    batch: &AtomicApplyBatchPlan,
) -> Result<String, CliError> {
    let (removed, retained) =
        batch
            .items()
            .iter()
            .fold((0usize, 0usize), |(removed, retained), item| match item {
                AtomicApplyItem::Instruction(plan) => plan.document().regions().iter().fold(
                    (removed, retained),
                    |(removed, retained), region| {
                        if region.disposition() == kitrove_core::ApplyDisposition::Remove {
                            (removed + 1, retained)
                        } else {
                            (removed, retained + 1)
                        }
                    },
                ),
                AtomicApplyItem::Mcp(plan) => plan.document().entries().iter().fold(
                    (removed, retained),
                    |(removed, retained), entry| {
                        if entry.disposition() == kitrove_core::ApplyDisposition::Remove {
                            (removed + 1, retained)
                        } else {
                            (removed, retained + 1)
                        }
                    },
                ),
                item if item.disposition() == kitrove_core::ApplyDisposition::Remove => {
                    (removed + 1, retained)
                }
                _ => (removed, retained + 1),
            });
    if arguments.json {
        return json_line(json!({
            "schema_version": 1,
            "operation": "pack_remove",
            "phase": "planned",
            "semantics": "atomic_reference_aware",
            "batch_digest": batch.digest().as_str(),
            "pack_id": arguments.pack_id.as_str(),
            "expected_prior": arguments.expected_prior.as_str(),
            "removed_receipts": removed,
            "retained_shared_receipts": retained,
        }));
    }
    Ok(format!(
        "pack removal plan: {}\npack: {}\nrevision: {}\nremove receipts: {}\nretain shared receipts: {}\nsemantics: exact reference-aware atomic removal; portable authority is retained\n",
        batch.digest(),
        arguments.pack_id,
        arguments.expected_prior,
        removed,
        retained,
    ))
}

fn render_pack_removal_result(
    arguments: &PackRemoveArgs,
    batch: &AtomicApplyBatchPlan,
    outcome: AtomicApplyBatchCommitOutcome,
) -> Result<String, CliError> {
    let outcome = match outcome {
        AtomicApplyBatchCommitOutcome::Committed => "committed",
    };
    if arguments.json {
        return json_line(json!({
            "schema_version": 1,
            "operation": "pack_remove",
            "phase": "complete",
            "batch_digest": batch.digest().as_str(),
            "pack_id": arguments.pack_id.as_str(),
            "outcome": outcome,
        }));
    }
    Ok(format!(
        "pack removal complete: {}\npack: {}\noutcome: {}\n",
        batch.digest(),
        arguments.pack_id,
        outcome,
    ))
}

fn render_plan(batch: &AtomicApplyBatchPlan, json_output: bool) -> Result<String, CliError> {
    if let [AtomicApplyItem::PromptCommandRemoval(plan)] = batch.items() {
        return render_whole_target_removal_plan(
            &WholeTargetRemovalRender {
                batch_digest: batch.digest(),
                asset_id: plan.asset_id().as_str(),
                target: plan.policy().harness.as_str(),
                scope: plan.policy().scope.as_str(),
                relative_destination: plan.relative_destination().as_str(),
                kind: "prompt-command",
                operation: "remove_prompt_command",
            },
            json_output,
        );
    }
    if let [AtomicApplyItem::AgentRemoval(plan)] = batch.items() {
        return render_whole_target_removal_plan(
            &WholeTargetRemovalRender {
                batch_digest: batch.digest(),
                asset_id: plan.asset_id().as_str(),
                target: plan.policy().harness.as_str(),
                scope: plan.policy().scope.as_str(),
                relative_destination: plan.relative_destination().as_str(),
                kind: "agent",
                operation: "remove_agent",
            },
            json_output,
        );
    }
    if let Some((document, entry)) = mcp_removal(batch) {
        if json_output {
            return json_line(json!({
                "schema_version": 1,
                "operation": "remove_mcp_entry",
                "phase": "planned",
                "semantics": "atomic",
                "batch_digest": batch.digest().as_str(),
                "asset_id": entry.asset_id().as_str(),
                "native_name": entry.native_name(),
                "target": entry.policy().harness.as_str(),
                "scope": entry.policy().scope.as_str(),
                "relative_destination": document.relative_destination().as_str(),
                "resulting_document_hash": document.rendered().document_hash().as_str(),
            }));
        }
        return Ok(format!(
            "MCP removal plan: {}\nasset: {}\nserver: {}\ntarget: {}\nscope: {}\nrelative destination: {}\nsemantics: exact receipt-backed logical-entry removal; portable authority and co-owned document content are retained\n",
            batch.digest(),
            entry.asset_id(),
            entry.native_name(),
            entry.policy().harness,
            entry.policy().scope.as_str(),
            document.relative_destination(),
        ));
    }
    let document = instruction_document(batch)?;
    let region = document.regions().first().ok_or_else(render_error)?;
    let targets = region
        .policies()
        .iter()
        .map(|policy| policy.harness.as_str())
        .collect::<Vec<_>>();
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": "remove_instruction",
            "phase": "planned",
            "semantics": "atomic",
            "batch_digest": batch.digest().as_str(),
            "asset_id": region.asset_id().as_str(),
            "targets": targets,
            "scope": region.policies()[0].scope.as_str(),
            "relative_destination": document.relative_destination().as_str(),
            "resulting_document_hash": document.rendered().document_hash().as_str(),
        }));
    }
    Ok(format!(
        "instruction removal plan: {}\nasset: {}\ntargets: {}\nscope: {}\nrelative destination: {}\nsemantics: exact receipt-backed region removal; portable authority is retained\n",
        batch.digest(),
        region.asset_id(),
        targets.join(","),
        region.policies()[0].scope.as_str(),
        document.relative_destination(),
    ))
}

fn render_result(
    batch: &AtomicApplyBatchPlan,
    outcome: AtomicApplyBatchCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if let [AtomicApplyItem::PromptCommandRemoval(plan)] = batch.items() {
        return render_whole_target_removal_result(
            &WholeTargetRemovalRender {
                batch_digest: batch.digest(),
                asset_id: plan.asset_id().as_str(),
                target: plan.policy().harness.as_str(),
                scope: plan.policy().scope.as_str(),
                relative_destination: plan.relative_destination().as_str(),
                kind: "prompt-command",
                operation: "remove_prompt_command",
            },
            outcome,
            json_output,
        );
    }
    if let [AtomicApplyItem::AgentRemoval(plan)] = batch.items() {
        return render_whole_target_removal_result(
            &WholeTargetRemovalRender {
                batch_digest: batch.digest(),
                asset_id: plan.asset_id().as_str(),
                target: plan.policy().harness.as_str(),
                scope: plan.policy().scope.as_str(),
                relative_destination: plan.relative_destination().as_str(),
                kind: "agent",
                operation: "remove_agent",
            },
            outcome,
            json_output,
        );
    }
    if let Some((_document, entry)) = mcp_removal(batch) {
        if json_output {
            return json_line(json!({
                "schema_version": 1,
                "operation": "remove_mcp_entry",
                "phase": "complete",
                "batch_digest": batch.digest().as_str(),
                "asset_id": entry.asset_id().as_str(),
                "native_name": entry.native_name(),
                "outcome": match outcome { AtomicApplyBatchCommitOutcome::Committed => "committed" },
            }));
        }
        return Ok(format!(
            "MCP removal complete: {}\nasset: {}\nserver: {}\noutcome: committed\n",
            batch.digest(),
            entry.asset_id(),
            entry.native_name(),
        ));
    }
    let document = instruction_document(batch)?;
    let region = document.regions().first().ok_or_else(render_error)?;
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": "remove_instruction",
            "phase": "complete",
            "batch_digest": batch.digest().as_str(),
            "asset_id": region.asset_id().as_str(),
            "outcome": match outcome { AtomicApplyBatchCommitOutcome::Committed => "committed" },
        }));
    }
    Ok(format!(
        "instruction removal complete: {}\nasset: {}\noutcome: committed\n",
        batch.digest(),
        region.asset_id(),
    ))
}

struct WholeTargetRemovalRender<'a> {
    batch_digest: &'a kitrove_model::ContentHash,
    asset_id: &'a str,
    target: &'a str,
    scope: &'a str,
    relative_destination: &'a str,
    kind: &'static str,
    operation: &'static str,
}

fn render_whole_target_removal_plan(
    view: &WholeTargetRemovalRender<'_>,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": view.operation,
            "phase": "planned",
            "semantics": "atomic",
            "batch_digest": view.batch_digest.as_str(),
            "asset_id": view.asset_id,
            "target": view.target,
            "scope": view.scope,
            "relative_destination": view.relative_destination,
        }));
    }
    Ok(format!(
        "{} removal plan: {}\nasset: {}\ntarget: {}\nscope: {}\nrelative destination: {}\nsemantics: exact receipt-backed whole-file removal; portable authority is retained\n",
        view.kind,
        view.batch_digest,
        view.asset_id,
        view.target,
        view.scope,
        view.relative_destination,
    ))
}

fn render_whole_target_removal_result(
    view: &WholeTargetRemovalRender<'_>,
    outcome: AtomicApplyBatchCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    let outcome = match outcome {
        AtomicApplyBatchCommitOutcome::Committed => "committed",
    };
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": view.operation,
            "phase": "complete",
            "batch_digest": view.batch_digest.as_str(),
            "asset_id": view.asset_id,
            "outcome": outcome,
        }));
    }
    Ok(format!(
        "{} removal complete: {}\nasset: {}\noutcome: {outcome}\n",
        view.kind, view.batch_digest, view.asset_id,
    ))
}

fn mcp_removal(
    batch: &AtomicApplyBatchPlan,
) -> Option<(
    &kitrove_core::CoalescedMcpDocument,
    &kitrove_core::CoalescedMcpEntry,
)> {
    let [AtomicApplyItem::Mcp(plan)] = batch.items() else {
        return None;
    };
    let [entry] = plan.document().entries() else {
        return None;
    };
    (entry.disposition() == kitrove_core::ApplyDisposition::Remove)
        .then_some((plan.document(), entry))
}

fn instruction_document(
    batch: &AtomicApplyBatchPlan,
) -> Result<&kitrove_core::CoalescedInstructionDocument, CliError> {
    match batch.items() {
        [kitrove_core::AtomicApplyItem::Instruction(plan)] => Ok(plan.document()),
        _ => Err(render_error()),
    }
}

fn json_line(value: serde_json::Value) -> Result<String, CliError> {
    serde_json::to_string(&value)
        .map(|encoded| format!("{encoded}\n"))
        .map_err(|_| render_error())
}

const fn render_error() -> CliError {
    CliError::new(
        "remove.output_failed",
        "the removal result could not be rendered",
    )
}
