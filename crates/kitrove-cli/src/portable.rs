use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use kitrove_adapter_api::ScopeSelection;
use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    AdoptionBlockReason, AdoptionCommitOutcome, AdoptionDisposition, AdoptionPlan,
    AdoptionPlanOutcome, AgentAdoptionOutcome, AgentAdoptionPlan, AgentUpdatePlan,
    InstructionAdoptionOutcome, InstructionAdoptionPlan, InstructionUpdatePlan, LockRepairOutcome,
    LockStatus, McpAdoptionOutcome, McpAdoptionPlan, McpUpdatePlan, NativeExtensionPlan,
    ObjectKind, ObjectState, PolicyRegistry, PortableJournalStatus, PromptCommandAdoptionOutcome,
    PromptCommandAdoptionPlan, PromptCommandUpdatePlan, UpdateCommitOutcome, UpdatePlan,
    UpdateRecoveryOutcome, UpdateSourceAuthority, VerifiedObjectEnvelope,
    VerifiedSkillObjectCatalog, commit_adoption, commit_agent_adoption, commit_agent_update,
    commit_instruction_adoption, commit_instruction_update, commit_lock_repair,
    commit_mcp_adoption, commit_mcp_update, commit_native_extension_plan,
    commit_prompt_command_adoption, commit_prompt_command_update, commit_update_adoption,
    inspect_portable_environment, inspect_portable_journal, load_native_skill_object,
    plan_adoption, plan_agent_adoption, plan_agent_update, plan_instruction_adoption,
    plan_instruction_update, plan_lock_repair, plan_mcp_adoption, plan_mcp_update,
    plan_native_extension_adoption, plan_native_extension_update, plan_prompt_command_adoption,
    plan_prompt_command_update, plan_update_adoption, recover_update_adoption,
};
use kitrove_model::{EnvironmentManifest, HarnessId, SyncLimits};
use serde_json::json;

use crate::adapters::{
    tier_one_agent_capabilities, tier_one_capabilities, tier_one_instruction_capabilities,
    tier_one_mcp_capabilities, tier_one_prompt_command_capabilities,
};
use crate::args::{AdoptArgs, CliError, EnvironmentArgs, ScanArgs};
use crate::scan::{
    read_portable_text, resolve_required_environment_root, resolve_required_state_root, scan_report,
};
use crate::sync::load_local_snapshot_exact;

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

pub(crate) struct CompletedCommand {
    pub output: String,
    pub status: u8,
}

pub(crate) fn run_status(arguments: EnvironmentArgs) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let status =
        inspect_portable_environment(&root, CaptureLimits::default()).map_err(transaction_error)?;
    let output = if arguments.json {
        let objects = status
            .objects()
            .findings()
            .iter()
            .map(|finding| {
                json!({
                    "asset_id": finding.asset_id().as_str(),
                    "harness": finding.harness().map(HarnessId::as_str),
                    "kind": object_kind(finding.kind()),
                    "root": finding.root().as_str(),
                    "state": object_state(finding.state()),
                    "expected_hash": finding.expected_hash().as_str(),
                    "actual_hash": finding.actual_hash().map(|hash| hash.as_str()),
                })
            })
            .collect::<Vec<_>>();
        format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "clean": status.is_clean(),
                "manifest_revision": status.manifest_revision().as_str(),
                "lock": lock_status(status.lock_status()),
                "journal": journal_status(status.journal_status()),
                "objects": objects,
            }))
            .map_err(serialization_error)?
        )
    } else {
        let mut rendered = format!(
            "portable status: {}\nmanifest revision: {}\nlock: {}\njournal: {}\n",
            if status.is_clean() {
                "clean"
            } else {
                "attention"
            },
            status.manifest_revision(),
            lock_status(status.lock_status()),
            journal_status(status.journal_status()),
        );
        for finding in status.objects().findings() {
            writeln!(
                rendered,
                "object {} {} {}: {}",
                finding.asset_id(),
                object_kind(finding.kind()),
                finding.harness().map_or("shared", HarnessId::as_str),
                object_state(finding.state()),
            )
            .expect("writing to a string cannot fail");
        }
        rendered
    };
    Ok(CompletedCommand {
        output,
        status: if status.is_clean() { 0 } else { 3 },
    })
}

pub(crate) fn run_lock(arguments: EnvironmentArgs) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let stored_lock = read_portable_text(&root, "kitrove.lock.json", MAX_CONTROL_BYTES)?;
    let plan = plan_lock_repair(&manifest, stored_lock.as_deref()).map_err(transaction_error)?;
    let prior = plan.observed_status();
    let digest = plan.digest().as_str().to_owned();
    let outcome =
        commit_lock_repair(&plan, &root, CaptureLimits::default()).map_err(transaction_error)?;
    let output = if arguments.json {
        format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "lock",
                "plan_digest": digest,
                "prior_status": lock_status(prior),
                "outcome": lock_outcome(outcome),
            }))
            .map_err(serialization_error)?
        )
    } else {
        format!(
            "lock plan {}: {} -> in_sync\nlock outcome: {}\n",
            digest,
            lock_status(prior),
            lock_outcome(outcome),
        )
    };
    Ok(CompletedCommand { output, status: 0 })
}

pub(crate) fn run_adopt(
    arguments: AdoptArgs,
    registry: &PolicyRegistry,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let AdoptArgs {
        observation_id,
        asset_id,
        update_asset_id,
        expected_prior,
        binding,
        harnesses,
        scope,
        project_root,
        roots,
        environment,
        json,
    } = arguments;
    let root = resolve_required_environment_root(environment.as_deref())?;
    let selection = AdoptionSelection {
        harnesses,
        scope,
        project_root,
        roots,
    };
    if update_asset_id.is_some() {
        match inspect_portable_journal(&root).map_err(transaction_error)? {
            PortableJournalStatus::Pending => {
                let state_root = resolve_required_state_root()?;
                let recovered =
                    recover_update_adoption(&root, &state_root, CaptureLimits::default())
                        .map_err(transaction_error)?;
                return Ok(CompletedCommand {
                    output: render_update_recovery(recovered, json)?,
                    status: 0,
                });
            }
            PortableJournalStatus::Invalid => {
                return Err(CliError::new(
                    "transaction.journal_invalid",
                    "the portable transaction journal is invalid and cannot be recovered",
                ));
            }
            PortableJournalStatus::Absent => {}
        }
    }
    let manifest = load_manifest(&root)?;
    let scan_arguments = adoption_scan_args(root.clone(), &selection);
    let report = scan_report(scan_arguments, registry)?;
    if let Some((entry, observation, selected_entry_hash)) =
        select_mcp_observation(&report, &observation_id)
    {
        let capabilities = tier_one_mcp_capabilities()?;
        if let (Some(update_asset_id), Some(expected_prior)) =
            (update_asset_id.as_ref(), expected_prior.as_ref())
        {
            let (manifest_text, lock_text) = read_update_authority(&root)?;
            let plan = plan_mcp_update(
                observation,
                selected_entry_hash,
                update_asset_id,
                expected_prior,
                binding.as_ref(),
                &manifest_text,
                &manifest,
                lock_text.as_deref(),
                &capabilities,
            )
            .map_err(|error| CliError::new(error.code(), error.message()))?;
            let output = render_mcp_update_plan(&plan, json)?;
            if !confirm(&output) {
                return Err(CliError::new(
                    "update.confirmation_required",
                    "the MCP update plan was not confirmed; no changes were made",
                ));
            }
            let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
            let (_, current, _) =
                select_mcp_observation(&reread, plan.selected_entry_hash().as_str())
                    .ok_or_else(update_observation_stale)?;
            let committed = commit_mcp_update(&plan, current, &root, CaptureLimits::default())
                .map_err(transaction_error)?;
            return Ok(CompletedCommand {
                output: render_mcp_update_result(&plan, committed, json)?,
                status: 0,
            });
        }
        let asset_id = match asset_id {
            Some(asset_id) => asset_id,
            None => {
                kitrove_model::AssetId::parse(entry.portable_name.as_deref().ok_or_else(|| {
                    CliError::new(
                        "mcp_adoption.asset_id_required",
                        "the blocked MCP entry requires an explicit --id",
                    )
                })?)
                .map_err(|_| {
                    CliError::new(
                        "mcp_adoption.asset_id_required",
                        "the MCP name is not a valid default asset identifier; use --id",
                    )
                })?
            }
        };
        let outcome = plan_mcp_adoption(
            observation,
            selected_entry_hash,
            &asset_id,
            binding.as_ref(),
            &manifest,
            &capabilities,
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let plan = match outcome {
            McpAdoptionOutcome::Ready(plan) => plan,
            McpAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_mcp_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let output = render_mcp_adoption_plan(&plan, json)?;
        if !confirm(&output) {
            return Err(CliError::new(
                "adoption.confirmation_required",
                "the adoption plan was not confirmed; no changes were made",
            ));
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let (_, current, _) = select_mcp_observation(&reread, plan.selected_entry_hash().as_str())
            .ok_or_else(observation_stale)?;
        let committed = commit_mcp_adoption(&plan, current, &root, CaptureLimits::default())
            .map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_mcp_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if binding.is_some() {
        return Err(CliError::new(
            "mcp_adoption.binding_unexpected",
            "--binding is valid only when selecting an MCP declaration",
        ));
    }
    let prompt_command_observation = if update_asset_id.is_none() {
        select_prompt_command_observation(&report, &observation_id)
    } else {
        None
    };
    if let Some(observation) = prompt_command_observation {
        if expected_prior.is_some() {
            return Err(CliError::new(
                "prompt_command_update.authority_incomplete",
                "prompt-command updates require both --update and --expected-prior",
            ));
        }
        let asset_id = match asset_id {
            Some(asset_id) => asset_id,
            None => kitrove_model::AssetId::parse(observation.observed().name().as_str()).map_err(
                |_| {
                    CliError::new(
                        "prompt_command_adoption.asset_id_required",
                        "the prompt-command name is not a valid default asset identifier; use --id",
                    )
                },
            )?,
        };
        let capabilities = tier_one_prompt_command_capabilities()?;
        let outcome =
            plan_prompt_command_adoption(observation, &asset_id, &manifest, &capabilities)
                .map_err(|error| CliError::new(error.code(), error.message()))?;
        let plan = match outcome {
            PromptCommandAdoptionOutcome::Ready(plan) => plan,
            PromptCommandAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_prompt_command_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let output = render_prompt_command_adoption_plan(&plan, json)?;
        if !confirm(&output) {
            return Err(CliError::new(
                "adoption.confirmation_required",
                "the adoption plan was not confirmed; no changes were made",
            ));
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let current = select_prompt_command_observation(&reread, observation.identity().as_str())
            .ok_or_else(observation_stale)?;
        let committed =
            commit_prompt_command_adoption(&plan, current, &root, CaptureLimits::default())
                .map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_prompt_command_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if let (Some(update_asset_id), Some(expected_prior)) =
        (update_asset_id.as_ref(), expected_prior.as_ref())
    {
        if let Some(observation) = select_prompt_command_observation(&report, &observation_id) {
            return run_prompt_command_update(
                observation.clone(),
                update_asset_id,
                expected_prior,
                selection,
                root,
                manifest,
                registry,
                json,
                confirm,
            );
        }
        if let Some(observation) = select_agent_observation(&report, &observation_id) {
            return run_agent_update(
                observation.clone(),
                update_asset_id,
                expected_prior,
                selection,
                root,
                manifest,
                registry,
                json,
                confirm,
            );
        }
    }
    let agent_observation = if update_asset_id.is_none() {
        report
            .agent_observations()
            .iter()
            .find(|observation| observation.identity().as_str() == observation_id)
    } else {
        None
    };
    if let Some(observation) = agent_observation {
        if expected_prior.is_some() {
            return Err(CliError::new(
                "agent_update.authority_incomplete",
                "agent updates require both --update and --expected-prior",
            ));
        }
        let asset_id = match asset_id {
            Some(asset_id) => asset_id,
            None => kitrove_model::AssetId::parse(observation.observed().name().as_str()).map_err(
                |_| {
                    CliError::new(
                        "agent_adoption.asset_id_required",
                        "the agent name is not a valid default asset identifier; use --id",
                    )
                },
            )?,
        };
        let outcome = plan_agent_adoption(
            observation,
            &asset_id,
            &manifest,
            &tier_one_agent_capabilities()?,
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let plan = match outcome {
            AgentAdoptionOutcome::Ready(plan) => plan,
            AgentAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_agent_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let output = render_agent_adoption_plan(&plan, json)?;
        if !confirm(&output) {
            return Err(CliError::new(
                "adoption.confirmation_required",
                "the adoption plan was not confirmed; no changes were made",
            ));
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let current = reread
            .agent_observations()
            .iter()
            .find(|candidate| candidate.identity() == observation.identity())
            .ok_or_else(observation_stale)?;
        let committed = commit_agent_adoption(&plan, current, &root, CaptureLimits::default())
            .map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_agent_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if let Some(observation) = report
        .native_extension_observations()
        .iter()
        .find(|observation| observation.identity().as_str() == observation_id)
    {
        let plan = match (update_asset_id, expected_prior) {
            (Some(asset_id), Some(expected_prior)) => {
                plan_native_extension_update(observation, asset_id, expected_prior, &manifest)
            }
            (None, None) => plan_native_extension_adoption(observation, asset_id, &manifest),
            _ => {
                return Err(CliError::new(
                    "native_extension.update_authority_incomplete",
                    "native extension updates require both --update and --expected-prior",
                ));
            }
        }
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let output = render_native_extension_adoption_plan(&plan, json)?;
        if !confirm(&output) {
            return Err(CliError::new(
                "adoption.confirmation_required",
                "the adoption plan was not confirmed; no changes were made",
            ));
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let current = reread
            .native_extension_observations()
            .iter()
            .find(|candidate| candidate.identity() == observation.identity())
            .ok_or_else(observation_stale)?;
        let native = &plan.asset().native_variants[&HarnessId::Pi];
        let envelope = VerifiedObjectEnvelope::native_extension(
            native.root.clone(),
            plan.native_object().clone(),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let (_, current_objects) = load_local_snapshot_exact(&root, SyncLimits::default())?;
        let proposed_objects = proposed_extension_catalog(
            &manifest,
            plan.asset().id.clone(),
            current_objects.as_slice(),
            envelope,
        )?;
        commit_native_extension_plan(
            &root,
            &plan,
            current,
            &current_objects,
            &proposed_objects,
            SyncLimits::default(),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        return Ok(CompletedCommand {
            output: render_native_extension_adoption_result(&plan, json)?,
            status: 0,
        });
    }
    if let Some((observation, observed_asset_id)) =
        select_instruction_observation(&report, &observation_id)
    {
        if let (Some(update_asset_id), Some(expected_prior)) =
            (update_asset_id.as_ref(), expected_prior.as_ref())
        {
            if update_asset_id != observed_asset_id {
                return Err(CliError::new(
                    "instruction_update.asset_id_mismatch",
                    "--update must match the selected managed instruction region",
                ));
            }
            let observation_revision = observation
                .region(observed_asset_id)
                .ok_or_else(observation_stale)?
                .observation_revision()
                .clone();
            let update_asset_id = update_asset_id.clone();
            let expected_prior = expected_prior.clone();
            return run_instruction_update(
                observation_revision,
                &update_asset_id,
                &expected_prior,
                selection,
                root,
                manifest,
                report,
                registry,
                json,
                confirm,
            );
        }
        if update_asset_id.is_some() || expected_prior.is_some() {
            return Err(CliError::new(
                "instruction_update.authority_incomplete",
                "standing-instruction updates require both --update and --expected-prior",
            ));
        }
        let selected_asset_id = asset_id.as_ref().unwrap_or(observed_asset_id);
        if selected_asset_id != observed_asset_id {
            return Err(CliError::new(
                "instruction_adoption.asset_id_mismatch",
                "--id must match the asset identifier in the selected managed region",
            ));
        }
        let capabilities = tier_one_instruction_capabilities()?;
        let outcome =
            plan_instruction_adoption(observation, selected_asset_id, &manifest, &capabilities)
                .map_err(instruction_adoption_error)?;
        let plan = match outcome {
            InstructionAdoptionOutcome::Ready(plan) => plan,
            InstructionAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_instruction_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let plan_output = render_instruction_adoption_plan(&plan, json)?;
        if !confirm(&plan_output) {
            return Err(CliError::new(
                "adoption.confirmation_required",
                "the adoption plan was not confirmed; no changes were made",
            ));
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let (current, current_asset_id) =
            select_instruction_observation(&reread, plan.observation_revision().as_str())
                .ok_or_else(observation_stale)?;
        if current_asset_id != &plan.asset().id {
            return Err(observation_stale());
        }
        let committed =
            commit_instruction_adoption(&plan, current, &root, CaptureLimits::default())
                .map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_instruction_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if let (Some(update_asset_id), Some(expected_prior)) = (update_asset_id, expected_prior) {
        return run_update_adoption(
            observation_id,
            update_asset_id,
            expected_prior,
            selection,
            root,
            manifest,
            report,
            registry,
            json,
            confirm,
        );
    }
    let candidate = report
        .observations()
        .iter()
        .find_map(|candidate| match candidate {
            kitrove_core::ObservedCandidate::Accepted(candidate)
                if candidate.observation_id().as_str() == observation_id =>
            {
                Some(candidate.as_ref())
            }
            _ => None,
        })
        .ok_or_else(observation_unavailable)?;
    let capabilities = tier_one_capabilities()?;
    let outcome =
        plan_adoption(candidate, asset_id, &manifest, &capabilities).map_err(adoption_error)?;
    let plan = match outcome {
        AdoptionPlanOutcome::Ready(plan) => plan,
        AdoptionPlanOutcome::Blocked(blocked) => {
            return Ok(CompletedCommand {
                output: render_adoption_block(&blocked, json)?,
                status: 1,
            });
        }
    };
    let plan_output = render_adoption_plan(&plan, json)?;
    if !confirm(&plan_output) {
        return Err(CliError::new(
            "adoption.confirmation_required",
            "the adoption plan was not confirmed; no changes were made",
        ));
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let reread_candidate = reread
        .observations()
        .iter()
        .find_map(|candidate| match candidate {
            kitrove_core::ObservedCandidate::Accepted(candidate)
                if candidate.observation_id() == plan.observation_id() =>
            {
                Some(candidate.as_ref())
            }
            _ => None,
        })
        .ok_or_else(observation_stale)?;
    let committed = commit_adoption(&plan, reread_candidate, &root, CaptureLimits::default())
        .map_err(transaction_error)?;
    let output = render_adoption_result(&plan, committed, json)?;
    Ok(CompletedCommand { output, status: 0 })
}

#[allow(clippy::too_many_arguments)]
fn run_instruction_update(
    observation_revision: kitrove_model::ContentHash,
    asset_id: &kitrove_model::AssetId,
    expected_prior: &kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    report: kitrove_core::ScanReport,
    registry: &PolicyRegistry,
    json: bool,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let state_root = resolve_required_state_root()?;
    let state_text = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let source = report
        .select_instruction_update_source(&observation_revision, asset_id, state_text.as_deref())
        .map_err(instruction_update_error)?;
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let capabilities = tier_one_instruction_capabilities()?;
    let plan = plan_instruction_update(
        &source,
        expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &capabilities,
    )
    .map_err(instruction_update_error)?;
    let output = render_instruction_update_plan(&plan, json)?;
    if !confirm(&output) {
        return Err(CliError::new(
            "update.confirmation_required",
            "the instruction update plan was not confirmed; no changes were made",
        ));
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let reread_state = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let reread_source = reread
        .select_instruction_update_source(&observation_revision, asset_id, reread_state.as_deref())
        .map_err(|_| update_observation_stale())?;
    if &reread_source != plan.source() {
        return Err(update_observation_stale());
    }
    let outcome = commit_instruction_update(
        &plan,
        reread_source.observation(),
        &root,
        &state_root,
        CaptureLimits::default(),
    )
    .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_instruction_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_prompt_command_update(
    observation: kitrove_core::PromptCommandObservation,
    asset_id: &kitrove_model::AssetId,
    expected_prior: &kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    registry: &PolicyRegistry,
    json: bool,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let capabilities = tier_one_prompt_command_capabilities()?;
    let plan = plan_prompt_command_update(
        &observation,
        asset_id,
        expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &capabilities,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let output = render_prompt_command_update_plan(&plan, json)?;
    if !confirm(&output) {
        return Err(CliError::new(
            "update.confirmation_required",
            "the prompt-command update plan was not confirmed; no changes were made",
        ));
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let current =
        select_prompt_command_observation(&reread, plan.observation().identity().as_str())
            .ok_or_else(update_observation_stale)?;
    let outcome = commit_prompt_command_update(&plan, current, &root, CaptureLimits::default())
        .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_prompt_command_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_agent_update(
    observation: kitrove_core::AgentObservation,
    asset_id: &kitrove_model::AssetId,
    expected_prior: &kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    registry: &PolicyRegistry,
    json: bool,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let plan = plan_agent_update(
        &observation,
        asset_id,
        expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &tier_one_agent_capabilities()?,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let output = render_agent_update_plan(&plan, json)?;
    if !confirm(&output) {
        return Err(CliError::new(
            "update.confirmation_required",
            "the agent update plan was not confirmed; no changes were made",
        ));
    }
    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let current = select_agent_observation(&reread, plan.observation().identity().as_str())
        .ok_or_else(update_observation_stale)?;
    let outcome = commit_agent_update(&plan, current, &root, CaptureLimits::default())
        .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_agent_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

fn select_agent_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    identity: &str,
) -> Option<&'a kitrove_core::AgentObservation> {
    report
        .agent_observations()
        .iter()
        .find(|observation| observation.identity().as_str() == identity)
}

fn select_prompt_command_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    identity: &str,
) -> Option<&'a kitrove_core::PromptCommandObservation> {
    report
        .prompt_command_observations()
        .iter()
        .find(|observation| observation.identity().as_str() == identity)
}

fn select_mcp_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    exact_entry_hash: &str,
) -> Option<(
    &'a kitrove_core::McpScanEntry,
    &'a kitrove_core::McpDocumentObservation,
    &'a kitrove_model::ContentHash,
)> {
    let entry = report.mcp_servers.iter().find(|entry| {
        entry
            .exact_entry_hash
            .as_ref()
            .is_some_and(|hash| hash.as_str() == exact_entry_hash)
            && entry.precedence == kitrove_core::McpPrecedence::Effective
    })?;
    let selected_entry_hash = entry.exact_entry_hash.as_ref()?;
    let selected_document_hash = entry.exact_document_hash.as_ref()?;
    let observation = report.mcp_observations().iter().find(|observation| {
        observation.harness() == &entry.harness
            && observation.scope() == entry.scope
            && observation.destination() == &entry.destination
            && observation.parsed().is_some_and(|document| {
                document.exact_document_hash() == selected_document_hash
                    && document
                        .entries()
                        .iter()
                        .any(|observed| observed.exact_entry_hash() == selected_entry_hash)
            })
    })?;
    Some((entry, observation, selected_entry_hash))
}

fn read_update_authority(root: &std::path::Path) -> Result<(String, Option<String>), CliError> {
    let manifest_text =
        read_portable_text(root, "kitrove.toml", MAX_CONTROL_BYTES)?.ok_or_else(|| {
            CliError::new(
                "cli.environment_manifest_missing",
                "the selected environment does not contain kitrove.toml",
            )
        })?;
    let lock_text = read_portable_text(root, "kitrove.lock.json", MAX_CONTROL_BYTES)?;
    Ok((manifest_text, lock_text))
}

fn select_instruction_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    revision: &str,
) -> Option<(
    &'a kitrove_core::InstructionDocumentObservation,
    &'a kitrove_model::AssetId,
)> {
    report
        .instruction_observations()
        .iter()
        .find_map(|observation| {
            observation.regions().find_map(|region| {
                (region.observation_revision().as_str() == revision)
                    .then_some((observation, region.asset_id()))
            })
        })
}

fn proposed_extension_catalog(
    manifest: &EnvironmentManifest,
    asset_id: kitrove_model::AssetId,
    current: &[VerifiedObjectEnvelope],
    proposed: VerifiedObjectEnvelope,
) -> Result<Vec<VerifiedObjectEnvelope>, CliError> {
    let replaced_root = manifest
        .assets
        .get(&asset_id)
        .and_then(|asset| asset.native_variants.get(&HarnessId::Pi))
        .map(|native| &native.root);
    let mut catalog = current
        .iter()
        .filter(|object| replaced_root != Some(object.descriptor().root()))
        .cloned()
        .map(|object| (object.descriptor().clone(), object))
        .collect::<BTreeMap<_, _>>();
    if catalog
        .insert(proposed.descriptor().clone(), proposed)
        .is_some()
    {
        return Err(CliError::new(
            "native_extension.object_catalog_invalid",
            "the proposed native extension object conflicts with existing object authority",
        ));
    }
    Ok(catalog.into_values().collect())
}

#[allow(clippy::too_many_arguments)]
fn run_update_adoption(
    observation_id: String,
    asset_id: kitrove_model::AssetId,
    expected_prior: kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    report: kitrove_core::ScanReport,
    registry: &PolicyRegistry,
    json: bool,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let observation_id = report
        .observations()
        .iter()
        .find_map(|observation| {
            observation
                .observation_id()
                .filter(|id| id.as_str() == observation_id)
                .cloned()
        })
        .ok_or_else(update_observation_unavailable)?;
    let state_root = resolve_required_state_root()?;
    let state_text = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let source = report
        .select_update_source(&observation_id, &asset_id, state_text.as_deref())
        .map_err(update_selection_error)?;
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let retained_objects = load_retained_native_objects(&manifest, &asset_id, &root)?;
    let capabilities = tier_one_capabilities()?;
    let plan = plan_update_adoption(
        &source,
        &expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &retained_objects,
        &capabilities,
        SyncLimits::default(),
    )
    .map_err(update_planning_error)?;
    let plan_output = render_update_plan(&plan, json)?;
    if !confirm(&plan_output) {
        return Err(CliError::new(
            "update.confirmation_required",
            "the update plan was not confirmed; no changes were made",
        ));
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let reread_state_text = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let reread_source = reread
        .select_update_source(
            plan.source().selected().observation_id(),
            plan.source().asset_id(),
            reread_state_text.as_deref(),
        )
        .map_err(|_| update_observation_stale())?;
    if &reread_source != plan.source() {
        return Err(update_observation_stale());
    }
    let outcome = commit_update_adoption(
        &plan,
        reread_source.selected(),
        &root,
        &state_root,
        CaptureLimits::default(),
    )
    .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

fn load_retained_native_objects(
    manifest: &EnvironmentManifest,
    asset_id: &kitrove_model::AssetId,
    root: &std::path::Path,
) -> Result<VerifiedSkillObjectCatalog, CliError> {
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        CliError::new(
            "update.asset_missing",
            "the requested update asset does not exist",
        )
    })?;
    let native = asset
        .native_variants
        .keys()
        .map(|harness| {
            load_native_skill_object(manifest, asset_id, harness, root, CaptureLimits::default())
                .map_err(|error| CliError::new(error.code(), error.message()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    VerifiedSkillObjectCatalog::new(Vec::new(), native)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

struct AdoptionSelection {
    harnesses: BTreeSet<HarnessId>,
    scope: ScopeSelection,
    project_root: Option<std::path::PathBuf>,
    roots: Vec<kitrove_adapter_api::ExplicitRoot>,
}

fn adoption_scan_args(environment: std::path::PathBuf, selection: &AdoptionSelection) -> ScanArgs {
    ScanArgs {
        harnesses: selection.harnesses.clone(),
        scope: selection.scope,
        project_root: selection.project_root.clone(),
        roots: selection.roots.clone(),
        environment: Some(environment),
        json: false,
    }
}

pub(crate) fn load_manifest(root: &std::path::Path) -> Result<EnvironmentManifest, CliError> {
    let text = read_portable_text(root, "kitrove.toml", MAX_CONTROL_BYTES)?.ok_or_else(|| {
        CliError::new(
            "cli.environment_manifest_missing",
            "the selected environment does not contain kitrove.toml",
        )
    })?;
    EnvironmentManifest::from_toml(&text).map_err(|_| {
        CliError::new(
            "cli.environment_manifest_invalid",
            "the selected environment manifest is invalid",
        )
    })
}

fn render_adoption_plan(plan: &AdoptionPlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        let fidelity = plan
            .asset()
            .compatibility
            .iter()
            .map(|(harness, result)| {
                (
                    harness.as_str().to_owned(),
                    json!({
                        "fidelity": fidelity(result.fidelity()),
                        "reason_codes": result.reasons().iter().map(|reason| reason.code.as_str()).collect::<Vec<_>>(),
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation_id().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "asset_revision": plan.asset().content_hash.as_str(),
                "disposition": adoption_disposition(plan.disposition()),
                "fidelity": fidelity,
            }))
            .map_err(serialization_error)?
        ));
    }
    let mut output = format!(
        "adoption plan: {}\nobservation: {}\nasset: {}\nrevision: {}\ndisposition: {}\n",
        plan.digest(),
        plan.observation_id(),
        plan.asset().id,
        plan.asset().content_hash,
        adoption_disposition(plan.disposition()),
    );
    for (harness, result) in &plan.asset().compatibility {
        writeln!(
            output,
            "fidelity {}: {}",
            harness,
            fidelity(result.fidelity())
        )
        .expect("writing to a string cannot fail");
    }
    Ok(output)
}

fn render_adoption_block(
    blocked: &kitrove_core::AdoptionBlock,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt",
                "phase": "blocked",
                "plan_digest": blocked.digest().as_str(),
                "observation_id": blocked.observation_id().as_str(),
                "asset_id": blocked.asset_id().map(|id| id.as_str()),
                "reason": adoption_block_tag(blocked.reason()),
                "message": adoption_block_message(blocked.reason()),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "adoption blocked: {}\nobservation: {}\nreason: {}\n",
        blocked.digest(),
        blocked.observation_id(),
        adoption_block_tag(blocked.reason()),
    ))
}

fn render_adoption_result(
    plan: &AdoptionPlan,
    outcome: AdoptionCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation_id().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "outcome": adoption_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "adoption plan: {}\nasset: {}\nadoption outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        adoption_outcome(outcome),
    ))
}

fn render_instruction_adoption_plan(
    plan: &InstructionAdoptionPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_instruction",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "observation_revision": plan.observation_revision().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "asset_revision": plan.asset().content_hash.as_str(),
                "origin_harness": plan.origin_harness().as_str(),
                "disposition": adoption_disposition(plan.disposition()),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "instruction adoption plan: {}\nobservation: {}\nasset: {}\nrevision: {}\norigin: {}\ndisposition: {}\n",
        plan.digest(),
        plan.observation_revision(),
        plan.asset().id,
        plan.asset().content_hash,
        plan.origin_harness(),
        adoption_disposition(plan.disposition()),
    ))
}

fn render_prompt_command_adoption_plan(
    plan: &PromptCommandAdoptionPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_prompt_command",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation().identity().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "asset_revision": plan.asset().content_hash.as_str(),
                "origin_harness": plan.observation().harness().as_str(),
                "disposition": adoption_disposition(plan.disposition()),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "prompt-command adoption plan: {}\nobservation: {}\nasset: {}\nrevision: {}\norigin: {}\ndisposition: {}\n",
        plan.digest(),
        plan.observation().identity(),
        plan.asset().id,
        plan.asset().content_hash,
        plan.observation().harness(),
        adoption_disposition(plan.disposition()),
    ))
}

fn render_agent_adoption_plan(
    plan: &AgentAdoptionPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_agent",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation().identity().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "asset_revision": plan.asset().content_hash.as_str(),
                "origin_harness": plan.observation().harness().as_str(),
                "disposition": adoption_disposition(plan.disposition()),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "agent adoption plan: {}\nobservation: {}\nasset: {}\nrevision: {}\norigin: {}\ndisposition: {}\n",
        plan.digest(),
        plan.observation().identity(),
        plan.asset().id,
        plan.asset().content_hash,
        plan.observation().harness(),
        adoption_disposition(plan.disposition()),
    ))
}

fn render_mcp_adoption_plan(plan: &McpAdoptionPlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        return serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "adopt_mcp",
            "plan_digest": plan.digest().as_str(),
            "observation": plan.selected_entry_hash().as_str(),
            "asset_id": plan.asset().id.as_str(),
            "asset_revision": plan.asset().content_hash.as_str(),
            "origin_harness": plan.observation().harness().as_str(),
            "disposition": adoption_disposition(plan.disposition()),
            "required_bindings": plan.asset().required_bindings.iter().map(|binding| binding.as_str()).collect::<Vec<_>>(),
        }))
        .map_err(serialization_error);
    }
    Ok(format!(
        "MCP adoption plan: {}\nobservation: {}\nasset: {}\nrevision: {}\norigin: {}\ndisposition: {}\nrequired bindings: {}\n",
        plan.digest(),
        plan.selected_entry_hash(),
        plan.asset().id,
        plan.asset().content_hash,
        plan.observation().harness(),
        adoption_disposition(plan.disposition()),
        plan.asset()
            .required_bindings
            .iter()
            .map(|binding| binding.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

fn render_mcp_adoption_block(
    blocked: &kitrove_core::McpAdoptionBlock,
    json_output: bool,
) -> Result<String, CliError> {
    let reason = match blocked.reason() {
        kitrove_core::McpAdoptionBlockReason::EntryUnavailable => "entry_unavailable",
        kitrove_core::McpAdoptionBlockReason::PortableProjectionUnavailable => {
            "portable_projection_unavailable"
        }
        kitrove_core::McpAdoptionBlockReason::BindingChoiceRequired => "binding_choice_required",
        kitrove_core::McpAdoptionBlockReason::UnexpectedBindingChoice => {
            "unexpected_binding_choice"
        }
        kitrove_core::McpAdoptionBlockReason::AssetConflict => "asset_conflict",
    };
    if json_output {
        return serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "adopt_mcp",
            "status": "blocked",
            "digest": blocked.digest().as_str(),
            "observation": blocked.exact_source_hash().as_str(),
            "asset_id": blocked.asset_id().as_str(),
            "reason": reason,
        }))
        .map_err(serialization_error);
    }
    Ok(format!(
        "MCP adoption blocked: {}\nasset: {}\nreason: {}\n",
        blocked.digest(),
        blocked.asset_id(),
        reason,
    ))
}

fn render_mcp_adoption_result(
    plan: &McpAdoptionPlan,
    outcome: AdoptionCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "adopt_mcp",
            "plan_digest": plan.digest().as_str(),
            "asset_id": plan.asset().id.as_str(),
            "outcome": adoption_outcome(outcome),
        }))
        .map_err(serialization_error);
    }
    Ok(format!(
        "MCP adoption plan: {}\nasset: {}\nadoption outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        adoption_outcome(outcome),
    ))
}

fn render_mcp_update_plan(plan: &McpUpdatePlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        return serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "update_mcp",
            "plan_digest": plan.digest().as_str(),
            "observation": plan.selected_entry_hash().as_str(),
            "asset_id": plan.asset().id.as_str(),
            "expected_prior": plan.expected_prior().as_str(),
            "proposed_revision": plan.asset().content_hash.as_str(),
            "required_bindings": plan.asset().required_bindings.iter().map(|binding| binding.as_str()).collect::<Vec<_>>(),
        }))
        .map_err(serialization_error);
    }
    Ok(format!(
        "MCP update plan: {}\nobservation: {}\nasset: {}\nold revision: {}\nnew revision: {}\nrequired bindings: {}\n",
        plan.digest(),
        plan.selected_entry_hash(),
        plan.asset().id,
        plan.expected_prior(),
        plan.asset().content_hash,
        plan.asset()
            .required_bindings
            .iter()
            .map(|binding| binding.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

fn render_mcp_update_result(
    plan: &McpUpdatePlan,
    outcome: UpdateCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "operation": "update_mcp",
            "plan_digest": plan.digest().as_str(),
            "asset_id": plan.asset().id.as_str(),
            "outcome": update_outcome(outcome),
        }))
        .map_err(serialization_error);
    }
    Ok(format!(
        "MCP update plan: {}\nasset: {}\nupdate outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        update_outcome(outcome),
    ))
}

fn render_prompt_command_adoption_block(
    blocked: &kitrove_core::PromptCommandAdoptionBlock,
    json_output: bool,
) -> Result<String, CliError> {
    let reason = match blocked.reason() {
        kitrove_core::PromptCommandAdoptionBlockReason::PortableProjectionUnavailable => {
            "portable_projection_unavailable"
        }
        kitrove_core::PromptCommandAdoptionBlockReason::CredentialShapedBody => {
            "credential_shaped_body"
        }
        kitrove_core::PromptCommandAdoptionBlockReason::AssetConflict => "asset_conflict",
    };
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_prompt_command",
                "phase": "blocked",
                "plan_digest": blocked.digest().as_str(),
                "asset_id": blocked.asset_id().as_str(),
                "exact_source_hash": blocked.exact_source_hash().as_str(),
                "reason": reason,
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "prompt-command adoption blocked: {}\nasset: {}\nreason: {}\n",
        blocked.digest(),
        blocked.asset_id(),
        reason,
    ))
}

fn render_agent_adoption_block(
    blocked: &kitrove_core::AgentAdoptionBlock,
    json_output: bool,
) -> Result<String, CliError> {
    let reason = match blocked.reason() {
        kitrove_core::AgentAdoptionBlockReason::PortableProjectionUnavailable => {
            "portable_projection_unavailable"
        }
        kitrove_core::AgentAdoptionBlockReason::CredentialShapedBody => "credential_shaped_body",
        kitrove_core::AgentAdoptionBlockReason::AssetConflict => "asset_conflict",
    };
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_agent",
                "phase": "blocked",
                "plan_digest": blocked.digest().as_str(),
                "asset_id": blocked.asset_id().as_str(),
                "exact_source_hash": blocked.exact_source_hash().as_str(),
                "reason": reason,
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "agent adoption blocked: {}\nasset: {}\nreason: {}\n",
        blocked.digest(),
        blocked.asset_id(),
        reason,
    ))
}

fn render_prompt_command_adoption_result(
    plan: &PromptCommandAdoptionPlan,
    outcome: AdoptionCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_prompt_command",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation().identity().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "outcome": adoption_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "prompt-command adoption plan: {}\nasset: {}\nadoption outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        adoption_outcome(outcome),
    ))
}

fn render_agent_adoption_result(
    plan: &AgentAdoptionPlan,
    outcome: AdoptionCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_agent",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation().identity().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "outcome": adoption_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "agent adoption plan: {}\nasset: {}\nadoption outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        adoption_outcome(outcome),
    ))
}

fn render_instruction_adoption_block(
    blocked: &kitrove_core::InstructionAdoptionBlock,
    json_output: bool,
) -> Result<String, CliError> {
    let reason = instruction_adoption_block_tag(blocked.reason());
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_instruction",
                "phase": "blocked",
                "plan_digest": blocked.digest().as_str(),
                "observation_revision": blocked.observation_revision().as_str(),
                "asset_id": blocked.asset_id().as_str(),
                "reason": reason,
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "instruction adoption blocked: {}\nobservation: {}\nasset: {}\nreason: {}\n",
        blocked.digest(),
        blocked.observation_revision(),
        blocked.asset_id(),
        reason,
    ))
}

fn render_instruction_adoption_result(
    plan: &InstructionAdoptionPlan,
    outcome: AdoptionCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_instruction",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "observation_revision": plan.observation_revision().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "outcome": adoption_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "instruction adoption plan: {}\nasset: {}\nadoption outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        adoption_outcome(outcome),
    ))
}

fn render_instruction_update_plan(
    plan: &InstructionUpdatePlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "update_instruction",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "old_asset_revision": plan.prior_asset().content_hash.as_str(),
                "new_asset_revision": plan.asset().content_hash.as_str(),
                "source_authority": "managed_modified",
                "receipt_rebased": true,
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "instruction update plan: {}\nasset: {}\nold revision: {}\nnew revision: {}\nsource authority: managed_modified\nreceipt rebase: yes\n",
        plan.digest(),
        plan.asset().id,
        plan.prior_asset().content_hash,
        plan.asset().content_hash,
    ))
}

fn render_prompt_command_update_plan(
    plan: &PromptCommandUpdatePlan,
    json_output: bool,
) -> Result<String, CliError> {
    render_inert_update_plan(
        &InertUpdateRender {
            plan_digest: plan.digest(),
            observation_id: plan.observation().identity().as_str(),
            asset_id: plan.asset().id.as_str(),
            old_asset_revision: plan.prior_asset().content_hash.as_str(),
            new_asset_revision: plan.asset().content_hash.as_str(),
            kind: "prompt-command",
            operation: "update_prompt_command",
        },
        json_output,
    )
}

fn render_agent_update_plan(plan: &AgentUpdatePlan, json_output: bool) -> Result<String, CliError> {
    render_inert_update_plan(
        &InertUpdateRender {
            plan_digest: plan.digest(),
            observation_id: plan.observation().identity().as_str(),
            asset_id: plan.asset().id.as_str(),
            old_asset_revision: plan.prior_asset().content_hash.as_str(),
            new_asset_revision: plan.asset().content_hash.as_str(),
            kind: "agent",
            operation: "update_agent",
        },
        json_output,
    )
}

struct InertUpdateRender<'a> {
    plan_digest: &'a kitrove_model::ContentHash,
    observation_id: &'a str,
    asset_id: &'a str,
    old_asset_revision: &'a str,
    new_asset_revision: &'a str,
    kind: &'static str,
    operation: &'static str,
}

fn render_inert_update_plan(
    view: &InertUpdateRender<'_>,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": view.operation,
                "phase": "planned",
                "plan_digest": view.plan_digest.as_str(),
                "observation_id": view.observation_id,
                "asset_id": view.asset_id,
                "old_asset_revision": view.old_asset_revision,
                "new_asset_revision": view.new_asset_revision,
                "receipt_rebased": false,
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "{} update plan: {}\nasset: {}\nold revision: {}\nnew revision: {}\nreceipt rebase: no\n",
        view.kind,
        view.plan_digest,
        view.asset_id,
        view.old_asset_revision,
        view.new_asset_revision,
    ))
}

fn render_prompt_command_update_result(
    plan: &PromptCommandUpdatePlan,
    outcome: UpdateCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    render_inert_update_result(
        &InertUpdateRender {
            plan_digest: plan.digest(),
            observation_id: plan.observation().identity().as_str(),
            asset_id: plan.asset().id.as_str(),
            old_asset_revision: plan.prior_asset().content_hash.as_str(),
            new_asset_revision: plan.asset().content_hash.as_str(),
            kind: "prompt-command",
            operation: "update_prompt_command",
        },
        outcome,
        json_output,
    )
}

fn render_agent_update_result(
    plan: &AgentUpdatePlan,
    outcome: UpdateCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    render_inert_update_result(
        &InertUpdateRender {
            plan_digest: plan.digest(),
            observation_id: plan.observation().identity().as_str(),
            asset_id: plan.asset().id.as_str(),
            old_asset_revision: plan.prior_asset().content_hash.as_str(),
            new_asset_revision: plan.asset().content_hash.as_str(),
            kind: "agent",
            operation: "update_agent",
        },
        outcome,
        json_output,
    )
}

fn render_inert_update_result(
    view: &InertUpdateRender<'_>,
    outcome: UpdateCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    let outcome = update_outcome(outcome);
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": view.operation,
                "phase": "complete",
                "plan_digest": view.plan_digest.as_str(),
                "asset_id": view.asset_id,
                "old_asset_revision": view.old_asset_revision,
                "new_asset_revision": view.new_asset_revision,
                "outcome": outcome,
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "{} update plan: {}\nasset: {}\nupdate outcome: {outcome}\n",
        view.kind, view.plan_digest, view.asset_id,
    ))
}

fn render_instruction_update_result(
    plan: &InstructionUpdatePlan,
    outcome: UpdateCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "update_instruction",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "old_asset_revision": plan.prior_asset().content_hash.as_str(),
                "new_asset_revision": plan.asset().content_hash.as_str(),
                "outcome": update_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "instruction update plan: {}\nasset: {}\nupdate outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        update_outcome(outcome),
    ))
}

const fn instruction_adoption_block_tag(
    reason: kitrove_core::InstructionAdoptionBlockReason,
) -> &'static str {
    match reason {
        kitrove_core::InstructionAdoptionBlockReason::CredentialShapedBody => {
            "credential_shaped_body"
        }
        kitrove_core::InstructionAdoptionBlockReason::AssetConflict => "asset_conflict",
    }
}

fn render_native_extension_adoption_plan(
    plan: &NativeExtensionPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_native_extension",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "observation_id": plan.observation().identity().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "target": "pi",
                "fidelity": "blocked",
                "blocked_reason": "executable_trust",
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "native extension adoption plan: {}\nobservation: {}\nasset: {}\ntarget: pi\nfidelity: blocked (executable_trust)\n",
        plan.digest(),
        plan.observation().identity(),
        plan.asset().id,
    ))
}

fn render_native_extension_adoption_result(
    plan: &NativeExtensionPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "adopt_native_extension",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "outcome": "preserved_without_trust",
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "native extension adoption plan: {}\nasset: {}\noutcome: preserved_without_trust\n",
        plan.digest(),
        plan.asset().id,
    ))
}

fn render_update_plan(plan: &UpdatePlan, json_output: bool) -> Result<String, CliError> {
    let portable_change = match (
        plan.prior_asset().portable.as_ref(),
        plan.asset().portable.as_ref(),
    ) {
        (Some(prior), Some(proposed)) if prior.object_hash == proposed.object_hash => "retained",
        (None, Some(_)) => "added",
        _ => "replaced",
    };
    let fidelity_results = plan
        .asset()
        .compatibility
        .iter()
        .map(|(harness, result)| {
            (
                harness.as_str().to_owned(),
                json!({
                    "fidelity": fidelity(result.fidelity()),
                    "reason_codes": result.reasons().iter().map(|reason| reason.code.as_str()).collect::<Vec<_>>(),
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let native_changes = plan
        .asset()
        .native_variants
        .iter()
        .map(|(harness, component)| {
            let change = plan
                .prior_asset()
                .native_variants
                .get(harness)
                .map_or("added", |prior| {
                    if prior.object_hash == component.object_hash {
                        "retained"
                    } else {
                        "replaced"
                    }
                });
            (harness.as_str().to_owned(), change)
        })
        .collect::<BTreeMap<_, _>>();
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "update_adoption",
                "phase": "planned",
                "plan_digest": plan.digest().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "old_asset_revision": plan.prior_asset().content_hash.as_str(),
                "new_asset_revision": plan.asset().content_hash.as_str(),
                "component_changes": {
                    "portable": portable_change,
                    "native": native_changes,
                },
                "fidelity": fidelity_results,
                "source_authority": update_authority(plan.source().authority()),
                "receipt_rebased": plan.proposed_local_state_text().is_some(),
            }))
            .map_err(serialization_error)?
        ));
    }
    let mut output = format!(
        "update adoption plan: {}\nasset: {}\nold revision: {}\nnew revision: {}\nportable component: {}\nsource authority: {}\nreceipt rebase: {}\n",
        plan.digest(),
        plan.asset().id,
        plan.prior_asset().content_hash,
        plan.asset().content_hash,
        portable_change,
        update_authority(plan.source().authority()),
        if plan.proposed_local_state_text().is_some() {
            "yes"
        } else {
            "no"
        },
    );
    for (harness, change) in native_changes {
        writeln!(output, "native component {harness}: {change}")
            .expect("writing to a string cannot fail");
    }
    for (harness, result) in &plan.asset().compatibility {
        writeln!(
            output,
            "fidelity {harness}: {}",
            fidelity(result.fidelity())
        )
        .expect("writing to a string cannot fail");
    }
    Ok(output)
}

fn render_update_result(
    plan: &UpdatePlan,
    outcome: UpdateCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "update_adoption",
                "phase": "complete",
                "plan_digest": plan.digest().as_str(),
                "asset_id": plan.asset().id.as_str(),
                "old_asset_revision": plan.prior_asset().content_hash.as_str(),
                "new_asset_revision": plan.asset().content_hash.as_str(),
                "outcome": update_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "update adoption plan: {}\nasset: {}\nupdate outcome: {}\n",
        plan.digest(),
        plan.asset().id,
        update_outcome(outcome),
    ))
}

fn render_update_recovery(
    outcome: UpdateRecoveryOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return Ok(format!(
            "{}\n",
            serde_json::to_string(&json!({
                "schema_version": 1,
                "operation": "update_adoption",
                "phase": "recovered",
                "outcome": update_recovery_outcome(outcome),
            }))
            .map_err(serialization_error)?
        ));
    }
    Ok(format!(
        "update recovery outcome: {}\n",
        update_recovery_outcome(outcome)
    ))
}

const fn lock_status(status: LockStatus) -> &'static str {
    match status {
        LockStatus::Missing => "missing",
        LockStatus::Invalid => "invalid",
        LockStatus::Drift => "drift",
        LockStatus::InSync => "in_sync",
    }
}

const fn journal_status(status: PortableJournalStatus) -> &'static str {
    match status {
        PortableJournalStatus::Absent => "absent",
        PortableJournalStatus::Pending => "pending",
        PortableJournalStatus::Invalid => "invalid",
    }
}

const fn object_kind(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Portable => "portable",
        ObjectKind::Native => "native",
    }
}

const fn object_state(state: ObjectState) -> &'static str {
    match state {
        ObjectState::Verified => "verified",
        ObjectState::Missing => "missing",
        ObjectState::HashMismatch => "hash_mismatch",
        ObjectState::Unsafe => "unsafe",
        ObjectState::Invalid => "invalid",
        ObjectState::Unreadable => "unreadable",
    }
}

const fn lock_outcome(outcome: LockRepairOutcome) -> &'static str {
    match outcome {
        LockRepairOutcome::AlreadyInSync => "already_in_sync",
        LockRepairOutcome::Repaired => "repaired",
        LockRepairOutcome::Recovered => "recovered",
    }
}

const fn adoption_disposition(disposition: AdoptionDisposition) -> &'static str {
    match disposition {
        AdoptionDisposition::First => "first",
        AdoptionDisposition::Idempotent => "idempotent",
    }
}

const fn adoption_outcome(outcome: AdoptionCommitOutcome) -> &'static str {
    match outcome {
        AdoptionCommitOutcome::Committed => "committed",
        AdoptionCommitOutcome::Repaired => "repaired",
        AdoptionCommitOutcome::Recovered => "recovered",
    }
}

const fn update_authority(authority: UpdateSourceAuthority) -> &'static str {
    match authority {
        UpdateSourceAuthority::ManagedModified => "managed_modified",
        UpdateSourceAuthority::ExplicitRoot => "explicit_root",
    }
}

const fn update_outcome(outcome: UpdateCommitOutcome) -> &'static str {
    match outcome {
        UpdateCommitOutcome::Committed => "committed",
        UpdateCommitOutcome::CommittedWithReceipt => "committed_with_receipt",
        UpdateCommitOutcome::CommittedWithoutReceipt => "committed_without_receipt",
        UpdateCommitOutcome::Recovered => "recovered",
        UpdateCommitOutcome::RecoveredWithReceipt => "recovered_with_receipt",
        UpdateCommitOutcome::RecoveredWithoutReceipt => "recovered_without_receipt",
    }
}

const fn update_recovery_outcome(outcome: UpdateRecoveryOutcome) -> &'static str {
    match outcome {
        UpdateRecoveryOutcome::NoJournal => "no_journal",
        UpdateRecoveryOutcome::DiscardedUncommitted => "discarded_uncommitted",
        UpdateRecoveryOutcome::Completed => "completed",
        UpdateRecoveryOutcome::CompletedWithReceipt => "completed_with_receipt",
        UpdateRecoveryOutcome::CompletedWithoutReceipt => "completed_without_receipt",
    }
}

pub(crate) const fn fidelity(value: kitrove_model::Fidelity) -> &'static str {
    match value {
        kitrove_model::Fidelity::Native => "native",
        kitrove_model::Fidelity::Portable => "portable",
        kitrove_model::Fidelity::Adapted => "adapted",
        kitrove_model::Fidelity::Partial => "partial",
        kitrove_model::Fidelity::Unsupported => "unsupported",
        kitrove_model::Fidelity::Blocked => "blocked",
    }
}

const fn adoption_block_tag(reason: AdoptionBlockReason) -> &'static str {
    match reason {
        AdoptionBlockReason::PortableProjectionUnavailable => "portable_projection_unavailable",
        AdoptionBlockReason::ExecutableTrustRequired => "executable_trust_required",
        AdoptionBlockReason::CredentialShapedNativeIdentity => "credential_shaped_native_identity",
        AdoptionBlockReason::AssetConflict => "asset_conflict",
    }
}

const fn adoption_block_message(reason: AdoptionBlockReason) -> &'static str {
    match reason {
        AdoptionBlockReason::PortableProjectionUnavailable => {
            "the selected observation has no authorized portable projection"
        }
        AdoptionBlockReason::ExecutableTrustRequired => {
            "this executable adoption path is unsupported; exact-content trust currently applies only to native Pi extensions"
        }
        AdoptionBlockReason::CredentialShapedNativeIdentity => {
            "the selected native identity has a credential-shaped value"
        }
        AdoptionBlockReason::AssetConflict => {
            "the proposed asset identifier already names a different revision"
        }
    }
}

fn observation_unavailable() -> CliError {
    CliError::new(
        "adoption.observation_unavailable",
        "the requested identifier is not a current accepted observation",
    )
}

fn observation_stale() -> CliError {
    CliError::new(
        "adoption.observation_stale",
        "the selected observation changed after planning; scan and plan again",
    )
}

fn update_observation_unavailable() -> CliError {
    CliError::new(
        "update_source.observation_unavailable",
        "the requested identifier is not a current classified update observation",
    )
}

fn update_observation_stale() -> CliError {
    CliError::new(
        "update.observation_stale",
        "the selected update observation changed after planning; scan and plan again",
    )
}

fn update_selection_error(error: kitrove_core::UpdateSelectionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn update_planning_error(error: kitrove_core::UpdatePlanningError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn adoption_error(error: kitrove_core::AdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn instruction_adoption_error(error: kitrove_core::InstructionAdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn instruction_update_error(error: kitrove_core::InstructionUpdateError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn transaction_error(error: kitrove_core::PortableTransactionError) -> CliError {
    CliError::new(error.code(), error.message())
}

pub(crate) fn serialization_error(_: serde_json::Error) -> CliError {
    CliError::new(
        "cli.serialization_failed",
        "the command result could not be serialized",
    )
}
