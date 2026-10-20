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
use crate::args::{AdoptArgs, ApprovalMode, CliError, EnvironmentArgs, ScanArgs};
mod approval;
use crate::scan::{
    read_portable_text, resolve_required_environment_root, resolve_required_state_root, scan_report,
};
use crate::sync::load_local_snapshot_exact;
use approval::review;

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

mod adoption;
pub(crate) use adoption::run_adopt;

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
