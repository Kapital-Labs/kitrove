use std::collections::BTreeSet;
use std::fmt::Write as _;

use kitrove_adapter_api::{EvidenceRef, TargetAnchor, VersionObservation};
use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    AgentApplyPlan, ApplyDisposition, ApplyPlan, AtomicApplyBatchCommitOutcome,
    AtomicApplyBatchPlan, AtomicApplyItem, CoalescedInstructionApplyPlan, CoalescedMcpApplyPlan,
    ExtensionApplyAuthority, ExtensionApplyPlan, InstructionProjection, McpProjection,
    NativeExtensionLayout, PackApplicationSelection, PiProjectTrustEvidence, PiProjectTrustStatus,
    PromptCommandApplyPlan, authorize_extension_apply, commit_atomic_apply_batch,
    guard_asset_materialization, inspect_pi_project_trust, load_native_extension_object,
    load_portable_agent_object, load_portable_instruction_object, load_portable_mcp_object,
    load_portable_prompt_command_object, load_portable_skill_object, observe_agent_destination,
    observe_extension_destination, observe_instruction_document, observe_mcp_document,
    observe_prompt_command_destination, observe_skill_destination, plan_agent_apply,
    plan_coalesced_instruction_apply, plan_coalesced_mcp_apply, plan_extension_apply,
    plan_prompt_command_apply, plan_skill_apply, render_native_extension, render_portable_skill,
    resolve_extension_destination, resolve_pack_asset_memberships, resolve_profile,
    resolve_target_destination,
};
use kitrove_model::{
    AssetId, AssetKind, EnvironmentManifest, HarnessId, HarnessScope, LocalState, ProfileId,
};
use serde_json::json;

use crate::adapters::{
    agent_target_policy_with_version, instruction_target_policy_with_version,
    mcp_target_policy_with_version, pi_extension_target_policy,
    prompt_command_target_policy_with_version, target_policy_with_version,
};
#[cfg(test)]
use crate::adapters::{instruction_target_policy, mcp_target_policy};
use crate::args::{CliError, MaterializeArgs};
use crate::batch_recovery::recover_pending_batch;
use crate::portable::CompletedCommand;
use crate::scan::{
    read_portable_text, resolve_materialization_anchor, resolve_required_environment_root,
    resolve_required_state_root,
};
use crate::version_probe::MaterializationVersionProbes;

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn run_plan(arguments: MaterializeArgs) -> Result<CompletedCommand, CliError> {
    let json = arguments.json;
    let planned = build_plans(&arguments)?;
    let batch = build_atomic_batch(&planned)?;
    Ok(CompletedCommand {
        output: render_plans(&planned, &batch, json)?,
        status: 0,
    })
}

pub(crate) fn run_apply(
    arguments: MaterializeArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let json = arguments.json;
    recover_pending_batch(arguments.environment.as_deref())?;
    let first = build_plans(&arguments)?;
    let first_batch = build_atomic_batch(&first)?;
    let plan_output = render_plans(&first, &first_batch, json)?;
    if !confirm(&plan_output) {
        return Err(CliError::new(
            "apply.confirmation_required",
            "the apply plan was not confirmed; no changes were made",
        ));
    }
    recover_pending_batch(arguments.environment.as_deref())?;
    let refreshed = build_plans(&arguments)?;
    let refreshed_batch = build_atomic_batch(&refreshed)?;
    if refreshed_batch.digest() != first_batch.digest()
        || refreshed.pack_selections != first.pack_selections
    {
        return Err(CliError::new(
            "apply.plan_stale",
            "materialization authority changed after confirmation",
        ));
    }
    let outcome = commit_atomic_apply_batch(
        &refreshed_batch,
        &refreshed.environment_root,
        &refreshed.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_batch_result(&refreshed_batch, outcome, json)?,
        status: 0,
    })
}

#[derive(Clone)]
enum MaterializationPlan {
    Skill(ApplyPlan),
    Agent(AgentApplyPlan),
    Extension(ExtensionApplyPlan),
    PromptCommand(PromptCommandApplyPlan),
}

impl MaterializationPlan {
    fn atomic_item(&self) -> AtomicApplyItem {
        match self {
            Self::Skill(plan) => AtomicApplyItem::Skill(plan.clone()),
            Self::Agent(plan) => AtomicApplyItem::Agent(plan.clone()),
            Self::Extension(plan) => AtomicApplyItem::Extension(plan.clone()),
            Self::PromptCommand(plan) => AtomicApplyItem::PromptCommand(plan.clone()),
        }
    }
}

#[derive(Clone, Copy)]
struct PlanSummary<'a> {
    target: &'a str,
    scope: &'a str,
}

impl<'a> PlanSummary<'a> {
    fn extension(plan: &'a ExtensionApplyPlan) -> Self {
        Self {
            target: plan.proposed_receipt().harness.as_str(),
            scope: plan.proposed_receipt().scope.as_str(),
        }
    }
}

struct PlannedItem {
    plan: MaterializationPlan,
}

struct PlannedMaterialization {
    manifest: EnvironmentManifest,
    items: Vec<PlannedItem>,
    instructions: Option<CoalescedInstructionApplyPlan>,
    mcp: Option<CoalescedMcpApplyPlan>,
    environment_root: std::path::PathBuf,
    state_root: std::path::PathBuf,
    active_profile: Option<ProfileId>,
    pack_selections: Vec<PackApplicationSelection>,
    independently_selected_assets: BTreeSet<AssetId>,
    targets: BTreeSet<HarnessId>,
    scope: HarnessScope,
}

struct MaterializationSelection {
    assets: BTreeSet<AssetId>,
    targets: BTreeSet<HarnessId>,
    active_profile: Option<ProfileId>,
    pack_selections: Vec<PackApplicationSelection>,
    independently_selected_assets: BTreeSet<AssetId>,
}

struct PlanContext<'a> {
    manifest: &'a EnvironmentManifest,
    environment_root: &'a std::path::Path,
    project_root: Option<&'a std::path::Path>,
    state_text: &'a str,
    scope: HarnessScope,
    version_probes: &'a MaterializationVersionProbes,
    pi_project_trust: Option<&'a PiProjectTrustEvidence>,
}

impl PlanContext<'_> {
    fn target_anchor(&self) -> Result<std::path::PathBuf, CliError> {
        resolve_materialization_anchor(self.scope, self.project_root)
    }

    fn policy_anchor(
        &self,
        target: &HarnessId,
        anchor: TargetAnchor,
    ) -> Result<std::path::PathBuf, CliError> {
        match anchor {
            TargetAnchor::Scope => self.target_anchor(),
            TargetAnchor::HarnessConfiguration if target == &HarnessId::OpenCode => {
                Ok(self.target_anchor()?.join(".config/opencode"))
            }
            TargetAnchor::HarnessConfiguration => Err(CliError::new(
                "apply.harness_configuration_anchor_unavailable",
                "the selected harness configuration root has not been verified locally",
            )),
        }
    }

    fn version_for(&self, target: &HarnessId) -> VersionObservation<'_> {
        match target {
            HarnessId::Pi => self
                .version_probes
                .pi()
                .map_or(VersionObservation::Unknown, |probe| {
                    VersionObservation::Verified(probe.evidence())
                }),
            HarnessId::OpenCode => self
                .version_probes
                .opencode_v2()
                .map_or(VersionObservation::Unknown, |probe| {
                    VersionObservation::Verified(probe.evidence())
                }),
            _ => VersionObservation::Unknown,
        }
    }
}

fn build_plans(arguments: &MaterializeArgs) -> Result<PlannedMaterialization, CliError> {
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
                "apply.local_state_missing",
                "apply requires an existing machine-local state.json",
            )
        })?;
    let local_state = LocalState::from_json(&state_text).map_err(|_| {
        CliError::new(
            "apply.local_state_invalid",
            "machine-local state.json is invalid",
        )
    })?;
    let selection = resolve_materialization_selection(arguments, &manifest, &local_state)?;
    let asset_ids = select_assets(&selection.assets, &manifest)?;
    let selected_asset_ids = asset_ids
        .iter()
        .map(|id| (*id).clone())
        .collect::<BTreeSet<_>>();
    let independently_selected_assets = if selection.pack_selections.is_empty() {
        selected_asset_ids
    } else {
        selection.independently_selected_assets.clone()
    };
    let targets = select_targets(&selection.targets, &local_state)?;
    let selected_targets = targets.iter().cloned().collect::<BTreeSet<_>>();
    let needs_pi_extension = asset_ids.iter().any(|asset_id| {
        manifest.assets[*asset_id].kind == AssetKind::Extension && targets.contains(&HarnessId::Pi)
    });
    let needs_opencode_v2 = targets.contains(&HarnessId::OpenCode)
        && asset_ids.iter().any(|asset_id| {
            matches!(
                manifest.assets[*asset_id].kind,
                AssetKind::Instruction | AssetKind::Command | AssetKind::Agent | AssetKind::Mcp
            )
        });
    let version_probes = MaterializationVersionProbes::acquire(
        &arguments.version_binaries,
        needs_pi_extension,
        needs_opencode_v2,
    )?;
    let extension_anchor = needs_pi_extension
        .then(|| resolve_materialization_anchor(arguments.scope, arguments.project_root.as_deref()))
        .transpose()?;
    let pi_project_trust = if needs_pi_extension && arguments.scope == HarnessScope::Project {
        let home = resolve_materialization_anchor(HarnessScope::User, None)?;
        let trust_store = home.join(".pi").join("agent").join("trust.json");
        match inspect_pi_project_trust(
            &trust_store,
            extension_anchor
                .as_deref()
                .expect("selected project anchor"),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?
        {
            PiProjectTrustStatus::Trusted(evidence) => Some(evidence),
            PiProjectTrustStatus::Declined => {
                return Err(CliError::new(
                    "apply.project_trust_declined",
                    "Pi has an effective saved refusal for the selected project",
                ));
            }
            PiProjectTrustStatus::Unknown => {
                return Err(CliError::new(
                    "apply.project_trust_required",
                    "Pi project extension materialization requires saved project trust",
                ));
            }
        }
    } else {
        None
    };
    let context = PlanContext {
        manifest: &manifest,
        environment_root: &environment_root,
        project_root: arguments.project_root.as_deref(),
        state_text: &state_text,
        scope: arguments.scope,
        version_probes: &version_probes,
        pi_project_trust: pi_project_trust.as_ref(),
    };
    let mut items = Vec::new();
    let mut instruction_projections = Vec::new();
    let mut mcp_projections = Vec::new();
    for asset_id in asset_ids {
        let asset = &manifest.assets[asset_id];
        for target in &targets {
            if asset.kind == AssetKind::Extension && target != &HarnessId::Pi {
                continue;
            }
            let plan = match asset.kind {
                AssetKind::Extension => {
                    MaterializationPlan::Extension(build_extension_plan(&context, asset_id)?)
                }
                AssetKind::Instruction => {
                    instruction_projections
                        .push(build_instruction_projection(&context, asset_id, target)?);
                    continue;
                }
                AssetKind::Mcp => {
                    mcp_projections.push(build_mcp_projection(&context, asset_id, target)?);
                    continue;
                }
                AssetKind::Command => MaterializationPlan::PromptCommand(
                    build_prompt_command_plan(&context, asset_id, target)?,
                ),
                AssetKind::Agent => {
                    MaterializationPlan::Agent(build_agent_plan(&context, asset_id, target)?)
                }
                AssetKind::Skill => {
                    guard_asset_materialization(&manifest, asset_id)
                        .map_err(|error| CliError::new(error.code(), error.message()))?;
                    MaterializationPlan::Skill(build_skill_plan(&context, asset_id, target)?)
                }
                _ => {
                    return Err(CliError::new(
                        "apply.asset_unsupported",
                        "a selected asset kind has no portable materialization workflow",
                    ));
                }
            };
            items.push(PlannedItem { plan });
        }
    }
    let instructions = if instruction_projections.is_empty() {
        None
    } else {
        Some(
            plan_coalesced_instruction_apply(
                &manifest,
                instruction_projections,
                &state_text,
                selection.active_profile.clone(),
                Default::default(),
            )
            .map_err(|error| CliError::new(error.code(), error.message()))?,
        )
    };
    let mcp = if mcp_projections.is_empty() {
        None
    } else {
        Some(
            plan_coalesced_mcp_apply(
                &manifest,
                mcp_projections,
                &state_text,
                selection.active_profile.clone(),
                Default::default(),
            )
            .map_err(|error| CliError::new(error.code(), error.message()))?,
        )
    };
    if items.is_empty() && instructions.is_none() && mcp.is_none() {
        return Err(CliError::new(
            "apply.selection_empty",
            "the selected assets and targets have no materializable combination",
        ));
    }
    Ok(PlannedMaterialization {
        manifest,
        items,
        instructions,
        mcp,
        environment_root,
        state_root,
        active_profile: selection.active_profile,
        pack_selections: selection.pack_selections,
        independently_selected_assets,
        targets: selected_targets,
        scope: arguments.scope,
    })
}

fn resolve_materialization_selection(
    arguments: &MaterializeArgs,
    manifest: &EnvironmentManifest,
    local_state: &LocalState,
) -> Result<MaterializationSelection, CliError> {
    if let Some(profile_id) = &arguments.profile {
        let resolved = resolve_profile(manifest, profile_id)
            .map_err(|error| CliError::new(error.code(), error.message()))?;
        if resolved.assets.is_empty() || resolved.targets.is_empty() {
            return Err(CliError::new(
                "apply.profile_selection_empty",
                "the selected profile has no materializable assets or targets",
            ));
        }
        return Ok(MaterializationSelection {
            assets: resolved.assets.clone(),
            targets: resolved.targets,
            active_profile: Some(profile_id.clone()),
            pack_selections: Vec::new(),
            independently_selected_assets: resolved.assets,
        });
    }

    let mut assets = arguments.assets.clone();
    let pack_memberships = resolve_pack_asset_memberships(manifest, &arguments.packs)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let pack_selections = pack_memberships
        .into_iter()
        .map(|(pack_id, leaf_assets)| {
            let pack_revision = manifest
                .packs
                .get(&pack_id)
                .ok_or_else(|| {
                    CliError::new(
                        "pack.missing",
                        "the selected pack is not present in the environment",
                    )
                })?
                .content_hash
                .clone();
            assets.extend(leaf_assets.iter().cloned());
            Ok(PackApplicationSelection {
                pack_id,
                pack_revision,
                leaf_assets,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    Ok(MaterializationSelection {
        assets,
        targets: arguments.targets.clone(),
        active_profile: local_state.machine.active_profile.clone(),
        pack_selections,
        independently_selected_assets: arguments.assets.clone(),
    })
}

fn build_atomic_batch(planned: &PlannedMaterialization) -> Result<AtomicApplyBatchPlan, CliError> {
    let items = planned
        .items
        .iter()
        .map(|item| item.plan.atomic_item())
        .collect();
    let batch = match (&planned.instructions, &planned.mcp) {
        (None, None) => AtomicApplyBatchPlan::new(items, planned.active_profile.clone()),
        (instructions, mcp) => {
            AtomicApplyBatchPlan::with_shared_documents(items, instructions.clone(), mcp.clone())
        }
    }
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    batch
        .with_pack_application_ownership(
            &planned.manifest,
            &planned.pack_selections,
            &planned.independently_selected_assets,
            planned.scope,
            planned.targets.clone(),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_mcp_projection(
    context: &PlanContext<'_>,
    asset_id: &kitrove_model::AssetId,
    target: &HarnessId,
) -> Result<McpProjection, CliError> {
    let version = context.version_for(target);
    let mut policy = mcp_target_policy_with_version(target, context.scope, version)?;
    bind_probe_evidence(&mut policy.evidence, version)?;
    let target_anchor = context.policy_anchor(target, policy.anchor)?;
    let object = load_portable_mcp_object(
        context.manifest,
        asset_id,
        context.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_mcp_document(&target_anchor, &policy, Default::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(McpProjection::new(
        asset_id.clone(),
        object,
        policy,
        observation,
    ))
}

fn build_instruction_projection(
    context: &PlanContext<'_>,
    asset_id: &kitrove_model::AssetId,
    target: &HarnessId,
) -> Result<InstructionProjection, CliError> {
    let version = context.version_for(target);
    let mut policy = instruction_target_policy_with_version(target, context.scope, version)?;
    bind_probe_evidence(&mut policy.evidence, version)?;
    let target_anchor = context.policy_anchor(target, policy.anchor)?;
    let object = load_portable_instruction_object(
        context.manifest,
        asset_id,
        context.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_instruction_document(&target_anchor, &policy, Default::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(InstructionProjection::new(
        asset_id.clone(),
        object,
        policy,
        observation,
    ))
}

fn build_skill_plan(
    context: &PlanContext<'_>,
    asset_id: &kitrove_model::AssetId,
    target: &HarnessId,
) -> Result<ApplyPlan, CliError> {
    let version = context.version_for(target);
    let mut policy = target_policy_with_version(target, context.scope, version)?;
    bind_probe_evidence(&mut policy.evidence, version)?;
    let target_anchor = context.target_anchor()?;
    let object = load_portable_skill_object(
        context.manifest,
        asset_id,
        context.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let rendered = render_portable_skill(&object, &policy)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let destination = resolve_target_destination(&target_anchor, &policy, rendered.package_name())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_skill_destination(
        std::path::Path::new(destination.as_str()),
        CaptureLimits::default(),
    );
    let plan = plan_skill_apply(
        context.manifest,
        asset_id,
        &object,
        &policy,
        &target_anchor,
        context.state_text,
        observation,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(plan)
}

fn build_prompt_command_plan(
    context: &PlanContext<'_>,
    asset_id: &kitrove_model::AssetId,
    target: &HarnessId,
) -> Result<PromptCommandApplyPlan, CliError> {
    let version = context.version_for(target);
    let mut policy = prompt_command_target_policy_with_version(target, context.scope, version)?;
    bind_probe_evidence(&mut policy.evidence, version)?;
    let target_anchor = context.policy_anchor(target, policy.anchor)?;
    let object = load_portable_prompt_command_object(
        context.manifest,
        asset_id,
        context.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_prompt_command_destination(
        &target_anchor,
        &policy,
        object.command().name(),
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    plan_prompt_command_apply(
        context.manifest,
        asset_id,
        &object,
        &policy,
        &observation,
        context.state_text,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_agent_plan(
    context: &PlanContext<'_>,
    asset_id: &kitrove_model::AssetId,
    target: &HarnessId,
) -> Result<AgentApplyPlan, CliError> {
    let version = context.version_for(target);
    let mut policy = agent_target_policy_with_version(target, context.scope, version)?;
    bind_probe_evidence(&mut policy.evidence, version)?;
    let target_anchor = context.policy_anchor(target, policy.anchor)?;
    let object = load_portable_agent_object(
        context.manifest,
        asset_id,
        context.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_agent_destination(
        &target_anchor,
        &policy,
        object.agent().name(),
        Default::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    plan_agent_apply(
        context.manifest,
        asset_id,
        &object,
        &policy,
        &observation,
        context.state_text,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))
}

fn build_extension_plan(
    context: &PlanContext<'_>,
    asset_id: &kitrove_model::AssetId,
) -> Result<ExtensionApplyPlan, CliError> {
    let version = context.version_for(&HarnessId::Pi);
    let policy = pi_extension_target_policy(context.scope, version)?;
    let object = load_native_extension_object(
        context.manifest,
        asset_id,
        &HarnessId::Pi,
        context.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let target_anchor = context.target_anchor()?;
    let version = context.version_probes.pi().ok_or_else(|| {
        CliError::new(
            "apply.harness_version_unverified",
            "extension materialization requires exact verified harness version evidence",
        )
    })?;
    let authority = ExtensionApplyAuthority::new(&target_anchor, version, context.pi_project_trust);
    authorize_extension_apply(
        context.manifest,
        asset_id,
        &object,
        &policy,
        authority,
        context.state_text,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let rendered = render_native_extension(&object, &policy)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let destination = resolve_extension_destination(&target_anchor, &policy, &rendered)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let observation = observe_extension_destination(
        std::path::Path::new(destination.as_str()),
        &object,
        CaptureLimits::default(),
    );
    let plan = plan_extension_apply(
        context.manifest,
        asset_id,
        &object,
        &policy,
        authority,
        context.state_text,
        observation,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(plan)
}

fn bind_probe_evidence(
    evidence: &mut EvidenceRef,
    version: VersionObservation<'_>,
) -> Result<(), CliError> {
    if let VersionObservation::Verified(verified) = version {
        *evidence = verified
            .plan_authority()
            .map_err(|error| CliError::new(error.code, error.message))?;
    }
    Ok(())
}

fn select_assets<'a>(
    explicit: &std::collections::BTreeSet<kitrove_model::AssetId>,
    manifest: &'a EnvironmentManifest,
) -> Result<Vec<&'a kitrove_model::AssetId>, CliError> {
    if manifest.assets.is_empty() {
        return Err(CliError::new(
            "apply.asset_missing",
            "the environment has no assets",
        ));
    }
    if explicit.is_empty() {
        return Ok(manifest.assets.keys().collect());
    }
    explicit
        .iter()
        .map(|id| {
            manifest
                .assets
                .get_key_value(id)
                .map(|(id, _)| id)
                .ok_or_else(|| {
                    CliError::new(
                        "apply.asset_missing",
                        "a selected asset is not in the environment",
                    )
                })
        })
        .collect()
}

fn select_targets(
    explicit: &std::collections::BTreeSet<HarnessId>,
    local_state: &LocalState,
) -> Result<Vec<HarnessId>, CliError> {
    if !explicit.is_empty() {
        return Ok(explicit.iter().cloned().collect());
    }
    if local_state.machine.enabled_targets.is_empty() {
        return Err(CliError::new(
            "apply.target_selection_required",
            "select at least one --target or enable machine targets",
        ));
    }
    Ok(local_state
        .machine
        .enabled_targets
        .iter()
        .cloned()
        .collect())
}

fn render_plans(
    planned: &PlannedMaterialization,
    batch: &AtomicApplyBatchPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if planned.items.len() == 1 && planned.instructions.is_none() && planned.mcp.is_none() {
        if json_output {
            let mut value = serde_json::from_str::<serde_json::Value>(&render_plan(
                &planned.items[0].plan,
                true,
            )?)
            .map_err(|_| serialization_error())?;
            let object = value.as_object_mut().ok_or_else(serialization_error)?;
            object.insert("semantics".to_owned(), json!("atomic"));
            object.insert("batch_digest".to_owned(), json!(batch.digest().as_str()));
            object.insert(
                "active_profile".to_owned(),
                json!(batch.active_profile().map(ProfileId::as_str)),
            );
            object.insert(
                "selected_packs".to_owned(),
                json!(pack_revision_values(&planned.pack_selections)),
            );
            return json_line(value);
        }
        let mut output = format!("atomic batch: {}\n", batch.digest());
        render_pack_revisions(&mut output, &planned.pack_selections)?;
        output.push_str(&render_plan(&planned.items[0].plan, false)?);
        return Ok(output);
    }
    if json_output {
        let mut items = planned
            .items
            .iter()
            .map(|item| {
                let encoded = render_plan(&item.plan, true)?;
                serde_json::from_str::<serde_json::Value>(&encoded)
                    .map_err(|_| serialization_error())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(instructions) = &planned.instructions {
            items.extend(instruction_plan_values(instructions));
        }
        if let Some(mcp) = &planned.mcp {
            items.extend(mcp_plan_values(mcp));
        }
        return json_line(json!({
            "schema_version": 1,
            "operation": "apply_batch",
            "phase": "planned",
            "semantics": "atomic",
            "batch_digest": batch.digest().as_str(),
            "active_profile": batch.active_profile().map(ProfileId::as_str),
            "selected_packs": pack_revision_values(&planned.pack_selections),
            "items": items,
        }));
    }
    let mut output = format!(
        "atomic materialization batch: {} items\nbatch: {}\nsemantics: all targets and machine state commit or recover together\n",
        batch.items().len(),
        batch.digest(),
    );
    render_pack_revisions(&mut output, &planned.pack_selections)?;
    for item in &planned.items {
        output.push_str(&render_plan(&item.plan, false)?);
    }
    if let Some(instructions) = &planned.instructions {
        output.push_str(&render_instruction_plans(instructions));
    }
    if let Some(mcp) = &planned.mcp {
        output.push_str(&render_mcp_plans(mcp));
    }
    Ok(output)
}

fn pack_revision_values(selections: &[PackApplicationSelection]) -> Vec<serde_json::Value> {
    selections
        .iter()
        .map(|selection| {
            json!({
                "pack_id": selection.pack_id.as_str(),
                "revision": selection.pack_revision.as_str(),
            })
        })
        .collect()
}

fn render_pack_revisions(
    output: &mut String,
    selections: &[PackApplicationSelection],
) -> Result<(), CliError> {
    for selection in selections {
        writeln!(
            output,
            "selected pack: {} @ {}",
            selection.pack_id, selection.pack_revision
        )
        .map_err(|_| serialization_error())?;
    }
    Ok(())
}

fn mcp_plan_values(plan: &CoalescedMcpApplyPlan) -> Vec<serde_json::Value> {
    plan.documents()
        .iter()
        .map(|document| {
            json!({
                "schema_version": 1,
                "operation": "apply_mcp_document",
                "phase": "planned",
                "plan_digest": document.digest().as_str(),
                "relative_destination": document.relative_destination().as_str(),
                "document_hash": document.rendered().document_hash().as_str(),
                "disposition": disposition(document.disposition()),
                "effect": "a future harness load may connect to the declared MCP endpoint",
                "entries": document.entries().iter().map(|entry| json!({
                    "asset_id": entry.asset_id().as_str(),
                    "native_name": entry.native_name(),
                    "target": entry.policy().harness.as_str(),
                    "scope": entry.policy().scope.as_str(),
                    "rendered_hash": entry.proposed_receipt().map(|receipt| receipt.rendered_hash.as_str()),
                    "disposition": disposition(entry.disposition()),
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn render_mcp_plans(plan: &CoalescedMcpApplyPlan) -> String {
    let mut output = String::new();
    for document in plan.documents() {
        writeln!(output, "MCP document plan: {}", document.digest()).expect("string write");
        writeln!(
            output,
            "relative destination: {}",
            document.relative_destination()
        )
        .expect("string write");
        writeln!(
            output,
            "disposition: {}",
            disposition(document.disposition())
        )
        .expect("string write");
        writeln!(
            output,
            "effect: a future harness load may connect to the declared MCP endpoint"
        )
        .expect("string write");
        for entry in document.entries() {
            writeln!(
                output,
                "MCP server: {} ({}) -> {} {} ({})",
                entry.asset_id(),
                entry.native_name(),
                entry.policy().harness,
                entry.policy().scope.as_str(),
                disposition(entry.disposition()),
            )
            .expect("string write");
        }
    }
    output
}

fn instruction_plan_values(plan: &CoalescedInstructionApplyPlan) -> Vec<serde_json::Value> {
    plan.documents()
        .iter()
        .map(|document| {
            json!({
                "schema_version": 1,
                "operation": "apply_instruction_document",
                "phase": "planned",
                "plan_digest": document.digest().as_str(),
                "relative_destination": document.relative_destination().as_str(),
                "document_hash": document.rendered().document_hash().as_str(),
                "disposition": disposition(document.disposition()),
                "regions": document.regions().iter().map(|region| json!({
                    "asset_id": region.asset_id().as_str(),
                    "targets": region.policies().iter()
                        .map(|policy| policy.harness.as_str())
                        .collect::<Vec<_>>(),
                    "scope": region.policies()[0].scope.as_str(),
                    "rendered_hash": region.proposed_receipt().map(|receipt| receipt.rendered_hash.as_str()),
                    "operation": if region.is_removal() { "remove" } else { "apply" },
                    "disposition": disposition(region.disposition()),
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn region_targets(region: &kitrove_core::CoalescedInstructionRegion) -> String {
    region
        .policies()
        .iter()
        .map(|policy| policy.harness.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn region_scope(region: &kitrove_core::CoalescedInstructionRegion) -> &str {
    region
        .policies()
        .first()
        .expect("a coalesced instruction region has at least one consumer")
        .scope
        .as_str()
}

fn render_instruction_plans(plan: &CoalescedInstructionApplyPlan) -> String {
    let mut output = String::new();
    for document in plan.documents() {
        writeln!(output, "instruction document plan: {}", document.digest()).expect("string write");
        writeln!(
            output,
            "relative destination: {}",
            document.relative_destination()
        )
        .expect("string write");
        writeln!(
            output,
            "disposition: {}",
            disposition(document.disposition())
        )
        .expect("string write");
        for region in document.regions() {
            writeln!(
                output,
                "instruction: {} -> {} {} ({}{})",
                region.asset_id(),
                region_targets(region),
                region_scope(region),
                if region.is_removal() { "remove, " } else { "" },
                disposition(region.disposition()),
            )
            .expect("string write");
        }
    }
    output
}

fn render_batch_result(
    batch: &AtomicApplyBatchPlan,
    outcome: AtomicApplyBatchCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        let items = batch
            .items()
            .iter()
            .map(|item| match item {
                AtomicApplyItem::Skill(plan) => json!({
                    "asset_id": plan.asset_id().as_str(),
                    "target": plan.harness().as_str(),
                    "scope": plan.scope().as_str(),
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::Extension(plan) => json!({
                    "asset_id": plan.asset_id().as_str(),
                    "target": plan.proposed_receipt().harness.as_str(),
                    "scope": plan.proposed_receipt().scope.as_str(),
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::Instruction(plan) => json!({
                    "kind": "instruction_document",
                    "assets": plan.document().regions().iter().map(|region| json!({
                        "asset_id": region.asset_id().as_str(),
                        "targets": region.policies().iter()
                            .map(|policy| policy.harness.as_str())
                            .collect::<Vec<_>>(),
                        "scope": region_scope(region),
                        "operation": if region.is_removal() { "remove" } else { "apply" },
                    })).collect::<Vec<_>>(),
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::PromptCommand(plan) => json!({
                    "asset_id": plan.asset_id().as_str(),
                    "kind": "prompt_command",
                    "target": plan.policy().harness.as_str(),
                    "scope": plan.policy().scope.as_str(),
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::PromptCommandRemoval(plan) => json!({
                    "asset_id": plan.asset_id().as_str(),
                    "kind": "prompt_command",
                    "target": plan.policy().harness.as_str(),
                    "scope": plan.policy().scope.as_str(),
                    "operation": "remove",
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::Agent(plan) => json!({
                    "asset_id": plan.asset_id().as_str(),
                    "kind": "agent",
                    "target": plan.policy().harness.as_str(),
                    "scope": plan.policy().scope.as_str(),
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::AgentRemoval(plan) => json!({
                    "asset_id": plan.asset_id().as_str(),
                    "kind": "agent",
                    "target": plan.policy().harness.as_str(),
                    "scope": plan.policy().scope.as_str(),
                    "operation": "remove",
                    "outcome": batch_outcome_name(outcome),
                }),
                AtomicApplyItem::Mcp(plan) => json!({
                    "kind": "mcp_document",
                    "entries": plan.document().entries().iter().map(|entry| json!({
                        "asset_id": entry.asset_id().as_str(),
                        "native_name": entry.native_name(),
                        "target": entry.policy().harness.as_str(),
                        "scope": entry.policy().scope.as_str(),
                    })).collect::<Vec<_>>(),
                    "outcome": batch_outcome_name(outcome),
                }),
            })
            .collect::<Vec<_>>();
        return json_line(json!({
            "schema_version": 1,
            "operation": "apply_batch",
            "phase": "complete",
            "semantics": "atomic",
            "batch_digest": batch.digest().as_str(),
            "active_profile": batch.active_profile().map(ProfileId::as_str),
            "participant_count": batch.items().len(),
            "outcome": batch_outcome_name(outcome),
            "items": items,
        }));
    }
    Ok(format!(
        "atomic materialization batch complete: {} items\noutcome: {}\nbatch: {}\n",
        batch.items().len(),
        batch_outcome_name(outcome),
        batch.digest(),
    ))
}

fn render_plan(plan: &MaterializationPlan, json_output: bool) -> Result<String, CliError> {
    match plan {
        MaterializationPlan::Skill(plan) => render_skill_plan(plan, json_output),
        MaterializationPlan::Agent(plan) => render_agent_plan(plan, json_output),
        MaterializationPlan::Extension(plan) => render_extension_plan(plan, json_output),
        MaterializationPlan::PromptCommand(plan) => render_prompt_command_plan(plan, json_output),
    }
}

fn render_agent_plan(plan: &AgentApplyPlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": "apply_agent",
            "phase": "planned",
            "plan_digest": plan.digest().as_str(),
            "asset_id": plan.asset_id().as_str(),
            "target": plan.policy().harness.as_str(),
            "scope": plan.policy().scope.as_str(),
            "relative_destination": plan.relative_destination().as_str(),
            "rendered_hash": plan.rendered().content_hash().as_str(),
            "disposition": disposition(plan.disposition()),
        }));
    }
    Ok(format!(
        "agent apply plan: {}\nasset: {}\ntarget: {} {}\nrelative destination: {}\ndisposition: {}\n",
        plan.digest(),
        plan.asset_id(),
        plan.policy().harness,
        plan.policy().scope.as_str(),
        plan.relative_destination(),
        disposition(plan.disposition()),
    ))
}

fn render_prompt_command_plan(
    plan: &PromptCommandApplyPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": "apply_prompt_command",
            "phase": "planned",
            "plan_digest": plan.digest().as_str(),
            "asset_id": plan.asset_id().as_str(),
            "target": plan.policy().harness.as_str(),
            "scope": plan.policy().scope.as_str(),
            "relative_destination": plan.relative_destination().as_str(),
            "rendered_hash": plan.rendered().content_hash().as_str(),
            "disposition": disposition(plan.disposition()),
        }));
    }
    Ok(format!(
        "prompt-command apply plan: {}\nasset: {}\ntarget: {} {}\nrelative destination: {}\ndisposition: {}\n",
        plan.digest(),
        plan.asset_id(),
        plan.policy().harness,
        plan.policy().scope.as_str(),
        plan.relative_destination(),
        disposition(plan.disposition()),
    ))
}

fn render_skill_plan(plan: &ApplyPlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": "apply",
            "phase": "planned",
            "plan_digest": plan.digest().as_str(),
            "asset_id": plan.asset_id().as_str(),
            "target": plan.harness().as_str(),
            "scope": plan.scope().as_str(),
            "destination": plan.destination().as_str(),
            "rendered_hash": plan.rendered().rendered_hash().as_str(),
            "disposition": disposition(plan.disposition()),
        }));
    }
    let mut output = String::new();
    writeln!(output, "apply plan: {}", plan.digest()).expect("string write");
    writeln!(output, "asset: {}", plan.asset_id()).expect("string write");
    writeln!(
        output,
        "target: {} {}",
        plan.harness(),
        plan.scope().as_str()
    )
    .expect("string write");
    writeln!(output, "destination: {}", plan.destination()).expect("string write");
    writeln!(output, "disposition: {}", disposition(plan.disposition())).expect("string write");
    Ok(output)
}

fn render_extension_plan(plan: &ExtensionApplyPlan, json_output: bool) -> Result<String, CliError> {
    let layout = extension_layout(plan.rendered().layout());
    let entrypoint = extension_entrypoint(plan);
    let summary = PlanSummary::extension(plan);
    if json_output {
        return json_line(json!({
            "schema_version": 1,
            "operation": "apply_extension",
            "phase": "planned",
            "plan_digest": plan.digest().as_str(),
            "asset_id": plan.asset_id().as_str(),
            "target": summary.target,
            "scope": summary.scope,
            "relative_destination": plan.relative_destination().as_str(),
            "layout": layout,
            "entrypoint": entrypoint,
            "native_id": plan.rendered().native_id().as_str(),
            "rendered_hash": plan.rendered().rendered_hash().as_str(),
            "disposition": disposition(plan.disposition()),
        }));
    }
    Ok(format!(
        "extension apply plan: {}\nasset: {}\ntarget: {} {}\nrelative destination: {}\nlayout: {}\nentrypoint: {}\nnative identity: {}\ndisposition: {}\n",
        plan.digest(),
        plan.asset_id(),
        summary.target,
        summary.scope,
        plan.relative_destination(),
        layout,
        entrypoint,
        plan.rendered().native_id(),
        disposition(plan.disposition()),
    ))
}

const fn extension_layout(layout: NativeExtensionLayout) -> &'static str {
    match layout {
        NativeExtensionLayout::Standalone => "standalone",
        NativeExtensionLayout::Directory => "directory",
    }
}

fn extension_entrypoint(plan: &ExtensionApplyPlan) -> &str {
    match plan.rendered().layout() {
        NativeExtensionLayout::Standalone => plan.rendered().relative_name().as_str(),
        NativeExtensionLayout::Directory => "index.ts",
    }
}

fn json_line(value: serde_json::Value) -> Result<String, CliError> {
    serde_json::to_string(&value)
        .map(|encoded| format!("{encoded}\n"))
        .map_err(|_| serialization_error())
}

const fn disposition(disposition: ApplyDisposition) -> &'static str {
    match disposition {
        ApplyDisposition::Install => "install",
        ApplyDisposition::NoOp => "no_op",
        ApplyDisposition::Restore => "restore",
        ApplyDisposition::ManagedUpdate => "managed_update",
        ApplyDisposition::Remove => "remove",
    }
}

const fn batch_outcome_name(outcome: AtomicApplyBatchCommitOutcome) -> &'static str {
    match outcome {
        AtomicApplyBatchCommitOutcome::Committed => "committed",
    }
}

const fn serialization_error() -> CliError {
    CliError::new(
        "apply.serialization_failed",
        "the materialization result could not be serialized",
    )
}

#[cfg(test)]
#[path = "materialize_tests.rs"]
mod tests;
