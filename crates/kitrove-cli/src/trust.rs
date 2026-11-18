use std::fmt::Write as _;

use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    ExecutableTrustCommitOutcome, ExecutableTrustDecision, ExecutableTrustDisposition,
    ExecutableTrustInspection, ExecutableTrustPlan, ExecutableTrustStatus, commit_executable_trust,
    inspect_executable_trust, load_native_extension_object, plan_executable_trust,
};
use kitrove_model::{AssetId, AssetKind, ContentClass, EnvironmentManifest, HarnessId};
use serde_json::json;

use crate::args::{CliError, TrustApplyArgs, TrustAuditArgs, TrustDecisionArg, TrustPlanArgs};
use crate::portable::CompletedCommand;
use crate::scan::{
    read_portable_text, resolve_required_environment_root, resolve_required_state_root,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn run_trust_plan(arguments: TrustPlanArgs) -> Result<CompletedCommand, CliError> {
    let (authority, plan) = build_plan(
        arguments.environment.as_deref(),
        &arguments.asset_id,
        arguments.decision,
    )?;
    Ok(CompletedCommand {
        output: render_subject_plan(&authority, &plan, arguments.json, "planned")?,
        status: 0,
    })
}

pub(crate) fn run_trust_apply(arguments: TrustApplyArgs) -> Result<CompletedCommand, CliError> {
    let (authority, plan) = build_plan(
        arguments.environment.as_deref(),
        &arguments.asset_id,
        arguments.decision,
    )?;
    if arguments.confirm != *plan.digest() {
        return Err(CliError::new(
            "trust.confirmation_mismatch",
            "--confirm does not match the exact current trust plan",
        ));
    }
    let skill_output = if is_skill(&authority, plan.asset_id()) {
        Some(render_subject_plan(
            &authority,
            &plan,
            arguments.json,
            "applied",
        )?)
    } else {
        None
    };
    let outcome = commit_executable_trust(
        &plan,
        &authority.environment_root,
        &authority.state_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: match skill_output {
            Some(output) => output,
            None => render_apply(&plan, outcome, arguments.json)?,
        },
        status: 0,
    })
}

pub(crate) fn run_trust_audit(arguments: TrustAuditArgs) -> Result<CompletedCommand, CliError> {
    let authority = load_authority(arguments.environment.as_deref())?;
    let asset_ids = match arguments.asset_id {
        Some(asset_id) => vec![asset_id],
        None => authority
            .manifest
            .assets
            .iter()
            .filter(|(_, asset)| {
                (asset.kind == AssetKind::Skill
                    || (asset.kind == AssetKind::Extension
                        && asset.native_variants.contains_key(&HarnessId::Pi)))
                    && asset.content_class == ContentClass::Executable
            })
            .map(|(asset_id, _)| asset_id.clone())
            .collect(),
    };
    let inspections = asset_ids
        .iter()
        .map(|asset_id| {
            if is_skill(&authority, asset_id) {
                let bundle = kitrove_core::load_scripted_skill_bundle(
                    &authority.manifest,
                    asset_id,
                    &authority.environment_root,
                    CaptureLimits::default(),
                )
                .map_err(trust_error)?;
                let status = kitrove_core::inspect_scripted_skill_trust(
                    &authority.manifest_text,
                    &authority.state_text,
                    asset_id,
                    &bundle,
                )
                .map_err(trust_error)?;
                Ok(TrustInspection::Skill {
                    id: asset_id.clone(),
                    revision: authority.manifest.assets[asset_id].content_hash.clone(),
                    status,
                    files: bundle.files(),
                })
            } else {
                let object = load_object(&authority, asset_id)?;
                inspect_executable_trust(
                    &authority.manifest_text,
                    &authority.state_text,
                    asset_id,
                    &object,
                )
                .map(TrustInspection::Extension)
                .map_err(trust_error)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let attention = inspections
        .iter()
        .any(|inspection| inspection.status() != ExecutableTrustStatus::Trusted);
    Ok(CompletedCommand {
        output: render_audit(&inspections, arguments.json)?,
        status: if attention { 3 } else { 0 },
    })
}

struct TrustAuthority {
    environment_root: std::path::PathBuf,
    state_root: std::path::PathBuf,
    manifest_text: String,
    manifest: EnvironmentManifest,
    state_text: String,
}

fn load_authority(
    explicit_environment: Option<&std::path::Path>,
) -> Result<TrustAuthority, CliError> {
    let environment_root = resolve_required_environment_root(explicit_environment)?;
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
                "trust.local_state_missing",
                "executable trust requires an existing machine-local state.json",
            )
        })?;
    Ok(TrustAuthority {
        environment_root,
        state_root,
        manifest_text,
        manifest,
        state_text,
    })
}

fn build_plan(
    explicit_environment: Option<&std::path::Path>,
    asset_id: &AssetId,
    decision: TrustDecisionArg,
) -> Result<(TrustAuthority, ExecutableTrustPlan), CliError> {
    let authority = load_authority(explicit_environment)?;
    let decision = match decision {
        TrustDecisionArg::Trusted => ExecutableTrustDecision::Trusted,
        TrustDecisionArg::Denied => ExecutableTrustDecision::Denied,
    };
    let plan = if is_skill(&authority, asset_id) {
        let bundle = kitrove_core::load_scripted_skill_bundle(
            &authority.manifest,
            asset_id,
            &authority.environment_root,
            CaptureLimits::default(),
        )
        .map_err(trust_error)?;
        kitrove_core::plan_scripted_skill_trust(
            &authority.manifest_text,
            &authority.state_text,
            asset_id,
            &bundle,
            decision,
        )
        .map_err(trust_error)?
    } else {
        let object = load_object(&authority, asset_id)?;
        plan_executable_trust(
            &authority.manifest_text,
            &authority.state_text,
            asset_id,
            &object,
            decision,
        )
        .map_err(trust_error)?
    };
    Ok((authority, plan))
}

fn load_object(
    authority: &TrustAuthority,
    asset_id: &AssetId,
) -> Result<kitrove_core::NativeExtensionObject, CliError> {
    load_native_extension_object(
        &authority.manifest,
        asset_id,
        &HarnessId::Pi,
        &authority.environment_root,
        CaptureLimits::default(),
    )
    .map_err(|error| CliError::new(error.code(), error.message()))
}

fn render_plan(plan: &ExecutableTrustPlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        return serde_json::to_string(&json!({
            "schema_version": 1,
            "operation": "trust",
            "phase": "planned",
            "asset_id": plan.asset_id().as_str(),
            "harness": HarnessId::Pi.as_str(),
            "object_hash": plan.object_hash().as_str(),
            "decision": decision_name(plan.decision()),
            "disposition": disposition_name(plan.disposition()),
            "plan_digest": plan.digest().as_str(),
        }))
        .map(|output| format!("{output}\n"))
        .map_err(serialization_error);
    }
    Ok(format!(
        "executable trust plan: {}\nasset: {}\nharness: {}\nobject: {}\ndecision: {}\ndisposition: {}\n",
        plan.digest(),
        plan.asset_id(),
        HarnessId::Pi,
        plan.object_hash(),
        decision_name(plan.decision()),
        disposition_name(plan.disposition()),
    ))
}

fn render_audit(inspections: &[TrustInspection], json_output: bool) -> Result<String, CliError> {
    if json_output {
        let records = inspections
            .iter()
            .map(|inspection| {
                match inspection {
                    TrustInspection::Extension(inspection) => json!({ "asset_id": inspection.asset_id().as_str(), "harness": inspection.harness().as_str(), "object_hash": inspection.object_hash().as_str(), "status": status_name(inspection.status()) }),
                    TrustInspection::Skill { id, revision, status, files } => json!({ "asset_id": id.as_str(), "kind": "skill", "asset_revision": revision.as_str(), "object_hash": revision.as_str(), "status": status_name(*status), "files": files_json(files) }),
                }
            })
            .collect::<Vec<_>>();
        return serde_json::to_string(&json!({
            "schema_version": 1,
            "operation": "trust",
            "phase": "audit",
            "objects": records,
        }))
        .map(|output| format!("{output}\n"))
        .map_err(serialization_error);
    }
    let mut output = String::from("executable trust audit\n");
    if inspections.is_empty() {
        output.push_str("objects: none\n");
    }
    for inspection in inspections {
        match inspection {
            TrustInspection::Extension(inspection) => writeln!(
                output,
                "{} {} {}: {}",
                inspection.asset_id(),
                inspection.harness(),
                inspection.object_hash(),
                status_name(inspection.status())
            ),
            TrustInspection::Skill {
                id,
                revision,
                status,
                ..
            } => writeln!(
                output,
                "{} skill {}: {}",
                id,
                revision,
                status_name(*status)
            ),
        }
        .expect("writing to a string cannot fail");
    }
    Ok(output)
}

fn render_apply(
    plan: &ExecutableTrustPlan,
    _outcome: ExecutableTrustCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return serde_json::to_string(&json!({
            "schema_version": 1,
            "operation": "trust",
            "phase": "applied",
            "asset_id": plan.asset_id().as_str(),
            "harness": HarnessId::Pi.as_str(),
            "object_hash": plan.object_hash().as_str(),
            "decision": decision_name(plan.decision()),
            "disposition": disposition_name(plan.disposition()),
            "plan_digest": plan.digest().as_str(),
        }))
        .map(|output| format!("{output}\n"))
        .map_err(serialization_error);
    }
    Ok(format!(
        "executable trust applied: {}\nasset: {}\nharness: {}\nobject: {}\ndecision: {}\ndisposition: {}\n",
        plan.digest(),
        plan.asset_id(),
        HarnessId::Pi,
        plan.object_hash(),
        decision_name(plan.decision()),
        disposition_name(plan.disposition()),
    ))
}

const fn decision_name(decision: ExecutableTrustDecision) -> &'static str {
    match decision {
        ExecutableTrustDecision::Trusted => "trusted",
        ExecutableTrustDecision::Denied => "denied",
    }
}

const fn disposition_name(disposition: ExecutableTrustDisposition) -> &'static str {
    match disposition {
        ExecutableTrustDisposition::First => "first",
        ExecutableTrustDisposition::Replace => "replace",
        ExecutableTrustDisposition::NoOp => "no_op",
    }
}

const fn status_name(status: ExecutableTrustStatus) -> &'static str {
    match status {
        ExecutableTrustStatus::Trusted => "trusted",
        ExecutableTrustStatus::Denied => "denied",
        ExecutableTrustStatus::Unreviewed => "unreviewed",
    }
}

fn trust_error(error: kitrove_core::ExecutableTrustError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn serialization_error(_: serde_json::Error) -> CliError {
    CliError::new(
        "trust.output_serialization_failed",
        "trust output could not be serialized",
    )
}

enum TrustInspection {
    Extension(ExecutableTrustInspection),
    Skill {
        id: AssetId,
        revision: kitrove_model::ContentHash,
        status: ExecutableTrustStatus,
        files: Vec<kitrove_core::ScriptedSkillFile>,
    },
}
impl TrustInspection {
    fn status(&self) -> ExecutableTrustStatus {
        match self {
            Self::Extension(i) => i.status(),
            Self::Skill { status, .. } => *status,
        }
    }
}
fn is_skill(authority: &TrustAuthority, id: &AssetId) -> bool {
    authority
        .manifest
        .assets
        .get(id)
        .is_some_and(|a| a.kind == AssetKind::Skill)
}
fn files_json(files: &[kitrove_core::ScriptedSkillFile]) -> Vec<serde_json::Value> {
    files.iter().map(|file| json!({ "component": file.component, "path": file.path, "mode": format!("{:?}", file.mode), "bytes": file.bytes, "hash": file.hash.as_str() })).collect()
}
fn render_subject_plan(
    authority: &TrustAuthority,
    plan: &ExecutableTrustPlan,
    json_output: bool,
    phase: &str,
) -> Result<String, CliError> {
    if !is_skill(authority, plan.asset_id()) {
        return render_plan(plan, json_output);
    }
    let bundle = kitrove_core::load_scripted_skill_bundle(
        &authority.manifest,
        plan.asset_id(),
        &authority.environment_root,
        CaptureLimits::default(),
    )
    .map_err(trust_error)?;
    if json_output {
        return serde_json::to_string(&json!({"schema_version":1,"operation":"trust","phase":phase,"asset_id":plan.asset_id().as_str(),"kind":"skill","object_hash":plan.object_hash().as_str(),"asset_revision":plan.object_hash().as_str(),"decision":decision_name(plan.decision()),"disposition":disposition_name(plan.disposition()),"plan_digest":plan.digest().as_str(),"files":files_json(&bundle.files())})).map(|text| format!("{text}\n")).map_err(serialization_error);
    }
    Ok(format!(
        "script-containing skill trust {phase}\nasset: {}\nbundle revision: {}\ndecision: {}\nplan: {}\nThis machine only. Denial does not remove existing tool files.\n",
        plan.asset_id(),
        plan.object_hash(),
        decision_name(plan.decision()),
        plan.digest()
    ))
}

/// An exact plan retained between review and the existing journaled trust commit.
pub(crate) struct SkillReview {
    authority: TrustAuthority,
    plan: ExecutableTrustPlan,
    pub(crate) files: Vec<kitrove_core::ScriptedSkillFile>,
    bundle: kitrove_core::ScriptedSkillBundle,
}
impl SkillReview {
    pub(crate) fn file_bytes(&self, index: usize) -> Option<&[u8]> {
        self.bundle.file_bytes(index)
    }
    pub(crate) fn revision(&self) -> &kitrove_model::ContentHash {
        self.plan.object_hash()
    }
    pub(crate) fn commit(self) -> Result<(), CliError> {
        commit_executable_trust(
            &self.plan,
            &self.authority.environment_root,
            &self.authority.state_root,
            CaptureLimits::default(),
        )
        .map(|_| ())
        .map_err(|e| CliError::new(e.code(), e.message()))
    }
}
pub(crate) fn prepare_skill_review(
    root: &std::path::Path,
    id: &AssetId,
) -> Result<Option<SkillReview>, CliError> {
    let authority = load_authority(Some(root))?;
    if !is_skill(&authority, id)
        || authority.manifest.assets[id].content_class != ContentClass::Executable
    {
        return Ok(None);
    }
    let bundle = kitrove_core::load_scripted_skill_bundle(
        &authority.manifest,
        id,
        root,
        CaptureLimits::default(),
    )
    .map_err(trust_error)?;
    if kitrove_core::inspect_scripted_skill_trust(
        &authority.manifest_text,
        &authority.state_text,
        id,
        &bundle,
    )
    .map_err(trust_error)?
        == ExecutableTrustStatus::Trusted
    {
        return Ok(None);
    }
    let plan = kitrove_core::plan_scripted_skill_trust(
        &authority.manifest_text,
        &authority.state_text,
        id,
        &bundle,
        ExecutableTrustDecision::Trusted,
    )
    .map_err(trust_error)?;
    Ok(Some(SkillReview {
        authority,
        plan,
        files: bundle.files(),
        bundle,
    }))
}
