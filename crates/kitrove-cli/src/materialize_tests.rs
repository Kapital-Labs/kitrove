use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use kitrove_adapter_api::{HarnessAdapter as _, VersionObservation};
#[cfg(unix)]
use kitrove_adapter_api::{RootId, RootTier};
use kitrove_adapter_claude::ClaudeAdapter;
use kitrove_adapter_codex::CodexAdapter;
use kitrove_adapter_opencode::OpenCodeAdapter;
use kitrove_adapter_pi::PiAdapter;
#[cfg(unix)]
use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, hash_tree};
#[cfg(unix)]
use kitrove_core::{
    CapturedNativeExtension, ExtensionDestinationObservation, NativeExtensionObservation,
    plan_native_extension_adoption,
};
use kitrove_core::{
    InstructionAdoptionOutcome, McpAdoptionOutcome, TierOneInstructionCapabilities,
    observe_mcp_document, plan_instruction_adoption, plan_mcp_adoption,
};
use kitrove_model::{AssetId, HarnessId, HarnessScope, MachineConfig, MachineId, SchemaVersion};
#[cfg(unix)]
use kitrove_model::{ContentClass, PortablePath, TrustDecision};
#[cfg(unix)]
use kitrove_version_probe::probe_pi_version;

use super::*;

fn coalesced_instruction_plan() -> CoalescedInstructionApplyPlan {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("AGENTS.md"),
        concat!(
            "<!-- kitrove:instruction review begin -->\n",
            "Review carefully.\n",
            "<!-- kitrove:instruction review end -->\n",
        ),
    )
    .unwrap();
    let source_root = fs::canonicalize(source.path()).unwrap();
    let source_policy = CodexAdapter
        .instruction_target_policy(HarnessScope::Project, VersionObservation::Unknown)
        .unwrap();
    let observation =
        observe_instruction_document(&source_root, &source_policy, Default::default()).unwrap();
    let manifest = EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
    let capabilities = TierOneInstructionCapabilities::new(BTreeMap::from([
        (HarnessId::Claude, ClaudeAdapter.capability_matrix(None)),
        (HarnessId::Codex, CodexAdapter.capability_matrix(None)),
        (HarnessId::Pi, PiAdapter.capability_matrix(None)),
        (HarnessId::OpenCode, OpenCodeAdapter.capability_matrix(None)),
    ]))
    .unwrap();
    let asset_id = AssetId::parse("review").unwrap();
    let InstructionAdoptionOutcome::Ready(adoption) =
        plan_instruction_adoption(&observation, &asset_id, &manifest, &capabilities).unwrap()
    else {
        panic!("valid fixture instruction must be adoptable");
    };
    let target = tempfile::tempdir().unwrap();
    let target_root = fs::canonicalize(target.path()).unwrap();
    let projections = [HarnessId::Codex, HarnessId::Pi]
        .into_iter()
        .map(|harness| {
            let policy = instruction_target_policy(&harness, HarnessScope::Project).unwrap();
            let observation =
                observe_instruction_document(&target_root, &policy, Default::default()).unwrap();
            InstructionProjection::new(
                asset_id.clone(),
                adoption.portable_object().clone(),
                policy,
                observation,
            )
        })
        .collect();
    let state = LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("instruction-renderer-test").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::new(),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: Vec::new(),
    };
    plan_coalesced_instruction_apply(
        adoption.proposed_manifest(),
        projections,
        &state.to_json().unwrap(),
        None,
        Default::default(),
    )
    .unwrap()
}

#[cfg(unix)]
fn verified_extension_plan(layout: NativeExtensionLayout) -> ExtensionApplyPlan {
    let (source, entrypoint, files) = match layout {
        NativeExtensionLayout::Standalone => (
            "review.ts",
            "review.ts",
            BTreeMap::from([(
                PortablePath::parse("review.ts").unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: b"export default {};\n".to_vec(),
                },
            )]),
        ),
        NativeExtensionLayout::Directory => (
            "review",
            "index.ts",
            BTreeMap::from([(
                PortablePath::parse("index.ts").unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: b"export default {};\n".to_vec(),
                },
            )]),
        ),
    };
    let observation = NativeExtensionObservation::new(
        HarnessScope::User,
        RootTier::User,
        RootId::parse("pi.user.native.extensions").unwrap(),
        15,
        PortablePath::parse(source).unwrap(),
        "review",
        CapturedNativeExtension {
            layout,
            entrypoint: entrypoint.to_owned(),
            exact: CapturedTree {
                hash: hash_tree(&files),
                files,
            },
            content_class: ContentClass::Executable,
        },
    )
    .unwrap();
    let manifest = EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
    let asset_id = AssetId::parse("native-review").unwrap();
    let adoption =
        plan_native_extension_adoption(&observation, Some(asset_id.clone()), &manifest).unwrap();
    let object = adoption.native_object();
    let state = LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("renderer-test-machine").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::from([HarnessId::Pi]),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::from([(
            object.hash().clone(),
            TrustDecision::Trusted {
                rationale: "private test rationale".to_owned(),
            },
        )]),
        scans: Vec::new(),
    };
    let version_root = tempfile::tempdir().unwrap();
    let binary = version_root.path().join("pi");
    fs::write(&binary, "#!/bin/sh\nprintf '0.83.0\\n'\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let version = probe_pi_version(&binary).unwrap();
    let policy = PiAdapter
        .extension_target_policy(
            HarnessScope::User,
            VersionObservation::Verified(version.evidence()),
        )
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(temporary.path()).unwrap();
    plan_extension_apply(
        adoption.proposed_manifest(),
        &asset_id,
        object,
        &policy,
        ExtensionApplyAuthority::new(&anchor, &version, None),
        &state.to_json().unwrap(),
        ExtensionDestinationObservation::Absent,
    )
    .unwrap()
}

fn coalesced_mcp_plan() -> CoalescedMcpApplyPlan {
    let source = tempfile::tempdir().unwrap();
    let source_root = fs::canonicalize(source.path()).unwrap();
    fs::write(
        source_root.join(".claude.json"),
        r#"{"mcpServers":{"company-docs":{"type":"http","url":"https://docs.example.com/mcp"}}}"#,
    )
    .unwrap();
    let policy = mcp_target_policy(&HarnessId::Claude, HarnessScope::User).unwrap();
    let observation = observe_mcp_document(&source_root, &policy, Default::default()).unwrap();
    let selected = observation.parsed().unwrap().entries()[0]
        .exact_entry_hash()
        .clone();
    let asset_id = AssetId::parse("company-docs").unwrap();
    let manifest = EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
    let McpAdoptionOutcome::Ready(adoption) = plan_mcp_adoption(
        &observation,
        &selected,
        &asset_id,
        None,
        &manifest,
        &crate::adapters::tier_one_mcp_capabilities().unwrap(),
    )
    .unwrap() else {
        panic!("valid fixture MCP server must be adoptable");
    };
    let target = tempfile::tempdir().unwrap();
    let target_root = fs::canonicalize(target.path()).unwrap();
    fs::write(target_root.join(".claude.json"), "{}\n").unwrap();
    let target_observation =
        observe_mcp_document(&target_root, &policy, Default::default()).unwrap();
    let state = LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("mcp-renderer-test").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::new(),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: Vec::new(),
    };
    plan_coalesced_mcp_apply(
        adoption.proposed_manifest(),
        vec![McpProjection::new(
            asset_id,
            adoption.portable_object().clone(),
            policy,
            target_observation,
        )],
        &state.to_json().unwrap(),
        None,
        Default::default(),
    )
    .unwrap()
}

#[cfg(unix)]
#[test]
fn verified_extension_plan_rendering_is_structural_and_path_redacted() {
    for (layout, relative_destination, entrypoint) in [
        (
            NativeExtensionLayout::Standalone,
            ".pi/agent/extensions/review.ts",
            "review.ts",
        ),
        (
            NativeExtensionLayout::Directory,
            ".pi/agent/extensions/review",
            "index.ts",
        ),
    ] {
        let plan = verified_extension_plan(layout);
        let json = render_extension_plan(&plan, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["relative_destination"], relative_destination);
        assert_eq!(value["layout"], extension_layout(layout));
        assert_eq!(value["entrypoint"], entrypoint);
        assert_eq!(value["native_id"], "review");
        assert!(!json.contains(plan.destination().as_str()));

        let text = render_extension_plan(&plan, false).unwrap();
        assert!(text.contains(&format!("relative destination: {relative_destination}")));
        assert!(text.contains(&format!("layout: {}", extension_layout(layout))));
        assert!(text.contains(&format!("entrypoint: {entrypoint}")));
        assert!(text.contains("native identity: review"));
        assert!(!text.contains(plan.destination().as_str()));
    }
}

#[test]
fn instruction_plan_rendering_reports_shared_physical_authority() {
    let plan = coalesced_instruction_plan();
    let values = instruction_plan_values(&plan);

    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["operation"], "apply_instruction_document");
    assert_eq!(values[0]["relative_destination"], "AGENTS.md");
    assert_eq!(values[0]["regions"].as_array().unwrap().len(), 1);
    assert_eq!(values[0]["regions"][0]["targets"], json!(["codex", "pi"]));
    assert!(
        !values[0]
            .to_string()
            .contains(plan.documents()[0].destination().as_str())
    );

    let text = render_instruction_plans(&plan);
    assert!(text.contains("relative destination: AGENTS.md"));
    assert!(text.contains("instruction: review -> codex,pi project (install)"));
    assert!(!text.contains(plan.documents()[0].destination().as_str()));
}

#[test]
fn mcp_plan_rendering_reports_logical_entries_without_absolute_paths() {
    let plan = coalesced_mcp_plan();
    let values = mcp_plan_values(&plan);

    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["operation"], "apply_mcp_document");
    assert_eq!(values[0]["relative_destination"], ".claude.json");
    assert_eq!(values[0]["entries"][0]["asset_id"], "company-docs");
    assert_eq!(values[0]["entries"][0]["native_name"], "company-docs");
    assert_eq!(values[0]["entries"][0]["target"], "claude");
    assert_eq!(
        values[0]["effect"],
        "a future harness load may connect to the declared MCP endpoint"
    );
    assert!(
        !values[0]
            .to_string()
            .contains(plan.documents()[0].destination().as_str())
    );

    let text = render_mcp_plans(&plan);
    assert!(text.contains("relative destination: .claude.json"));
    assert!(text.contains("a future harness load may connect"));
    assert!(text.contains("MCP server: company-docs (company-docs) -> claude user (install)"));
    assert!(!text.contains(plan.documents()[0].destination().as_str()));
}

#[test]
fn unknown_opencode_version_blocks_instruction_materialization() {
    let error = instruction_target_policy(&HarnessId::OpenCode, HarnessScope::Project).unwrap_err();

    assert_eq!(error.code, "apply.harness_version_unverified");
}

#[test]
fn unknown_opencode_version_blocks_prompt_command_materialization() {
    let error = prompt_command_target_policy_with_version(
        &HarnessId::OpenCode,
        HarnessScope::Project,
        VersionObservation::Unknown,
    )
    .unwrap_err();

    assert_eq!(error.code, "apply.harness_version_unverified");
}
