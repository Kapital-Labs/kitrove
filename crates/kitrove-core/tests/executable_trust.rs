use std::collections::{BTreeMap, BTreeSet};

use kitrove_adapter_api::{RootId, RootTier};
use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, hash_tree};
use kitrove_core::{
    CapturedNativeExtension, ExecutableTrustDecision, ExecutableTrustDisposition,
    ExecutableTrustStatus, NativeExtensionLayout, NativeExtensionObservation,
    inspect_executable_trust, plan_executable_trust, plan_native_extension_adoption,
};
use kitrove_model::{
    AssetId, ContentClass, HarnessId, HarnessScope, LocalState, MachineConfig, MachineId,
    PortablePath, SchemaVersion, TrustDecision,
};
use kitrove_testkit::portable_manifest;

fn asset_id() -> AssetId {
    AssetId::parse("native-review").unwrap()
}

fn extension(bytes: &[u8]) -> NativeExtensionObservation {
    let files = BTreeMap::from([(
        PortablePath::parse("review.ts").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: bytes.to_vec(),
        },
    )]);
    NativeExtensionObservation::new(
        HarnessScope::User,
        RootTier::User,
        RootId::parse("pi.user.native.extensions").unwrap(),
        15,
        PortablePath::parse("review.ts").unwrap(),
        "review",
        CapturedNativeExtension {
            layout: NativeExtensionLayout::Standalone,
            entrypoint: "review.ts".to_owned(),
            exact: CapturedTree {
                hash: hash_tree(&files),
                files,
            },
            content_class: ContentClass::Executable,
        },
    )
    .unwrap()
}

fn manifest_and_object(
    bytes: &[u8],
) -> (
    kitrove_model::EnvironmentManifest,
    kitrove_core::NativeExtensionObject,
) {
    let mut manifest = portable_manifest();
    manifest.assets.clear();
    manifest.packs.clear();
    manifest.profiles.clear();
    manifest.required_bindings.clear();
    let plan =
        plan_native_extension_adoption(&extension(bytes), Some(asset_id()), &manifest).unwrap();
    (
        plan.proposed_manifest().clone(),
        plan.native_object().clone(),
    )
}

fn local_state() -> LocalState {
    LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("trust-test-machine").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::from([HarnessId::Pi]),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: vec![],
    }
}

#[test]
fn exact_object_trust_is_local_planned_and_idempotent() {
    let (manifest, object) = manifest_and_object(b"export default {}\n");
    let manifest_text = manifest.to_toml().unwrap();
    let state_text = local_state().to_json().unwrap();

    let first = plan_executable_trust(
        &manifest_text,
        &state_text,
        &asset_id(),
        &object,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap();
    assert_eq!(first.disposition(), ExecutableTrustDisposition::First);
    assert_eq!(first.object_hash(), object.hash());
    assert_eq!(
        first.proposed_local_state().trust[object.hash()],
        TrustDecision::Trusted {
            rationale: "explicit_exact_content_review".to_owned()
        }
    );
    assert_eq!(state_text, local_state().to_json().unwrap());
    assert!(!manifest_text.contains("explicit_exact_content_review"));

    let first_text = first.proposed_local_state().to_json().unwrap();
    let repeated = plan_executable_trust(
        &manifest_text,
        &first_text,
        &asset_id(),
        &object,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap();
    assert_eq!(repeated.disposition(), ExecutableTrustDisposition::NoOp);
    assert_eq!(
        repeated.proposed_local_state().to_json().unwrap(),
        first_text
    );
}

#[test]
fn denial_replaces_trust_without_touching_unrelated_local_authority() {
    let (manifest, object) = manifest_and_object(b"export default {}\n");
    let manifest_text = manifest.to_toml().unwrap();
    let mut state = local_state();
    state.trust.insert(
        object.hash().clone(),
        TrustDecision::Trusted {
            rationale: "prior-local-review".to_owned(),
        },
    );
    let unrelated = kitrove_model::ContentHash::digest(b"unrelated");
    state.trust.insert(
        unrelated.clone(),
        TrustDecision::Denied {
            rationale: "keep-this-record".to_owned(),
        },
    );

    let plan = plan_executable_trust(
        &manifest_text,
        &state.to_json().unwrap(),
        &asset_id(),
        &object,
        ExecutableTrustDecision::Denied,
    )
    .unwrap();
    assert_eq!(plan.disposition(), ExecutableTrustDisposition::Replace);
    assert!(matches!(
        plan.proposed_local_state().trust[object.hash()],
        TrustDecision::Denied { .. }
    ));
    assert_eq!(
        plan.proposed_local_state().trust[&unrelated],
        TrustDecision::Denied {
            rationale: "keep-this-record".to_owned()
        }
    );
}

#[test]
fn changed_executable_content_never_inherits_prior_exact_hash_trust() {
    let (old_manifest, old_object) = manifest_and_object(b"export default { old: true }\n");
    let (new_manifest, new_object) = manifest_and_object(b"export default { new: true }\n");
    assert_ne!(old_object.hash(), new_object.hash());
    let mut state = local_state();
    state.trust.insert(
        old_object.hash().clone(),
        TrustDecision::Trusted {
            rationale: "explicit_exact_content_review".to_owned(),
        },
    );

    let plan = plan_executable_trust(
        &new_manifest.to_toml().unwrap(),
        &state.to_json().unwrap(),
        &asset_id(),
        &new_object,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap();
    assert_eq!(plan.disposition(), ExecutableTrustDisposition::First);
    assert!(
        plan.proposed_local_state()
            .trust
            .contains_key(old_object.hash())
    );
    assert!(
        plan.proposed_local_state()
            .trust
            .contains_key(new_object.hash())
    );
    assert!(
        !old_manifest
            .to_toml()
            .unwrap()
            .contains("explicit_exact_content_review")
    );
    assert!(
        !new_manifest
            .to_toml()
            .unwrap()
            .contains("explicit_exact_content_review")
    );
}

#[test]
fn planner_rejects_wrong_objects_and_redacts_local_state_from_debug() {
    let (manifest, object) = manifest_and_object(b"export default {}\n");
    let (_, wrong) = manifest_and_object(b"export default { hostile: true }\n");
    let mut state = local_state();
    state.trust.insert(
        object.hash().clone(),
        TrustDecision::Denied {
            rationale: "LOCAL-TRUST-CANARY".to_owned(),
        },
    );
    let state_text = state.to_json().unwrap();
    let error = plan_executable_trust(
        &manifest.to_toml().unwrap(),
        &state_text,
        &asset_id(),
        &wrong,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap_err();
    assert_eq!(error.code(), "trust.asset_invalid");
    assert!(!format!("{error:?}").contains("LOCAL-TRUST-CANARY"));

    let plan = plan_executable_trust(
        &manifest.to_toml().unwrap(),
        &state_text,
        &asset_id(),
        &object,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap();
    assert!(!format!("{plan:?}").contains("LOCAL-TRUST-CANARY"));
}

#[test]
fn plan_digest_binds_exact_local_state_and_requested_decision() {
    let (manifest, object) = manifest_and_object(b"export default {}\n");
    let manifest_text = manifest.to_toml().unwrap();
    let state = local_state();
    let state_text = state.to_json().unwrap();
    let trusted = plan_executable_trust(
        &manifest_text,
        &state_text,
        &asset_id(),
        &object,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap();
    let denied = plan_executable_trust(
        &manifest_text,
        &state_text,
        &asset_id(),
        &object,
        ExecutableTrustDecision::Denied,
    )
    .unwrap();
    assert_ne!(trusted.digest(), denied.digest());

    let mut changed = state;
    changed.machine.enabled_targets.clear();
    let changed_plan = plan_executable_trust(
        &manifest_text,
        &changed.to_json().unwrap(),
        &asset_id(),
        &object,
        ExecutableTrustDecision::Trusted,
    )
    .unwrap();
    assert_ne!(trusted.digest(), changed_plan.digest());
}

#[test]
fn inspection_reports_exact_local_status_without_exposing_rationale() {
    let (manifest, object) = manifest_and_object(b"export default {}\n");
    let manifest_text = manifest.to_toml().unwrap();
    let state = local_state();
    let unreviewed = inspect_executable_trust(
        &manifest_text,
        &state.to_json().unwrap(),
        &asset_id(),
        &object,
    )
    .unwrap();
    assert_eq!(unreviewed.asset_id(), &asset_id());
    assert_eq!(unreviewed.object_hash(), object.hash());
    assert_eq!(unreviewed.status(), ExecutableTrustStatus::Unreviewed);

    let mut denied_state = state;
    denied_state.trust.insert(
        object.hash().clone(),
        TrustDecision::Denied {
            rationale: "LOCAL-INSPECTION-CANARY".to_owned(),
        },
    );
    let denied = inspect_executable_trust(
        &manifest_text,
        &denied_state.to_json().unwrap(),
        &asset_id(),
        &object,
    )
    .unwrap();
    assert_eq!(denied.status(), ExecutableTrustStatus::Denied);
    assert!(!format!("{denied:?}").contains("LOCAL-INSPECTION-CANARY"));
    assert!(!format!("{denied:?}").contains(asset_id().as_str()));
}
