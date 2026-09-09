use std::collections::BTreeMap;
#[cfg(unix)]
use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::sync::OnceLock;

#[cfg(unix)]
use kitrove_adapter_api::{
    EvidenceRef, HarnessAdapter as _, HarnessVersion, PolicyLine, VersionObservation,
};
use kitrove_adapter_api::{ExtensionTargetPolicy, RootId, RootTier, VersionObservationOwned};
#[cfg(unix)]
use kitrove_adapter_pi::PiAdapter;
use kitrove_agent_skills::{CaptureLimits, CapturedFile, CapturedTree, FileMode, hash_tree};
#[cfg(unix)]
use kitrove_core::{
    ApplyDisposition, ExtensionApplyAuthority, PiProjectTrustStatus, inspect_pi_project_trust,
    plan_extension_apply as plan_extension_apply_with_version,
};
use kitrove_core::{
    CapturedNativeExtension, ExtensionDestinationObservation, NativeExtensionLayout,
    NativeExtensionObservation, observe_extension_destination, plan_native_extension_adoption,
    render_native_extension,
};
use kitrove_model::{AssetId, ContentClass, HarnessScope, PortablePath};
#[cfg(unix)]
use kitrove_model::{
    ContentHash, HarnessId, LocalState, MachineConfig, MachineId, SchemaVersion, TrustDecision,
};
use kitrove_testkit::portable_manifest;
#[cfg(unix)]
use kitrove_version_probe::{VerifiedPiVersion, probe_pi_version};

#[cfg(unix)]
fn verified_pi_version(observed: &'static str) -> VerifiedPiVersion {
    static V0_83_0: OnceLock<VerifiedPiVersion> = OnceLock::new();
    static V0_84_0: OnceLock<VerifiedPiVersion> = OnceLock::new();

    let version = match observed {
        "0.83.0" => &V0_83_0,
        "0.84.0" => &V0_84_0,
        _ => panic!("unsupported synthetic Pi version"),
    };
    version
        .get_or_init(|| {
            let root = tempfile::tempdir().unwrap();
            let binary = root.path().join("pi");
            fs::write(&binary, format!("#!/bin/sh\nprintf '{observed}\\n'\n")).unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
            probe_pi_version(&binary).unwrap()
        })
        .clone()
}

#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
fn plan_extension_apply(
    manifest: &kitrove_model::EnvironmentManifest,
    asset_id: &AssetId,
    object: &kitrove_core::NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    anchor: &std::path::Path,
    project_trust: Option<&kitrove_core::PiProjectTrustEvidence>,
    local_state_text: &str,
    destination_observation: ExtensionDestinationObservation,
) -> Result<kitrove_core::ExtensionApplyPlan, kitrove_core::MaterializationError> {
    plan_extension_apply_with_version(
        manifest,
        asset_id,
        object,
        policy,
        ExtensionApplyAuthority::new(anchor, &verified_pi_version("0.83.0"), project_trust),
        local_state_text,
        destination_observation,
    )
}

fn asset_id() -> AssetId {
    AssetId::parse("native-review").unwrap()
}

fn policy(scope: HarnessScope) -> ExtensionTargetPolicy {
    #[cfg(unix)]
    {
        let version = verified_pi_version("0.83.0");
        PiAdapter
            .extension_target_policy(scope, VersionObservation::Verified(version.evidence()))
            .unwrap()
    }
    #[cfg(not(unix))]
    {
        ExtensionTargetPolicy::pi_native_extensions(scope, VersionObservationOwned::Unknown)
    }
}

fn manifest_and_object(
    layout: NativeExtensionLayout,
    bytes: &[u8],
) -> (
    kitrove_model::EnvironmentManifest,
    kitrove_core::NativeExtensionObject,
) {
    manifest_and_object_with_helper_mode(layout, bytes, FileMode::Regular)
}

fn manifest_and_object_with_helper_mode(
    layout: NativeExtensionLayout,
    bytes: &[u8],
    directory_helper_mode: FileMode,
) -> (
    kitrove_model::EnvironmentManifest,
    kitrove_core::NativeExtensionObject,
) {
    let files = match layout {
        NativeExtensionLayout::Standalone => BTreeMap::from([(
            PortablePath::parse("review.ts").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: bytes.to_vec(),
            },
        )]),
        NativeExtensionLayout::Directory => BTreeMap::from([
            (
                PortablePath::parse("index.ts").unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: bytes.to_vec(),
                },
            ),
            (
                PortablePath::parse("helper.ts").unwrap(),
                CapturedFile {
                    mode: directory_helper_mode,
                    bytes: b"export const helper = true;\n".to_vec(),
                },
            ),
        ]),
    };
    let entrypoint = match layout {
        NativeExtensionLayout::Standalone => "review.ts",
        NativeExtensionLayout::Directory => "index.ts",
    };
    let source = match layout {
        NativeExtensionLayout::Standalone => "review.ts",
        NativeExtensionLayout::Directory => "review",
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
    let mut manifest = portable_manifest();
    manifest.assets.clear();
    manifest.packs.clear();
    manifest.profiles.clear();
    manifest.required_bindings.clear();
    let plan = plan_native_extension_adoption(&observation, Some(asset_id()), &manifest).unwrap();
    (
        plan.proposed_manifest().clone(),
        plan.native_object().clone(),
    )
}

#[test]
fn rendering_refuses_modes_the_current_platform_cannot_preserve() {
    let (_, object) = manifest_and_object_with_helper_mode(
        NativeExtensionLayout::Directory,
        b"export default {};\n",
        FileMode::Executable,
    );
    let rendered = render_native_extension(&object, &policy(HarnessScope::User));
    if cfg!(unix) {
        assert_eq!(rendered.unwrap().tree(), object.tree());
    } else {
        assert_eq!(
            rendered.unwrap_err().code(),
            "apply.extension_mode_unsupported"
        );
    }
}

#[cfg(unix)]
fn local_state(object_hash: &ContentHash, trusted: bool) -> LocalState {
    LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("extension-apply-machine").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::from([HarnessId::Pi]),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: if trusted {
            BTreeMap::from([(
                object_hash.clone(),
                TrustDecision::Trusted {
                    rationale: "PRIVATE-TRUST-RATIONALE".to_owned(),
                },
            )])
        } else {
            BTreeMap::new()
        },
        scans: vec![],
    }
}

#[test]
fn exact_render_preserves_both_pi_layouts_without_transformation() {
    for layout in [
        NativeExtensionLayout::Standalone,
        NativeExtensionLayout::Directory,
    ] {
        let (_, object) = manifest_and_object(layout, b"export default {};\n");
        let rendered = render_native_extension(&object, &policy(HarnessScope::User)).unwrap();
        assert_eq!(rendered.layout(), layout);
        assert_eq!(rendered.tree(), object.tree());
        assert_eq!(rendered.rendered_hash(), object.hash());
        assert_eq!(
            rendered.relative_name().as_str(),
            match layout {
                NativeExtensionLayout::Standalone => "review.ts",
                NativeExtensionLayout::Directory => "review",
            }
        );
    }
}

#[cfg(unix)]
#[test]
fn planning_requires_exact_content_and_saved_project_trust() {
    let (manifest, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(root.path()).unwrap();
    let untrusted = local_state(object.hash(), false).to_json().unwrap();
    let error = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &untrusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.executable_trust_required");

    let mut denied_state = local_state(object.hash(), false);
    denied_state.trust.insert(
        object.hash().clone(),
        TrustDecision::Denied {
            rationale: "reviewed and denied".to_owned(),
        },
    );
    let denied = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &denied_state.to_json().unwrap(),
        ExtensionDestinationObservation::Absent,
    )
    .unwrap_err();
    assert_eq!(denied.code(), "apply.executable_trust_denied");

    let trusted = local_state(object.hash(), true).to_json().unwrap();
    let project_error = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::Project),
        &anchor,
        None,
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap_err();
    assert_eq!(project_error.code(), "apply.project_trust_required");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let trust_directory = anchor.join(".pi/agent");
        fs::create_dir_all(&trust_directory).unwrap();
        for directory in [anchor.join(".pi"), trust_directory.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let trust_store = trust_directory.join("trust.json");
        fs::write(
            &trust_store,
            format!("{{\"{}\":true}}", anchor.to_str().unwrap()),
        )
        .unwrap();
        fs::set_permissions(&trust_store, fs::Permissions::from_mode(0o600)).unwrap();
        let PiProjectTrustStatus::Trusted(project_trust) =
            inspect_pi_project_trust(&trust_store, &anchor).unwrap()
        else {
            panic!("saved trust should authorize the exact project anchor");
        };
        let project = plan_extension_apply(
            &manifest,
            &asset_id(),
            &object,
            &policy(HarnessScope::Project),
            &anchor,
            Some(&project_trust),
            &trusted,
            ExtensionDestinationObservation::Absent,
        )
        .unwrap();
        assert_eq!(project.proposed_receipt().scope, HarnessScope::Project);
        assert!(
            project
                .destination()
                .as_str()
                .ends_with("/.pi/extensions/review.ts")
        );
    }
}

#[cfg(unix)]
#[test]
fn planning_rejects_constructed_policy_outside_compiled_pi_authority() {
    let (manifest, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(root.path()).unwrap();
    let trusted = local_state(object.hash(), true).to_json().unwrap();
    let mut forged = policy(HarnessScope::User);
    forged.relative_root = PortablePath::parse(".pi/other").unwrap();

    let error = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &forged,
        &anchor,
        None,
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.extension_policy_invalid");
    assert!(!anchor.join(".pi/other/review.ts").exists());

    let mut forged_version = policy(HarnessScope::User);
    forged_version.version = VersionObservationOwned::Verified {
        observed: HarnessVersion::parse("0.78.9").unwrap(),
        policy_line: PolicyLine::PiLatest,
        evidence: EvidenceRef::parse(concat!(
            "local.version_probe.pi.blake3.",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ))
        .unwrap(),
    };
    let error = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &forged_version,
        &anchor,
        None,
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.harness_version_unverified");
}

#[cfg(unix)]
#[test]
fn confirmation_digest_binds_exact_harness_version_evidence() {
    let (manifest, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(root.path()).unwrap();
    let trusted = local_state(object.hash(), true).to_json().unwrap();
    let first_policy = policy(HarnessScope::User);
    let first = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &first_policy,
        &anchor,
        None,
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();
    let second_version = verified_pi_version("0.84.0");
    let second_policy = PiAdapter
        .extension_target_policy(
            HarnessScope::User,
            VersionObservation::Verified(second_version.evidence()),
        )
        .unwrap();
    let second = plan_extension_apply_with_version(
        &manifest,
        &asset_id(),
        &object,
        &second_policy,
        ExtensionApplyAuthority::new(&anchor, &second_version, None),
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();

    assert_ne!(first.digest(), second.digest());
    assert!(!first.same_confirmed_authority(&second));
}

#[cfg(unix)]
#[test]
fn confirmation_digest_binds_the_exact_project_trust_store_source() {
    let (manifest, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(root.path()).unwrap();
    let trusted = local_state(object.hash(), true).to_json().unwrap();
    let version = verified_pi_version("0.83.0");
    let policy = PiAdapter
        .extension_target_policy(
            HarnessScope::Project,
            VersionObservation::Verified(version.evidence()),
        )
        .unwrap();
    let body = format!("{{\"{}\":true}}", anchor.display());
    let first_store = anchor.join("trust-a.json");
    let second_store = anchor.join("trust-b.json");
    for store in [&first_store, &second_store] {
        fs::write(store, &body).unwrap();
        fs::set_permissions(store, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let first_trust = match inspect_pi_project_trust(&first_store, &anchor).unwrap() {
        PiProjectTrustStatus::Trusted(evidence) => evidence,
        status => panic!("unexpected trust status: {status:?}"),
    };
    let second_trust = match inspect_pi_project_trust(&second_store, &anchor).unwrap() {
        PiProjectTrustStatus::Trusted(evidence) => evidence,
        status => panic!("unexpected trust status: {status:?}"),
    };
    assert_eq!(
        first_trust.trust_store_hash(),
        second_trust.trust_store_hash()
    );

    let first = plan_extension_apply_with_version(
        &manifest,
        &asset_id(),
        &object,
        &policy,
        ExtensionApplyAuthority::new(&anchor, &version, Some(&first_trust)),
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();
    let second = plan_extension_apply_with_version(
        &manifest,
        &asset_id(),
        &object,
        &policy,
        ExtensionApplyAuthority::new(&anchor, &version, Some(&second_trust)),
        &trusted,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();

    assert_ne!(first.digest(), second.digest());
}

#[cfg(unix)]
#[test]
fn receipt_rules_cover_install_noop_restore_update_and_refusal() {
    let (manifest, object) =
        manifest_and_object(NativeExtensionLayout::Directory, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(root.path()).unwrap();
    let initial_state = local_state(object.hash(), true);
    let install = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &initial_state.to_json().unwrap(),
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();
    assert_eq!(install.disposition(), ApplyDisposition::Install);
    assert!(
        install
            .relative_destination()
            .as_str()
            .ends_with(".pi/agent/extensions/review")
    );
    assert!(!format!("{install:?}").contains("PRIVATE-TRUST-RATIONALE"));

    let receipt_state = install.proposed_local_state().clone();
    let exact = ExtensionDestinationObservation::Present {
        layout: object.layout(),
        object_hash: object.hash().clone(),
    };
    let no_op = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &receipt_state.to_json().unwrap(),
        exact.clone(),
    )
    .unwrap();
    assert_eq!(no_op.disposition(), ApplyDisposition::NoOp);

    let restore = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &receipt_state.to_json().unwrap(),
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();
    assert_eq!(restore.disposition(), ApplyDisposition::Restore);

    let mut prior_authority = receipt_state;
    prior_authority
        .receipts
        .values_mut()
        .next()
        .unwrap()
        .source_hash = ContentHash::digest(b"prior-source");
    let managed_update = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &prior_authority.to_json().unwrap(),
        exact,
    )
    .unwrap();
    assert_eq!(
        managed_update.disposition(),
        ApplyDisposition::ManagedUpdate
    );

    let unmanaged = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &initial_state.to_json().unwrap(),
        ExtensionDestinationObservation::Present {
            layout: object.layout(),
            object_hash: object.hash().clone(),
        },
    )
    .unwrap_err();
    assert_eq!(unmanaged.code(), "apply.destination_unmanaged");
}

#[test]
fn destination_observation_reconstructs_exact_standalone_and_directory_objects() {
    for layout in [
        NativeExtensionLayout::Standalone,
        NativeExtensionLayout::Directory,
    ] {
        let (_, object) = manifest_and_object(layout, b"export default {};\n");
        let root = tempfile::tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let destination = root_path.join(match layout {
            NativeExtensionLayout::Standalone => "review.ts",
            NativeExtensionLayout::Directory => "review",
        });
        match layout {
            NativeExtensionLayout::Standalone => {
                fs::write(
                    &destination,
                    &object.tree().files.values().next().unwrap().bytes,
                )
                .unwrap();
            }
            NativeExtensionLayout::Directory => {
                fs::create_dir_all(&destination).unwrap();
                for (path, file) in &object.tree().files {
                    fs::write(destination.join(path.as_str()), &file.bytes).unwrap();
                }
            }
        }
        assert_eq!(
            observe_extension_destination(&destination, &object, CaptureLimits::default()),
            ExtensionDestinationObservation::Present {
                layout,
                object_hash: object.hash().clone(),
            }
        );
    }
}

#[test]
fn destination_observation_refuses_layout_collisions() {
    let (_, standalone) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let standalone_root = tempfile::tempdir().unwrap();
    let standalone_destination = standalone_root.path().join("review.ts");
    fs::create_dir(&standalone_destination).unwrap();
    assert_eq!(
        observe_extension_destination(
            &standalone_destination,
            &standalone,
            CaptureLimits::default(),
        ),
        ExtensionDestinationObservation::Unsafe
    );

    let (_, directory) =
        manifest_and_object(NativeExtensionLayout::Directory, b"export default {};\n");
    let directory_root = tempfile::tempdir().unwrap();
    let directory_destination = directory_root.path().join("review");
    fs::write(&directory_destination, b"native-id collision\n").unwrap();
    assert_eq!(
        observe_extension_destination(&directory_destination, &directory, CaptureLimits::default(),),
        ExtensionDestinationObservation::Unsafe
    );
}

#[cfg(unix)]
#[test]
fn destination_observation_refuses_links_unsafe_ancestors_and_special_files() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let (_, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");

    let link_root = tempfile::tempdir().unwrap();
    let real_file = link_root.path().join("real.ts");
    fs::write(&real_file, b"export default {};\n").unwrap();
    let linked_destination = link_root.path().join("review.ts");
    symlink(&real_file, &linked_destination).unwrap();
    assert_eq!(
        observe_extension_destination(&linked_destination, &object, CaptureLimits::default(),),
        ExtensionDestinationObservation::Unsafe
    );

    let ancestor_root = tempfile::tempdir().unwrap();
    let real_parent = ancestor_root.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = ancestor_root.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    assert_eq!(
        observe_extension_destination(
            &linked_parent.join("review.ts"),
            &object,
            CaptureLimits::default(),
        ),
        ExtensionDestinationObservation::Unsafe
    );

    let socket_root = tempfile::tempdir().unwrap();
    let socket_destination = socket_root.path().join("review.ts");
    let _listener = UnixListener::bind(&socket_destination).unwrap();
    assert_eq!(
        observe_extension_destination(&socket_destination, &object, CaptureLimits::default(),),
        ExtensionDestinationObservation::Unsafe
    );
}

#[cfg(windows)]
#[test]
fn destination_observation_refuses_windows_reparse_ancestors() {
    let (_, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let real_parent = root.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = root.path().join("linked-parent");
    std::os::windows::fs::symlink_dir(&real_parent, &linked_parent)
        .expect("Windows CI must support creating a test reparse point");
    assert_eq!(
        observe_extension_destination(
            &linked_parent.join("review.ts"),
            &object,
            CaptureLimits::default(),
        ),
        ExtensionDestinationObservation::Unsafe
    );
}

#[cfg(unix)]
#[test]
fn machine_a_trust_never_authorizes_machine_b_through_portable_authority() {
    let (manifest, object) =
        manifest_and_object(NativeExtensionLayout::Standalone, b"export default {};\n");
    let root = tempfile::tempdir().unwrap();
    let anchor = fs::canonicalize(root.path()).unwrap();
    let machine_a = local_state(object.hash(), true).to_json().unwrap();
    let machine_b = local_state(object.hash(), false).to_json().unwrap();
    let planned_a = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &machine_a,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap();
    assert_eq!(planned_a.disposition(), ApplyDisposition::Install);
    let error_b = plan_extension_apply(
        &manifest,
        &asset_id(),
        &object,
        &policy(HarnessScope::User),
        &anchor,
        None,
        &machine_b,
        ExtensionDestinationObservation::Absent,
    )
    .unwrap_err();
    assert_eq!(error_b.code(), "apply.executable_trust_required");
    let portable = manifest.to_toml().unwrap();
    assert!(!portable.contains("PRIVATE-TRUST-RATIONALE"));
    assert!(!portable.contains("decision"));
}
