use std::collections::BTreeMap;
use std::fs;

use kitrove_agent_skills::{
    CaptureLimits, CaptureMeter, CapturedFile, CapturedTree, FileMode, hash_tree,
};
use kitrove_core::{
    NativeExtensionLayout, NativeExtensionObject, NativeExtensionSource, ObjectInstallOutcome,
    ObjectStageOutcome, ObjectState, ObjectStore, VerifiedObjectEnvelope, capture_pi_extension,
    capture_pi_extension_metered, load_native_extension_object, verify_referenced_objects,
};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, HarnessId, NativeVariant, PortablePath, SnapshotObjectKind,
};
use kitrove_testkit::portable_manifest;
use tempfile::TempDir;

#[cfg(target_os = "macos")]
fn temporary_directory() -> TempDir {
    tempfile::tempdir_in("/private/tmp").unwrap()
}

#[cfg(not(target_os = "macos"))]
fn temporary_directory() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn tree(path: &str, bytes: &[u8]) -> CapturedTree {
    let files = BTreeMap::from([(
        PortablePath::parse(path).unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: bytes.to_vec(),
        },
    )]);
    let hash = hash_tree(&files);
    CapturedTree { files, hash }
}

#[test]
fn standalone_capture_preserves_exact_bytes_without_execution() {
    let temporary = temporary_directory();
    let path = temporary.path().join("review.ts");
    let sentinel = temporary.path().join("must-not-exist");
    let bytes = format!(
        "await Deno.writeTextFile({:?}, 'executed');\nthrow new Error('must never run');\n",
        sentinel
    );
    fs::write(&path, bytes.as_bytes()).unwrap();

    let captured = capture_pi_extension(
        &NativeExtensionSource::Standalone { path },
        CaptureLimits::default(),
    )
    .unwrap();

    assert_eq!(captured.layout, NativeExtensionLayout::Standalone);
    assert_eq!(captured.entrypoint, "review.ts");
    assert_eq!(captured.content_class, ContentClass::Executable);
    assert_eq!(
        captured
            .exact
            .files
            .get(&PortablePath::parse("review.ts").unwrap())
            .unwrap()
            .bytes,
        bytes.as_bytes()
    );
    assert!(!sentinel.exists());
}

#[test]
fn directory_capture_preserves_every_exact_file_and_mode() {
    let temporary = temporary_directory();
    let extension = temporary.path().join("review");
    fs::create_dir(&extension).unwrap();
    fs::write(
        extension.join("index.ts"),
        b"export { helper } from './helper.ts';\n",
    )
    .unwrap();
    fs::write(extension.join("helper.ts"), b"export const helper = 7;\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            extension.join("helper.ts"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let captured = capture_pi_extension(
        &NativeExtensionSource::Directory { path: extension },
        CaptureLimits::default(),
    )
    .unwrap();

    assert_eq!(captured.layout, NativeExtensionLayout::Directory);
    assert_eq!(captured.entrypoint, "index.ts");
    assert_eq!(captured.exact.files.len(), 2);
    assert_eq!(
        captured.exact.files[&PortablePath::parse("index.ts").unwrap()].bytes,
        b"export { helper } from './helper.ts';\n"
    );
    assert_eq!(
        captured.exact.files[&PortablePath::parse("helper.ts").unwrap()].bytes,
        b"export const helper = 7;\n"
    );
    #[cfg(unix)]
    assert_eq!(
        captured.exact.files[&PortablePath::parse("helper.ts").unwrap()].mode,
        FileMode::Executable
    );
}

#[test]
fn native_capture_refuses_private_keys_and_aggregate_limit_overflow() {
    let temporary = temporary_directory();
    let extension = temporary.path().join("review");
    fs::create_dir(&extension).unwrap();
    fs::write(extension.join("index.ts"), b"export default {};\n").unwrap();
    fs::write(
        extension.join("helper.ts"),
        b"-----BEGIN PRIVATE KEY-----\nNATIVE_CAPTURE_CANARY\n", // gitleaks:allow -- synthetic rejection fixture
    )
    .unwrap();
    assert_eq!(
        capture_pi_extension(
            &NativeExtensionSource::Directory {
                path: extension.clone(),
            },
            CaptureLimits::default(),
        )
        .unwrap_err()
        .code(),
        "skill.credential_artifact"
    );

    fs::write(extension.join("helper.ts"), b"0123456789").unwrap();
    let error = capture_pi_extension(
        &NativeExtensionSource::Directory { path: extension },
        CaptureLimits {
            max_files: 8,
            max_file_bytes: 64,
            max_total_bytes: 12,
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "capture.total_size_limit");
}

#[test]
fn native_capture_public_debug_and_errors_redact_source_paths_and_bytes() {
    let temporary = temporary_directory();
    let path = temporary.path().join("absolute-path-canary.ts");
    let authored_canary = "NATIVE_AUTHORED_CANARY_5f41";
    fs::write(
        &path,
        format!("-----BEGIN PRIVATE KEY-----\n{authored_canary}\n"),
    )
    .unwrap();
    let source = NativeExtensionSource::Standalone { path: path.clone() };
    assert!(!format!("{source:?}").contains(path.to_string_lossy().as_ref()));
    let error = capture_pi_extension(&source, CaptureLimits::default()).unwrap_err();
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(!rendered.contains(path.to_string_lossy().as_ref()));
        assert!(!rendered.contains(authored_canary));
    }
    assert_eq!(
        error.path(),
        std::path::Path::new("native-extension-source")
    );
}

#[cfg(unix)]
#[test]
fn native_capture_refuses_symlinks_and_special_files() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let temporary = temporary_directory();
    let extension = temporary.path().join("review");
    fs::create_dir(&extension).unwrap();
    fs::write(extension.join("index.ts"), b"export default {};\n").unwrap();
    symlink("index.ts", extension.join("linked.ts")).unwrap();
    assert_eq!(
        capture_pi_extension(
            &NativeExtensionSource::Directory {
                path: extension.clone(),
            },
            CaptureLimits::default(),
        )
        .unwrap_err()
        .code(),
        "capture.symlink"
    );
    fs::remove_file(extension.join("linked.ts")).unwrap();
    let _listener = UnixListener::bind(extension.join("agent.sock")).unwrap();
    assert_eq!(
        capture_pi_extension(
            &NativeExtensionSource::Directory { path: extension },
            CaptureLimits::default(),
        )
        .unwrap_err()
        .code(),
        "capture.special_file"
    );
}

#[test]
fn directory_capture_requires_root_index_and_refuses_credentials() {
    let temporary = temporary_directory();
    let extension = temporary.path().join("review");
    fs::create_dir(&extension).unwrap();
    fs::write(extension.join("helper.ts"), b"export const value = 1;\n").unwrap();

    assert_eq!(
        capture_pi_extension(
            &NativeExtensionSource::Directory {
                path: extension.clone(),
            },
            CaptureLimits::default(),
        )
        .unwrap_err()
        .code(),
        "native_extension.entrypoint_missing"
    );

    fs::write(extension.join("index.ts"), b"export default {};\n").unwrap();
    fs::write(extension.join("credentials.json"), b"{}\n").unwrap();
    assert_eq!(
        capture_pi_extension(
            &NativeExtensionSource::Directory { path: extension },
            CaptureLimits::default(),
        )
        .unwrap_err()
        .code(),
        "skill.credential_artifact"
    );
}

#[test]
fn caller_meter_can_refuse_before_file_body_read() {
    struct RefusingMeter;
    impl CaptureMeter for RefusingMeter {
        fn try_file_attempt(&mut self) -> bool {
            false
        }
        fn remaining_bytes(&self) -> u64 {
            0
        }
        fn try_charge_bytes(&mut self, _bytes: u64) -> bool {
            panic!("bytes cannot be charged after the file attempt was refused")
        }
    }

    let temporary = temporary_directory();
    let path = temporary.path().join("refused.ts");
    fs::write(&path, b"secret body that must not be read").unwrap();
    let error = capture_pi_extension_metered(
        &NativeExtensionSource::Standalone { path },
        CaptureLimits::default(),
        &mut RefusingMeter,
    )
    .unwrap_err();
    assert_eq!(error.code(), "capture.request_budget_exhausted");
}

#[test]
fn native_extension_identity_is_versioned_and_metadata_round_trips_strictly() {
    let object = NativeExtensionObject::new(
        HarnessId::Pi,
        NativeExtensionLayout::Standalone,
        "review.ts",
        "review",
        tree("review.ts", b"export default {};\n"),
    )
    .unwrap();

    assert_eq!(
        object.hash().as_str(),
        "blake3:40cd75f5c1812d78b5b1057f7e85e22f573d837fcd96a69745965fcdb0c17d55"
    );
    assert_eq!(
        NativeExtensionObject::from_stored(&object.metadata_json(), object.tree().clone()).unwrap(),
        object
    );
    assert!(!format!("{object:?}").contains("export default"));

    let unknown = object
        .metadata_json()
        .replacen("{\n", "{\n  \"unexpected\": true,\n", 1);
    assert_eq!(
        NativeExtensionObject::from_stored(&unknown, object.tree().clone())
            .unwrap_err()
            .code(),
        "native_extension.invalid_metadata"
    );
}

#[test]
fn only_pi_and_supported_shapes_are_accepted() {
    assert_eq!(
        NativeExtensionObject::new(
            HarnessId::Claude,
            NativeExtensionLayout::Standalone,
            "review.ts",
            "review",
            tree("review.ts", b"export default {};\n"),
        )
        .unwrap_err()
        .code(),
        "native_extension.unsupported_harness"
    );
    assert_eq!(
        NativeExtensionObject::new(
            HarnessId::Pi,
            NativeExtensionLayout::Directory,
            "main.ts",
            "review",
            tree("main.ts", b"export default {};\n"),
        )
        .unwrap_err()
        .code(),
        "native_extension.directory_entrypoint"
    );
}

#[test]
fn native_extension_round_trips_through_store_manifest_and_descriptor() {
    let temporary = temporary_directory();
    let environment = temporary.path();
    let store = ObjectStore::open(environment).unwrap();
    let object = NativeExtensionObject::new(
        HarnessId::Pi,
        NativeExtensionLayout::Directory,
        "index.ts",
        "review",
        tree("index.ts", b"export default {};\n"),
    )
    .unwrap();
    let staging = PortablePath::parse("staging/review").unwrap();
    let destination = PortablePath::parse("assets/review/pi/native").unwrap();
    assert_eq!(
        store
            .stage_native_extension(&staging, &object, CaptureLimits::default())
            .unwrap(),
        ObjectStageOutcome::Written
    );
    assert_eq!(
        store
            .install_native_extension(
                &staging,
                &destination,
                object.hash(),
                CaptureLimits::default(),
            )
            .unwrap(),
        ObjectInstallOutcome::Installed
    );

    let mut manifest = portable_manifest();
    let asset = manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap();
    let provenance = asset.portable.as_ref().unwrap().provenance.clone();
    asset.kind = AssetKind::Extension;
    asset.portable = None;
    asset.native_variants.clear();
    asset.native_variants.insert(
        HarnessId::Pi,
        NativeVariant {
            harness: HarnessId::Pi,
            format: "kitrove-native-pi-extension-object/v1".to_owned(),
            root: destination.clone(),
            object_hash: object.hash().clone(),
            content_class: ContentClass::Executable,
            provenance,
        },
    );
    asset.content_class = ContentClass::Executable;
    asset.refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();

    let loaded = load_native_extension_object(
        &manifest,
        &AssetId::parse("review").unwrap(),
        &HarnessId::Pi,
        environment,
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(loaded, object);
    let verification =
        verify_referenced_objects(&manifest, environment, CaptureLimits::default()).unwrap();
    assert!(verification.is_clean());
    assert_eq!(verification.findings()[0].state(), ObjectState::Verified);

    let envelope = VerifiedObjectEnvelope::native_extension(destination, object).unwrap();
    assert_eq!(
        envelope.descriptor().kind(),
        SnapshotObjectKind::NativeExtensionObject
    );
}
