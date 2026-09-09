use std::fs;

use kitrove_agent_skills::{
    CaptureLimits, NativeSkillObject, SkillSourceLayout, StoredSkillTree, capture_tree,
};
use kitrove_core::{
    ObjectKind, ObjectState, load_portable_skill_object_bounded, verify_referenced_objects,
};
use kitrove_model::{AssetId, ContentClass, HarnessId, NativeVariant, PortablePath};
use kitrove_testkit::portable_manifest;

fn write_tree(environment: &std::path::Path, root: &str, marker: &[u8]) {
    let object = environment.join(root);
    fs::create_dir_all(object.join("references")).unwrap();
    fs::write(object.join("SKILL.md"), marker).unwrap();
    fs::write(object.join("references/check.md"), b"check\n").unwrap();
}

fn manifest_with_portable_and_native_objects(
    environment: &std::path::Path,
) -> kitrove_model::EnvironmentManifest {
    write_tree(environment, "objects/portable/payload", b"portable\n");
    write_tree(environment, "objects/native/payload", b"native\n");

    let portable_tree = capture_tree(
        &environment.join("objects/portable/payload"),
        CaptureLimits::default(),
    )
    .unwrap();
    let portable_object = StoredSkillTree::new(portable_tree).unwrap();
    fs::write(
        environment.join("objects/portable/metadata.json"),
        portable_object.metadata_json(),
    )
    .unwrap();
    let native_tree = capture_tree(
        &environment.join("objects/native/payload"),
        CaptureLimits::default(),
    )
    .unwrap();
    let native_object = NativeSkillObject::new(
        SkillSourceLayout::Directory,
        "SKILL.md",
        "review",
        native_tree,
    )
    .unwrap();
    fs::write(
        environment.join("objects/native/metadata.json"),
        native_object.metadata_json(),
    )
    .unwrap();

    let mut manifest = portable_manifest();
    let asset = manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap();
    let portable = asset.portable.as_mut().unwrap();
    portable.root = PortablePath::parse("objects/portable").unwrap();
    portable.object_hash = portable_object.tree().hash.clone();
    let provenance = portable.provenance.clone();
    asset.native_variants.insert(
        HarnessId::Claude,
        NativeVariant {
            harness: HarnessId::Claude,
            format: "kitrove-native-skill-object/v1".to_owned(),
            root: PortablePath::parse("objects/native").unwrap(),
            object_hash: native_object.hash().clone(),
            content_class: ContentClass::AgentActive,
            provenance,
        },
    );
    asset.refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();
    manifest
}

#[test]
fn verifies_portable_and_native_references_independently() {
    let environment = tempfile::tempdir().unwrap();
    let root = environment.path().canonicalize().unwrap();
    let manifest = manifest_with_portable_and_native_objects(&root);

    let report = verify_referenced_objects(&manifest, &root, CaptureLimits::default()).unwrap();

    assert!(report.is_clean());
    assert_eq!(report.findings().len(), 2);
    assert_eq!(report.findings()[0].kind(), ObjectKind::Portable);
    assert_eq!(report.findings()[0].state(), ObjectState::Verified);
    assert_eq!(report.findings()[1].kind(), ObjectKind::Native);
    assert_eq!(report.findings()[1].state(), ObjectState::Verified);
}

#[test]
fn reports_missing_and_hash_mismatch_without_mutation() {
    let environment = tempfile::tempdir().unwrap();
    let root = environment.path().canonicalize().unwrap();
    let manifest = manifest_with_portable_and_native_objects(&root);
    fs::remove_dir_all(root.join("objects/native")).unwrap();
    fs::write(root.join("objects/portable/payload/SKILL.md"), b"changed\n").unwrap();

    let report = verify_referenced_objects(&manifest, &root, CaptureLimits::default()).unwrap();

    assert!(!report.is_clean());
    assert_eq!(report.findings()[0].state(), ObjectState::HashMismatch);
    assert_eq!(report.findings()[1].state(), ObjectState::Missing);
}

#[test]
fn local_multi_file_envelope_cannot_exceed_the_per_object_allowance() {
    let environment = tempfile::tempdir().unwrap();
    let root = environment.path().canonicalize().unwrap();
    let manifest = manifest_with_portable_and_native_objects(&root);
    let object_root = root.join("objects/portable");
    fs::write(object_root.join("metadata.json"), b"x").unwrap();
    fs::write(object_root.join("payload/SKILL.md"), b"aa").unwrap();
    fs::write(object_root.join("payload/references/check.md"), b"bb").unwrap();

    let error = load_portable_skill_object_bounded(
        &manifest,
        &AssetId::parse("review").unwrap(),
        &root,
        CaptureLimits {
            max_files: 8,
            max_file_bytes: 2,
            max_total_bytes: 2,
        },
        2,
    )
    .unwrap_err();

    assert_eq!(error.code(), "object.portable_unreadable");
}

#[cfg(unix)]
#[test]
fn rejects_object_symlinks_without_reading_or_echoing_the_target() {
    use std::os::unix::fs::symlink;

    let canary = "DO_NOT_READ_OR_ECHO_OBJECT_TARGET_3c91";
    let environment = tempfile::tempdir().unwrap();
    let root = environment.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret"), canary).unwrap();
    fs::create_dir_all(root.join("objects")).unwrap();
    symlink(outside.path(), root.join("objects/portable")).unwrap();

    let mut manifest = portable_manifest();
    let asset = manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap();
    asset.portable.as_mut().unwrap().root = PortablePath::parse("objects/portable").unwrap();
    asset.refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();

    let report = verify_referenced_objects(&manifest, &root, CaptureLimits::default()).unwrap();
    let debug = format!("{report:?}");

    assert_eq!(report.findings()[0].state(), ObjectState::Unsafe);
    assert!(!debug.contains(canary));
    assert!(!debug.contains(&outside.path().display().to_string()));
}

#[test]
fn invalid_manifest_blocks_object_access() {
    let environment = tempfile::tempdir().unwrap();
    let root = environment.path().canonicalize().unwrap();
    let mut manifest = portable_manifest();
    manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap()
        .portable
        .as_mut()
        .unwrap()
        .root = PortablePath::parse("objects/absent").unwrap();

    assert_eq!(
        verify_referenced_objects(&manifest, &root, CaptureLimits::default())
            .unwrap_err()
            .code(),
        "manifest.asset_content_hash_mismatch"
    );
}
