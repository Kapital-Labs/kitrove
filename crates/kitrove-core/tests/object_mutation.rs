use std::collections::BTreeMap;
use std::fs;

use kitrove_agent_skills::{
    CaptureLimits, CapturedFile, CapturedTree, FileMode, NativeSkillObject, SkillSourceLayout,
    StoredSkillTree, hash_tree,
};
use kitrove_core::{
    ObjectInstallOutcome, ObjectStageOutcome, ObjectStore, verify_referenced_objects,
};
use kitrove_model::{AssetId, ContentClass, HarnessId, NativeVariant, PortablePath};
use kitrove_testkit::portable_manifest;

fn path(value: &str) -> PortablePath {
    PortablePath::parse(value).unwrap()
}

fn tree(bytes: &[u8], mode: FileMode) -> CapturedTree {
    let files = BTreeMap::from([
        (
            path("SKILL.md"),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: bytes.to_vec(),
            },
        ),
        (
            path("scripts/check.sh"),
            CapturedFile {
                mode,
                bytes: b"#!/bin/sh\nexit 0\n".to_vec(),
            },
        ),
    ]);
    CapturedTree {
        hash: hash_tree(&files),
        files,
    }
}

fn environment() -> (tempfile::TempDir, std::path::PathBuf, ObjectStore) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let store = ObjectStore::open(&root).unwrap();
    (temporary, root, store)
}

fn small_payload_many_files() -> CapturedTree {
    let files = (0..16)
        .map(|index| {
            (
                path(&format!("references/file-{index:02}.md")),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: vec![b'x'],
                },
            )
        })
        .collect();
    CapturedTree {
        hash: hash_tree(&files),
        files,
    }
}

#[test]
fn stages_and_installs_a_portable_object_without_losing_modes() {
    let (_temporary, root, store) = environment();
    let object = StoredSkillTree::new(tree(b"portable\n", FileMode::Executable)).unwrap();
    let staging = path(".kitrove-stage/transaction/portable");
    let destination = path("assets/review/portable");

    assert_eq!(
        store
            .stage_portable(&staging, &object, CaptureLimits::default())
            .unwrap(),
        ObjectStageOutcome::Written
    );
    assert_eq!(
        store
            .stage_portable(&staging, &object, CaptureLimits::default())
            .unwrap(),
        ObjectStageOutcome::AlreadyPresent
    );
    assert_eq!(
        store
            .install_portable(
                &staging,
                &destination,
                &object.tree().hash,
                CaptureLimits::default(),
            )
            .unwrap(),
        ObjectInstallOutcome::Installed
    );
    assert!(!root.join(staging.as_str()).exists());

    let mut manifest = portable_manifest();
    let asset = manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap();
    asset.portable.as_mut().unwrap().root = destination;
    asset.portable.as_mut().unwrap().object_hash = object.tree().hash.clone();
    asset.refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();
    let report = verify_referenced_objects(&manifest, &root, CaptureLimits::default()).unwrap();
    assert!(report.is_clean());
}

#[test]
fn metadata_allowance_is_independent_from_payload_file_limits() {
    let (_temporary, _root, store) = environment();
    let object = StoredSkillTree::new(small_payload_many_files()).unwrap();
    assert!(object.metadata_json().len() > 64);
    let limits = CaptureLimits {
        max_files: 32,
        max_file_bytes: 64,
        max_total_bytes: 1024,
    };
    store
        .stage_portable(&path("stage/metadata"), &object, limits)
        .unwrap();

    let oversized_files = BTreeMap::from([(
        path("SKILL.md"),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: vec![b'x'; 65],
        },
    )]);
    let oversized = StoredSkillTree::new(CapturedTree {
        hash: hash_tree(&oversized_files),
        files: oversized_files,
    })
    .unwrap();
    assert_eq!(
        store
            .stage_portable(&path("stage/oversized"), &oversized, limits)
            .unwrap_err()
            .code(),
        "object.verification_failed"
    );
}

#[test]
fn stages_and_installs_a_native_object_envelope() {
    let (_temporary, root, store) = environment();
    let object = NativeSkillObject::new(
        SkillSourceLayout::Directory,
        "SKILL.md",
        "review",
        tree(b"native\n", FileMode::Regular),
    )
    .unwrap();
    let staging = path(".kitrove-stage/transaction/native");
    let destination = path("assets/review/native/claude");
    store
        .stage_native(&staging, &object, CaptureLimits::default())
        .unwrap();
    store
        .install_native(
            &staging,
            &destination,
            object.hash(),
            CaptureLimits::default(),
        )
        .unwrap();

    let mut manifest = portable_manifest();
    let asset = manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap();
    let provenance = asset.portable.as_ref().unwrap().provenance.clone();
    asset.portable = None;
    asset.native_variants.insert(
        HarnessId::Claude,
        NativeVariant {
            harness: HarnessId::Claude,
            format: "kitrove-native-skill-object/v1".to_owned(),
            root: destination,
            object_hash: object.hash().clone(),
            content_class: ContentClass::Executable,
            provenance,
        },
    );
    asset.refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();
    assert!(
        verify_referenced_objects(&manifest, &root, CaptureLimits::default())
            .unwrap()
            .is_clean()
    );
}

#[test]
fn conflicting_staging_and_destination_content_is_never_replaced() {
    let (_temporary, root, store) = environment();
    let first = StoredSkillTree::new(tree(b"first\n", FileMode::Regular)).unwrap();
    let second = StoredSkillTree::new(tree(b"second\n", FileMode::Regular)).unwrap();
    let first_stage = path("stage/first");
    let second_stage = path("stage/second");
    let destination = path("objects/portable");

    store
        .stage_portable(&first_stage, &first, CaptureLimits::default())
        .unwrap();
    assert_eq!(
        store
            .stage_portable(&first_stage, &second, CaptureLimits::default())
            .unwrap_err()
            .code(),
        "object.existing_conflict"
    );
    store
        .install_portable(
            &first_stage,
            &destination,
            &first.tree().hash,
            CaptureLimits::default(),
        )
        .unwrap();
    store
        .stage_portable(&second_stage, &second, CaptureLimits::default())
        .unwrap();
    assert_eq!(
        store
            .install_portable(
                &second_stage,
                &destination,
                &second.tree().hash,
                CaptureLimits::default(),
            )
            .unwrap_err()
            .code(),
        "object.existing_conflict"
    );
    assert_eq!(
        fs::read(root.join("objects/portable/payload/SKILL.md")).unwrap(),
        b"first\n"
    );
    assert!(root.join(second_stage.as_str()).exists());
}

#[cfg(unix)]
#[test]
fn staging_refuses_a_symlink_parent_without_writing_through_it() {
    use std::os::unix::fs::symlink;

    let (_temporary, root, store) = environment();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.join("linked-stage")).unwrap();
    let object = StoredSkillTree::new(tree(b"body\n", FileMode::Regular)).unwrap();
    let error = store
        .stage_portable(
            &path("linked-stage/object"),
            &object,
            CaptureLimits::default(),
        )
        .unwrap_err();

    assert_eq!(error.code(), "object.unsafe_path");
    assert!(!outside.path().join("object").exists());
    assert!(!format!("{error:?}").contains(&outside.path().display().to_string()));
}
