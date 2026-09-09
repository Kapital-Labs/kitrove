use std::collections::BTreeMap;

use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, StoredSkillTree, hash_tree};
use kitrove_model::PortablePath;

fn tree(mode: FileMode, bytes: &[u8]) -> CapturedTree {
    let files = BTreeMap::from([(
        PortablePath::parse("scripts/check.sh").unwrap(),
        CapturedFile {
            mode,
            bytes: bytes.to_vec(),
        },
    )]);
    CapturedTree {
        hash: hash_tree(&files),
        files,
    }
}

#[test]
fn stored_modes_override_host_payload_modes_portably() {
    let original = StoredSkillTree::new(tree(FileMode::Executable, b"#!/bin/sh\n")).unwrap();
    let host_payload = tree(FileMode::Regular, b"#!/bin/sh\n");

    let restored = StoredSkillTree::from_stored(&original.metadata_json(), host_payload).unwrap();

    assert_eq!(restored, original);
    assert_eq!(restored.tree().hash, original.tree().hash);
}

#[test]
fn metadata_is_strict_and_payload_paths_must_match() {
    let original = StoredSkillTree::new(tree(FileMode::Regular, b"body\n")).unwrap();
    let metadata = original.metadata_json();
    let different_payload = {
        let files = BTreeMap::from([(
            PortablePath::parse("other.txt").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"body\n".to_vec(),
            },
        )]);
        CapturedTree {
            hash: hash_tree(&files),
            files,
        }
    };

    assert_eq!(
        StoredSkillTree::from_stored(&metadata, different_payload)
            .unwrap_err()
            .code(),
        "stored_tree.payload_mismatch"
    );
    assert_eq!(
        StoredSkillTree::from_stored(
            r#"{"schema_version":1,"files":{},"extra":true}"#,
            tree(FileMode::Regular, b"body\n")
        )
        .unwrap_err()
        .code(),
        "stored_tree.invalid_metadata"
    );
}

#[test]
fn constructor_rejects_a_forged_tree_hash() {
    let mut forged = tree(FileMode::Regular, b"body\n");
    forged.hash = kitrove_model::ContentHash::digest(b"not-the-tree");

    assert_eq!(
        StoredSkillTree::new(forged).unwrap_err().code(),
        "stored_tree.hash_mismatch"
    );
}

#[test]
fn constructor_refuses_unbounded_storage_metadata() {
    let oversized_path = format!("{}.txt", "a".repeat(4 * 1024 * 1024));
    let files = BTreeMap::from([(
        PortablePath::parse(oversized_path).unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: Vec::new(),
        },
    )]);
    let oversized = CapturedTree {
        hash: hash_tree(&files),
        files,
    };

    assert_eq!(
        StoredSkillTree::new(oversized).unwrap_err().code(),
        "stored_tree.metadata_limit"
    );
}

#[test]
fn constructor_rejects_supported_platform_path_collisions() {
    let files = BTreeMap::from([
        (
            PortablePath::parse("References/one.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: Vec::new(),
            },
        ),
        (
            PortablePath::parse("references/two.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: Vec::new(),
            },
        ),
    ]);
    let colliding = CapturedTree {
        hash: hash_tree(&files),
        files,
    };

    assert_eq!(
        StoredSkillTree::new(colliding).unwrap_err().code(),
        "stored_tree.path_collision"
    );
}
