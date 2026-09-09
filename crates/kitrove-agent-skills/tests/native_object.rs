use std::collections::BTreeMap;

use kitrove_agent_skills::{
    CapturedFile, CapturedTree, FileMode, NativeSkillObject, SkillSourceLayout, hash_tree,
};
use kitrove_model::PortablePath;

fn tree(document: &str, bytes: &[u8]) -> CapturedTree {
    let files = BTreeMap::from([(
        PortablePath::parse(document).unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: bytes.to_vec(),
        },
    )]);
    let hash = hash_tree(&files);
    CapturedTree { files, hash }
}

#[test]
fn native_object_identity_has_a_fixed_versioned_vector() {
    let object = NativeSkillObject::new(
        SkillSourceLayout::Standalone,
        "review.md",
        "review",
        tree("review.md", b"# Review\n"),
    )
    .unwrap();

    assert_eq!(
        object.hash().as_str(),
        "blake3:6ded7a4750dcd08e5c621b207bc6eeee46dd76269bac5b096970e090aa54974b"
    );
    assert!(!format!("{object:?}").contains("# Review"));
}

#[test]
fn layout_document_name_native_id_and_tree_each_change_identity() {
    let base = NativeSkillObject::new(
        SkillSourceLayout::Standalone,
        "review.md",
        "review",
        tree("review.md", b"# Review\n"),
    )
    .unwrap();
    let cases = [
        NativeSkillObject::new(
            SkillSourceLayout::Directory,
            "review.md",
            "review",
            tree("review.md", b"# Review\n"),
        )
        .unwrap(),
        NativeSkillObject::new(
            SkillSourceLayout::Standalone,
            "other.md",
            "review",
            tree("other.md", b"# Review\n"),
        )
        .unwrap(),
        NativeSkillObject::new(
            SkillSourceLayout::Standalone,
            "review.md",
            "other",
            tree("review.md", b"# Review\n"),
        )
        .unwrap(),
        NativeSkillObject::new(
            SkillSourceLayout::Standalone,
            "review.md",
            "review",
            tree("review.md", b"# Changed\n"),
        )
        .unwrap(),
    ];

    for changed in cases {
        assert_ne!(changed.hash(), base.hash());
    }
}

#[test]
fn stored_metadata_round_trips_strictly() {
    let object = NativeSkillObject::new(
        SkillSourceLayout::Standalone,
        "review.md",
        "review",
        tree("review.md", b"# Review\n"),
    )
    .unwrap();
    let decoded = NativeSkillObject::from_stored(&object.metadata_json(), object.tree().clone())
        .expect("stored metadata remains valid");

    assert_eq!(decoded, object);
    assert_eq!(
        NativeSkillObject::from_stored(
            r#"{"schema_version":1,"layout":"standalone","original_document_name":"review.md","native_id":"review","extra":true}"#,
            tree("review.md", b"# Review\n")
        )
        .unwrap_err()
        .code(),
        "native_object.invalid_metadata"
    );
}

#[test]
fn standalone_shape_and_document_presence_are_enforced() {
    let mut two_files = tree("review.md", b"# Review\n");
    two_files.files.insert(
        PortablePath::parse("extra.md").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: Vec::new(),
        },
    );
    two_files.hash = hash_tree(&two_files.files);

    assert_eq!(
        NativeSkillObject::new(
            SkillSourceLayout::Standalone,
            "review.md",
            "review",
            two_files
        )
        .unwrap_err()
        .code(),
        "native_object.standalone_shape"
    );
    assert_eq!(
        NativeSkillObject::new(
            SkillSourceLayout::Directory,
            "missing.md",
            "review",
            tree("review.md", b"# Review\n")
        )
        .unwrap_err()
        .code(),
        "native_object.document_missing"
    );
}
