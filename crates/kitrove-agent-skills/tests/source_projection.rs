#![forbid(unsafe_code)]

use std::path::PathBuf;

use kitrove_agent_skills::{
    CaptureLimits, PortableProjection, SkillManifest, SkillSource, capture_skill_source,
    project_skill_source,
};
use kitrove_model::{AssetId, FidelityReason, PortablePath};
use std::collections::BTreeMap;

fn portable(path: &str) -> PortablePath {
    PortablePath::parse(path).unwrap()
}

fn source(path: impl Into<PathBuf>) -> SkillSource {
    let path = path.into().canonicalize().unwrap();
    if path.is_dir() {
        SkillSource::Directory { path }
    } else {
        SkillSource::Standalone { path }
    }
}

fn project(source: &SkillSource) -> PortableProjection {
    let captured = capture_skill_source(source, CaptureLimits::default()).unwrap();
    project_skill_source(
        &captured,
        AssetId::parse("review").unwrap(),
        "Review a change.".to_owned(),
        vec![FidelityReason::new(
            "projection.policy_applied",
            "policy selected the asset ID",
        )],
    )
    .unwrap()
}

fn projected_tree(projection: PortableProjection) -> kitrove_agent_skills::CapturedTree {
    match projection {
        PortableProjection::Available { tree, .. } => tree,
        PortableProjection::Unavailable { .. } => panic!("policy supplied a portable identity"),
    }
}

fn standard_document() -> &'static [u8] {
    b"---\nname: authored-review\ndescription: Authored description.\nlicense: MIT\ncompatibility: Requires Git.\nmetadata:\n  owner: kitrove\nallowed-tools: Read Grep\n---\n# Review\n"
}

#[test]
fn equal_projected_content_matches_across_layouts() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("review-directory");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("SKILL.md"), standard_document()).unwrap();
    let standalone = root.path().join("review.md");
    std::fs::write(&standalone, standard_document()).unwrap();

    let directory = projected_tree(project(&source(directory)));
    let standalone = projected_tree(project(&source(standalone)));

    assert_eq!(directory.hash, standalone.hash);
    assert_eq!(
        directory.files[&portable("SKILL.md")].bytes,
        standalone.files[&portable("SKILL.md")].bytes
    );
}

#[test]
fn projection_uses_policy_fields_retains_authored_optional_fields_and_supporting_bytes() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("review-directory");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("SKILL.md"), standard_document()).unwrap();
    std::fs::create_dir(directory.join("references")).unwrap();
    let supporting_bytes = b"unchanged\xff\r\n\0\r\n";
    std::fs::write(directory.join("references/checklist.bin"), supporting_bytes).unwrap();

    let projection = project(&source(&directory));
    let PortableProjection::Available {
        manifest,
        tree,
        reasons,
        ..
    } = projection
    else {
        panic!("policy supplied a portable identity");
    };

    assert_eq!(
        *manifest,
        SkillManifest {
            name: AssetId::parse("review").unwrap(),
            description: "Review a change.".to_owned(),
            license: Some("MIT".to_owned()),
            compatibility: Some("Requires Git.".to_owned()),
            metadata: BTreeMap::from([("owner".to_owned(), "kitrove".to_owned())]),
            allowed_tools: Some("Read Grep".to_owned()),
        }
    );
    assert_eq!(reasons.len(), 1);
    assert_eq!(
        tree.files[&portable("references/checklist.bin")].bytes,
        supporting_bytes
    );
    assert_eq!(
        tree.files[&portable("SKILL.md")].bytes,
        b"---\nname: review\ndescription: Review a change.\nlicense: MIT\ncompatibility: Requires Git.\nmetadata:\n  owner: kitrove\nallowed-tools: Read Grep\n---\n# Review\n"
    );
}

#[test]
fn unavailable_projection_keeps_its_public_reason_representation() {
    let reasons = vec![FidelityReason::new(
        "projection.unavailable",
        "policy did not supply portable fields",
    )];
    let projection = PortableProjection::Unavailable {
        reasons: reasons.clone(),
    };

    let PortableProjection::Unavailable { reasons: actual } = projection else {
        panic!("unavailable representation must remain a distinct variant");
    };

    assert_eq!(actual, reasons);
}

#[test]
fn standalone_projection_replaces_the_authored_document_path_with_skill_md() {
    let root = tempfile::tempdir().unwrap();
    let standalone = root.path().join("review.md");
    std::fs::write(&standalone, standard_document()).unwrap();

    let tree = projected_tree(project(&source(standalone)));

    assert_eq!(tree.files.len(), 1);
    assert!(tree.files.contains_key(&portable("SKILL.md")));
    assert!(!tree.files.contains_key(&portable("review.md")));
}

#[test]
fn projection_rejects_a_policy_asset_id_that_is_not_a_standard_skill_name() {
    let root = tempfile::tempdir().unwrap();
    let standalone = root.path().join("review.md");
    std::fs::write(&standalone, standard_document()).unwrap();
    let captured = capture_skill_source(&source(standalone), CaptureLimits::default()).unwrap();

    let error = project_skill_source(
        &captured,
        AssetId::parse("review_name").unwrap(),
        "Review a change.".to_owned(),
        Vec::new(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "skill.name_invalid");
}

#[test]
fn projection_rejects_secret_metadata_without_leaking_its_value() {
    let root = tempfile::tempdir().unwrap();
    let standalone = root.path().join("review.md");
    let canary = "KITROVE_PORTABLE_PROJECTION_METADATA_CANARY_455e736b";
    std::fs::write(
        &standalone,
        format!("---\nmetadata:\n  openai_api_key: {canary}\n---\n# Review\n"),
    )
    .unwrap();
    let captured = capture_skill_source(&source(standalone), CaptureLimits::default()).unwrap();

    let error = project_skill_source(
        &captured,
        AssetId::parse("review").unwrap(),
        "Review a change.".to_owned(),
        Vec::new(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "skill.credential_metadata");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}
