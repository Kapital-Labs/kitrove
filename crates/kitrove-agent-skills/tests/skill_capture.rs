#![forbid(unsafe_code)]

use std::path::PathBuf;

use kitrove_agent_skills::{CaptureLimits, SkillSnapshot, capture_skill};
use kitrove_model::{ContentClass, PortablePath};

fn skill_directory(name: &str, skill_document: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join(name);
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("SKILL.md"), skill_document).unwrap();
    let directory = directory.canonicalize().unwrap();
    (parent, directory)
}

fn portable(path: &str) -> PortablePath {
    PortablePath::parse(path).unwrap()
}

#[test]
fn captures_exact_evidence_and_projects_only_the_standard_skill_document() {
    let skill_document = b"---\nhooks:\n  Stop: ./scripts/stop.sh\ndescription: Review a change.\nname: code-review\nallowed-tools: Read Grep\nmetadata:\n  owner: kitrove\nlicense: MIT\ndisable-model-invocation: true\ncompatibility: Requires Git.\n---\n# Review\n";
    let (_parent, directory) = skill_directory("code-review", skill_document);
    std::fs::create_dir(directory.join("references")).unwrap();
    std::fs::create_dir(directory.join("scripts")).unwrap();
    std::fs::write(
        directory.join("references/checklist.md"),
        b"check every changed boundary\n",
    )
    .unwrap();
    std::fs::write(directory.join("scripts/stop.sh"), b"#!/bin/sh\nexit 0\n").unwrap();

    let snapshot: SkillSnapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.source_directory, directory);
    assert_eq!(snapshot.manifest.name.as_str(), "code-review");
    assert_eq!(snapshot.body, "# Review\n");
    assert_eq!(snapshot.content_class, ContentClass::Executable);
    assert_eq!(
        snapshot
            .native_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["disable-model-invocation", "hooks"]
    );
    assert_eq!(
        snapshot.exact.files[&portable("SKILL.md")].bytes,
        skill_document
    );
    assert_ne!(snapshot.exact.hash, snapshot.portable.hash);
    let projected = &snapshot.portable.files[&portable("SKILL.md")].bytes;
    assert_eq!(
        projected,
        b"---\nname: code-review\ndescription: Review a change.\nlicense: MIT\ncompatibility: Requires Git.\nmetadata:\n  owner: kitrove\nallowed-tools: Read Grep\n---\n# Review\n"
    );
    assert_eq!(
        snapshot.portable.files[&portable("references/checklist.md")].bytes,
        b"check every changed boundary\n"
    );
}

#[test]
fn standards_only_projection_order_and_lf_preserve_the_exact_tree_hash() {
    let skill_document = b"---\nname: code-review\ndescription: Review a change.\nlicense: MIT\ncompatibility: Requires Git.\nmetadata:\n  owner: kitrove\nallowed-tools: Read Grep\n---\n# Review\n";
    let (_parent, directory) = skill_directory("code-review", skill_document);

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.exact, snapshot.portable);
}

#[test]
fn projection_normalizes_skill_text_but_preserves_supporting_bytes_exactly() {
    let skill_document = b"---\r\ndescription: \"true\"\r\nname: code-review\r\nmetadata:\r\n  zeta: \"007\"\r\n  alpha: \"null\"\r\n---\r\n# Review\r\n\r\n\r\n";
    let (_parent, directory) = skill_directory("code-review", skill_document);
    std::fs::create_dir(directory.join("references")).unwrap();
    let supporting_bytes = b"unchanged\xff\r\n\0\r\n";
    std::fs::write(directory.join("references/exact.bin"), supporting_bytes).unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(
        snapshot.portable.files[&portable("SKILL.md")].bytes,
        b"---\nname: code-review\ndescription: 'true'\nmetadata:\n  alpha: 'null'\n  zeta: '007'\n---\n# Review\n"
    );
    assert_eq!(
        snapshot.portable.files[&portable("references/exact.bin")].bytes,
        supporting_bytes
    );
    assert_eq!(
        snapshot.exact.files[&portable("references/exact.bin")],
        snapshot.portable.files[&portable("references/exact.bin")]
    );
}

#[test]
fn projection_normalizes_mixed_crlf_and_standalone_cr_body_endings_to_lf() {
    let mixed_document = b"---\nname: code-review\ndescription: Review a change.\n---\n# Review\r\nFirst boundary\rSecond boundary\n";
    let lf_document = b"---\nname: code-review\ndescription: Review a change.\n---\n# Review\nFirst boundary\nSecond boundary\n";
    let (_mixed_parent, mixed_directory) = skill_directory("code-review", mixed_document);
    let (_lf_parent, lf_directory) = skill_directory("code-review", lf_document);

    let mixed = capture_skill(&mixed_directory, CaptureLimits::default()).unwrap();
    let lf = capture_skill(&lf_directory, CaptureLimits::default()).unwrap();

    assert_eq!(
        mixed.exact.files[&portable("SKILL.md")].bytes,
        mixed_document
    );
    assert_ne!(mixed.exact.hash, lf.exact.hash);
    assert_eq!(
        mixed.portable.files[&portable("SKILL.md")].bytes,
        b"---\nname: code-review\ndescription: Review a change.\n---\n# Review\nFirst boundary\nSecond boundary\n"
    );
    assert_eq!(mixed.portable.hash, lf.portable.hash);
}

#[test]
fn rejects_a_directory_name_that_disagrees_with_the_manifest_name() {
    let skill_document =
        b"---\nname: manifest-name\ndescription: Review a change.\n---\n# Review\n";
    let (_parent, directory) = skill_directory("directory-name", skill_document);

    let error = capture_skill(&directory, CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "skill.directory_name_mismatch");
}

#[test]
fn refuses_compound_credential_metadata_before_returning_a_portable_projection() {
    let canary = "KITROVE_C1_PORTABLE_CREDENTIAL_METADATA_CANARY_80d20fca";
    let skill_document = format!(
        "---\nname: code-review\ndescription: Review a change.\nmetadata:\n  openai_api_key: {canary}\n---\n# Review\n"
    );
    let (_parent, directory) = skill_directory("code-review", skill_document.as_bytes());

    let error = capture_skill(&directory, CaptureLimits::default())
        .expect_err("credential metadata must not reach a portable snapshot");

    assert_eq!(error.code(), "skill.credential_metadata");
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn rejects_a_tree_without_an_exact_skill_document_entry() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("skill.md"), b"ordinary supporting text\n").unwrap();
    let direct_root = root.path().canonicalize().unwrap();

    let error = capture_skill(&direct_root, CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "skill.document_missing");
}

#[test]
fn c1_required_field_errors_precede_credential_artifact_errors() {
    let (_parent, directory) = skill_directory("code-review", b"# Review\n");
    std::fs::write(
        directory.join("credentials.json"),
        b"this must not alter the compatibility error ordering\n",
    )
    .unwrap();

    let error = capture_skill(&directory, CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "skill.frontmatter_missing");
}
