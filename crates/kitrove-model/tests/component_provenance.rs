use kitrove_model::{
    ComponentProvenance, ContentHash, HarnessId, HarnessScope, PortablePath, ProvenanceId,
    RepositoryUrl, Revision, Source,
};

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).unwrap()
}

fn harness_provenance() -> ComponentProvenance {
    ComponentProvenance::new(
        Source::Harness {
            harness: HarnessId::Claude,
            origin: PortablePath::parse("claude/user/review").unwrap(),
        },
        Revision::parse("observation:review-v1").unwrap(),
        hash('a'),
        Some(HarnessScope::User),
    )
    .unwrap()
}

#[test]
fn component_provenance_has_a_stable_versioned_identity() {
    assert_eq!(
        harness_provenance().provenance_id().as_str(),
        "provenance:blake3:c3d3648177d967a4afc620c929c4d1d4308839a282cf5e7e21e5b38f3aa145c9"
    );
}

#[test]
fn every_provenance_field_changes_the_identity() {
    let baseline = harness_provenance();
    let baseline_id = baseline.provenance_id();
    let mutations = [
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Codex,
                origin: PortablePath::parse("claude/user/review").unwrap(),
            },
            baseline.revision().clone(),
            baseline.exact_source_hash().clone(),
            baseline.origin_scope(),
        )
        .unwrap(),
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Claude,
                origin: PortablePath::parse("claude/project/review").unwrap(),
            },
            baseline.revision().clone(),
            baseline.exact_source_hash().clone(),
            baseline.origin_scope(),
        )
        .unwrap(),
        ComponentProvenance::new(
            baseline.source().clone(),
            Revision::parse("observation:review-v2").unwrap(),
            baseline.exact_source_hash().clone(),
            baseline.origin_scope(),
        )
        .unwrap(),
        ComponentProvenance::new(
            baseline.source().clone(),
            baseline.revision().clone(),
            hash('b'),
            baseline.origin_scope(),
        )
        .unwrap(),
        ComponentProvenance::new(
            baseline.source().clone(),
            baseline.revision().clone(),
            baseline.exact_source_hash().clone(),
            Some(HarnessScope::Project),
        )
        .unwrap(),
    ];

    for mutation in mutations {
        assert_ne!(mutation.provenance_id(), baseline_id);
    }
}

#[test]
fn origin_scope_is_present_exactly_for_harness_sources() {
    let local = Source::Local {
        path: PortablePath::parse("imports/review").unwrap(),
    };
    assert_eq!(
        ComponentProvenance::new(
            local.clone(),
            Revision::parse("local:review-v1").unwrap(),
            hash('a'),
            Some(HarnessScope::User),
        )
        .unwrap_err()
        .code(),
        "provenance.origin_scope_unexpected"
    );
    assert_eq!(
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Claude,
                origin: PortablePath::parse("claude/user/review").unwrap(),
            },
            Revision::parse("observation:review-v1").unwrap(),
            hash('a'),
            None,
        )
        .unwrap_err()
        .code(),
        "provenance.origin_scope_required"
    );
    ComponentProvenance::new(
        local,
        Revision::parse("local:review-v1").unwrap(),
        hash('a'),
        None,
    )
    .unwrap();
}

#[test]
fn strict_persistence_rejects_invalid_scope_unknown_fields_and_ids() {
    let invalid_scope = r#"
source = { kind = "local", path = "imports/review" }
revision = "local:review-v1"
exact_source_hash = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
origin_scope = "user"
"#;
    assert!(toml::from_str::<ComponentProvenance>(invalid_scope).is_err());

    let unknown = r#"
source = { kind = "local", path = "imports/review" }
revision = "local:review-v1"
exact_source_hash = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
secret = "must-not-be-admitted"
"#;
    assert!(toml::from_str::<ComponentProvenance>(unknown).is_err());

    assert!(ProvenanceId::parse(format!("provenance:blake3:{}", "a".repeat(64))).is_ok());
    assert!(ProvenanceId::parse(format!("provenance:blake3:{}", "A".repeat(64))).is_err());
    assert!(ProvenanceId::parse(format!("blake3:{}", "a".repeat(64))).is_err());
}

#[test]
fn git_provenance_serialization_contains_no_credentials_or_machine_path() {
    let provenance = ComponentProvenance::new(
        Source::Git {
            repository: RepositoryUrl::parse("https://example.test/capabilities.git").unwrap(),
            subdirectory: Some(PortablePath::parse("skills/review").unwrap()),
        },
        Revision::parse("git:0123456789abcdef").unwrap(),
        hash('a'),
        None,
    )
    .unwrap();
    let encoded = toml::to_string(&provenance).unwrap();
    assert!(!encoded.contains("/Users/"));
    assert!(!encoded.contains("token"));
    assert!(!encoded.contains("secret"));
    assert_eq!(
        provenance.provenance_id().as_str(),
        "provenance:blake3:29908368631c09f155cba47d7fe7b492a4b0802ea2a182ba2df612722bd208c9"
    );
}
