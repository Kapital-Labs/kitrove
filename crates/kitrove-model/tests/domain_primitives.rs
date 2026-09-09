use kitrove_model::{
    BindingName, BlockedRequirement, CommunityHarnessId, ContentHash, Fidelity, FidelityEvidence,
    FidelityResult, HarnessId, PortablePath, RepositoryUrl,
};

#[test]
fn content_hash_requires_qualified_lowercase_blake3() {
    let valid = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_eq!(
        ContentHash::parse(valid).expect("valid hash").as_str(),
        valid
    );

    for invalid in [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "blake3:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
        "blake3:0123",
    ] {
        assert!(ContentHash::parse(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn content_hash_digest_matches_blake3_empty_input_vector() {
    assert_eq!(
        ContentHash::digest(b"").as_str(),
        "blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

#[test]
fn portable_paths_reject_escape_and_platform_absolute_forms() {
    for invalid in [
        "",
        "../secret",
        "skills/../secret",
        "/etc/passwd",
        "C:/Users/name/token",
        r"C:\Users\name\token",
        "skills//review",
        "skills/./review",
        r"skills\review",
    ] {
        assert!(
            PortablePath::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }

    let path = PortablePath::parse("skills/review/SKILL.md").expect("portable path");
    assert_eq!(path.as_str(), "skills/review/SKILL.md");
}

#[test]
fn community_harness_ids_are_namespaced() {
    assert_eq!(
        HarnessId::parse("claude").expect("tier-one id"),
        HarnessId::Claude
    );
    assert_eq!(
        HarnessId::parse("acme/tool")
            .expect("namespaced community id")
            .as_str(),
        "acme/tool"
    );
    assert!(CommunityHarnessId::parse("Acme/tool").is_err());
    assert!(HarnessId::parse("community").is_err());
    assert!(HarnessId::parse("Acme/tool").is_err());
}

#[test]
fn binding_names_are_symbolic_identifiers() {
    assert!(BindingName::parse("github_mcp_token").is_ok());
    assert!(BindingName::parse("GITHUB_TOKEN").is_err());
    assert!(BindingName::parse("../token").is_err());
}

#[test]
fn repository_urls_reject_embedded_credentials_and_ambiguous_components() {
    assert!(RepositoryUrl::parse("https://example.test/capabilities.git").is_ok());
    assert!(RepositoryUrl::parse("ssh://git@example.test/capabilities.git").is_ok());

    for invalid in [
        "https://token@example.test/private.git",
        "https://example.test/private.git?token=secret",
        "https://example.test/private.git#credential",
        "file:///tmp/private",
        "example.test/private.git",
    ] {
        assert!(
            RepositoryUrl::parse(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn lossy_fidelity_requires_a_reason() {
    assert!(
        FidelityResult::new(Fidelity::Partial, vec![], vec![], vec![], "adapter/1", None,).is_err()
    );

    assert!(
        FidelityResult::new(
            Fidelity::Unsupported,
            vec![],
            vec![],
            vec![],
            "adapter/1",
            None,
        )
        .is_err()
    );

    assert!(
        FidelityResult::new(Fidelity::Blocked, vec![], vec![], vec![], "adapter/1", None,).is_err()
    );
}

#[test]
fn fidelity_claims_require_evidence_and_category_appropriate_bindings() {
    assert!(
        FidelityResult::exact(Fidelity::Portable, vec![], "adapter/1", None).is_err(),
        "an exact claim without evidence must fail"
    );
    assert!(
        FidelityResult::exact(
            Fidelity::Partial,
            vec![FidelityEvidence::new("matrix", "target omits hooks")],
            "adapter/1",
            None,
        )
        .is_err(),
        "the exact constructor must reject lossy categories"
    );
    assert!(
        FidelityResult::new(
            Fidelity::Portable,
            vec![],
            vec![FidelityEvidence::new("matrix", "portable format supported")],
            vec![BlockedRequirement::binding(
                BindingName::parse("token").expect("binding"),
            )],
            "adapter/1",
            None,
        )
        .is_err(),
        "only blocked results may carry blocked requirements"
    );
}

#[test]
fn blocked_requirements_distinguish_bindings_from_executable_trust() {
    let binding = BlockedRequirement::binding(BindingName::parse("token").unwrap());
    let result = FidelityResult::new(
        Fidelity::Blocked,
        vec![kitrove_model::FidelityReason::new(
            "trust.required",
            "local requirements must be satisfied before apply",
        )],
        vec![FidelityEvidence::new("fixture", "typed requirements")],
        vec![binding.clone(), BlockedRequirement::ExecutableTrust],
        "adapter/1",
        None,
    )
    .unwrap();

    assert_eq!(
        result.blocked_requirements()[0].binding_name(),
        binding.binding_name()
    );
    assert_eq!(result.blocked_requirements()[1].binding_name(), None);
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(encoded.contains("\"kind\":\"binding\""));
    assert!(encoded.contains("\"kind\":\"executable_trust\""));
    assert!(serde_json::from_str::<FidelityResult>(
        r#"{"fidelity":"blocked","reasons":[{"code":"trust.required","message":"required"}],"evidence":[{"kind":"fixture","detail":"legacy"}],"blocked_requirements":["token"],"adapter_version":"adapter/1","harness_version":null}"#,
    )
    .is_err());
}

#[test]
fn fidelity_rejects_empty_reason_and_evidence_records() {
    assert!(
        FidelityResult::exact(
            Fidelity::Portable,
            vec![FidelityEvidence::new("", "")],
            "adapter/1",
            None,
        )
        .is_err()
    );
    assert!(
        FidelityResult::new(
            Fidelity::Partial,
            vec![kitrove_model::FidelityReason::new("", "")],
            vec![FidelityEvidence::new("matrix", "target omits hooks")],
            vec![],
            "adapter/1",
            None,
        )
        .is_err()
    );
}

#[test]
fn exact_fidelity_preserves_evidence_and_versions() {
    let result = FidelityResult::new(
        Fidelity::Portable,
        vec![],
        vec![FidelityEvidence::new(
            "agent-skills/v1",
            "harness consumes the portable directory unchanged",
        )],
        vec![],
        "adapter/1",
        Some("2.4.0".to_owned()),
    )
    .expect("portable result");

    assert_eq!(result.evidence().len(), 1);
    assert_eq!(result.adapter_version(), "adapter/1");
    assert_eq!(result.harness_version(), Some("2.4.0"));
}
