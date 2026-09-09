use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, HarnessId, HarnessScope, LocalState,
    NormalizedDestination, ReceiptTarget, Revision,
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn normalized_destination_ancestry_is_host_independent_and_segment_aware() {
    let unix = NormalizedDestination::parse("/Users/review/.claude/skills").unwrap();
    assert_eq!(
        unix.strict_ancestor_strings().collect::<Vec<_>>(),
        ["/", "/Users", "/Users/review", "/Users/review/.claude"]
    );
    assert!(
        NormalizedDestination::parse("/Users/review")
            .unwrap()
            .is_ancestor_of(&unix)
    );
    assert!(
        !NormalizedDestination::parse("/Users/rev")
            .unwrap()
            .is_ancestor_of(&unix)
    );

    let windows = NormalizedDestination::parse(r"c:\Users\review\.codex\skills").unwrap();
    assert_eq!(
        windows.strict_ancestor_strings().collect::<Vec<_>>(),
        [
            "C:/",
            "C:/Users",
            "C:/Users/review",
            "C:/Users/review/.codex"
        ]
    );
    assert!(
        NormalizedDestination::parse("C:/Users/review")
            .unwrap()
            .is_ancestor_of(&windows)
    );
    assert!(
        !NormalizedDestination::parse("C:/Users/rev")
            .unwrap()
            .is_ancestor_of(&windows)
    );
}

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).expect("test hash")
}

fn receipt(scope: HarnessScope, destination: &str) -> DeploymentReceipt {
    DeploymentReceipt {
        asset_id: AssetId::parse("review").expect("asset id"),
        harness: HarnessId::Claude,
        scope,
        destination: NormalizedDestination::parse(destination).expect("destination"),
        target: ReceiptTarget::WholeTarget,
        logical_key: None,
        shared_with: BTreeSet::new(),
        shared_adapter_versions: BTreeMap::new(),
        source_hash: hash('a'),
        rendered_hash: hash('b'),
        document_hash: None,
        prior_hash: None,
        adapter_version: "claude-adapter/1".to_owned(),
        environment_revision: Revision::parse("manifest:blake3:0001").expect("revision"),
    }
}

#[test]
fn managed_region_identity_includes_canonical_consumer_set() {
    let mut managed = receipt(HarnessScope::Project, "/repo/AGENTS.md");
    managed.harness = HarnessId::Codex;
    managed.adapter_version = "codex-instructions/1".to_owned();
    managed.target = ReceiptTarget::ManagedInstructionRegion;
    managed.shared_with = BTreeSet::from([HarnessId::Pi, HarnessId::OpenCode]);
    managed.shared_adapter_versions = BTreeMap::from([
        (HarnessId::Pi, "pi-instructions/1".to_owned()),
        (HarnessId::OpenCode, "opencode-instructions/1".to_owned()),
    ]);

    let original = managed.receipt_id().expect("managed receipt ID");
    managed.shared_with.remove(&HarnessId::OpenCode);
    managed.shared_adapter_versions.remove(&HarnessId::OpenCode);
    assert_ne!(original, managed.receipt_id().expect("reduced consumer ID"));

    managed.harness = HarnessId::OpenCode;
    managed.shared_with = BTreeSet::from([HarnessId::Codex]);
    managed.shared_adapter_versions =
        BTreeMap::from([(HarnessId::Codex, "codex-instructions/1".to_owned())]);
    assert_eq!(
        managed.receipt_id().unwrap_err().code(),
        "receipt.consumers_noncanonical"
    );
}

#[test]
fn shared_receipts_require_exact_per_consumer_policy_versions() {
    let mut managed = receipt(HarnessScope::Project, "/repo/AGENTS.md");
    managed.harness = HarnessId::Codex;
    managed.adapter_version = "codex-instructions/1".to_owned();
    managed.target = ReceiptTarget::ManagedInstructionRegion;
    managed.shared_with = BTreeSet::from([HarnessId::Pi]);
    assert_eq!(
        managed.receipt_id().unwrap_err().code(),
        "receipt.consumer_versions_invalid"
    );

    managed.shared_adapter_versions =
        BTreeMap::from([(HarnessId::Pi, "pi-instructions/1".to_owned())]);
    assert_eq!(
        managed.adapter_version_for(&HarnessId::Codex),
        Some("codex-instructions/1")
    );
    assert_eq!(
        managed.adapter_version_for(&HarnessId::Pi),
        Some("pi-instructions/1")
    );
    let encoded = serde_json::to_string(&managed).unwrap();
    assert!(encoded.contains("shared_adapter_versions"));
    assert_eq!(
        serde_json::from_str::<DeploymentReceipt>(&encoded).unwrap(),
        managed
    );
}

#[test]
fn legacy_whole_target_shape_and_identity_remain_stable() {
    let receipt = receipt(HarnessScope::User, "/home/dev/.claude/skills/review");
    let encoded = serde_json::to_string(&receipt).unwrap();
    assert!(!encoded.contains("target"));
    assert!(!encoded.contains("shared_with"));
    assert!(!encoded.contains("shared_adapter_versions"));
    assert!(!encoded.contains("logical_key"));
    assert!(!encoded.contains("document_hash"));
    assert_eq!(
        serde_json::from_str::<DeploymentReceipt>(&encoded).unwrap(),
        receipt
    );
}

#[test]
fn managed_mcp_identity_binds_the_logical_key_and_requires_document_authority() {
    let mut managed = receipt(HarnessScope::User, "/home/dev/.claude.json");
    managed.target = ReceiptTarget::ManagedMcpEntry;
    managed.logical_key = Some("company-tools".to_owned());
    managed.document_hash = Some(hash('c'));

    let original = managed.receipt_id().expect("managed MCP receipt ID");
    managed.document_hash = Some(hash('d'));
    assert_eq!(
        original,
        managed
            .receipt_id()
            .expect("document revisions retain receipt identity")
    );
    managed.logical_key = Some("company-search".to_owned());
    assert_ne!(
        original,
        managed.receipt_id().expect("logical key changes identity")
    );

    managed.document_hash = None;
    assert_eq!(
        managed.receipt_id().unwrap_err().code(),
        "receipt.structured_authority_invalid"
    );
    managed.document_hash = Some(hash('d'));
    managed.logical_key = Some("INVALID_KEY".to_owned());
    assert_eq!(
        managed.receipt_id().unwrap_err().code(),
        "receipt.logical_key_invalid"
    );
}

#[test]
fn non_mcp_receipts_reject_structured_entry_authority() {
    let mut whole = receipt(HarnessScope::User, "/home/dev/.claude.json");
    whole.logical_key = Some("company-tools".to_owned());
    assert_eq!(
        whole.receipt_id().unwrap_err().code(),
        "receipt.structured_authority_invalid"
    );
}

#[test]
fn receipt_consumer_invariants_are_bounded_and_target_specific() {
    let mut receipt = receipt(HarnessScope::Project, "/repo/AGENTS.md");
    receipt.shared_with = BTreeSet::from([HarnessId::Codex]);
    receipt.shared_adapter_versions =
        BTreeMap::from([(HarnessId::Codex, "codex-instructions/1".to_owned())]);
    assert_eq!(
        receipt.receipt_id().unwrap_err().code(),
        "receipt.shared_whole_target"
    );

    receipt.target = ReceiptTarget::ManagedInstructionRegion;
    receipt.shared_with = BTreeSet::from([
        HarnessId::Codex,
        HarnessId::Pi,
        HarnessId::OpenCode,
        HarnessId::parse("community/example").unwrap(),
    ]);
    receipt.shared_adapter_versions = receipt
        .shared_with
        .iter()
        .cloned()
        .map(|harness| (harness, "instructions/1".to_owned()))
        .collect();
    assert_eq!(
        receipt.receipt_id().unwrap_err().code(),
        "receipt.consumer_limit"
    );
}

#[test]
fn receipt_identity_includes_scope_and_normalized_destination() {
    let user = receipt(HarnessScope::User, "/home/dev/.claude/skills/review");
    let project = receipt(HarnessScope::Project, "/home/dev/.claude/skills/review");

    assert_ne!(
        user.receipt_id().expect("user receipt id"),
        project.receipt_id().expect("project receipt id")
    );
    assert_eq!(
        user.receipt_id().expect("user receipt id").as_str().len(),
        72
    );
    assert_eq!(
        user.receipt_id().expect("user receipt id").as_str(),
        "receipt-d75e3dc5bbec4e6548f5a7d0e2025262e1e691a28764bb97d826e9b2918a2645"
    );
}

#[test]
fn local_state_requires_receipt_scope() {
    let error = LocalState::from_json(include_str!("fixtures/receipt-without-scope.json"))
        .expect_err("scope is required in unreleased schema version 1");
    assert_eq!(error.code(), "local_state.invalid_json");
}

#[test]
fn destinations_reject_ambiguous_windows_and_parent_forms() {
    for value in [
        "../skill",
        "/tmp/../skill",
        "//server/share/skill",
        r"\\?\C:\skill",
        r"\\.\C:\skill",
        r"\\server\share\skill",
    ] {
        assert!(
            NormalizedDestination::parse(value).is_err(),
            "accepted {value:?}"
        );
    }
    assert_eq!(
        NormalizedDestination::parse(r"c:\Users\dev\skill")
            .expect("drive-letter destination")
            .as_str(),
        "C:/Users/dev/skill"
    );
}

#[test]
fn windows_destinations_reject_win32_alias_sensitive_components() {
    for value in [
        r"C:\root.\skill",
        r"C:\root \skill",
        r"C:\root:stream\skill",
        r"C:\CON\skill",
        r"C:\con.txt\skill",
        r"C:\COM1\skill",
        r"C:\lpt9.log\skill",
        "C:\\control\u{1f}name\\skill",
        r#"C:\quoted"name\skill"#,
    ] {
        assert!(
            NormalizedDestination::parse(value).is_err(),
            "accepted alias-sensitive Windows destination {value:?}"
        );
    }
}

#[test]
fn destinations_preserve_colon_leading_unix_components_without_panicking() {
    for (input, expected) in [("/:skill", "/:skill"), ("/:💥", "/:💥")] {
        assert_eq!(
            NormalizedDestination::parse(input)
                .expect("absolute Unix destination")
                .as_str(),
            expected
        );
    }
}
