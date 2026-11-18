use super::tests::{machine, script, skill};

#[test]
fn grouped_sources_keep_their_original_inventory_numbers_and_no_default_winner() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-source-groups-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "alpha", "Original source.");
    let output = script(
        &a,
        &format!("1\n{}\na\ny\nall\nn\n5\n", a.join("collection").display()),
        false,
        "",
    );
    assert!(output.contains("alpha · 2 source copies"));
    assert!(output.contains("1. claude"));
    assert!(output.contains("2. opencode"));
    assert!(super::tests::manifest(&a).assets.is_empty());
}

#[test]
fn matching_and_changed_native_content_are_distinct_collection_statuses() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-content-status-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "alpha", "Original source.");
    script(
        &a,
        &format!(
            "1\n{}\na\ny\nfrom claude\ny\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    let before = std::fs::read(a.join("collection/kitrove.toml")).unwrap();
    let matched = script(&a, "\n1\nfrom claude\nn\n5\n", true, "");
    assert!(matched.contains("already collected (exact native content matches)"));
    skill(&a, "alpha", "Changed source.");
    let changed = script(&a, "\n1\nfrom claude\nn\n5\n", true, "");
    assert!(changed.contains("same name, different native content"));
    assert_eq!(
        std::fs::read(a.join("collection/kitrove.toml")).unwrap(),
        before
    );
    assert!(!matched.contains("Adopted 0"));
}

#[test]
fn missing_native_evidence_or_other_tool_variants_never_count_as_matching_content() {
    use super::*;
    let tmp = kitrove_testkit::trusted_tempdir(".setup-unverified-content-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "alpha", "Original source.");
    script(
        &a,
        &format!(
            "1\n{}\na\ny\nfrom claude\ny\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    let manifest = super::tests::manifest(&a);
    let id = AssetId::parse("alpha").unwrap();
    let object = kitrove_core::load_native_skill_object(
        &manifest,
        &id,
        &HarnessId::Claude,
        &a.join("collection"),
        CaptureLimits::default(),
    )
    .unwrap();
    let mut entry = kitrove_core::ScanEntry {
        observation_id: None,
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        root_tier: None,
        logical_root: None,
        policy_rank: None,
        source_relative_path: None,
        layout: None,
        native_id: Some("alpha".to_owned()),
        asset_id: None,
        receipt_id: None,
        normalized_destination: None,
        receipt_rendered_hash: None,
        classification: kitrove_core::ScanClassification::Unmanaged,
        exact_source_hash: Some(kitrove_agent_skills::hash_skill_source(
            object.layout(),
            object.original_document_name(),
            object.tree(),
        )),
        portable_hash: None,
        shadowed_by: None,
        findings: Vec::new(),
    };
    assert_eq!(
        super::collection_status::existing(&a.join("collection"), &manifest, &id, &entry),
        super::collection_status::MATCHING
    );
    entry.harness = HarnessId::OpenCode;
    assert_eq!(
        super::collection_status::existing(&a.join("collection"), &manifest, &id, &entry),
        super::collection_status::UNVERIFIED
    );
    entry.harness = HarnessId::Claude;
    let native = &manifest.assets[&id].native_variants[&HarnessId::Claude];
    std::fs::remove_dir_all(a.join("collection").join(native.root.as_str())).unwrap();
    assert_eq!(
        super::collection_status::existing(&a.join("collection"), &manifest, &id, &entry),
        super::collection_status::UNVERIFIED
    );
}

#[test]
fn repeated_matching_collection_review_skips_rename_and_points_to_tools() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-matching-review-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "alpha", "Original source.");
    script(
        &a,
        &format!(
            "1\n{}\na\ny\nfrom claude\ny\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    let before = std::fs::read(a.join("collection/kitrove.toml")).unwrap();
    let original = std::fs::read(a.join("home/.claude/skills/alpha/SKILL.md")).unwrap();
    let output = script(&a, "\n1\nfrom claude\nr\n5\n", true, "");
    assert!(
        output.contains("Add collected skills to a tool"),
        "{output}"
    );
    assert!(output.contains("Skipped 1 already-collected"), "{output}");
    assert!(!output.contains("New collection name"), "{output}");
    assert!(!output.contains("Adopted 0"));
    assert_eq!(
        std::fs::read(a.join("collection/kitrove.toml")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(a.join("home/.claude/skills/alpha/SKILL.md")).unwrap(),
        original
    );
    assert!(!a.join("home/.config/opencode/skills/alpha").exists());
    // A changed copy still needs the existing explicit rename/review path.
    skill(&a, "alpha", "Changed source.");
    let changed = script(&a, "\n1\nfrom claude\nr\nn\n5\n", true, "");
    assert!(changed.contains("New collection name"), "{changed}");
    assert!(!changed.contains("Skipped 1 already-collected"));
    assert_eq!(
        std::fs::read(a.join("collection/kitrove.toml")).unwrap(),
        before
    );
}
