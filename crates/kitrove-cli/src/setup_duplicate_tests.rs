use super::tests::{machine, manifest, script, skill};
use super::*;

fn start(a: &std::path::Path, collection_input: &str) -> String {
    script(
        a,
        &format!(
            "1\n{}\na\nyes\n{collection_input}",
            a.join("collection").display()
        ),
        false,
        "",
    )
}

#[test]
fn all_ambiguous_preview_has_no_empty_write_approval_or_success() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-empty-preview-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    // Claude's skill is also observed through OpenCode's compatibility root.
    skill(&a, "shared", "Preserve this source.");
    let output = start(&a, "\nn\n5\n");
    assert!(manifest(&a).assets.is_empty());
    assert!(output.contains("No skills ready to collect. Nothing has changed."));
    assert!(!output.contains("Adopt the previewed set"));
    assert!(!output.contains("Adopted 0 skills"));
}

#[test]
fn explicit_tool_selection_preserves_its_native_bytes_without_merging_other_copies() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-source-choice-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "shared", "Claude content.");
    let claude = a.join("home/.claude/skills/shared/SKILL.md");
    std::fs::write(
        &claude,
        "---\nname: shared\ndescription: Claude.\nmodel: local-model\n---\nClaude content.\n",
    )
    .unwrap();
    let codex = a.join("home/.agents/skills/shared/SKILL.md");
    std::fs::create_dir_all(codex.parent().unwrap()).unwrap();
    std::fs::write(
        &codex,
        "---\nname: shared\ndescription: Different.\n---\nDifferent source.\n",
    )
    .unwrap();
    let before = [
        std::fs::read(&claude).unwrap(),
        std::fs::read(&codex).unwrap(),
    ];
    let output = start(&a, "from claude\ny\n5\n");
    let adopted = manifest(&a);
    let id = AssetId::parse("shared".to_owned()).unwrap();
    assert_eq!(adopted.assets.len(), 1);
    assert_eq!(adopted.assets[&id].native_variants.len(), 1);
    let native = kitrove_core::load_native_skill_object(
        &adopted,
        &id,
        &HarnessId::Claude,
        &a.join("collection"),
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        native.tree().files[&kitrove_model::PortablePath::parse("SKILL.md".to_owned()).unwrap()]
            .bytes,
        before[0]
    );
    assert_eq!(std::fs::read(&claude).unwrap(), before[0]);
    assert_eq!(std::fs::read(&codex).unwrap(), before[1]);
    assert!(output.contains("Partial"));
    assert!(output.contains("skill.native_field_omitted"));
    assert!(output.contains("Adopted 1 skills"));
    let state = kitrove_model::LocalState::from_json(
        &std::fs::read_to_string(a.join("state/state.json")).unwrap(),
    )
    .unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.trust.is_empty());
}

#[test]
fn source_choice_exclusions_bind_original_inventory_numbers() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-source-exclude-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "alpha", "Alpha.");
    skill(&a, "beta", "Beta.");
    let output = start(&a, "v\nfrom claude,-2\ny\n5\n");
    assert_eq!(
        manifest(&a)
            .assets
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>(),
        ["alpha"]
    );
    assert!(output.contains("Excluded: 2. beta"));
    assert!(a.join("home/.claude/skills/beta/SKILL.md").is_file());
}

#[test]
fn empty_preview_can_choose_a_source_without_rescanning_or_restarting_setup() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-reselect-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "shared", "Keep original.");
    let output = start(&a, "\n\nfrom claude\ny\n5\n");
    assert_eq!(manifest(&a).assets.len(), 1);
    assert_eq!(output.matches("Collection scan (read-only)").count(), 1);
    assert!(output.contains("No skills ready to collect"));
    assert!(!output.contains("Adopted 0 skills"));
}

#[test]
fn omission_output_is_bounded_but_details_retain_all_original_entries() {
    for details in [false, true] {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-omission-summary-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        for n in 0..30 {
            skill(&a, &format!("shared-{n:02}"), "Original source.");
        }
        let output = start(&a, if details { "\nd\nn\n5\n" } else { "\nn\n5\n" });
        assert!(manifest(&a).assets.is_empty());
        assert!(output.contains("60 selected but omitted"));
        if details {
            assert!(output.contains("Omitted: 60. shared-29"));
        } else {
            assert!(output.matches("Omitted:").count() <= 20);
            assert!(output.contains("Show all skipped-item details"));
        }
        assert!(!output.contains("Adopt the previewed set"));
    }
}

#[test]
fn occupied_names_remain_unchanged_and_never_count_as_successful_adoptions() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-occupied-source-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "shared", "Keep original.");
    start(&a, "1\ny\n5\n");
    let before = std::fs::read(a.join("collection/kitrove.toml")).unwrap();
    let output = script(&a, "\n1\nfrom claude\nn\n5\n", true, "");
    assert_eq!(
        std::fs::read(a.join("collection/kitrove.toml")).unwrap(),
        before
    );
    assert!(output.contains("collection name already in use"));
    assert!(!output.contains("Adopt the previewed set"));
    assert!(!output.contains("Adopted 0 skills"));
}

#[test]
fn empty_preview_rejects_yes_and_eof_stops_without_writes() {
    for (input, error) in [
        ("\ny\nn\n5\n", ""),
        ("\n", "setup.cancelled"),
        ("\nq\n", "setup.cancelled"),
    ] {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-empty-cancel-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        skill(&a, "shared", "Keep original.");
        let output = script(
            &a,
            &format!("1\n{}\na\nyes\n{input}", a.join("collection").display()),
            false,
            error,
        );
        assert!(manifest(&a).assets.is_empty());
        assert!(!output.contains("Adopted 0 skills"));
        assert!(!output.contains("Adopt the previewed set"));
    }
}

#[test]
fn invalid_source_selectors_reprompt_without_changing_the_collection() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-source-invalid-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "shared", "Keep original.");
    let output = start(
        &a,
        "from absent\nfrom claude,1\nfrom claude,-0\nfrom claude,-999\nfrom claude,\nfrom claude,-1,2\nn\n5\n",
    );
    assert!(manifest(&a).assets.is_empty());
    assert_eq!(output.matches("Use a displayed tool").count(), 6);
}
