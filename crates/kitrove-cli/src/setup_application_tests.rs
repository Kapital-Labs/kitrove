use super::tests::{machine, script};
use super::*;

fn prepared() -> (tempfile::TempDir, PathBuf) {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-tools-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    let skill = a.join("home/.pi/agent/skills/alpha");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nname: alpha\ndescription: Review changes carefully.\n---\nRead the diff.\n",
    )
    .unwrap();
    script(
        &a,
        &format!(
            "1\n{}\na\ny\nfrom pi\ny\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    // The captured source stays native evidence; empty all destinations before apply.
    std::fs::remove_dir_all(a.join("home/.pi/agent/skills/alpha")).unwrap();
    (tmp, a)
}

#[test]
fn all_four_tools_choose_destination_first_and_install_skills_without_version_probe() {
    for (key, destination) in [
        ("1", ".claude/skills"),
        ("2", ".agents/skills"),
        ("3", ".pi/agent/skills"),
        ("4", ".config/opencode/skills"),
    ] {
        let (_tmp, a) = prepared();
        let output = script(&a, &format!("\n2\n{key}\n1\n1\ny\n5\n"), true, "");
        assert!(output.find("Which AI tools").unwrap() < output.find("Which saved items").unwrap());
        assert!(!output.contains("Absolute trusted"));
        assert!(output.contains("Review changes carefully."));
        assert!(output.contains("Files added"));
        assert!(output.contains("ready        Skills ready to add or update (recommended)"));
        assert!(output.contains("all          Every matching item, including needs-review items"));
        assert!(output.contains("All does not bypass checks"));
        assert!(
            a.join("home")
                .join(destination)
                .join("alpha/SKILL.md")
                .is_file()
        );
    }
}

#[test]
fn project_scope_for_each_tool_writes_only_the_confirmed_project() {
    for (key, destination) in [
        ("1", ".claude/skills"),
        ("2", ".agents/skills"),
        ("3", ".pi/skills"),
        ("4", ".opencode/skills"),
    ] {
        let (_tmp, a) = prepared();
        let project = a.join("working");
        let output = script(
            &a,
            &format!("\n2\n{key}\n2\n{}\n1\ny\n5\n", project.display()),
            true,
            "",
        );
        assert!(project.join(destination).join("alpha/SKILL.md").is_file());
        for user in [
            ".claude/skills",
            ".agents/skills",
            ".pi/agent/skills",
            ".config/opencode/skills",
        ] {
            assert!(!a.join("home").join(user).join("alpha").exists());
        }
        assert!(output.contains("This project"));
        if key == "2" {
            assert!(output.contains("Pi and OpenCode may also discover"));
        }
    }
}

#[test]
fn apply_preview_enter_still_skips_writes_and_does_not_probe_tools() {
    let (_tmp, a) = prepared();
    let output = script(&a, "\n2\nm\n3,4\n1\n1\n\n5\n", true, "");
    assert!(output.contains("Application skipped"));
    for destination in [".pi/agent/skills/alpha", ".config/opencode/skills/alpha"] {
        assert!(!a.join("home").join(destination).exists());
    }
}

#[test]
fn unmanaged_destination_is_reported_without_overwrite_or_adoption_of_ownership() {
    let (_tmp, a) = prepared();
    let existing = a.join("home/.config/opencode/skills/alpha");
    std::fs::create_dir_all(&existing).unwrap();
    std::fs::write(existing.join("SKILL.md"), "User owned content.").unwrap();
    let output = script(&a, "\n2\n4\n1\n1\n5\n", true, "apply.destination_unmanaged");
    assert!(output.contains("Needs review"));
    assert_eq!(
        std::fs::read_to_string(existing.join("SKILL.md")).unwrap(),
        "User owned content."
    );
}

#[test]
fn newly_collected_items_can_go_directly_to_a_tool_with_separate_confirmation() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-next-tool-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    super::tests::skill(&a, "alpha", "Read the diff.");
    let output = script(
        &a,
        &format!(
            "1\n{}\na\ny\nfrom claude\ny\n2\n4\n1\n\ny\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    assert!(output.contains("use option 2: Add skills or packs to a tool"));
    assert!(output.contains("just collected"));
    assert!(output.contains("additional managed copies in the OpenCode destination"));
    assert!(output.contains("matching IDs may override"));
    assert!(
        a.join("home/.config/opencode/skills/alpha/SKILL.md")
            .is_file()
    );
    assert!(
        output.find("Adopted 1 skills").unwrap() < output.find("Add to tools — preview").unwrap()
    );
}

#[test]
fn repeated_apply_reports_managed_current_content_without_rewriting_it() {
    let (_tmp, a) = prepared();
    script(&a, "\n2\n4\n1\n1\ny\n5\n", true, "");
    let target = a.join("home/.config/opencode/skills/alpha/SKILL.md");
    let before = std::fs::read(&target).unwrap();
    let output = script(&a, "\n2\n4\n1\n1\ny\n5\n", true, "");
    assert!(output.contains("Already current (managed)"));
    assert_eq!(std::fs::read(target).unwrap(), before);
}

#[test]
fn collecting_another_skill_keeps_existing_tool_copies_current() {
    for (key, destination) in [
        ("1", ".claude/skills"),
        ("2", ".agents/skills"),
        ("3", ".pi/agent/skills"),
        ("4", ".config/opencode/skills"),
    ] {
        let (_tmp, a) = prepared();
        script(&a, &format!("\n2\n{key}\n1\n1\ny\n5\n"), true, "");
        let target = a.join("home").join(destination).join("alpha/SKILL.md");
        let before = std::fs::read(&target).unwrap();
        let modified = std::fs::metadata(&target).unwrap().modified().unwrap();
        super::tests::skill(&a, "beta", "A newly collected unrelated skill.");
        script(&a, "\n1\nfrom claude\ny\n5\n", true, "");
        let beta_target = a.join("home").join(destination).join("beta/SKILL.md");
        let beta_before = std::fs::read(&beta_target).ok();
        let output = script(&a, &format!("\n2\n{key}\n1\n1\ny\n5\n"), true, "");
        assert!(output.contains("Already current (managed)"));
        assert!(!output.contains("bounded recovery authority"));
        assert_eq!(std::fs::read(&target).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&target).unwrap().modified().unwrap(),
            modified
        );
        assert_eq!(std::fs::read(&beta_target).ok(), beta_before);
    }
}

#[test]
fn filtered_all_selects_only_filtered_items_and_preserves_original_numbers() {
    let (_tmp, a) = prepared();
    let beta = a.join("home/.pi/agent/skills/beta");
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(
        beta.join("SKILL.md"),
        "---\nname: beta\ndescription: Another test skill.\n---\nPreserve beta.\n",
    )
    .unwrap();
    script(&a, "\n1\nfrom pi\ny\n5\n", true, "");
    let output = script(&a, "\n2\n4\n1\n/alpha\nall\ny\n5\n", true, "");
    assert!(output.contains("1. alpha"));
    assert!(
        a.join("home/.config/opencode/skills/alpha/SKILL.md")
            .is_file()
    );
    assert!(!a.join("home/.config/opencode/skills/beta").exists());
}

#[test]
fn large_preview_is_paged_and_hostile_labels_cannot_inject_prompt_lines() {
    let items: Vec<_> = (0..30).map(|i| serde_json::json!({
        "asset_id": format!("skill-{i:02}"), "destination": format!("/synthetic/{i}"), "disposition": "install",
    })).collect();
    let encoded = serde_json::json!({"items": items}).to_string();
    let mut dialog = Dialog {
        input: io::Cursor::new("n\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(!super::application_preview::confirm(&mut dialog, &encoded).unwrap());
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(output.contains("skill-00"));
    assert!(!output.contains("skill-29"));
    assert!(output.contains("30 destinations"));
    let encoded = serde_json::json!({"asset_id": "skill\n? Fake approval\u{1b}[2J", "destination":"/synthetic", "disposition":"install"}).to_string();
    let mut dialog = Dialog {
        input: io::Cursor::new("n\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(!super::application_preview::confirm(&mut dialog, &encoded).unwrap());
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(!output.contains("\n? Fake approval"));
    assert!(!output.contains('\u{1b}'));
}

#[test]
fn opencode_version_prompt_tracks_selected_asset_kinds_including_pack_leaves() {
    use kitrove_core::{
        InstructionAdoptionOutcome, commit_instruction_adoption, observe_instruction_document,
        plan_instruction_adoption,
    };
    let (_tmp, a) = prepared();
    let source = a.join("working");
    std::fs::write(source.join("AGENTS.md"), "<!-- kitrove:instruction review begin -->\nReview the whole diff.\n<!-- kitrove:instruction review end -->\n").unwrap();
    let policy =
        crate::adapters::instruction_target_policy(&HarnessId::Codex, HarnessScope::Project)
            .unwrap();
    let observation = observe_instruction_document(&source, &policy, Default::default()).unwrap();
    let id = AssetId::parse("review").unwrap();
    let InstructionAdoptionOutcome::Ready(plan) = plan_instruction_adoption(
        &observation,
        &id,
        &super::tests::manifest(&a),
        &crate::adapters::tier_one_instruction_capabilities().unwrap(),
    )
    .unwrap() else {
        panic!("fixture must be adoptable");
    };
    commit_instruction_adoption(
        &plan,
        &observation,
        &a.join("collection"),
        CaptureLimits::default(),
    )
    .unwrap();
    let pack = kitrove_core::plan_authored_pack_creation(
        &super::tests::manifest(&a),
        AssetId::parse("toolkit").unwrap(),
        BTreeSet::from([id]),
    )
    .unwrap();
    kitrove_core::commit_pack_creation(&pack, &a.join("collection"), CaptureLimits::default())
        .unwrap();
    // Skill-only selection ignores the unselected gated instruction and pack.
    let skill = script(&a, "\n2\n4\n1\n2\nn\n5\n", true, "");
    assert!(!skill.contains("Absolute trusted"));
    // Both a direct instruction and the instruction reached through a pack need V2 evidence.
    for selection in ["1", "3"] {
        let gated = script(&a, &format!("\n2\n4\n1\n{selection}\n\n5\n"), true, "");
        assert!(gated.contains("Absolute trusted opencode2 executable path"));
        assert!(!gated.contains("Add to tools — preview"));
    }
    assert!(!a.join("home/.config/opencode").exists());
}

#[test]
fn ready_shortcut_excludes_unmanaged_conflicts_without_touching_them() {
    let (_tmp, a) = prepared();
    let beta = a.join("home/.pi/agent/skills/beta");
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::write(
        beta.join("SKILL.md"),
        "---\nname: beta\ndescription: Another skill.\n---\nKeep beta.\n",
    )
    .unwrap();
    script(&a, "\n1\nfrom pi\ny\n5\n", true, "");
    let conflict = a.join("home/.config/opencode/skills/alpha/SKILL.md");
    std::fs::create_dir_all(conflict.parent().unwrap()).unwrap();
    std::fs::write(&conflict, "User-owned alpha.\n").unwrap();
    let output = script(&a, "\n2\n4\n1\nready\ny\n5\n", true, "");
    assert!(output.contains("Needs review"));
    assert!(output.contains("Ready to add"));
    assert!(
        a.join("home/.config/opencode/skills/beta/SKILL.md")
            .is_file()
    );
    assert_eq!(
        std::fs::read_to_string(conflict).unwrap(),
        "User-owned alpha.\n"
    );
}

#[test]
fn incompatible_bulk_selection_can_be_reselected_without_partial_application() {
    let (_tmp, a) = prepared();
    super::tests::skill(&a, "beta", "A separately selected compatible skill.");
    std::fs::write(
        a.join("home/.claude/skills/beta/SKILL.md"),
        "---\nname: beta\n---\nA description inferred from Claude's first paragraph.\n",
    )
    .unwrap();
    script(&a, "\n1\nfrom claude\ny\n5\n", true, "");
    assert_eq!(
        super::tests::manifest(&a).assets[&AssetId::parse("beta").unwrap()].compatibility
            [&HarnessId::OpenCode]
            .fidelity(),
        kitrove_model::Fidelity::Partial
    );
    let output = script(&a, "\n2\n4\n1\nall\ns\n1\ny\n5\n", true, "");
    assert!(output.contains("Selection not applied"));
    assert!(output.contains("Choose different items"));
    assert!(output.contains("Not compatible with the selected tools"));
    assert!(!a.join("home/.config/opencode/skills/beta").exists());
    assert!(
        a.join("home/.config/opencode/skills/alpha/SKILL.md")
            .is_file()
    );
    let state: kitrove_model::LocalState =
        serde_json::from_slice(&std::fs::read(a.join("state/state.json")).unwrap()).unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(
        state.receipts.values().next().unwrap().asset_id.as_str(),
        "alpha"
    );
}

#[test]
fn structured_preview_keeps_removals_and_later_page_connection_effects_visible() {
    let mut items = vec![serde_json::json!({
        "relative_destination": "AGENTS.md", "disposition": "managed_update",
        "regions": [{"asset_id": "old-region", "operation": "remove", "targets": ["codex"], "scope":"project"}]
    })];
    items.extend((0..11).map(|i| serde_json::json!({"asset_id":format!("skill-{i}"),"disposition":"install","destination":"/synthetic"})));
    items.push(serde_json::json!({"relative_destination":"opencode.json", "disposition":"managed_update", "effect":"A future harness load may connect to the declared MCP endpoint", "entries":[{"asset_id":"remote-tools", "native_name":"review-tools", "target":"opencode", "disposition":"install"}]}));
    let encoded = serde_json::json!({"items":items}).to_string();
    let mut dialog = Dialog {
        input: io::Cursor::new("n\n"),
        output: Vec::new(),
        color: false,
        single_key: false,
    };
    assert!(!super::application_preview::confirm(&mut dialog, &encoded).unwrap());
    let output = String::from_utf8(dialog.output).unwrap();
    assert!(output.contains("remove: old-region"));
    assert!(output.contains("may connect to the declared MCP endpoint"));
    assert!(
        !output.contains("remote-tools"),
        "later-page items stay paged; their connection effect stays visible"
    );
}

#[test]
fn core_recovery_guard_is_not_hidden_by_advisory_destination_readiness() {
    let (_tmp, a) = prepared();
    let target = a.join("home/.config/opencode/skills/alpha/SKILL.md");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(&target, "User-owned target.\n").unwrap();
    let journal = a.join("state/.kitrove/atomic-apply-journal.json");
    let invalid = b"{\"not\":\"valid journal authority\"}";
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(journal.parent().unwrap()).unwrap();
        std::fs::write(&journal, invalid).unwrap();
        std::fs::set_permissions(
            journal.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    {
        kitrove_windows_security::ensure_private_directory_for_tests(journal.parent().unwrap())
            .unwrap();
        kitrove_windows_security::write_current_user_owned_file_for_tests(&journal, invalid)
            .unwrap();
    }
    assert_eq!(
        kitrove_core::inspect_atomic_apply_batch_journal(&a.join("state"))
            .unwrap_err()
            .code(),
        "apply.batch_journal_invalid"
    );
    let before = std::fs::read(&journal).unwrap();
    let output = script(&a, "\n2\n4\n1\n1\n", true, "apply.batch_journal_invalid");
    assert!(output.contains("Needs review"));
    assert_eq!(std::fs::read(journal).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(target).unwrap(),
        "User-owned target.\n"
    );
}

#[test]
fn saved_pack_is_first_and_applies_all_members_with_one_preview() {
    let (_tmp, a) = prepared();
    let pack = kitrove_core::plan_authored_pack_creation(
        &super::tests::manifest(&a),
        AssetId::parse("z-review-pack").unwrap(),
        BTreeSet::from([AssetId::parse("alpha").unwrap()]),
    )
    .unwrap();
    kitrove_core::commit_pack_creation(&pack, &a.join("collection"), CaptureLimits::default())
        .unwrap();
    let output = script(&a, "\n2\n4\n1\n1\ny\n5\n", true, "");
    assert!(output.contains("2. Add skills or packs to a tool"));
    assert!(
        output.contains("1. z-review-pack [Pack · 1 item]"),
        "{output}"
    );
    assert!(output.find("1. z-review-pack").unwrap() < output.find("2. alpha").unwrap());
    assert!(output.contains("kitrove apply"));
    assert!(
        a.join("home/.config/opencode/skills/alpha/SKILL.md")
            .is_file()
    );
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("state/state.json")).unwrap()).unwrap();
    assert!(
        !state["pack_applications"].as_object().unwrap().is_empty(),
        "{state}"
    );
}

fn prepared_scripted_skill() -> (tempfile::TempDir, PathBuf) {
    prepared_scripted_skill_bytes(b"from pathlib import Path\nPath('KITROVE_SCRIPT_EXECUTED').write_text('bad')\nraise SystemExit('must never execute')\n")
}
fn prepared_scripted_skill_bytes(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let (temporary, a) = prepared();
    super::tests::skill(
        &a,
        "rv",
        "Use helper.py only when the tool user permits it.",
    );
    std::fs::write(a.join("home/.claude/skills/rv/helper.py"), bytes).unwrap();
    let output = script(&a, "\n1\nfrom claude\ny\n5\n", true, "");
    assert!(output.contains("Adopted 1 skills"), "{output}");
    let state: kitrove_model::LocalState =
        serde_json::from_slice(&std::fs::read(a.join("state/state.json")).unwrap()).unwrap();
    assert!(state.trust.is_empty() && state.receipts.is_empty());
    (temporary, a)
}

#[test]
fn scripted_skill_needs_separate_exact_local_approval_for_each_tool() {
    for (tool, folder) in [
        ("1", ".claude/skills"),
        ("2", ".agents/skills"),
        ("3", ".pi/agent/skills"),
        ("4", ".config/opencode/skills"),
    ] {
        let (_tmp, a) = prepared_scripted_skill();
        let native = std::fs::read(a.join("home/.claude/skills/rv/helper.py")).unwrap();
        // A managed destination must be empty; native evidence remains in collection.
        std::fs::remove_dir_all(a.join("home/.claude/skills/rv")).unwrap();
        let output = script(&a, &format!("\n2\n{tool}\n1\n2\ny\ny\n5\n"), true, "");
        assert!(output.contains("Script-containing skill: rv"), "{output}");
        assert!(
            output.find("Exact bundle approved locally").unwrap()
                < output.find("Add the previewed items?").unwrap()
        );
        assert_eq!(
            std::fs::read(a.join("home").join(folder).join("rv/helper.py")).unwrap(),
            native
        );
        let state: kitrove_model::LocalState =
            serde_json::from_slice(&std::fs::read(a.join("state/state.json")).unwrap()).unwrap();
        let id = AssetId::parse("rv").unwrap();
        assert!(matches!(
            state
                .trust
                .get(&super::tests::manifest(&a).assets[&id].content_hash),
            Some(kitrove_model::TrustDecision::Trusted { .. })
        ));
        assert_eq!(state.receipts.len(), 1);
        assert!(!a.join("working/KITROVE_SCRIPT_EXECUTED").exists());
        assert!(!a.join("home/KITROVE_SCRIPT_EXECUTED").exists());
    }
}

#[test]
fn skipping_script_approval_keeps_entire_pack_unapplied_and_trust_empty() {
    let (_tmp, a) = prepared_scripted_skill();
    let pack = kitrove_core::plan_authored_pack_creation(
        &super::tests::manifest(&a),
        AssetId::parse("work-pack").unwrap(),
        BTreeSet::from([
            AssetId::parse("alpha").unwrap(),
            AssetId::parse("rv").unwrap(),
        ]),
    )
    .unwrap();
    kitrove_core::commit_pack_creation(&pack, &a.join("collection"), CaptureLimits::default())
        .unwrap();
    let output = script(&a, "\n2\n4\n1\n1\n\n5\n", true, "");
    assert!(output.contains("Selection was not applied"));
    assert!(!a.join("home/.config/opencode/skills").exists());
    let state: kitrove_model::LocalState =
        serde_json::from_slice(&std::fs::read(a.join("state/state.json")).unwrap()).unwrap();
    assert!(
        state.trust.is_empty() && state.receipts.is_empty() && state.pack_applications.is_empty()
    );
}

#[test]
fn stored_script_file_inspection_escapes_controls_pages_long_lines_and_grants_no_trust() {
    let bytes = format!("# stored source \u{1b}[2J{}\n", "a".repeat(300));
    let (_tmp, a) = prepared_scripted_skill_bytes(bytes.as_bytes());
    let output = script(&a, "\n2\n4\n1\n2\nf\n2\n\n\n5\n", true, "");
    assert!(output.contains("Stored file:"));
    assert!(output.contains("\\u{1b}[2J"));
    assert!(!output.contains('\u{1b}'));
    assert!(
        !output.contains(&"a".repeat(200)),
        "source lines must be wrapped into bounded rows"
    );
    assert!(output.contains("Selection was not applied"));
    let state: kitrove_model::LocalState =
        serde_json::from_slice(&std::fs::read(a.join("state/state.json")).unwrap()).unwrap();
    assert!(state.trust.is_empty() && state.receipts.is_empty());
    assert!(!a.join("home/.config/opencode/skills").exists());
}
