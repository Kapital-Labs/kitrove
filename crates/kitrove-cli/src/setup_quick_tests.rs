use super::tests::{machine, manifest, script, script_target, skill};
use super::*;

// Pi's own user root avoids the intentionally overlapping Claude/OpenCode roots.
fn unique_skill(machine: &std::path::Path, id: &str) {
    let directory = machine.join("home/.pi/agent/skills").join(id);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("SKILL.md"),
        format!(
            "---\nname: {id}\ndescription: A test skill.\n---\nPreserve original instructions.\n"
        ),
    )
    .unwrap();
}

#[test]
fn exclusion_selection_is_exact_and_unambiguous() {
    assert_eq!(selection("all,-2,-4", 4), Some(vec![0, 2]));
    assert_eq!(selection("-2,-4", 4), Some(vec![0, 2]));
    assert_eq!(selection("all, -2, -2", 4), Some(vec![0, 2, 3]));
    assert_eq!(selection("all,-1,-2", 2), Some(vec![]));
    for invalid in ["all,2", "1,-2", "-0", "-5", "all,-", "all,", "all,all"] {
        assert_eq!(selection(invalid, 4), None, "{invalid}");
    }
}

#[test]
fn quick_adoption_defaults_preview_then_one_y_commits_only_included_items() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-quick-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    for id in ["alpha", "beta", "gamma"] {
        unique_skill(&a, id);
    }
    let original = std::fs::read(a.join("home/.pi/agent/skills/alpha/SKILL.md")).unwrap();
    let output = script(
        &a,
        &format!(
            "1\n{}\na\ny\nall,-2\ny\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    assert_eq!(
        manifest(&a)
            .assets
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>(),
        ["alpha", "gamma"]
    );
    assert!(output.contains("Excluded: 2. beta"));
    assert!(output.contains("Adopted 2 skills"));
    assert_eq!(
        std::fs::read(a.join("home/.pi/agent/skills/alpha/SKILL.md")).unwrap(),
        original
    );
    assert!(
        !a.join("home/.agents/skills/alpha").exists(),
        "adoption is not Apply"
    );
    let local = kitrove_model::LocalState::from_json(
        &std::fs::read_to_string(a.join("state/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(local.machine.id.as_str(), "a");
    assert!(local.receipts.is_empty());
    assert!(local.trust.is_empty());
    let portable = manifest(&a).to_toml().unwrap();
    assert!(!portable.contains("machine"));
    assert!(!portable.contains(a.to_str().unwrap()));
}

#[test]
fn quick_preview_blank_n_and_eof_never_authorize_bulk_writes() {
    for (index, decision, error) in [
        (0, "\nn\n5\n", ""),
        (1, "", "setup.cancelled"),
        (2, "q\n", "setup.cancelled"),
    ] {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-no-bulk-consent-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, &format!("a-{index}"));
        skill(&a, "alpha", "Keep alpha.");
        let output = script(
            &a,
            &format!(
                "1\n{}\na\nyes\n\n{decision}",
                a.join("collection").display()
            ),
            false,
            error,
        );
        assert!(manifest(&a).assets.is_empty());
        assert!(output.contains("Adoption preview"));
    }
}

#[test]
fn individual_review_accepts_enter_and_skips_n_without_a_name_prompt() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-individual-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    unique_skill(&a, "alpha");
    unique_skill(&a, "beta");
    let output = script(
        &a,
        &format!(
            "1\n{}\na\nyes\n\nr\n\nn\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    assert_eq!(
        manifest(&a)
            .assets
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>(),
        ["alpha"]
    );
    assert!(!output.contains("Collection name for"));
    assert!(output.contains("Skipped this skill"));
}

#[test]
fn recommendations_never_choose_between_same_named_native_sources() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-duplicate-names-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    skill(&a, "shared", "Claude original.");
    let codex = a.join("home/.agents/skills/shared");
    std::fs::create_dir_all(&codex).unwrap();
    std::fs::write(
        codex.join("SKILL.md"),
        "---\nname: shared\ndescription: Codex source.\n---\nDifferent native content.\n",
    )
    .unwrap();
    unique_skill(&a, "unique");
    let output = script(
        &a,
        &format!("1\n{}\na\nyes\n\ny\n5\n", a.join("collection").display()),
        false,
        "",
    );
    assert_eq!(
        manifest(&a)
            .assets
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>(),
        ["unique"]
    );
    assert!(output.contains("same name"));
    assert!(output.contains("claude"));
    assert!(output.contains("codex"));
}

#[test]
fn individual_rename_preserves_both_exact_native_sources() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-rename-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    unique_skill(&a, "alpha");
    unique_skill(&a, "beta");
    let output = script(
        &a,
        &format!(
            "1\n{}\na\nyes\n\nr\nr\nfirst-copy\n\nr\nfirst-copy\nsecond-copy\n\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    let assets = manifest(&a).assets;
    assert_eq!(
        assets.keys().map(AssetId::as_str).collect::<Vec<_>>(),
        ["first-copy", "second-copy"]
    );
    assert_ne!(
        assets[&AssetId::parse("first-copy".to_owned()).unwrap()].native_variants,
        assets[&AssetId::parse("second-copy".to_owned()).unwrap()].native_variants
    );
    assert!(output.contains("already in use"));
    assert!(a.join("home/.pi/agent/skills/alpha/SKILL.md").is_file());
    assert!(a.join("home/.pi/agent/skills/beta/SKILL.md").is_file());
}

#[test]
fn bulk_preview_retains_partial_reasons_and_omits_executable_content() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-warnings-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    // An explicitly selected Claude source avoids its OpenCode compatibility alias.
    skill(&a, "partial", "Preserve native-only metadata.");
    std::fs::write(
        a.join("home/.claude/skills/partial/SKILL.md"),
        "---\nname: partial\ndescription: Test partial.\nmodel: test-model\n---\nKeep body.\n",
    )
    .unwrap();
    let output = script(
        &a,
        &format!("1\n{}\na\nyes\n1\ny\n5\n", a.join("collection").display()),
        false,
        "",
    );
    assert!(output.contains("Partial"));
    assert!(output.contains("skill.native_field_omitted"));
    let adopted = manifest(&a);
    let native_object = kitrove_core::load_native_skill_object(
        &adopted,
        &AssetId::parse("partial".to_owned()).unwrap(),
        &HarnessId::Claude,
        &a.join("collection"),
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        native_object.tree().files
            [&kitrove_model::PortablePath::parse("SKILL.md".to_owned()).unwrap()]
            .bytes,
        std::fs::read(a.join("home/.claude/skills/partial/SKILL.md")).unwrap()
    );
    assert!(
        format!("{native_object:?}").find("test-model").is_none(),
        "debug remains redacted"
    );
    unique_skill(&a, "executable");
    unique_skill(&a, "credential");
    std::fs::write(
        a.join("home/.pi/agent/skills/credential/.env"),
        "TEST=kitrove-synthetic-secret-canary-12345",
    )
    .unwrap();
    std::fs::write(
        a.join("home/.pi/agent/skills/executable/run.sh"),
        "#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    let output = script(&a, "\n1\nall\ny\n5\n", true, "");
    assert!(output.contains("ExecutableTrustRequired"));
    assert!(!output.contains("kitrove-synthetic-secret-canary-12345"));
    assert!(
        !manifest(&a)
            .assets
            .contains_key(&AssetId::parse("credential".to_owned()).unwrap())
    );
    assert!(
        !manifest(&a)
            .assets
            .contains_key(&AssetId::parse("executable".to_owned()).unwrap())
    );
}

#[test]
fn short_confirmations_do_not_change_other_blank_defaults() {
    for input in ["y\n", "yes\n", "Y\n"] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
        };
        assert!(dialog.confirm("change?").unwrap());
    }
    for input in ["\n", "n\n", "no\n"] {
        let mut dialog = Dialog {
            input: io::Cursor::new(input),
            output: Vec::new(),
            color: false,
        };
        assert!(!dialog.confirm("change?").unwrap());
    }
    let mut dialog = Dialog {
        input: io::Cursor::new("maybe\ny\n"),
        output: Vec::new(),
        color: false,
    };
    assert!(dialog.confirm("change?").unwrap());
    assert!(
        String::from_utf8(dialog.output)
            .unwrap()
            .contains("Nothing has changed")
    );
}

#[test]
fn compact_inventory_and_exclusions_use_the_same_numbering_after_view() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-view-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "a");
    for n in 1..=21 {
        unique_skill(&a, &format!("skill-{n:02}"));
    }
    let output = script(
        &a,
        &format!(
            "1\n{}\na\nyes\nv\n-1,-21\nn\n5\n",
            a.join("collection").display()
        ),
        false,
        "",
    );
    assert!(output.contains("Showing the first 20"));
    assert!(output.contains("21. skill-21"));
    assert!(output.contains("Excluded: 1. skill-01"));
    assert!(output.contains("Excluded: 21. skill-21"));
    assert!(manifest(&a).assets.is_empty());
}

#[test]
fn real_bulk_loop_refuses_stale_sources_and_stops_after_partial_progress() {
    for mode in ["before", "after-first", "manifest", "journal"] {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-race-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = machine(&root, "a");
        for id in ["alpha", "beta", "gamma"] {
            unique_skill(&a, id);
        }
        script_target(
            &a,
            &format!("1\n{}\na\nyes\nn\n5\n", a.join("collection").display()),
            false,
            mode,
            "setup::quick_tests::race_child",
        );
        assert_eq!(
            manifest(&a).assets.len(),
            usize::from(mode == "after-first")
        );
    }
}

struct RaceWriter {
    output: Vec<u8>,
    collection: PathBuf,
    mode: String,
    mutated: bool,
}

impl Write for RaceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        let text = String::from_utf8_lossy(&self.output);
        let trigger = if self.mode == "after-first" {
            "Adopted alpha."
        } else {
            "y/yes = adopt the previewed set"
        };
        if !self.mutated && text.contains(trigger) {
            if self.mode == "journal" {
                std::fs::write(
                    self.collection.join(".kitrove/adoption-journal.json"),
                    b"invalid-external-journal",
                )?;
            } else if self.mode == "manifest" {
                let path = self.collection.join("kitrove.toml");
                let original = std::fs::read_to_string(&path)?;
                // Valid new portable authority, not a formatting-only edit.
                let mut manifest =
                    kitrove_model::EnvironmentManifest::from_toml(&original).unwrap();
                manifest.required_bindings.insert(
                    kitrove_model::BindingName::parse("external_binding".to_owned()).unwrap(),
                );
                let changed = manifest.to_toml().unwrap();
                assert_ne!(original, changed);
                std::fs::write(path, changed)?;
            } else {
                let id = if self.mode == "after-first" {
                    "beta"
                } else {
                    "alpha"
                };
                std::fs::write(
                    self.collection
                        .parent()
                        .unwrap()
                        .join(format!("home/.pi/agent/skills/{id}/SKILL.md")),
                    format!(
                        "---\nname: {id}\ndescription: Changed after preview.\n---\nChanged source bytes.\n"
                    ),
                )?;
            }
            self.mutated = true;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "invoked by isolated parent fixtures"]
fn race_child() {
    let collection = PathBuf::from(std::env::var_os("KITROVE_TEST_COLLECTION").unwrap());
    let mut init = Dialog {
        input: io::Cursor::new(std::env::var("KITROVE_TEST_SETUP_INPUT").unwrap()),
        output: Vec::new(),
        color: false,
    };
    run(
        &mut init,
        Some(collection.clone()),
        false,
        &crate::tier_one_registry(),
    )
    .unwrap();
    let mode = std::env::var("KITROVE_TEST_EXPECT_ERROR").unwrap();
    let state_path = collection.parent().unwrap().join("state/state.json");
    let state = std::fs::read(&state_path).unwrap();
    let mut dialog = Dialog {
        input: io::Cursor::new("\ny\n"),
        color: false,
        output: RaceWriter {
            output: Vec::new(),
            collection: collection.clone(),
            mode: mode.clone(),
            mutated: false,
        },
    };
    let result = collect(&mut dialog, &collection, &crate::tier_one_registry());
    assert!(result.is_err());
    assert!(dialog.output.mutated);
    assert_eq!(std::fs::read(state_path).unwrap(), state);
    let output = String::from_utf8(dialog.output.output).unwrap();
    assert!(output.contains(if mode == "after-first" {
        "Stopped after 1 completed"
    } else {
        "Stopped after 0 completed"
    }));
    if mode == "manifest" {
        // Preserve the deliberate external edit; the wizard must not repair it.
        assert!(
            manifest(collection.parent().unwrap())
                .required_bindings
                .contains(
                    &kitrove_model::BindingName::parse("external_binding".to_owned()).unwrap()
                )
        );
    }
    if mode == "journal" {
        assert_eq!(
            std::fs::read(collection.join(".kitrove/adoption-journal.json")).unwrap(),
            b"invalid-external-journal"
        );
        assert_eq!(result.unwrap_err().code, "adoption.recovery_required");
    }
    println!("{output}");
}
