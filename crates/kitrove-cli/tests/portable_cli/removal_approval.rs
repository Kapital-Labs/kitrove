use super::*;

fn command_fixture() -> Fixture {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    assert!(fixture.adopt(&observation, None).status.success());
    fixture.initialize_local_state();
    assert!(fixture.apply("pi").status.success());
    fixture
}

fn run(fixture: &Fixture, arguments: &[&str]) -> Output {
    fixture
        .command()
        .args(arguments)
        .args([
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn direct(fixture: &Fixture, flags: &[&str]) -> Output {
    let mut args = vec!["remove", "--asset", "review", "--target", "pi"];
    args.extend_from_slice(flags);
    run(fixture, &args)
}

fn authority(fixture: &Fixture) -> [Vec<u8>; 3] {
    [
        fs::read(fixture.state_home.join("state.json")).unwrap(),
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        fs::read(fixture.environment.join("kitrove.lock.json")).unwrap(),
    ]
}

#[test]
fn direct_preview_and_exact_approval_preserve_portable_authority() {
    let fixture = command_fixture();
    let target = fixture.home.join(".pi/agent/prompts/review.md");
    let bytes = fs::read(&target).unwrap();
    let before = authority(&fixture);
    let plan = direct(&fixture, &["--plan"]);
    assert!(plan.status.success(), "{plan:?}");
    assert!(plan.stderr.is_empty());
    assert_eq!(authority(&fixture), before);
    assert_eq!(fs::read(&target).unwrap(), bytes);
    let value = json(&plan);
    let digest = value["batch_digest"].as_str().unwrap();
    let wrong = direct(
        &fixture,
        &["--confirm", ContentHash::digest(b"wrong").as_str()],
    );
    assert_eq!(wrong.status.code(), Some(1));
    assert_eq!(authority(&fixture), before);
    let removed = direct(&fixture, &["--confirm", digest]);
    assert!(removed.status.success(), "{removed:?}");
    assert!(removed.stderr.is_empty());
    assert!(!target.exists());
    let after = authority(&fixture);
    assert_eq!(after[1..], before[1..]);
    assert_ne!(after[0], before[0]);
    assert_eq!(
        direct(&fixture, &["--confirm", digest]).status.code(),
        Some(1)
    );
}

#[test]
fn modified_target_and_pending_recovery_cannot_consume_approval() {
    for pending in [false, true] {
        let fixture = command_fixture();
        let plan = direct(&fixture, &["--plan"]);
        assert!(plan.status.success(), "{plan:?}");
        let target = fixture.home.join(".pi/agent/prompts/review.md");
        let journal = fixture
            .state_home
            .join(".kitrove/atomic-apply-journal.json");
        if pending {
            owned_fixture::create(&journal, b"PENDING CANARY");
            assert_eq!(direct(&fixture, &["--plan"]).status.code(), Some(1));
        } else {
            fs::write(&target, "USER EDIT").unwrap();
        }
        let before = authority(&fixture);
        let bytes = fs::read(&target).unwrap();
        let result = direct(
            &fixture,
            &["--confirm", json(&plan)["batch_digest"].as_str().unwrap()],
        );
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert_eq!(authority(&fixture), before);
        assert_eq!(fs::read(&target).unwrap(), bytes);
        if pending {
            assert_eq!(fs::read(journal).unwrap(), b"PENDING CANARY");
        }
    }
}

#[test]
fn approved_pack_removal_retains_overlapping_ownership() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    assert!(
        fixture
            .confirmed_apply(&[
                "--pack",
                "inner-pack",
                "--pack",
                "outer-pack",
                "--target",
                "codex"
            ])
            .status
            .success()
    );
    for pack in ["outer-pack", "inner-pack"] {
        let revision = manifest_pack_revision(&fixture, pack).to_string();
        let base = [
            "pack",
            "remove",
            "--pack",
            pack,
            "--expected-prior",
            &revision,
        ];
        let before = authority(&fixture);
        let mut args = base.to_vec();
        args.push("--plan");
        let plan = run(&fixture, &args);
        assert!(plan.status.success(), "{plan:?}");
        assert_eq!(authority(&fixture), before);
        let value = json(&plan);
        let mut args = base.to_vec();
        args.extend(["--confirm", value["batch_digest"].as_str().unwrap()]);
        let removed = run(&fixture, &args);
        assert!(removed.status.success(), "{removed:?}");
        assert!(removed.stderr.is_empty());
        assert_eq!(
            fixture.home.join(".agents/skills/pack-alpha").exists(),
            pack == "outer-pack"
        );
        assert_eq!(
            fixture.home.join(".agents/skills/pack-beta").exists(),
            pack == "outer-pack"
        );
    }
}

#[test]
fn removal_approval_flags_are_strict() {
    let fixture = Fixture::new();
    let hash = ContentHash::digest(b"approval");
    for flags in [
        vec!["--plan", "--plan"],
        vec!["--plan", "--confirm", hash.as_str()],
        vec!["--confirm", hash.as_str(), "--plan"],
        vec!["--confirm", hash.as_str(), "--confirm", hash.as_str()],
        vec!["--confirm", "invalid"],
    ] {
        assert_eq!(direct(&fixture, &flags).status.code(), Some(2));
        let mut pack = vec![
            "pack",
            "remove",
            "--pack",
            "suite",
            "--expected-prior",
            hash.as_str(),
        ];
        pack.extend(flags);
        assert_eq!(run(&fixture, &pack).status.code(), Some(2));
    }
    assert!(!fixture.state_home.exists());
}
