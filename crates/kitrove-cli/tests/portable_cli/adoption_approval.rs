use super::*;

fn fixture(kind: &str) -> (Fixture, PathBuf) {
    let fixture = Fixture::new();
    let (path, text) = match kind {
        "skill" => (
            fixture.home.join("explicit-skills/review/SKILL.md"),
            "---\nname: review\ndescription: Review.\n---\nfirst\n",
        ),
        "command" => (
            fixture.home.join(".claude/commands/review.md"),
            "first $ARGUMENTS\n",
        ),
        "agent" => (
            fixture.home.join(".claude/agents/review.md"),
            "---\nname: review\ndescription: Review.\n---\nfirst\n",
        ),
        "mcp" => (
            fixture.home.join(".claude.json"),
            "{\"mcpServers\":{\"review\":{\"type\":\"http\",\"url\":\"https://first.example.com/mcp\"}}}",
        ),
        "instruction" => (
            fixture.home.join(".claude/CLAUDE.md"),
            "<!-- kitrove:instruction review begin -->\nfirst\n<!-- kitrove:instruction review end -->\n",
        ),
        "extension" => (
            fixture.home.join(".pi/agent/extensions/review.ts"),
            "export const review = 'first';\n",
        ),
        _ => unreachable!(),
    };
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    owned_fixture::create(&path, text.as_bytes());
    fs::write(
        fixture.environment.join("kitrove.toml"),
        EnvironmentManifest::from_toml(EMPTY_MANIFEST)
            .unwrap()
            .to_toml()
            .unwrap(),
    )
    .unwrap();
    let lock = fixture
        .command()
        .args(["lock", "--environment"])
        .arg(&fixture.environment)
        .output()
        .unwrap();
    assert!(lock.status.success(), "{lock:?}");
    (fixture, path)
}

fn observation(fixture: &Fixture, kind: &str) -> String {
    match kind {
        "skill" => fixture.scan_explicit_observation(
            "claude",
            &format!(
                "claude:user:{}",
                fixture.home.join("explicit-skills").display()
            ),
            "review",
        ),
        "command" => fixture.scan_prompt_command_observation("claude", "review"),
        "agent" => fixture.scan_agent_observation("claude", "review"),
        "mcp" => fixture.scan_mcp_observation("claude", "review"),
        "extension" => scan_extension_observation(fixture, "review"),
        "instruction" => {
            let scan = fixture
                .command()
                .args([
                    "scan",
                    "--harness",
                    "claude",
                    "--scope",
                    "user",
                    "--environment",
                ])
                .arg(&fixture.environment)
                .arg("--json")
                .output()
                .unwrap();
            json(&scan)["instructions"][0]["observation_revision"]
                .as_str()
                .unwrap_or_else(|| panic!("{scan:?}"))
                .to_owned()
        }
        _ => unreachable!(),
    }
}

fn run(fixture: &Fixture, kind: &str, observation: &str, flags: &[&str]) -> Output {
    let mut command = fixture.command();
    if kind == "skill" {
        command.arg("adopt").args([
            "--root",
            &format!(
                "claude:user:{}",
                fixture.home.join("explicit-skills").display()
            ),
        ]);
    } else {
        command.arg("adopt");
    }
    command
        .args([observation, "--environment"])
        .arg(&fixture.environment)
        .arg("--json")
        .args([
            "--scope",
            "user",
            "--harness",
            if kind == "extension" { "pi" } else { "claude" },
        ])
        .args(flags)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn authority(fixture: &Fixture) -> [Vec<u8>; 2] {
    ["kitrove.toml", "kitrove.lock.json"].map(|p| fs::read(fixture.environment.join(p)).unwrap())
}

#[test]
fn native_only_skill_fields_require_partial_cross_harness_fidelity() {
    for origin in ["claude", "codex", "pi", "opencode"] {
        let (fixture, source) = fixture("skill");
        let bytes =
            b"---\nname: review\ndescription: Review.\nmodel: FIELD_VALUE_CANARY\n---\nfirst\n";
        fs::write(&source, bytes).unwrap();
        let root = format!(
            "{origin}:user:{}",
            source.parent().unwrap().parent().unwrap().display()
        );
        let observed = fixture.scan_explicit_observation(origin, &root, "review");
        let adopt = |flags: &[&str]| {
            fixture
                .command()
                .args([
                    "adopt",
                    &observed,
                    "--harness",
                    origin,
                    "--scope",
                    "user",
                    "--root",
                    &root,
                    "--environment",
                ])
                .arg(&fixture.environment)
                .arg("--json")
                .args(flags)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        let plan = adopt(&["--plan"]);
        assert!(plan.status.success(), "{origin}: {plan:?}");
        assert!(!String::from_utf8_lossy(&plan.stdout).contains("FIELD_VALUE_CANARY"));
        let adopted = adopt(&["--confirm", json(&plan)["plan_digest"].as_str().unwrap()]);
        assert!(adopted.status.success(), "{origin}: {adopted:?}");
        assert_partial_skill(&fixture, origin, bytes);
        assert_eq!(fs::read(source).unwrap(), bytes);
        assert!(!fixture.state_home.exists());
    }
}

fn assert_partial_skill(fixture: &Fixture, origin: &str, bytes: &[u8]) -> EnvironmentManifest {
    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let id = AssetId::parse("review").unwrap();
    let asset = &manifest.assets[&id];
    for harness in ["claude", "codex", "pi", "opencode"] {
        let fidelity = &asset.compatibility[&HarnessId::parse(harness).unwrap()];
        assert_eq!(
            fidelity.fidelity(),
            if harness == origin {
                kitrove_model::Fidelity::Native
            } else {
                kitrove_model::Fidelity::Partial
            },
            "origin={origin}, target={harness}",
        );
        if harness != origin {
            assert!(!fidelity.reasons().is_empty());
            assert!(!format!("{:?}", fidelity.reasons()).contains("FIELD_VALUE_CANARY"));
        }
    }
    let native = kitrove_core::load_native_skill_object(
        &manifest,
        &id,
        &HarnessId::parse(origin).unwrap(),
        &fixture.environment,
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        native.tree().files[&PortablePath::parse("SKILL.md").unwrap()].bytes,
        bytes
    );
    let portable = kitrove_core::load_portable_skill_object(
        &manifest,
        &id,
        &fixture.environment,
        CaptureLimits::default(),
    )
    .unwrap();
    assert!(
        !String::from_utf8_lossy(
            &portable.tree().files[&PortablePath::parse("SKILL.md").unwrap()].bytes
        )
        .contains("model:")
    );
    assert_eq!(
        fs::read_to_string(fixture.environment.join("kitrove.lock.json")).unwrap(),
        derive_lockfile(&manifest).unwrap().to_json().unwrap()
    );
    manifest
}

#[test]
fn native_only_reverse_update_and_sync_preserve_partial_fidelity_and_prior_bytes() {
    let (machine_a, source) = fixture("skill");
    let original = fs::read(&source).unwrap();
    let observed = observation(&machine_a, "skill");
    let plan = run(&machine_a, "skill", &observed, &["--plan"]);
    assert!(plan.status.success(), "{plan:?}");
    let adopted = run(
        &machine_a,
        "skill",
        &observed,
        &["--confirm", json(&plan)["plan_digest"].as_str().unwrap()],
    );
    assert!(adopted.status.success(), "{adopted:?}");
    machine_a.initialize_local_state_for("fidelity-a");
    let prior = EnvironmentManifest::from_toml(
        &fs::read_to_string(machine_a.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let id = AssetId::parse("review").unwrap();
    let bytes = b"---\nname: review\ndescription: Review.\nmodel: FIELD_VALUE_CANARY\n---\nfirst\n";
    fs::write(&source, bytes).unwrap();
    let observed = observation(&machine_a, "skill");
    let flags = [
        "--update",
        "review",
        "--expected-prior",
        prior.assets[&id].content_hash.as_str(),
    ];
    let mut preview = flags.to_vec();
    preview.push("--plan");
    let plan = run(&machine_a, "skill", &observed, &preview);
    assert!(plan.status.success(), "{plan:?}");
    let value = json(&plan);
    let mut approved = flags.to_vec();
    approved.extend(["--confirm", value["plan_digest"].as_str().unwrap()]);
    let updated = run(&machine_a, "skill", &observed, &approved);
    assert!(updated.status.success(), "{updated:?}");
    let after = assert_partial_skill(&machine_a, "claude", bytes);
    assert_eq!(
        prior.assets[&id].portable.as_ref().unwrap().object_hash,
        after.assets[&id].portable.as_ref().unwrap().object_hash
    );
    assert_ne!(
        prior.assets[&id].native_variants[&HarnessId::Claude].object_hash,
        after.assets[&id].native_variants[&HarnessId::Claude].object_hash
    );
    let retained = kitrove_core::load_native_skill_object(
        &prior,
        &id,
        &HarnessId::Claude,
        &machine_a.environment,
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        retained.tree().files[&PortablePath::parse("SKILL.md").unwrap()].bytes,
        original
    );

    let (machine_b, _) = fixture("skill");
    let remote = tempfile::tempdir().unwrap();
    let remote = fs::canonicalize(remote.path()).unwrap();
    machine_b.initialize_local_state_for("fidelity-b");
    sync_plan_and_apply(&machine_a, &remote, "publish", "native-only update publish");
    sync_plan_and_apply(&machine_b, &remote, "receive", "native-only update receive");
    assert_partial_skill(&machine_a, "claude", bytes);
    assert_partial_skill(&machine_b, "claude", bytes);
}

#[test]
fn every_adoption_and_update_accepts_only_exact_approval_with_closed_stdin() {
    exercise_adoption_and_update(false);
}

#[test]
fn every_member_update_refreshes_nested_authored_packs_under_exact_approval() {
    exercise_adoption_and_update(true);
}

fn exercise_adoption_and_update(with_packs: bool) {
    for kind in [
        "skill",
        "command",
        "agent",
        "mcp",
        "instruction",
        "extension",
    ] {
        let (fixture, source) = fixture(kind);
        let observed = observation(&fixture, kind);
        let before = authority(&fixture);
        let original = fs::read(&source).unwrap();
        let plan = run(&fixture, kind, &observed, &["--plan"]);
        assert!(plan.status.success(), "{kind}: {plan:?}");
        assert!(plan.stderr.is_empty(), "{kind}: {plan:?}");
        assert_eq!(authority(&fixture), before);
        assert!(!fixture.state_home.exists());
        let wrong = run(
            &fixture,
            kind,
            &observed,
            &["--confirm", ContentHash::digest(b"wrong").as_str()],
        );
        assert_eq!(wrong.status.code(), Some(1), "{kind}: {wrong:?}");
        assert_eq!(authority(&fixture), before);
        let adopted = run(
            &fixture,
            kind,
            &observed,
            &["--confirm", json(&plan)["plan_digest"].as_str().unwrap()],
        );
        assert!(adopted.status.success(), "{kind}: {adopted:?}");
        assert!(adopted.stderr.is_empty(), "{kind}: {adopted:?}");
        assert_eq!(fs::read(&source).unwrap(), original);
        assert!(!fixture.state_home.exists());

        if with_packs {
            for (pack, member) in [("inner", "review"), ("outer", "inner")] {
                let args = [
                    "pack",
                    "create",
                    "--authored",
                    "--pack",
                    pack,
                    "--member",
                    member,
                ];
                let plan = fixture
                    .command()
                    .args(args)
                    .args(["--environment"])
                    .arg(&fixture.environment)
                    .args(["--plan", "--json"])
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                assert!(plan.status.success(), "{kind}: {plan:?}");
                let created = fixture
                    .command()
                    .args(args)
                    .args(["--environment"])
                    .arg(&fixture.environment)
                    .args([
                        "--confirm",
                        json(&plan)["digest"].as_str().unwrap(),
                        "--json",
                    ])
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                assert!(created.status.success(), "{kind}: {created:?}");
            }
        }

        fixture.initialize_local_state();
        if kind == "instruction" {
            // Adoption preserves an unmanaged source; it does not claim it.
            // Establish a receipt before exercising managed-modified update.
            fs::write(&source, "Human-owned preface.\n").unwrap();
            let applied = fixture.confirmed_apply(&["--asset", "review", "--target", "claude"]);
            assert!(applied.status.success(), "{applied:?}");
        }
        let local_before = fs::read(fixture.state_home.join("state.json")).unwrap();
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
        )
        .unwrap();
        let prior = manifest.assets[&AssetId::parse("review").unwrap()]
            .content_hash
            .to_string();
        fs::write(
            &source,
            fs::read_to_string(&source)
                .unwrap()
                .replace("first", "second"),
        )
        .unwrap();
        let observed = observation(&fixture, kind);
        let before = authority(&fixture);
        let flags = ["--update", "review", "--expected-prior", &prior];
        let mut preview = flags.to_vec();
        preview.push("--plan");
        let plan = run(&fixture, kind, &observed, &preview);
        assert!(plan.status.success(), "{kind}: {plan:?}");
        assert_eq!(authority(&fixture), before);
        assert_eq!(
            fs::read(fixture.state_home.join("state.json")).unwrap(),
            local_before
        );
        let value = json(&plan);
        let mut approved = flags.to_vec();
        approved.extend(["--confirm", value["plan_digest"].as_str().unwrap()]);
        let result = run(&fixture, kind, &observed, &approved);
        assert!(result.status.success(), "{kind}: {result:?}");
        assert!(result.stderr.is_empty());
        assert_ne!(authority(&fixture), before);
        if with_packs {
            let updated = EnvironmentManifest::from_toml(
                &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
            )
            .unwrap();
            for (pack, member) in [("inner", "review"), ("outer", "inner")] {
                let pack = AssetId::parse(pack).unwrap();
                let member = AssetId::parse(member).unwrap();
                assert_ne!(
                    updated.packs[&pack].content_hash,
                    manifest.packs[&pack].content_hash
                );
                assert_eq!(updated.packs[&pack].source, manifest.packs[&pack].source);
                let expected = updated
                    .assets
                    .get(&member)
                    .map(|asset| &asset.content_hash)
                    .unwrap_or_else(|| &updated.packs[&member].content_hash);
                assert_eq!(&updated.packs[&pack].members[&member], expected);
            }
            assert_eq!(
                fs::read_to_string(fixture.environment.join("kitrove.lock.json")).unwrap(),
                kitrove_core::derive_lockfile(&updated)
                    .unwrap()
                    .to_json()
                    .unwrap()
            );
        }
        let local_after = fs::read(fixture.state_home.join("state.json")).unwrap();
        if kind == "instruction" {
            assert_ne!(local_after, local_before);
            assert!(
                fs::read_to_string(&source)
                    .unwrap()
                    .contains("Human-owned preface.")
            );
        } else {
            assert_eq!(local_after, local_before);
        }
    }
}

#[test]
fn approval_does_not_make_unmanaged_standard_root_skills_update_eligible() {
    let (fixture, explicit_source) = fixture("skill");
    let source = fixture.home.join(".claude/skills/review/SKILL.md");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::copy(explicit_source, &source).unwrap();
    let observed = fixture.scan_observation("claude", "review");
    let plan = run(&fixture, "standard-skill", &observed, &["--plan"]);
    assert!(plan.status.success(), "{plan:?}");
    let adopted = run(
        &fixture,
        "standard-skill",
        &observed,
        &["--confirm", json(&plan)["plan_digest"].as_str().unwrap()],
    );
    assert!(adopted.status.success(), "{adopted:?}");
    fixture.initialize_local_state();
    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let prior = manifest.assets[&AssetId::parse("review").unwrap()]
        .content_hash
        .to_string();
    fs::write(
        &source,
        "---\nname: review\ndescription: Review.\n---\nsecond\n",
    )
    .unwrap();
    let observed = fixture.scan_observation("claude", "review");
    let before = authority(&fixture);
    let source_before = fs::read(&source).unwrap();
    let state_before = fs::read(fixture.state_home.join("state.json")).unwrap();
    let digest = ContentHash::digest(b"approval-does-not-grant-ownership");
    for approval in [vec!["--plan"], vec!["--confirm", digest.as_str()]] {
        let mut flags = vec!["--update", "review", "--expected-prior", &prior];
        flags.extend(approval);
        let refused = run(&fixture, "standard-skill", &observed, &flags);
        assert_eq!(refused.status.code(), Some(1), "{refused:?}");
        assert!(
            stderr(&refused).contains("update_source.not_eligible"),
            "{refused:?}"
        );
        assert_eq!(authority(&fixture), before);
        assert_eq!(fs::read(&source).unwrap(), source_before);
        assert_eq!(
            fs::read(fixture.state_home.join("state.json")).unwrap(),
            state_before
        );
    }
}

#[test]
fn stale_source_and_pending_journal_refuse_approval_without_recovery() {
    for kind in ["skill", "extension"] {
        for pending in [false, true] {
            let (fixture, source) = fixture(kind);
            let observed = observation(&fixture, kind);
            let plan = run(&fixture, kind, &observed, &["--plan"]);
            assert!(plan.status.success(), "{plan:?}");
            let journal = fixture.environment.join(".kitrove/adoption-journal.json");
            if pending {
                owned_fixture::create(&journal, b"PENDING CANARY");
                assert_eq!(
                    run(&fixture, kind, &observed, &["--plan"]).status.code(),
                    Some(1)
                );
            } else {
                let text = fs::read_to_string(&source)
                    .unwrap()
                    .replace("first", "changed");
                fs::write(&source, text).unwrap();
            }
            let before = authority(&fixture);
            let result = run(
                &fixture,
                kind,
                &observed,
                &["--confirm", json(&plan)["plan_digest"].as_str().unwrap()],
            );
            assert_eq!(result.status.code(), Some(1), "{result:?}");
            assert_eq!(authority(&fixture), before);
            assert!(!fixture.state_home.exists());
            if pending {
                assert_eq!(fs::read(journal).unwrap(), b"PENDING CANARY");
            }
        }
    }
}

#[test]
fn adoption_approval_flags_are_strict() {
    let fixture = Fixture::new();
    let hash = ContentHash::digest(b"approval");
    for flags in [
        vec!["--plan", "--plan"],
        vec!["--plan", "--confirm", hash.as_str()],
        vec!["--confirm", hash.as_str(), "--plan"],
        vec!["--confirm", hash.as_str(), "--confirm", hash.as_str()],
        vec!["--confirm", "invalid"],
    ] {
        assert_eq!(
            run(&fixture, "skill", "review", &flags).status.code(),
            Some(2)
        );
    }
    assert!(!fixture.state_home.exists());
}
