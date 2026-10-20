#![forbid(unsafe_code)]

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

struct Fixture {
    root: tempfile::TempDir,
    home: PathBuf,
    environment: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = kitrove_testkit::trusted_tempdir(".kitrove-approval-cli-");
        let canonical_root = fs::canonicalize(root.path()).unwrap();
        let home = canonical_root.join("home");
        let environment = canonical_root.join("collection");
        let state = canonical_root.join("state");
        fs::create_dir(&home).unwrap();
        let fixture = Self {
            root,
            home,
            environment,
            state,
        };
        let init = fixture.run(&[
            "init",
            "--machine-id",
            "approval-fixture",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ]);
        assert!(init.status.success(), "{init:?}");
        let source = fixture.home.join(".claude/skills/review");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("SKILL.md"),
            "---\nname: review\ndescription: Synthetic approval fixture.\n---\nReview carefully.\n",
        )
        .unwrap();
        let mut child = fixture
            .command()
            .args([
                "adopt",
                "review",
                "--harness",
                "claude",
                "--scope",
                "user",
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(self.root.path())
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_ENV", &self.environment)
            .env("KITROVE_STATE_HOME", &self.state)
            .env_remove("XDG_DATA_HOME")
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn plan(&self) -> Value {
        let output = self.run(&["plan", "--asset", "review", "--target", "codex", "--json"]);
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn apply(&self, digest: &str) -> Output {
        self.run(&[
            "apply",
            "--asset",
            "review",
            "--target",
            "codex",
            "--confirm",
            digest,
            "--json",
        ])
    }
}

#[test]
fn exact_batch_approval_works_with_closed_stdin_and_rejects_item_digest() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let prior_state = fs::read(fixture.state.join("state.json")).unwrap();
    let wrong = fixture.apply(plan["plan_digest"].as_str().unwrap());
    assert_eq!(wrong.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("apply.plan_stale"));
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        prior_state
    );
    assert!(!fixture.home.join(".agents/skills/review").exists());
    let applied = fixture.apply(plan["batch_digest"].as_str().unwrap());
    assert!(applied.status.success(), "{applied:?}");
    assert!(applied.stderr.is_empty());
    assert!(
        fixture
            .home
            .join(".agents/skills/review/SKILL.md")
            .is_file()
    );
    let stale = fixture.apply(plan["batch_digest"].as_str().unwrap());
    assert_eq!(stale.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("apply.plan_stale"));
    let fresh = fixture.plan();
    assert!(
        fixture
            .apply(fresh["batch_digest"].as_str().unwrap())
            .status
            .success()
    );
}

#[test]
fn confirmation_syntax_is_strict_and_plan_cannot_accept_approval() {
    let fixture = Fixture::new();
    let digest = format!("blake3:{}", "a".repeat(64));
    for args in [
        vec!["apply", "--confirm"],
        vec!["apply", "--confirm", "bad"],
        vec!["apply", "--confirm", &digest, "--confirm", &digest],
        vec!["plan", "--confirm", &digest],
    ] {
        assert_eq!(fixture.run(&args).status.code(), Some(2));
    }
    let no_approval = fixture.run(&["apply", "--asset", "review", "--target", "codex"]);
    assert_eq!(no_approval.status.code(), Some(1));
    assert!(!fixture.home.join(".agents/skills/review").exists());
}

#[test]
fn stale_approval_cannot_overwrite_new_unmanaged_content() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let target = fixture.home.join(".agents/skills/review");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("SKILL.md"), "UNMANAGED CANARY").unwrap();
    let prior_state = fs::read(fixture.state.join("state.json")).unwrap();
    let output = fixture.apply(plan["batch_digest"].as_str().unwrap());
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        fs::read(target.join("SKILL.md")).unwrap(),
        b"UNMANAGED CANARY"
    );
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        prior_state
    );
}

#[test]
fn invalid_recovery_authority_is_preserved_without_consuming_approval() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let control = fixture.state.join(".kitrove");
    fs::create_dir_all(&control).unwrap();
    let journal = control.join("atomic-apply-journal.json");
    kitrove_testkit::owned_fixture::create(&journal, b"not a recovery journal");
    let prior_state = fs::read(fixture.state.join("state.json")).unwrap();
    let result = fixture.apply(plan["batch_digest"].as_str().unwrap());
    assert_eq!(result.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("Confirm"));
    assert_eq!(fs::read(&journal).unwrap(), b"not a recovery journal");
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        prior_state
    );
    assert!(!fixture.home.join(".agents/skills/review").exists());
}

#[test]
fn approval_cannot_expand_destinations_or_ignore_changed_state() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    let digest = plan["batch_digest"].as_str().unwrap();
    let expanded = fixture.run(&[
        "apply",
        "--asset",
        "review",
        "--target",
        "codex",
        "--target",
        "pi",
        "--confirm",
        digest,
        "--json",
    ]);
    assert_eq!(expanded.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&expanded.stderr).contains("apply.plan_stale"),
        "{expanded:?}"
    );
    assert!(!fixture.home.join(".agents/skills/review").exists());

    // Even semantically identical state with different observed bytes invalidates approval.
    let state_path = fixture.state.join("state.json");
    let mut state = fs::read(&state_path).unwrap();
    state.push(b'\n');
    fs::write(&state_path, &state).unwrap();
    let changed = fixture.apply(digest);
    assert_eq!(changed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&changed.stderr).contains("apply.plan_stale"));
    assert_eq!(fs::read(state_path).unwrap(), state);
    assert!(!fixture.home.join(".agents/skills/review").exists());
}
