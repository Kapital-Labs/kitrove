#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};

use kitrove_cli::tier_one_registry;
use kitrove_model::HarnessId;
use serde_json::Value;
use tempfile::TempDir;

const EMPTY_MANIFEST: &str = "schema_version = 1\n";
#[cfg(unix)]
const EMPTY_LOCAL_STATE: &str = r#"{
  "schema_version": 1,
  "machine": {
    "id": "cli-test",
    "active_profile": null,
    "enabled_targets": [],
    "harness_roots": {}
  },
  "bindings": {},
  "receipts": {},
  "trust": {},
  "scans": []
}
"#;

struct Fixture {
    _root: TempDir,
    root: PathBuf,
    home: PathBuf,
    working: PathBuf,
    state_home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let home = root_path.join("home");
        let working = root_path.join("working");
        let state_home = root_path.join("state-home-absent");
        fs::create_dir_all(home.join(".claude/skills")).unwrap();
        fs::create_dir_all(home.join(".claude/commands")).unwrap();
        fs::create_dir_all(home.join(".pi/agent/skills")).unwrap();
        fs::create_dir_all(home.join(".agents/skills")).unwrap();
        fs::create_dir_all(home.join(".config/opencode/skills")).unwrap();
        fs::create_dir_all(&working).unwrap();
        Self {
            _root: root,
            root: root_path,
            home,
            working,
            state_home,
        }
    }

    fn command(&self) -> ProcessCommand {
        let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.working)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state_home)
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME");
        command
    }

    fn environment(&self, name: &str, contents: &str) -> PathBuf {
        let root = self.root.join(name);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("kitrove.toml"), contents).unwrap();
        root
    }

    fn skill(&self, root: &Path, directory: &str, name: &str) {
        let package = root.join(directory);
        fs::create_dir_all(&package).unwrap();
        fs::write(
            package.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: A deterministic CLI fixture.\n---\n# Skill\n"),
        )
        .unwrap();
    }
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).unwrap()
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).unwrap()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout={}\nstderr={}",
            stdout(output),
            stderr(output)
        )
    })
}

#[test]
fn tier_one_registry_has_exact_stable_order() {
    assert_eq!(
        tier_one_registry().harness_ids(),
        [
            HarnessId::Claude,
            HarnessId::Codex,
            HarnessId::Pi,
            HarnessId::OpenCode,
        ]
    );
}

#[test]
fn repeated_harnesses_collapse_and_clean_inventory_exits_zero() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "claude",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["mode"], "inventory");
    assert_eq!(value["entries"], serde_json::json!([]));
    assert_eq!(
        value["versions"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["claude"]
    );
    assert!(
        !fixture.state_home.exists(),
        "an absent local-state root must not be created"
    );
}

#[test]
fn repeated_typed_roots_retain_order_and_split_only_two_separators() {
    let fixture = Fixture::new();
    let first = fixture.root.join(if cfg!(windows) {
        "first-root"
    } else {
        "first:root:with:colons"
    });
    let second = fixture.root.join("second-root");
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    fixture.skill(&first, "alpha", "alpha");
    fixture.skill(&second, "beta", "beta");
    let first_arg = format!("pi:user:{}", first.display());
    let second_arg = format!("pi:user:{}", second.display());

    let output = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "pi",
            "--scope",
            "user",
            "--root",
            &first_arg,
            "--root",
            &second_arg,
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    let entries = value["entries"].as_array().unwrap();
    assert!(entries.iter().any(|entry| entry["native_id"] == "alpha"));
    assert!(entries.iter().any(|entry| entry["native_id"] == "beta"));
    assert!(entries.iter().all(|entry| entry["harness"] == "pi"));
}

#[test]
fn sibling_explicit_pi_files_are_both_retained_without_an_authority_conflict() {
    let fixture = Fixture::new();
    let parent = fixture.root.join("explicit-files");
    fs::create_dir_all(&parent).unwrap();
    let first = parent.join("first.md");
    let second = parent.join("second.md");
    fs::write(
        &first,
        "---\nname: first\ndescription: First explicit skill.\n---\nInert.\n",
    )
    .unwrap();
    fs::write(
        &second,
        "---\nname: second\ndescription: Second explicit skill.\n---\nInert.\n",
    )
    .unwrap();
    let first_arg = format!("pi:user:{}", first.display());
    let second_arg = format!("pi:user:{}", second.display());

    let output = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "pi",
            "--scope",
            "user",
            "--root",
            &first_arg,
            "--root",
            &second_arg,
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let report = json(&output);
    assert_eq!(
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["native_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert!(!stdout(&output).contains("scan.policy_root_conflict"));
}

#[test]
fn every_cli_selectable_harness_honors_an_exact_explicit_directory_root() {
    for harness in ["claude", "codex", "pi", "opencode"] {
        let fixture = Fixture::new();
        let explicit = fixture.root.join(format!("explicit-{harness}"));
        fs::create_dir_all(&explicit).unwrap();
        fixture.skill(&explicit, "only-explicit", "only-explicit");
        let root_arg = format!("{harness}:user:{}", explicit.display());

        let output = fixture
            .command()
            .args([
                "scan",
                "--harness",
                harness,
                "--scope",
                "user",
                "--root",
                &root_arg,
                "--json",
            ])
            .output()
            .unwrap();

        assert_eq!(
            output.status.code(),
            Some(3),
            "{harness}: {}",
            stderr(&output)
        );
        let value = json(&output);
        assert!(
            value["entries"].as_array().unwrap().iter().any(|entry| {
                entry["harness"] == harness
                    && entry["native_id"] == "only-explicit"
                    && entry["root_tier"] == "explicit"
            }),
            "{harness}: {}",
            stdout(&output)
        );
    }
}

#[test]
fn explicit_environment_outranks_kitrove_env_and_kitrove_env_outranks_discovery() {
    let fixture = Fixture::new();
    let explicit = fixture.environment("explicit-environment", EMPTY_MANIFEST);
    let from_variable = fixture.environment("variable-environment", EMPTY_MANIFEST);
    let discovered = fixture.environment("discovered-environment", "not valid toml = [");
    let nested = discovered.join("nested");
    fs::create_dir_all(&nested).unwrap();

    let output = fixture
        .command()
        .current_dir(&nested)
        .env("KITROVE_ENV", &from_variable)
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--environment",
            explicit.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(json(&output)["mode"], "classified");

    let output = fixture
        .command()
        .current_dir(&nested)
        .env("KITROVE_ENV", &from_variable)
        .args(["scan", "--harness", "claude", "--scope", "user", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(json(&output)["mode"], "classified");
}

#[test]
fn nearest_ancestor_manifest_is_discovered() {
    let fixture = Fixture::new();
    let environment = fixture.environment("ancestor-environment", EMPTY_MANIFEST);
    let nested = environment.join("one/two");
    fs::create_dir_all(&nested).unwrap();

    let output = fixture
        .command()
        .current_dir(&nested)
        .args(["scan", "--harness", "claude", "--scope", "user", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(json(&output)["mode"], "classified");
}

#[test]
fn relative_state_override_is_ignored_in_favor_of_platform_local_state() {
    let fixture = Fixture::new();
    let environment = fixture.environment("state-environment", EMPTY_MANIFEST);
    let relative_state = fixture.working.join("relative-state");
    fs::create_dir_all(&relative_state).unwrap();
    fs::write(relative_state.join("state.json"), "not valid local state").unwrap();

    let output = fixture
        .command()
        .env("KITROVE_STATE_HOME", "relative-state")
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--environment",
            environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(json(&output)["mode"], "classified");
}

#[test]
fn project_root_and_regular_git_file_bound_project_discovery_without_git() {
    let fixture = Fixture::new();
    let repository = fixture.root.join("repository");
    let nested = repository.join("nested/deeper");
    fs::create_dir_all(&nested).unwrap();
    fs::write(repository.join(".git"), "gitdir: elsewhere\n").unwrap();
    fs::create_dir_all(repository.join(".claude/commands")).unwrap();
    fixture.skill(&repository.join(".claude/skills"), "review", "review");

    let discovered = fixture
        .command()
        .current_dir(&nested)
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "project",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(discovered.status.code(), Some(3), "{}", stderr(&discovered));
    assert!(
        json(&discovered)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["native_id"] == "review")
    );

    fs::remove_file(repository.join(".git")).unwrap();
    let explicit = fixture
        .command()
        .current_dir(&nested)
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "project",
            "--project-root",
            repository.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(explicit.status.code(), Some(3), "{}", stderr(&explicit));
    assert!(
        json(&explicit)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["native_id"] == "review")
    );
}

#[cfg(unix)]
#[test]
fn unsafe_inner_git_marker_stops_pi_before_an_outer_repository() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let outer = fixture.root.join("outer");
    let inner = outer.join("inner/deep");
    fs::create_dir_all(outer.join(".git")).unwrap();
    fs::create_dir_all(&inner).unwrap();
    fixture.skill(&outer.join(".agents/skills"), "outer-only", "outer-only");
    symlink(outer.join(".git"), outer.join("inner/.git")).unwrap();

    let output = fixture
        .command()
        .current_dir(&inner)
        .args(["scan", "--harness", "pi", "--scope", "project", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
    let report = json(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["mode"], "inventory");
    let entries = report["entries"].as_array().unwrap();
    assert!(entries.is_empty(), "{}", stdout(&output));
    assert!(
        entries.iter().all(|entry| {
            entry["native_id"] != "outer-only"
                && entry["source_relative_path"] != "outer-only"
                && entry["logical_root"] != "pi.project.compatibility.skills.0002.unknown"
        }),
        "{}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("outer-only"),
        "{}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("pi.project.compatibility.skills.0002"),
        "{}",
        stdout(&output)
    );
    assert!(
        !stdout(&output).contains("\"observation_id\""),
        "{}",
        stdout(&output)
    );
}

#[test]
fn text_and_json_inventory_use_the_same_attention_exit() {
    let fixture = Fixture::new();
    fixture.skill(&fixture.home.join(".claude/skills"), "review", "review");

    let text_output = fixture
        .command()
        .args(["scan", "--harness", "claude", "--scope", "user"])
        .output()
        .unwrap();
    assert_eq!(
        text_output.status.code(),
        Some(3),
        "{}",
        stderr(&text_output)
    );
    assert!(stdout(&text_output).starts_with("kitrove scan v1\nmode inventory\n"));
    assert!(stdout(&text_output).contains("classification=\"unmanaged\""));

    let json_output = fixture
        .command()
        .args(["scan", "--harness", "claude", "--scope", "user", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        json_output.status.code(),
        Some(3),
        "{}",
        stderr(&json_output)
    );
    assert_eq!(
        json(&json_output)["entries"][0]["classification"],
        "unmanaged"
    );
}

#[test]
fn no_home_default_all_scans_project_without_fabricating_user_roots() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.working.join(".opencode/skills"),
        "project-skill",
        "project-skill",
    );
    fixture.skill(
        &fixture.working.join(".config/opencode/skills"),
        "false-home-skill",
        "false-home-skill",
    );

    let output = fixture
        .command()
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .args(["scan", "--harness", "opencode", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    let entries = value["entries"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry["native_id"] == "project-skill")
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry["native_id"] != "false-home-skill")
    );
    assert!(entries.iter().all(|entry| entry["scope"] == "project"));
}

#[test]
fn missing_user_context_is_operational_failure_unless_an_explicit_root_is_usable() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.working.join(".pi/agent/skills"),
        "false-home-skill",
        "false-home-skill",
    );
    let output = fixture
        .command()
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .args(["scan", "--harness", "pi", "--scope", "user"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("scan.context_unavailable"));

    let explicit = fixture.root.join("explicit-root");
    fs::create_dir_all(&explicit).unwrap();
    fixture.skill(&explicit, "review", "review");
    let root_arg = format!("pi:user:{}", explicit.display());
    let output = fixture
        .command()
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .args([
            "scan",
            "--harness",
            "pi",
            "--scope",
            "user",
            "--root",
            &root_arg,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    let entries = value["entries"].as_array().unwrap();
    assert!(entries.iter().any(|entry| entry["native_id"] == "review"));
    assert!(
        entries
            .iter()
            .all(|entry| entry["native_id"] != "false-home-skill")
    );
    assert!(entries.iter().all(|entry| entry["root_tier"] == "explicit"));
}

#[test]
fn no_home_project_scope_scans_only_project_roots() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.working.join(".pi/skills"),
        "project-skill",
        "project-skill",
    );
    fixture.skill(
        &fixture.working.join(".pi/agent/skills"),
        "false-home-skill",
        "false-home-skill",
    );

    let output = fixture
        .command()
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .args(["scan", "--harness", "pi", "--scope", "project", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    let entries = value["entries"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry["native_id"] == "project-skill")
    );
    assert!(
        entries
            .iter()
            .all(|entry| entry["native_id"] != "false-home-skill")
    );
    assert!(entries.iter().all(|entry| entry["scope"] == "project"));
}

#[test]
fn usage_errors_return_two_and_version_probe_flags_do_not_exist() {
    let fixture = Fixture::new();
    for arguments in [
        vec!["scan", "--unknown"],
        vec!["scan", "--harness"],
        vec!["scan", "--scope", "user", "--scope", "project"],
        vec!["scan", "--root", "pi:admin:/tmp"],
        vec!["scan", "--version-probe"],
        vec!["scan", "--verified-version", "pi:1.0"],
    ] {
        let output = fixture.command().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert!(stderr(&output).contains("kitrove scan"));
    }
}

#[cfg(unix)]
#[test]
fn symlinked_manifest_and_state_are_never_followed() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let environment = fixture.root.join("unsafe-environment");
    fs::create_dir_all(&environment).unwrap();
    let manifest_target = fixture.root.join("manifest-target.toml");
    fs::write(&manifest_target, EMPTY_MANIFEST).unwrap();
    symlink(&manifest_target, environment.join("kitrove.toml")).unwrap();

    let output = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--environment",
            environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["mode"], "degraded");
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "scan.environment_invalid")
    );

    let safe_environment = fixture.environment("safe-environment", EMPTY_MANIFEST);
    let state_home = fixture.root.join("unsafe-state-home");
    fs::create_dir_all(&state_home).unwrap();
    let state_target = fixture.root.join("state-target.json");
    fs::write(&state_target, EMPTY_LOCAL_STATE).unwrap();
    symlink(&state_target, state_home.join("state.json")).unwrap();

    let output = fixture
        .command()
        .env("KITROVE_STATE_HOME", &state_home)
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--environment",
            safe_environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["mode"], "degraded");
    assert!(
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "scan.local_state_invalid")
    );
}

#[cfg(unix)]
#[test]
fn unsafe_state_without_manifest_is_reported_as_redacted_attention() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let state_home = fixture.root.join("private-state-home-canary");
    fs::create_dir_all(&state_home).unwrap();
    let state_target = fixture.root.join("private-state-target-canary.json");
    fs::write(&state_target, EMPTY_LOCAL_STATE).unwrap();
    symlink(&state_target, state_home.join("state.json")).unwrap();

    let output = fixture
        .command()
        .env("KITROVE_STATE_HOME", &state_home)
        .args(["scan", "--harness", "claude", "--scope", "user", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["mode"], "inventory");
    assert!(value["findings"].as_array().unwrap().iter().any(|finding| {
        finding["code"] == "scan.local_state_invalid"
            && finding["severity"] == "attention"
            && finding["subject"]["type"] == "report"
    }));
    let rendered = format!("{}{}", stdout(&output), stderr(&output));
    assert!(!rendered.contains(state_home.to_str().unwrap()));
    assert!(!rendered.contains(state_target.to_str().unwrap()));
}

#[cfg(unix)]
#[test]
fn unsafe_state_survives_invalid_manifest_as_redacted_attention() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let environment = fixture.environment("invalid-environment", "not valid toml = [");
    let state_home = fixture.root.join("private-invalid-state-home-canary");
    fs::create_dir_all(&state_home).unwrap();
    let state_target = fixture
        .root
        .join("private-invalid-state-target-canary.json");
    fs::write(&state_target, EMPTY_LOCAL_STATE).unwrap();
    symlink(&state_target, state_home.join("state.json")).unwrap();

    let output = fixture
        .command()
        .env("KITROVE_STATE_HOME", &state_home)
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--environment",
            environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["mode"], "degraded");
    let codes = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["code"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"scan.environment_invalid"));
    assert!(codes.contains(&"scan.local_state_invalid"));
    let rendered = format!("{}{}", stdout(&output), stderr(&output));
    assert!(!rendered.contains(state_home.to_str().unwrap()));
    assert!(!rendered.contains(state_target.to_str().unwrap()));
}

#[test]
fn existing_information_commands_remain_available() {
    let fixture = Fixture::new();
    let version = fixture.command().arg("--version").output().unwrap();
    assert_eq!(version.status.code(), Some(0));
    assert!(stdout(&version).starts_with("kitrove "));

    let help = fixture.command().arg("help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(stdout(&help).contains("scan"));
    assert!(stdout(&help).contains("north-star"));
}
