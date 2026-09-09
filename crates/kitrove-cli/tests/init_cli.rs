#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use kitrove_core::derive_lockfile;
use kitrove_model::{EnvironmentManifest, LocalState, Lockfile};
use serde_json::Value;

struct Fixture {
    _temporary: tempfile::TempDir,
    home: PathBuf,
    working: PathBuf,
    environment: PathBuf,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = kitrove_testkit::trusted_tempdir(".kitrove-init-test-");
        let root = fs::canonicalize(temporary.path()).unwrap();
        let home = root.join("home");
        let working = root.join("working");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&working).unwrap();
        Self {
            _temporary: temporary,
            home,
            working,
            environment: root.join("environment"),
            state: root.join("state"),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.working)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state)
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME");
        command
    }
}

#[cfg(unix)]
fn install_probe_canary(fixture: &Fixture, command: &mut Command) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let bin = fixture.home.join("probe-bin");
    fs::create_dir(&bin).unwrap();
    let probe = bin.join("claude");
    fs::write(
        &probe,
        "#!/bin/sh\nprintf called > \"$KITROVE_PROBE_MARKER\"\nprintf '1.0.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = fixture.home.join("probe-marker");
    command
        .env("PATH", bin)
        .env("KITROVE_PROBE_MARKER", &marker);
    marker
}

#[test]
fn init_creates_complete_exact_authority_and_refuses_reinitialization() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .args([
            "init",
            "--machine-id",
            "test-machine",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["operation"], "init");
    assert_eq!(result["machine_id"], "test-machine");
    assert_eq!(result["harnesses_inspected"], 4);

    let manifest_text = fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap();
    let lock_text = fs::read_to_string(fixture.environment.join("kitrove.lock.json")).unwrap();
    let state_text = fs::read_to_string(fixture.state.join("state.json")).unwrap();
    assert!(fixture.state.join(".kitrove/lifecycle.lock").is_file());
    let manifest = EnvironmentManifest::from_toml(&manifest_text).unwrap();
    let lock = Lockfile::from_json(&lock_text).unwrap();
    let state = LocalState::from_json(&state_text).unwrap();
    assert_eq!(lock, derive_lockfile(&manifest).unwrap());
    assert_eq!(state.machine.id.as_str(), "test-machine");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(fixture.state.join("state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let mut second_command = fixture.command();
    #[cfg(unix)]
    let probe_marker = install_probe_canary(&fixture, &mut second_command);
    let second = second_command
        .args([
            "init",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    assert!(stderr(&second).contains("init.already_initialized"));
    #[cfg(unix)]
    assert!(
        !probe_marker.exists(),
        "rejected init invoked a version probe"
    );
    assert_eq!(
        fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
        manifest_text
    );
    assert_eq!(
        fs::read_to_string(fixture.environment.join("kitrove.lock.json")).unwrap(),
        lock_text
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join("state.json")).unwrap(),
        state_text
    );
}

#[test]
fn init_creates_a_bounded_missing_state_suffix() {
    let mut fixture = Fixture::new();
    fixture.state = fixture.home.join("missing/parent/state");

    let output = fixture
        .command()
        .args([
            "init",
            "--machine-id",
            "missing-parent-machine",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(fixture.state.join("state.json").is_file());
    assert!(fixture.state.join(".kitrove/lifecycle.lock").is_file());
}

#[test]
fn rejected_initialization_does_not_create_state() {
    for existing_environment in [false, true] {
        let fixture = Fixture::new();
        let environment = if existing_environment {
            fs::create_dir(&fixture.environment).unwrap();
            fs::write(
                fixture.environment.join("kitrove.toml"),
                "schema_version = 1\n",
            )
            .unwrap();
            fixture.environment.clone()
        } else {
            fixture.state.join("nested-environment")
        };

        let output = fixture
            .command()
            .args(["init", "--environment", environment.to_str().unwrap()])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1));
        assert!(!fixture.state.exists());
    }
}

#[test]
fn init_preserves_and_rejects_unknown_partial_state() {
    let fixture = Fixture::new();
    let (_, guard) =
        kitrove_state_lifecycle::StateAuthority::initialize_absent(&fixture.state).unwrap();
    drop(guard);
    let unknown = fixture.state.join("unexpected-journal");
    fs::write(&unknown, "foreign authority").unwrap();

    let mut command = fixture.command();
    #[cfg(unix)]
    let probe_marker = install_probe_canary(&fixture, &mut command);
    let output = command
        .args([
            "init",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("init.create_failed"));
    assert_eq!(fs::read_to_string(unknown).unwrap(), "foreign authority");
    #[cfg(unix)]
    assert!(
        !probe_marker.exists(),
        "rejected partial state invoked a version probe"
    );
    assert!(!fixture.environment.exists());
    assert!(!fixture.state.join("state.json").exists());
}

#[test]
fn init_resumes_an_exact_lifecycle_only_state_root() {
    let fixture = Fixture::new();
    let (_, guard) =
        kitrove_state_lifecycle::StateAuthority::initialize_absent(&fixture.state).unwrap();
    drop(guard);

    let output = fixture
        .command()
        .args([
            "init",
            "--machine-id",
            "resumed-machine",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.machine.id.as_str(), "resumed-machine");
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
