use super::*;
use crate::test_support::{
    EMPTY_STATE, initialized_state, private_tempdir, upgrade_releases_with_bytes,
};
use kitrove_release_provenance::AuthenticatedRecoveryMaterial;
use std::fs;

struct Fixture {
    destination: tempfile::TempDir,
    _state_parent: tempfile::TempDir,
    state: PathBuf,
    material: AuthenticatedRecoveryMaterial,
}

impl Fixture {
    fn new(succeeds: bool) -> Self {
        let script = if succeeds {
            b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n".as_slice()
        } else {
            b"#!/bin/sh\nexit 1\n".as_slice()
        };
        let (_, material) = upgrade_releases_with_bytes(script, b"unused candidate");
        let (parent, state) = initialized_state(EMPTY_STATE);
        Self {
            destination: private_tempdir(),
            _state_parent: parent,
            state,
            material,
        }
    }

    fn request(&self, command: &str, operation: Option<&str>) -> Box<Request> {
        let mut args = arguments(command);
        let destination = args.iter().position(|arg| arg == "--destination").unwrap();
        args[destination + 1] = self.destination.path().as_os_str().to_owned();
        if command != "history-status" {
            args.extend([
                OsString::from("--state-root"),
                self.state.as_os_str().to_owned(),
            ]);
        }
        if let Some(operation) = operation {
            args.extend(["--operation", operation].map(OsString::from));
        }
        let Parsed::Request(request) = parse(args).unwrap() else {
            panic!("not a request")
        };
        request
    }

    fn execute(&self, command: &str, operation: Option<&str>) -> Result<String, String> {
        // Fixture provenance enters after production authentication; no public bypass exists.
        execute(&self.request(command, operation), &self.material)
    }

    fn installed(&self) -> PathBuf {
        self.destination.path().join(
            self.material
                .executable()
                .subject()
                .spec()
                .executable_name(),
        )
    }

    fn snapshot(
        &self,
    ) -> (
        kitrove_testkit::FilesystemSnapshot,
        kitrove_testkit::FilesystemSnapshot,
    ) {
        (
            kitrove_testkit::FilesystemSnapshot::capture(self.destination.path()).unwrap(),
            kitrove_testkit::FilesystemSnapshot::capture(&self.state).unwrap(),
        )
    }

    fn operation(&self) -> String {
        fs::read_dir(
            self.destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY),
        )
        .unwrap()
        .map(Result::unwrap)
        .find(|entry| entry.file_type().unwrap().is_dir())
        .unwrap()
        .file_name()
        .into_string()
        .unwrap()
    }
}

#[test]
fn command_workflow_installs_recovers_and_inspects_retained_history() {
    let fixture = Fixture::new(true);
    let before = fixture.snapshot();
    assert!(
        fixture
            .execute("preflight-install", None)
            .unwrap()
            .contains("without mutation")
    );
    assert_eq!(fixture.snapshot(), before);
    let installed = fixture.execute("install", None).unwrap();
    let operation = fixture.operation();
    assert!(installed.ends_with(&operation));
    assert_eq!(
        fs::read(fixture.installed()).unwrap(),
        fixture.material.executable().bytes()
    );
    assert!(
        fixture
            .execute("recover-install", None)
            .unwrap()
            .ends_with(&operation)
    );
    fixture.execute("retire-install", None).unwrap();
    fs::write(fixture.installed(), b"later executable").unwrap();
    let before = fixture.snapshot();
    for command in ["history-status", "history-sync", "history-sync"] {
        assert!(
            fixture
                .execute(command, Some(&operation))
                .unwrap()
                .contains("Committed")
        );
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn command_workflow_failed_probe_preserves_restoration_and_history() {
    let fixture = Fixture::new(false);
    assert!(fixture.execute("install", None).is_err());
    assert!(!fixture.installed().exists());
    let operation = fixture.operation();
    assert!(fixture.execute("recover-install", None).is_err());
    assert!(!fixture.installed().exists());
    fixture.execute("retire-install", None).unwrap();
    let before = fixture.snapshot();
    for command in ["history-status", "history-sync"] {
        assert!(
            fixture
                .execute(command, Some(&operation))
                .unwrap()
                .contains("RolledBack")
        );
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn command_preflight_refuses_occupied_invalid_busy_and_unfinished_state_without_mutation() {
    for change in ["occupied", "invalid", "busy", "unfinished"] {
        let fixture = Fixture::new(true);
        let authority =
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
        let guard = if change == "busy" {
            Some(authority.try_lock_shared().unwrap())
        } else {
            None
        };
        match change {
            "occupied" => fs::write(fixture.installed(), b"unmanaged executable").unwrap(),
            "invalid" => fs::write(fixture.state.join("state.json"), b"invalid").unwrap(),
            "unfinished" => {
                drop(
                    PreparedInstallation::prepare(
                        fixture.destination.path(),
                        fixture.material.executable(),
                        std::slice::from_ref(&fixture.state),
                    )
                    .unwrap(),
                );
            }
            "busy" => {}
            _ => unreachable!(),
        }
        let before = fixture.snapshot();
        assert!(
            fixture.execute("preflight-install", None).is_err(),
            "accepted {change}"
        );
        assert_eq!(fixture.snapshot(), before);
        drop(guard);
    }
}
