use super::*;
use crate::test_support::{
    EMPTY_STATE, TestDestination, initialized_state, private_tempdir, upgrade_releases,
};
use kitrove_state_lifecycle::StateAuthority;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

struct Fixture {
    destination: TestDestination,
    executable: AuthenticatedApplicationExecutable,
    _state_parent: TestDestination,
    state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let (executable, _) = upgrade_releases();
        let (parent, state) = initialized_state(EMPTY_STATE);
        Self {
            destination: private_tempdir(),
            executable,
            _state_parent: parent,
            state,
        }
    }

    fn prepare(&self) -> Result<PreparedInstallation, InstallerStageError> {
        PreparedInstallation::prepare(
            self.destination.path(),
            &self.executable,
            std::slice::from_ref(&self.state),
        )
    }

    fn installed(&self) -> PathBuf {
        self.destination
            .path()
            .join(self.executable.subject().spec().executable_name())
    }

    fn operation(&self, prepared: &PreparedInstallation) -> PathBuf {
        self.destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id())
    }
}

#[test]
fn preparation_retains_guards_and_durable_exact_state_without_installing() {
    let fixture = Fixture::new();
    let mut prepared = fixture.prepare().unwrap();
    prepared.revalidate().unwrap();
    assert!(!fixture.installed().exists());
    let operation = fixture.operation(&prepared);
    let bytes = fs::read(operation.join(INSTALL_STATE_RECORD)).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["state_roots"].as_array().unwrap().len(), 1);
    assert_eq!(
        value["candidate_record_sha256"],
        crate::record::encode_hex(&Sha256::digest(prepared.staged.record.to_json().unwrap()))
    );
    assert_eq!(
        fs::metadata(operation.join(INSTALL_STATE_RECORD))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        fs::read(operation.join("application")).unwrap(),
        fixture.executable.bytes()
    );
    let authority = StateAuthority::open_existing(&fixture.state).unwrap();
    assert!(authority.try_lock_shared().is_err());
    assert_eq!(fixture.prepare().err(), Some(InstallerStageError::Conflict));
    assert!(!format!("{prepared:?}").contains(&fixture.state.display().to_string()));
    drop(prepared);
    let _guard = authority.try_lock_exclusive().unwrap();
    assert_eq!(
        fs::read(operation.join(INSTALL_STATE_RECORD)).unwrap(),
        bytes
    );
}

#[test]
fn preparation_refuses_bad_state_or_an_occupied_destination_before_staging() {
    for change in ["state", "occupied", "locked"] {
        let fixture = Fixture::new();
        let authority = StateAuthority::open_existing(&fixture.state).unwrap();
        let _guard = if change == "locked" {
            Some(authority.try_lock_shared().unwrap())
        } else {
            None
        };
        if change == "state" {
            fs::write(fixture.state.join("state.json"), b"invalid").unwrap();
        }
        if change == "occupied" {
            fs::write(fixture.installed(), b"unmanaged").unwrap();
        }
        assert!(fixture.prepare().is_err());
        assert!(
            !fixture
                .destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .exists()
        );
        if change == "occupied" {
            assert_eq!(fs::read(fixture.installed()).unwrap(), b"unmanaged");
        }
    }
}

#[test]
fn preparation_interruptions_preserve_partial_evidence_and_release_guards() {
    for stop in [
        PreparationBoundary::StatesLocked,
        PreparationBoundary::Staged,
        PreparationBoundary::StateRecorded,
    ] {
        let fixture = Fixture::new();
        assert!(
            PreparedInstallation::prepare_with_hook(
                fixture.destination.path(),
                &fixture.executable,
                std::slice::from_ref(&fixture.state),
                |point| if point == stop {
                    Err(InstallerStageError::RecoveryRequired)
                } else {
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(!fixture.installed().exists());
        assert_eq!(
            fixture
                .destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .exists(),
            stop != PreparationBoundary::StatesLocked
        );
        let authority = StateAuthority::open_existing(&fixture.state).unwrap();
        let _guard = authority.try_lock_exclusive().unwrap();
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            EMPTY_STATE
        );
    }
}

#[test]
fn preparation_refuses_late_writers_without_repairing_or_installing() {
    for change in ["state", "record", "identity", "target"] {
        let fixture = Fixture::new();
        let mut prepared = fixture.prepare().unwrap();
        let operation = fixture.operation(&prepared);
        let path = match change {
            "state" => fixture.state.join("state.json"),
            "target" => fixture.installed(),
            _ => operation.join(INSTALL_STATE_RECORD),
        };
        let bytes = if change == "identity" {
            fs::read(&path).unwrap()
        } else {
            b"late writer".to_vec()
        };
        if change == "identity" {
            fs::rename(
                &path,
                fixture.destination.path().join("retained-state-record"),
            )
            .unwrap();
        }
        fs::write(&path, &bytes).unwrap();
        if change == "identity" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(prepared.revalidate().is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        if change != "target" {
            assert!(!fixture.installed().exists());
        }
    }
}

#[test]
fn fresh_state_record_reopening_requires_exact_roots_and_candidate_operation() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    let operation_path = fixture.operation(&prepared);
    let record = prepared.staged.record.clone();
    drop(prepared);
    let operation =
        cap_std::fs::Dir::open_ambient_dir(&operation_path, cap_std::ambient_authority()).unwrap();
    let mut states = InspectedStateRoots::capture(std::slice::from_ref(&fixture.state)).unwrap();
    let evidence = RetainedInstallState::reopen(&operation, &record, &mut states).unwrap();
    evidence
        .revalidate(&operation, &record, &mut states)
        .unwrap();
    let mut omitted = InspectedStateRoots::capture(&[]).unwrap();
    assert!(RetainedInstallState::reopen(&operation, &record, &mut omitted).is_err());
    let other = Fixture::new();
    let other_prepared = other.prepare().unwrap();
    assert!(
        RetainedInstallState::reopen(&operation, &other_prepared.staged.record, &mut states)
            .is_err()
    );
    drop(states);
    let (_extra_parent, extra_root) = initialized_state(EMPTY_STATE);
    let mut extra = InspectedStateRoots::capture(&[fixture.state.clone(), extra_root]).unwrap();
    assert!(RetainedInstallState::reopen(&operation, &record, &mut extra).is_err());
    drop(extra);
    fs::write(
        fixture.state.join("state.json"),
        br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#,
    )
    .unwrap();
    let mut changed = InspectedStateRoots::capture(std::slice::from_ref(&fixture.state)).unwrap();
    assert!(RetainedInstallState::reopen(&operation, &record, &mut changed).is_err());
}

#[test]
fn fresh_state_record_reopening_preserves_missing_noncanonical_and_foreign_evidence() {
    for change in [
        "missing",
        "noncanonical",
        "unknown",
        "schema",
        "symlink",
        "mode",
        "oversized",
    ] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let operation_path = fixture.operation(&prepared);
        let record = prepared.staged.record.clone();
        drop(prepared);
        let path = operation_path.join(INSTALL_STATE_RECORD);
        let mut bytes = fs::read(&path).unwrap();
        match change {
            "missing" | "symlink" => {
                let retained = operation_path.join("retained-state-record");
                fs::rename(&path, &retained).unwrap();
                if change == "symlink" {
                    symlink(&retained, &path).unwrap();
                }
            }
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "noncanonical" => {
                bytes.push(b'\n');
                fs::write(&path, &bytes).unwrap();
            }
            "oversized" => {
                bytes = vec![b'x'; MAX_INSTALL_STATE_BYTES + 1];
                fs::write(&path, &bytes).unwrap();
            }
            _ => {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                value[if change == "schema" {
                    "schema"
                } else {
                    "unknown"
                }] = serde_json::json!(99);
                bytes = serde_json::to_vec(&value).unwrap();
                fs::write(&path, &bytes).unwrap();
            }
        }
        let operation =
            cap_std::fs::Dir::open_ambient_dir(&operation_path, cap_std::ambient_authority())
                .unwrap();
        let mut states =
            InspectedStateRoots::capture(std::slice::from_ref(&fixture.state)).unwrap();
        assert!(RetainedInstallState::reopen(&operation, &record, &mut states).is_err());
        if change != "missing" {
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        assert!(!fixture.installed().exists());
    }
}

#[test]
fn explicit_empty_root_selection_still_requires_a_durable_record() {
    let fixture = Fixture::new();
    let prepared =
        PreparedInstallation::prepare(fixture.destination.path(), &fixture.executable, &[])
            .unwrap();
    let operation_path = fixture.operation(&prepared);
    let record = prepared.staged.record.clone();
    drop(prepared);
    let operation =
        cap_std::fs::Dir::open_ambient_dir(&operation_path, cap_std::ambient_authority()).unwrap();
    let mut states = InspectedStateRoots::capture(&[]).unwrap();
    RetainedInstallState::reopen(&operation, &record, &mut states).unwrap();
    fs::rename(
        operation_path.join(INSTALL_STATE_RECORD),
        operation_path.join("retained-state-record"),
    )
    .unwrap();
    assert!(RetainedInstallState::reopen(&operation, &record, &mut states).is_err());
}
