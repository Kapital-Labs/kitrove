use super::*;
use crate::installation_state::recovery::{RecoveryBoundary, ReopenedInstallation};
use crate::test_support::{
    EMPTY_STATE, TestDestination, initialized_state, private_tempdir, upgrade_releases,
};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

#[cfg(test)]
#[path = "first_install_state_retirement_tests.rs"]
mod retirement_tests;

#[test]
fn recovery_appends_pending_prefixes_without_replacing_their_file_identity() {
    use std::os::unix::fs::MetadataExt as _;
    for size in [0, 1, 2, 3] {
        let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
            InstallPhase::Verified,
            unix_install::PhaseWriteBoundary::FileSynced,
        ));
        let pending = fixture
            .operation
            .join(InstallPhase::Verified.pending_file_name());
        let canonical = fs::read(&pending).unwrap();
        let length = match size {
            0 => 0,
            1 => 1,
            2 => canonical.len() / 2,
            _ => canonical.len(),
        };
        fs::write(&pending, &canonical[..length]).unwrap();
        let identity = fs::metadata(&pending).unwrap().ino();
        let expected = kitrove_model::ContentHash::digest(fixture.executable.bytes());
        fixture
            .reopen()
            .unwrap()
            .recover_with(|_, _| Ok(expected), |_| Ok(()))
            .unwrap();
        let published = fixture.operation.join(InstallPhase::Verified.file_name());
        assert_eq!(fs::metadata(&published).unwrap().ino(), identity);
        assert_eq!(fs::read(&published).unwrap(), canonical);
        assert!(!pending.exists());
    }
}

#[test]
fn state_writers_at_recovery_journal_boundaries_stop_further_progress() {
    for phase in [
        InstallPhase::Replaced,
        InstallPhase::Verified,
        InstallPhase::Committed,
    ] {
        for stop in [
            RecoveryBoundary::PhaseCreated(phase),
            RecoveryBoundary::PhaseCompleted(phase),
            RecoveryBoundary::PhasePublished(phase),
        ] {
            let fixture = Fixture::interrupted(ExecutionBoundary::Published);
            let expected = kitrove_model::ContentHash::digest(fixture.executable.bytes());
            let mut reached = false;
            assert!(
                fixture
                    .reopen()
                    .unwrap()
                    .recover_with(
                        |_, _| Ok(expected),
                        |point| {
                            if point == stop {
                                reached = true;
                                fs::write(fixture.state.join("state.json"), b"late state writer")
                                    .unwrap();
                            }
                            Ok(())
                        }
                    )
                    .is_err()
            );
            assert!(reached);
            let published = matches!(stop, RecoveryBoundary::PhasePublished(_));
            assert_eq!(
                fixture.operation.join(phase.file_name()).exists(),
                published
            );
            assert_eq!(
                fixture.operation.join(phase.pending_file_name()).exists(),
                !published
            );
            assert_eq!(
                fs::read(fixture.state.join("state.json")).unwrap(),
                b"late state writer"
            );
        }
    }
}

#[test]
fn substituted_release_and_completed_phase_evidence_are_read_only_refusals() {
    let fixture = Fixture::interrupted(ExecutionBoundary::BeforeProbe);
    let before = fixture.snapshot();
    let (_, other_release) = upgrade_releases();
    assert!(
        ReopenedInstallation::reopen(
            fixture.destination.path(),
            other_release.executable(),
            std::slice::from_ref(&fixture.state)
        )
        .is_err()
    );
    assert_eq!(fixture.snapshot(), before);
    fs::write(
        fixture.operation.join(InstallPhase::Replaced.file_name()),
        b"foreign completed phase",
    )
    .unwrap();
    let changed = fixture.snapshot();
    assert!(fixture.reopen().is_err());
    assert_eq!(fixture.snapshot(), changed);
}

#[test]
fn a_reopened_owner_refuses_later_state_changes_without_reconciling_pending_bytes() {
    let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
        InstallPhase::Verified,
        unix_install::PhaseWriteBoundary::Created,
    ));
    let before = fixture.snapshot();
    let mut reopened = fixture.reopen().unwrap();
    fs::write(fixture.state.join("state.json"), b"late state writer").unwrap();
    assert!(reopened.revalidate().is_err());
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        b"late state writer"
    );
}

struct Fixture {
    destination: TestDestination,
    _state_parent: TestDestination,
    state: PathBuf,
    executable: AuthenticatedApplicationExecutable,
    operation: PathBuf,
}

impl Fixture {
    fn interrupted(stop: ExecutionBoundary) -> Self {
        let destination = private_tempdir();
        let (parent, state) = initialized_state(EMPTY_STATE);
        let (executable, _) = upgrade_releases();
        let prepared = PreparedInstallation::prepare(
            destination.path(),
            &executable,
            std::slice::from_ref(&state),
        )
        .unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        let expected = kitrove_model::ContentHash::digest(executable.bytes());
        assert!(
            prepared
                .install_with(
                    |_, _| Ok(expected),
                    |point| {
                        if point == stop {
                            Err(InstallerStageError::RecoveryRequired)
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        Self {
            destination,
            _state_parent: parent,
            state,
            executable,
            operation,
        }
    }

    fn reopen(&self) -> Result<ReopenedInstallation, InstallerStageError> {
        ReopenedInstallation::reopen(
            self.destination.path(),
            &self.executable,
            std::slice::from_ref(&self.state),
        )
    }

    fn snapshot(&self) -> Vec<(std::ffi::OsString, Vec<u8>)> {
        let mut files = fs::read_dir(&self.operation)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    }
}

fn execution_boundaries() -> Vec<ExecutionBoundary> {
    use unix_install::PhaseWriteBoundary;
    let mut boundaries = vec![
        ExecutionBoundary::BeforePublication,
        ExecutionBoundary::Published,
        ExecutionBoundary::BeforeProbe,
        ExecutionBoundary::Probed,
        ExecutionBoundary::Verified,
        ExecutionBoundary::Committed,
    ];
    for phase in [
        InstallPhase::Replaced,
        InstallPhase::Verified,
        InstallPhase::Committed,
    ] {
        for point in [
            PhaseWriteBoundary::Created,
            PhaseWriteBoundary::FileSynced,
            PhaseWriteBoundary::Published,
            PhaseWriteBoundary::DirectorySynced,
        ] {
            boundaries.push(ExecutionBoundary::PhaseWrite(phase, point));
        }
    }
    boundaries
}

#[test]
fn fresh_reopening_is_read_only_at_every_execution_and_journal_boundary() {
    for stop in execution_boundaries() {
        let fixture = Fixture::interrupted(stop);
        let before = fixture.snapshot();
        let mut reopened = fixture
            .reopen()
            .unwrap_or_else(|error| panic!("{stop:?}: {error:?}"));
        reopened.revalidate().unwrap();
        assert_eq!(fixture.snapshot(), before);
        let authority =
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
        assert!(authority.try_lock_shared().is_err());
        drop(reopened);
        assert!(authority.try_lock_exclusive().is_ok());
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn recovery_commits_after_every_first_install_interruption_and_always_probes() {
    for stop in execution_boundaries() {
        let fixture = Fixture::interrupted(stop);
        let expected = kitrove_model::ContentHash::digest(fixture.executable.bytes());
        let mut probed = false;
        let installed = fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| {
                    probed = true;
                    Ok(expected)
                },
                |_| Ok(()),
            )
            .unwrap_or_else(|error| panic!("{stop:?}: {error:?}"));
        assert!(probed);
        assert_eq!(
            fs::read(installed.path()).unwrap(),
            fixture.executable.bytes()
        );
        assert!(
            fixture
                .operation
                .join(InstallPhase::Committed.file_name())
                .exists()
        );
        for &phase in InstallPhase::all() {
            assert!(!fixture.operation.join(phase.pending_file_name()).exists());
        }
    }
}

#[test]
fn failed_fresh_probe_preserves_earlier_complete_and_pending_journal_evidence() {
    for stop in [
        ExecutionBoundary::BeforeProbe,
        ExecutionBoundary::PhaseWrite(
            InstallPhase::Verified,
            unix_install::PhaseWriteBoundary::FileSynced,
        ),
        ExecutionBoundary::PhaseWrite(
            InstallPhase::Committed,
            unix_install::PhaseWriteBoundary::FileSynced,
        ),
        ExecutionBoundary::Committed,
    ] {
        let fixture = Fixture::interrupted(stop);
        let before = fixture.snapshot();
        assert_eq!(
            fixture
                .reopen()
                .unwrap()
                .recover_with(
                    |_, _| Err(InstallerStageError::VerificationFailed),
                    |_| Ok(())
                )
                .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        for (name, bytes) in before {
            assert_eq!(fs::read(fixture.operation.join(name)).unwrap(), bytes);
        }
        assert!(
            !fixture
                .destination
                .path()
                .join(fixture.executable.subject().spec().executable_name())
                .exists()
        );
        assert_eq!(
            fs::read(
                fixture
                    .operation
                    .join(crate::install_phase::FAILED_EXECUTABLE)
            )
            .unwrap(),
            fixture.executable.bytes()
        );
        let terminal = fixture.snapshot();
        assert_eq!(
            fixture
                .reopen()
                .unwrap()
                .recover_with(|_, _| panic!("restored layout was probed"), |_| Ok(()))
                .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert_eq!(fixture.snapshot(), terminal);
    }
}

#[test]
fn recovery_survives_a_second_interruption_at_every_forward_journal_boundary() {
    let mut stops = vec![RecoveryBoundary::Synced, RecoveryBoundary::Probed];
    for phase in [
        InstallPhase::Replaced,
        InstallPhase::Verified,
        InstallPhase::Committed,
    ] {
        stops.extend([
            RecoveryBoundary::PhaseCreated(phase),
            RecoveryBoundary::PhaseCompleted(phase),
            RecoveryBoundary::PhasePublished(phase),
        ]);
    }
    for stop in stops {
        let fixture = Fixture::interrupted(ExecutionBoundary::Published);
        let expected = kitrove_model::ContentHash::digest(fixture.executable.bytes());
        let mut reached = false;
        assert!(
            fixture
                .reopen()
                .unwrap()
                .recover_with(
                    |_, _| Ok(expected.clone()),
                    |point| {
                        if point == stop {
                            reached = true;
                            Err(InstallerStageError::RecoveryRequired)
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        assert!(reached, "missed {stop:?}");
        let installed = fixture
            .reopen()
            .unwrap()
            .recover_with(|_, _| Ok(expected), |_| Ok(()))
            .unwrap_or_else(|error| panic!("{stop:?}: {error:?}"));
        assert_eq!(
            fs::read(installed.path()).unwrap(),
            fixture.executable.bytes()
        );
    }
}

#[test]
fn interrupted_recovery_rollback_retains_forward_pending_and_commit_history() {
    for initial in [
        ExecutionBoundary::PhaseWrite(
            InstallPhase::Committed,
            unix_install::PhaseWriteBoundary::FileSynced,
        ),
        ExecutionBoundary::Committed,
    ] {
        for stop in [
            RecoveryBoundary::Restored,
            RecoveryBoundary::Synced,
            RecoveryBoundary::PhaseCreated(InstallPhase::RolledBack),
            RecoveryBoundary::PhaseCompleted(InstallPhase::RolledBack),
            RecoveryBoundary::PhasePublished(InstallPhase::RolledBack),
        ] {
            let fixture = Fixture::interrupted(initial);
            let before = fixture.snapshot();
            let mut reached = false;
            let mut restored = false;
            assert!(
                fixture
                    .reopen()
                    .unwrap()
                    .recover_with(
                        |_, _| Err(InstallerStageError::VerificationFailed),
                        |point| {
                            restored |= point == RecoveryBoundary::Restored;
                            if point == stop && restored {
                                reached = true;
                                Err(InstallerStageError::RecoveryRequired)
                            } else {
                                Ok(())
                            }
                        }
                    )
                    .is_err()
            );
            assert!(reached, "missed {initial:?}/{stop:?}");
            assert_eq!(
                fixture
                    .reopen()
                    .unwrap()
                    .recover_with(|_, _| panic!("rollback reinstalled candidate"), |_| Ok(()))
                    .unwrap_err(),
                InstallerStageError::VerificationFailed
            );
            for (name, bytes) in before {
                assert_eq!(fs::read(fixture.operation.join(name)).unwrap(), bytes);
            }
            assert!(
                !fixture
                    .destination
                    .path()
                    .join(fixture.executable.subject().spec().executable_name())
                    .exists()
            );
        }
    }
}

#[test]
fn recovery_refuses_late_state_changes_before_any_new_phase_or_rollback() {
    let fixture = Fixture::interrupted(ExecutionBoundary::BeforeProbe);
    let before = fixture.snapshot();
    assert!(
        fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |point| {
                    if point == RecoveryBoundary::Probed {
                        fs::write(fixture.state.join("state.json"), b"late state writer").unwrap();
                    }
                    Ok(())
                }
            )
            .is_err()
    );
    assert_eq!(fixture.snapshot(), before);
    assert!(
        fixture
            .destination
            .path()
            .join(fixture.executable.subject().spec().executable_name())
            .exists()
    );
}

#[test]
fn wrong_roots_changed_state_and_foreign_pending_bytes_are_never_reconciled() {
    for change in ["omitted", "state", "pending", "phase", "record"] {
        let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
            InstallPhase::Verified,
            unix_install::PhaseWriteBoundary::FileSynced,
        ));
        match change {
            "state" => fs::write(
                fixture.state.join("state.json"),
                br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#,
            )
            .unwrap(),
            "pending" => fs::write(
                fixture
                    .operation
                    .join(InstallPhase::Verified.pending_file_name()),
                b"foreign",
            )
            .unwrap(),
            "phase" => fs::rename(
                fixture
                    .operation
                    .join(InstallPhase::Verified.pending_file_name()),
                fixture
                    .operation
                    .join(InstallPhase::Committed.pending_file_name()),
            )
            .unwrap(),
            "record" => fs::write(
                fixture.operation.join(INSTALL_STATE_RECORD),
                b"foreign state evidence",
            )
            .unwrap(),
            _ => {}
        }
        let before = fixture.snapshot();
        let result = if change == "omitted" {
            ReopenedInstallation::reopen(fixture.destination.path(), &fixture.executable, &[])
        } else {
            fixture.reopen()
        };
        assert!(result.is_err(), "accepted {change}");
        assert_eq!(fixture.snapshot(), before);
    }
}

#[test]
fn partial_canonical_pending_prefixes_are_retained_and_identity_bound() {
    let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
        InstallPhase::Verified,
        unix_install::PhaseWriteBoundary::FileSynced,
    ));
    let pending = fixture
        .operation
        .join(InstallPhase::Verified.pending_file_name());
    let canonical = fs::read(&pending).unwrap();
    for length in [0, 1, canonical.len() / 2, canonical.len()] {
        fs::write(&pending, &canonical[..length]).unwrap();
        let before = fixture.snapshot();
        let mut reopened = fixture.reopen().unwrap();
        reopened.revalidate().unwrap();
        assert_eq!(fixture.snapshot(), before);
    }
    let mut reopened = fixture.reopen().unwrap();
    fs::rename(
        &pending,
        fixture.destination.path().join("retained-pending"),
    )
    .unwrap();
    fs::write(&pending, &canonical).unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(reopened.revalidate().is_err());
    assert_eq!(fs::read(&pending).unwrap(), canonical);
}

#[test]
fn failed_install_layouts_reopen_without_changing_either_executable_name() {
    for layout in ["rolled-back", "rolling-back", "handoff"] {
        let destination = private_tempdir();
        let (_parent, state) = initialized_state(EMPTY_STATE);
        let (executable, _) = upgrade_releases();
        let prepared = PreparedInstallation::prepare(
            destination.path(),
            &executable,
            std::slice::from_ref(&state),
        )
        .unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        assert_eq!(
            prepared
                .install_with(
                    |_, _| Err(InstallerStageError::VerificationFailed),
                    |_| Ok(())
                )
                .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        if layout != "rolled-back" {
            fs::rename(
                operation.join(InstallPhase::RolledBack.file_name()),
                destination.path().join("retained-marker"),
            )
            .unwrap();
        }
        let installed = destination
            .path()
            .join(executable.subject().spec().executable_name());
        if layout == "handoff" {
            fs::hard_link(
                operation.join(crate::install_phase::FAILED_EXECUTABLE),
                &installed,
            )
            .unwrap();
        }
        let mut reopened = ReopenedInstallation::reopen(
            destination.path(),
            &executable,
            std::slice::from_ref(&state),
        )
        .unwrap();
        reopened.revalidate().unwrap();
        assert_eq!(installed.exists(), layout == "handoff");
        assert_eq!(
            fs::read(operation.join(crate::install_phase::FAILED_EXECUTABLE)).unwrap(),
            executable.bytes()
        );
        let result = reopened.recover_with(
            |_, _| panic!("restored layout was executed"),
            |point| {
                if point == RecoveryBoundary::HandoffRemoved {
                    Err(InstallerStageError::RecoveryRequired)
                } else {
                    Ok(())
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(
            ReopenedInstallation::reopen(
                destination.path(),
                &executable,
                std::slice::from_ref(&state)
            )
            .unwrap()
            .recover_with(
                |_, _| panic!("second rollback recovery executed candidate"),
                |_| Ok(())
            )
            .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert!(!installed.exists());
    }
}
