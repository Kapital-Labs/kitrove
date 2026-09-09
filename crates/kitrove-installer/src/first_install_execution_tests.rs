use super::*;
use crate::test_support::{EMPTY_STATE, initialized_state, private_tempdir, upgrade_releases};
use std::fs;

#[test]
fn unknown_inventory_during_journal_creation_preserves_empty_pending_marker() {
    let destination = private_tempdir();
    let (_parent, state) = initialized_state(EMPTY_STATE);
    let (executable, _) = upgrade_releases();
    let prepared =
        PreparedInstallation::prepare(destination.path(), &executable, &[state]).unwrap();
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
                    if point
                        == ExecutionBoundary::PhaseWrite(
                            InstallPhase::Replaced,
                            unix_install::PhaseWriteBoundary::Created,
                        )
                    {
                        fs::write(operation.join("foreign"), b"unmanaged").unwrap();
                    }
                    Ok(())
                }
            )
            .is_err()
    );
    assert_eq!(fs::read(operation.join("foreign")).unwrap(), b"unmanaged");
    assert_eq!(
        fs::read(operation.join(InstallPhase::Replaced.pending_file_name())).unwrap(),
        b""
    );
    assert!(!operation.join(InstallPhase::Replaced.file_name()).exists());
}

#[test]
fn state_changes_inside_phase_writes_stop_at_the_observed_boundary() {
    use unix_install::PhaseWriteBoundary;
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
            let expected = kitrove_model::ContentHash::digest(executable.bytes());
            assert!(
                prepared
                    .install_with(
                        |_, _| Ok(expected),
                        |observed| {
                            if observed == ExecutionBoundary::PhaseWrite(phase, point) {
                                fs::write(state.join("state.json"), b"late journal writer")
                                    .unwrap();
                            }
                            Ok(())
                        }
                    )
                    .is_err()
            );
            let published = matches!(
                point,
                PhaseWriteBoundary::Published | PhaseWriteBoundary::DirectorySynced
            );
            assert_eq!(operation.join(phase.file_name()).exists(), published);
            assert_eq!(
                operation.join(phase.pending_file_name()).exists(),
                !published
            );
            assert_eq!(
                fs::read(state.join("state.json")).unwrap(),
                b"late journal writer"
            );
            assert_eq!(
                fs::read(
                    destination
                        .path()
                        .join(executable.subject().spec().executable_name())
                )
                .unwrap(),
                executable.bytes()
            );
            let authority = kitrove_state_lifecycle::StateAuthority::open_existing(&state).unwrap();
            assert!(authority.try_lock_exclusive().is_ok());
        }
    }
}

#[test]
fn changed_record_and_unknown_inventory_never_gain_a_phase_record() {
    for change in ["record", "inventory"] {
        let destination = private_tempdir();
        let (_parent, state) = initialized_state(EMPTY_STATE);
        let (executable, _) = upgrade_releases();
        let prepared =
            PreparedInstallation::prepare(destination.path(), &executable, &[state]).unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        let expected = kitrove_model::ContentHash::digest(executable.bytes());
        let path = operation.join(if change == "record" {
            INSTALL_STATE_RECORD
        } else {
            "foreign"
        });
        assert!(
            prepared
                .install_with(
                    |_, _| Ok(expected),
                    |observed| {
                        if observed == ExecutionBoundary::Published {
                            fs::write(&path, b"foreign evidence").unwrap();
                        }
                        Ok(())
                    }
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"foreign evidence");
        assert!(!operation.join(InstallPhase::Replaced.file_name()).exists());
        assert!(
            !operation
                .join(InstallPhase::Replaced.pending_file_name())
                .exists()
        );
    }
}

#[test]
fn guarded_install_commits_exact_bytes_while_holding_selected_state() {
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
    let expected = kitrove_model::ContentHash::digest(executable.bytes());
    let installed = prepared
        .install_with(
            |path, _| {
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                assert_eq!(fs::read(path).unwrap(), executable.bytes());
                Ok(expected)
            },
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(fs::read(installed.path()).unwrap(), executable.bytes());
    assert!(
        operation
            .join(crate::install_phase::COMMITTED_RECORD)
            .exists()
    );
    assert!(operation.join(INSTALL_STATE_RECORD).exists());
    let authority = kitrove_state_lifecycle::StateAuthority::open_existing(&state).unwrap();
    assert!(authority.try_lock_exclusive().is_ok());
}

#[test]
fn guarded_failed_probe_restores_absence_without_discarding_evidence() {
    let destination = private_tempdir();
    let (_parent, state) = initialized_state(EMPTY_STATE);
    let (executable, _) = upgrade_releases();
    let prepared =
        PreparedInstallation::prepare(destination.path(), &executable, &[state]).unwrap();
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
    assert!(
        !destination
            .path()
            .join(executable.subject().spec().executable_name())
            .exists()
    );
    assert_eq!(
        fs::read(operation.join(crate::install_phase::FAILED_EXECUTABLE)).unwrap(),
        executable.bytes()
    );
    assert!(
        operation
            .join(crate::install_phase::ROLLED_BACK_RECORD)
            .exists()
    );
    assert!(operation.join(INSTALL_STATE_RECORD).exists());
}

#[test]
fn late_state_writers_block_every_execution_boundary_and_preserve_their_bytes() {
    for stop in [
        ExecutionBoundary::BeforePublication,
        ExecutionBoundary::Published,
        ExecutionBoundary::BeforeProbe,
        ExecutionBoundary::Probed,
        ExecutionBoundary::Verified,
        ExecutionBoundary::Committed,
    ] {
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
        let expected = kitrove_model::ContentHash::digest(executable.bytes());
        assert!(
            prepared
                .install_with(
                    |_, _| Ok(expected),
                    |point| {
                        if point == stop {
                            fs::write(state.join("state.json"), b"late writer").unwrap();
                        }
                        Ok(())
                    }
                )
                .is_err(),
            "accepted {stop:?}"
        );
        assert_eq!(fs::read(state.join("state.json")).unwrap(), b"late writer");
        assert_eq!(
            destination
                .path()
                .join(executable.subject().spec().executable_name())
                .exists(),
            stop != ExecutionBoundary::BeforePublication
        );
        assert_eq!(
            operation
                .join(crate::install_phase::COMMITTED_RECORD)
                .exists(),
            stop == ExecutionBoundary::Committed
        );
    }
}

#[test]
fn changed_state_after_failed_probe_does_not_authorize_rollback() {
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
    assert!(
        prepared
            .install_with(
                |_, _| {
                    fs::write(state.join("state.json"), b"late writer").unwrap();
                    Err(InstallerStageError::VerificationFailed)
                },
                |_| Ok(())
            )
            .is_err()
    );
    assert!(
        destination
            .path()
            .join(executable.subject().spec().executable_name())
            .exists()
    );
    assert!(
        !operation
            .join(crate::install_phase::ROLLED_BACK_RECORD)
            .exists()
    );
    assert!(
        !operation
            .join(crate::install_phase::FAILED_EXECUTABLE)
            .exists()
    );
}
