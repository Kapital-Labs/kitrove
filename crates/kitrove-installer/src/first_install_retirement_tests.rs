use super::*;
use crate::test_support::{EMPTY_STATE, initialized_state, private_tempdir, staging_input};
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

const EXECUTABLE: &[u8] = b"first installation";

fn completed(succeeds: bool) -> (tempfile::TempDir, PathBuf) {
    let destination = private_tempdir();
    let staged =
        crate::unix_staging::stage(destination.path(), &staging_input(EXECUTABLE)).unwrap();
    let operation = destination
        .path()
        .join(crate::INSTALLER_STATE_DIRECTORY)
        .join(staged.record.operation_id());
    let result = super::super::install_impl(staged, |_, _| {
        if succeeds {
            Ok(kitrove_model::ContentHash::digest(EXECUTABLE))
        } else {
            Err(InstallerStageError::VerificationFailed)
        }
    });
    assert_eq!(result.is_ok(), succeeds);
    (destination, operation)
}

fn archived(destination: &Path, operation: &Path) -> PathBuf {
    destination
        .join(crate::INSTALLER_HISTORY_DIRECTORY)
        .join(operation.file_name().unwrap())
}

#[test]
fn terminal_first_install_preserves_every_record_and_executable() {
    for succeeds in [true, false] {
        let (destination, operation) = completed(succeeds);
        let before = fs::read_dir(&operation)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        let (_state_parent, state) = initialized_state(EMPTY_STATE);
        retire_with(
            destination.path(),
            &staging_input(EXECUTABLE),
            &[state],
            |_| Ok(()),
        )
        .unwrap();
        assert!(!operation.exists());
        let history = archived(destination.path(), &operation);
        assert_eq!(fs::read_dir(&history).unwrap().count(), before.len());
        for (name, bytes) in before {
            assert_eq!(fs::read(history.join(name)).unwrap(), bytes);
        }
        let installed = destination
            .path()
            .join(staging_input(EXECUTABLE).executable_name);
        assert_eq!(installed.exists(), succeeds);
        if succeeds {
            assert_eq!(fs::read(installed).unwrap(), EXECUTABLE);
        } else {
            crate::unix_staging::stage(destination.path(), &staging_input(EXECUTABLE)).unwrap();
        }
    }
}

#[test]
fn every_first_install_retirement_boundary_preserves_recoverable_history() {
    use RetirementBoundary::*;
    for point in [HistoryReady, BeforeMove, Moved, HistorySynced, SourceSynced] {
        let (destination, operation) = completed(false);
        assert!(
            retire_with(
                destination.path(),
                &staging_input(EXECUTABLE),
                &[],
                |seen| {
                    if seen == point {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        let history = archived(destination.path(), &operation);
        let moved = matches!(point, Moved | HistorySynced | SourceSynced);
        assert_eq!(operation.exists(), !moved);
        assert_eq!(history.exists(), moved);
        let retained = if moved { &history } else { &operation };
        assert!(retained.join("rolled-back.json").is_file());
        if !moved {
            retire_with(destination.path(), &staging_input(EXECUTABLE), &[], |_| {
                Ok(())
            })
            .unwrap();
        }
        crate::unix_staging::stage(destination.path(), &staging_input(EXECUTABLE)).unwrap();
    }
}

#[test]
fn pending_first_install_evidence_is_preserved_without_reconciliation() {
    let (destination, operation) = completed(true);
    let pending = operation.join("committed.pending");
    fs::write(&pending, b"retained-prefix").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        retire_with(
            destination.path(),
            &staging_input(EXECUTABLE),
            &[],
            |_| panic!("pending evidence")
        )
        .is_err()
    );
    assert_eq!(fs::read(&pending).unwrap(), b"retained-prefix");
    assert!(operation.join("committed.json").is_file());
    assert!(
        !destination
            .path()
            .join(crate::INSTALLER_HISTORY_DIRECTORY)
            .exists()
    );
}

#[test]
fn nonterminal_and_wrong_release_cannot_retire_first_install() {
    let destination = private_tempdir();
    let staged =
        crate::unix_staging::stage(destination.path(), &staging_input(EXECUTABLE)).unwrap();
    drop(staged);
    assert!(
        retire_with(
            destination.path(),
            &staging_input(EXECUTABLE),
            &[],
            |_| panic!("not terminal")
        )
        .is_err()
    );
    let (destination, operation) = completed(true);
    assert!(
        retire_with(
            destination.path(),
            &staging_input(b"different executable"),
            &[],
            |_| panic!("wrong release")
        )
        .is_err()
    );
    assert!(operation.is_dir());
}

#[test]
fn late_changes_are_preserved_and_block_first_install_retirement() {
    for change in ["record", "staged", "installed", "state", "parent"] {
        let (destination, operation) = completed(true);
        let (_state_parent, state) = initialized_state(EMPTY_STATE);
        assert!(
            retire_with(
                destination.path(),
                &staging_input(EXECUTABLE),
                std::slice::from_ref(&state),
                |point| {
                    if point == RetirementBoundary::BeforeMove {
                        let path = match change {
                            "record" => operation.join("committed.json"),
                            "staged" => operation.join("application"),
                            "installed" => destination
                                .path()
                                .join(staging_input(EXECUTABLE).executable_name),
                            "state" => state.join("unexpected"),
                            "parent" => {
                                let history =
                                    destination.path().join(crate::INSTALLER_HISTORY_DIRECTORY);
                                fs::rename(&history, destination.path().join("preserved-history"))
                                    .unwrap();
                                fs::create_dir(&history).unwrap();
                                fs::set_permissions(&history, fs::Permissions::from_mode(0o700))
                                    .unwrap();
                                return Ok(());
                            }
                            _ => unreachable!(),
                        };
                        fs::write(path, b"preserved edit").unwrap();
                    }
                    Ok(())
                }
            )
            .is_err(),
            "{change}"
        );
        assert!(operation.is_dir());
    }
}

#[cfg(debug_assertions)]
#[test]
fn authenticated_first_install_can_advance_to_its_first_upgrade() {
    for (script, succeeds) in [
        (b"#!/bin/sh\nprintf 'kitrove 1.2.4\\n'\n".as_slice(), true),
        (b"#!/bin/sh\nprintf 'kitrove 9.9.9\\n'\n".as_slice(), false),
    ] {
        let (candidate, recovery) = crate::test_support::upgrade_releases_with_bytes(
            b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n",
            script,
        );
        let destination = private_tempdir();
        let old = recovery.executable();
        let staged =
            crate::unix_staging::stage(destination.path(), &StagingInput::from(old)).unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record.operation_id());
        super::super::install(staged).unwrap();
        let (_state_parent, state) = initialized_state(EMPTY_STATE);
        StagedApplication::retire_completed_install(
            destination.path(),
            old,
            std::slice::from_ref(&state),
        )
        .unwrap();
        let result = crate::upgrade_transaction::PreparedReplacement::prepare(
            destination.path(),
            &candidate,
            &recovery,
            &[state],
        )
        .unwrap()
        .install();
        assert_eq!(result.is_ok(), succeeds);
        assert_eq!(
            fs::read(
                destination
                    .path()
                    .join(old.subject().spec().executable_name())
            )
            .unwrap(),
            if succeeds {
                candidate.bytes()
            } else {
                old.bytes()
            }
        );
        assert!(
            archived(destination.path(), &operation)
                .join("committed.json")
                .is_file()
        );
    }
}
