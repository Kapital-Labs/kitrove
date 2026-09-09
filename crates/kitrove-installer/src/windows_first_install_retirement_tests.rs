use super::*;
use crate::installation_history::ArchivedInstallation;
use crate::installation_history::synchronization::{HistorySyncBoundary, synchronize_with};
use crate::installation_state::recovery::{ClosedInstallation, retirement::RetirementBoundary};
use crate::record::history::journal::HistoricalInstallOutcome;

fn inspect(
    fixture: &Fixture,
    operation: &Path,
) -> Result<ArchivedInstallation, InstallerStageError> {
    ArchivedInstallation::open(
        fixture.destination.path(),
        operation.file_name().unwrap().to_str().unwrap(),
        &fixture.executable,
    )
}

fn sync_history(
    fixture: &Fixture,
    operation: &Path,
    boundary: impl FnMut(HistorySyncBoundary) -> Result<(), InstallerStageError>,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    synchronize_with(
        fixture.destination.path(),
        operation.file_name().unwrap().to_str().unwrap(),
        &fixture.executable,
        std::slice::from_ref(&fixture.state),
        boundary,
    )
}

fn terminal(succeeds: bool) -> (Fixture, PathBuf) {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let operation = fixture.operation(&prepared);
    let hash = prepared.staged.executable_content_hash.clone();
    let result = prepared.install_with(
        |_, _| {
            if succeeds {
                Ok(hash)
            } else {
                Err(InstallerStageError::VerificationFailed)
            }
        },
        |_| Ok(()),
    );
    assert_eq!(result.is_ok(), succeeds);
    (fixture, operation)
}

fn history(fixture: &Fixture, operation: &Path) -> PathBuf {
    fixture
        .destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY)
        .join(operation.file_name().unwrap())
}

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_terminal_history_retention() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    for succeeds in [true, false] {
        let (fixture, operation) = terminal(succeeds);
        let before = snapshot(&operation);
        let archived = history(&fixture, &operation);
        // Historical state may differ, but freshly selected roots remain locked.
        kitrove_windows_security::write_current_user_owned_file_for_tests(
            &fixture.state.join("state.json"),
            br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#,
        )
        .unwrap();
        ClosedInstallation::retire_with(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state),
            |_| {
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                Ok(())
            },
        )
        .unwrap();
        assert!(!operation.exists());
        assert_eq!(snapshot(&archived), before);
        if succeeds {
            kitrove_windows_security::write_current_user_owned_file_for_tests(
                &fixture
                    .destination
                    .path()
                    .join(fixture.executable.subject().spec().executable_name()),
                b"a later executable",
            )
            .unwrap();
        }
        let retained = inspect(&fixture, &operation).unwrap();
        assert_eq!(
            retained.outcome().unwrap(),
            if succeeds {
                HistoricalInstallOutcome::Committed
            } else {
                HistoricalInstallOutcome::RolledBack
            }
        );
        assert!(inspect(&fixture, &operation).is_err());
        assert!(std::fs::write(archived.join(INSTALL_STATE_RECORD), b"foreign").is_err());
        assert_eq!(snapshot(&archived), before);
        drop(retained);
        for _ in 0..2 {
            sync_history(&fixture, &operation, |_| {
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                assert!(inspect(&fixture, &operation).is_err());
                Ok(())
            })
            .unwrap();
            assert_eq!(snapshot(&archived), before);
        }
        if !succeeds {
            let next = fixture.prepare();
            assert_ne!(fixture.operation(&next), operation);
            assert_eq!(snapshot(&archived), before);
        }
    }

    for stop in [
        RetirementBoundary::HistoryReady,
        RetirementBoundary::BeforeMove,
        RetirementBoundary::Moved,
        RetirementBoundary::OperationSynced,
        RetirementBoundary::HistorySynced,
        RetirementBoundary::SourceSynced,
        RetirementBoundary::Validated,
    ] {
        let (fixture, operation) = terminal(true);
        let before = snapshot(&operation);
        let archived = history(&fixture, &operation);
        let mut hit = false;
        assert!(
            ClosedInstallation::retire_with(
                fixture.destination.path(),
                &fixture.executable,
                std::slice::from_ref(&fixture.state),
                |point| if point == stop {
                    hit = true;
                    Err(InstallerStageError::RecoveryRequired)
                } else {
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(hit);
        if operation.exists() {
            assert!(!archived.exists());
            assert_eq!(snapshot(&operation), before);
            ClosedInstallation::retire(
                fixture.destination.path(),
                &fixture.executable,
                std::slice::from_ref(&fixture.state),
            )
            .unwrap();
        }
        assert_eq!(snapshot(&archived), before);
    }

    // Completed restoration retains an earlier pending commit without completing it.
    let (fixture, operation) = execution_tests::interrupted(
        ExecutionBoundary::PhaseWrite(InstallPhase::Committed, PhaseWriteBoundary::FileSynced),
        false,
    );
    assert!(
        reopen(&fixture)
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |_| Ok(()),
            )
            .is_err()
    );
    assert!(
        operation
            .join(InstallPhase::Committed.pending_file_name())
            .exists()
    );
    let before = snapshot(&operation);
    ClosedInstallation::retire(
        fixture.destination.path(),
        &fixture.executable,
        std::slice::from_ref(&fixture.state),
    )
    .unwrap();
    assert_eq!(snapshot(&history(&fixture, &operation)), before);
    assert_eq!(
        inspect(&fixture, &operation).unwrap().outcome().unwrap(),
        HistoricalInstallOutcome::RolledBack
    );
    assert_eq!(snapshot(&history(&fixture, &operation)), before);
    sync_history(&fixture, &operation, |_| Ok(())).unwrap();
    assert_eq!(snapshot(&history(&fixture, &operation)), before);

    for stop in [
        HistorySyncBoundary::Inspected,
        HistorySyncBoundary::FilesSynced,
        HistorySyncBoundary::OperationSynced,
        HistorySyncBoundary::HistorySynced,
        HistorySyncBoundary::SourceSynced,
    ] {
        for late_writer in [false, true] {
            let (fixture, operation) = terminal(false);
            ClosedInstallation::retire(
                fixture.destination.path(),
                &fixture.executable,
                std::slice::from_ref(&fixture.state),
            )
            .unwrap();
            let archived = history(&fixture, &operation);
            let before = snapshot(&archived);
            let mut hit = false;
            assert!(
                sync_history(&fixture, &operation, |point| {
                    if point == stop {
                        hit = true;
                        if late_writer {
                            std::fs::write(fixture.state.join("late-writer"), b"preserve").unwrap();
                        } else {
                            return Err(InstallerStageError::RecoveryRequired);
                        }
                    }
                    Ok(())
                })
                .is_err()
            );
            assert!(hit);
            assert_eq!(snapshot(&archived), before);
            if late_writer {
                assert_eq!(
                    std::fs::read(fixture.state.join("late-writer")).unwrap(),
                    b"preserve"
                );
            } else {
                sync_history(&fixture, &operation, |_| Ok(())).unwrap();
                assert_eq!(snapshot(&archived), before);
            }
        }
    }

    // Inspection preserves unknown inventory and altered records, never repairing them.
    for name in ["unknown", INSTALL_STATE_RECORD, "replaced.json"] {
        let (fixture, operation) = terminal(true);
        ClosedInstallation::retire(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state),
        )
        .unwrap();
        let archived = history(&fixture, &operation);
        if name == "unknown" {
            std::fs::write(archived.join(name), b"preserve").unwrap();
        } else {
            kitrove_windows_security::write_current_user_owned_file_for_tests(
                &archived.join(name),
                b"preserve",
            )
            .unwrap();
        }
        let before = snapshot(&archived);
        assert!(inspect(&fixture, &operation).is_err());
        assert_eq!(snapshot(&archived), before);
    }

    // A newly observed state writer stops further work at every flush boundary.
    for stop in [
        RetirementBoundary::BeforeMove,
        RetirementBoundary::OperationSynced,
        RetirementBoundary::HistorySynced,
        RetirementBoundary::SourceSynced,
    ] {
        let (fixture, operation) = terminal(true);
        let before = snapshot(&operation);
        let mut hit = false;
        assert!(
            ClosedInstallation::retire_with(
                fixture.destination.path(),
                &fixture.executable,
                std::slice::from_ref(&fixture.state),
                |point| {
                    if point == stop {
                        hit = true;
                        std::fs::write(fixture.state.join("late-writer"), b"unmanaged").unwrap();
                    }
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(hit);
        let archived = history(&fixture, &operation);
        assert_eq!(
            snapshot(if operation.exists() {
                &operation
            } else {
                &archived
            }),
            before
        );
        assert_eq!(
            std::fs::read(fixture.state.join("late-writer")).unwrap(),
            b"unmanaged"
        );
        assert_ne!(operation.exists(), archived.exists());
    }

    // New staging refuses an invalid history root without replacing its contents.
    let fixture = Fixture::new();
    let invalid_history = fixture
        .destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY);
    std::fs::write(&invalid_history, b"unknown history").unwrap();
    assert!(
        PreparedInstallation::prepare(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state)
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&invalid_history).unwrap(), b"unknown history");

    // A preexisting private history entry must remain untouched.
    let (fixture, operation) = terminal(true);
    let before = snapshot(&operation);
    let archived = history(&fixture, &operation);
    kitrove_windows_security::ensure_private_directory_for_tests(archived.parent().unwrap())
        .unwrap();
    kitrove_windows_security::ensure_private_directory_for_tests(&archived).unwrap();
    assert!(
        ClosedInstallation::retire(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state)
        )
        .is_err()
    );
    assert_eq!(snapshot(&operation), before);
    assert!(snapshot(&archived).is_empty());

    // Closing movable leases never authorizes accepting changed journal bytes.
    let (fixture, operation) = terminal(true);
    let archived = history(&fixture, &operation);
    assert!(
        ClosedInstallation::retire_with(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state),
            |point| {
                if point == RetirementBoundary::BeforeMove {
                    kitrove_windows_security::write_current_user_owned_file_for_tests(
                        &operation.join(INSTALL_STATE_RECORD),
                        b"foreign evidence",
                    )
                    .unwrap();
                }
                Ok(())
            },
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(archived.join(INSTALL_STATE_RECORD)).unwrap(),
        b"foreign evidence"
    );

    // Unfinished installation is never reclassified as history.
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let operation = fixture.operation(&prepared);
    drop(prepared);
    let before = snapshot(&operation);
    assert!(
        ClosedInstallation::retire(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state)
        )
        .is_err()
    );
    assert_eq!(snapshot(&operation), before);
    assert!(
        !fixture
            .destination
            .path()
            .join(crate::INSTALLER_HISTORY_DIRECTORY)
            .exists()
    );
}
