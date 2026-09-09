use super::*;
use crate::installation_history::synchronization::{
    HistorySyncBoundary, synchronize, synchronize_with,
};

fn boundaries() -> [HistorySyncBoundary; 5] {
    use HistorySyncBoundary::*;
    [
        Inspected,
        FilesSynced,
        OperationSynced,
        HistorySynced,
        SourceSynced,
    ]
}

fn retry(
    fixture: &Fixture,
    boundary: impl FnMut(HistorySyncBoundary) -> Result<(), InstallerStageError>,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    synchronize_with(
        fixture.destination.path(),
        fixture.operation.file_name().unwrap().to_str().unwrap(),
        &fixture.executable,
        std::slice::from_ref(&fixture.state),
        boundary,
    )
}

#[test]
fn history_sync_is_idempotent_and_uses_only_current_selected_roots() {
    for rollback in [false, true] {
        let fixture = completed_history(rollback);
        let before = history_snapshot(&fixture);
        let (_parent, current) = initialized_state(EMPTY_STATE);
        fs::rename(&fixture.state, fixture.state.with_extension("old")).unwrap();
        let installed = fixture
            .destination
            .path()
            .join(fixture.executable.subject().spec().executable_name());
        fs::write(&installed, b"later executable").unwrap();
        for _ in 0..2 {
            let mut seen = Vec::new();
            let outcome = synchronize_with(
                fixture.destination.path(),
                fixture.operation.file_name().unwrap().to_str().unwrap(),
                &fixture.executable,
                std::slice::from_ref(&current),
                |point| {
                    seen.push(point);
                    let authority =
                        kitrove_state_lifecycle::StateAuthority::open_existing(&current).unwrap();
                    assert!(authority.try_lock_shared().is_err());
                    assert!(inspect(&fixture).is_err());
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(seen, boundaries());
            assert_eq!(
                outcome,
                if rollback {
                    HistoricalInstallOutcome::RolledBack
                } else {
                    HistoricalInstallOutcome::Committed
                }
            );
            assert_eq!(history_snapshot(&fixture), before);
            assert_eq!(fs::read(&installed).unwrap(), b"later executable");
            let authority =
                kitrove_state_lifecycle::StateAuthority::open_existing(&current).unwrap();
            let _guard = authority.try_lock_exclusive().unwrap();
        }
    }
}

#[test]
fn history_sync_retries_every_interruption_without_losing_evidence() {
    for rollback in [false, true] {
        for stop in boundaries() {
            let fixture = completed_history(rollback);
            let before = history_snapshot(&fixture);
            let mut hit = false;
            assert!(
                retry(&fixture, |point| {
                    if point == stop {
                        hit = true;
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            assert!(hit);
            assert_eq!(history_snapshot(&fixture), before);
            retry(&fixture, |_| Ok(())).unwrap();
            assert_eq!(history_snapshot(&fixture), before);
        }
    }
}

#[test]
fn history_sync_refuses_late_state_or_archive_changes_at_every_boundary() {
    for archive_change in [false, true] {
        for stop in boundaries() {
            let fixture = completed_history(false);
            let changed = if archive_change {
                archive(&fixture)
            } else {
                fixture.state.clone()
            }
            .join("late-writer");
            let mut hit = false;
            assert!(
                retry(&fixture, |point| {
                    if point == stop {
                        hit = true;
                        fs::write(&changed, b"preserve").unwrap();
                    }
                    Ok(())
                })
                .is_err()
            );
            assert!(hit);
            assert_eq!(fs::read(&changed).unwrap(), b"preserve");
            assert!(
                retry(&fixture, |_| panic!(
                    "invalid evidence reached synchronization"
                ))
                .is_err()
            );
        }
    }
}

#[test]
fn history_sync_preserves_pending_prefixes_and_refuses_bad_preflight() {
    let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
        InstallPhase::Committed,
        unix_install::PhaseWriteBoundary::FileSynced,
    ));
    let pending = fixture
        .operation
        .join(InstallPhase::Committed.pending_file_name());
    fs::write(&pending, b"").unwrap();
    assert!(
        fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |_| Ok(())
            )
            .is_err()
    );
    retire(&fixture).unwrap();
    let before = history_snapshot(&fixture);
    retry(&fixture, |_| Ok(())).unwrap();
    assert_eq!(history_snapshot(&fixture), before);
    let selected = fixture.operation.file_name().unwrap().to_str().unwrap();
    assert!(
        synchronize(
            fixture.destination.path(),
            selected,
            &fixture.executable,
            &[fixture.state.clone(), fixture.state.clone()]
        )
        .is_err()
    );
    let retained = inspect(&fixture).unwrap();
    assert!(
        retry(&fixture, |_| panic!(
            "locked history reached synchronization"
        ))
        .is_err()
    );
    drop(retained);
    assert_eq!(history_snapshot(&fixture), before);
}
