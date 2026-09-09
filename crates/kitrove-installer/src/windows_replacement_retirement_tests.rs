use super::*;
use crate::installation_history::replacement::synchronization;
use crate::installation_history::synchronization::HistorySyncBoundary;
use crate::upgrade_transaction::windows_retirement::Boundary;

pub(super) fn exercise_retirement() {
    for committed in [false, true] {
        for cut in [
            Boundary::HistoryReady,
            Boundary::BeforeMove,
            Boundary::Moved,
            Boundary::Sync(HistorySyncBoundary::Inspected),
            Boundary::Sync(HistorySyncBoundary::FilesSynced),
            Boundary::Sync(HistorySyncBoundary::OperationSynced),
            Boundary::Sync(HistorySyncBoundary::HistorySynced),
            Boundary::Sync(HistorySyncBoundary::SourceSynced),
        ] {
            let direction = ReplacementDirection::Upgrade;
            let (fixture, selected, operation) =
                history_tests::terminal_fixture(direction, committed);
            let before = crate::windows_test_support::snapshot_tree(&operation);
            let archived = fixture
                .destination
                .path()
                .join(crate::INSTALLER_HISTORY_DIRECTORY)
                .join(&selected);
            let mut reached = false;
            let result = history_tests::retire(&fixture, direction, |point| {
                assert!(
                    kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                        .unwrap()
                        .try_lock_shared()
                        .is_err()
                );
                assert!(fs::write(fixture.installed(), b"must remain protected").is_err());
                if point == cut {
                    reached = true;
                    return Err(InstallerStageError::RecoveryRequired);
                }
                Ok(())
            });
            assert!(reached);
            assert_eq!(result.unwrap_err(), InstallerStageError::RecoveryRequired);
            assert_ne!(operation.exists(), archived.exists());
            let retained = if archived.exists() {
                &archived
            } else {
                &operation
            };
            assert_eq!(crate::windows_test_support::snapshot_tree(retained), before);
            if operation.exists() {
                history_tests::retire(&fixture, direction, |_| Ok(())).unwrap();
            } else {
                synchronization::synchronize_test_archive(
                    std::slice::from_ref(&fixture.state),
                    || history_tests::open(&fixture, &selected, direction),
                    |_| Ok(()),
                )
                .unwrap();
            }
            assert!(!operation.exists());
            assert_eq!(
                crate::windows_test_support::snapshot_tree(&archived),
                before
            );
        }
    }
    for alteration in 0..3 {
        let after_move = alteration != 0;
        let direction = ReplacementDirection::Rollback;
        let (fixture, selected, operation) = history_tests::terminal_fixture(direction, true);
        let archived = fixture
            .destination
            .path()
            .join(crate::INSTALLER_HISTORY_DIRECTORY)
            .join(&selected);
        let mut after_change = None;
        let result = history_tests::retire(&fixture, direction, |point| {
            if point
                == if after_move {
                    Boundary::Moved
                } else {
                    Boundary::BeforeMove
                }
            {
                if alteration == 2 {
                    let record = archived.join(crate::staging_policy::OPERATION_RECORD);
                    let bytes = fs::read(&record).unwrap();
                    fs::rename(&record, fixture.destination.path().join("preserved-record"))
                        .unwrap();
                    let destination = kitrove_windows_security::validate_install_directory(
                        fixture.destination.path(),
                    )
                    .unwrap();
                    let history = kitrove_windows_security::open_private_directory(
                        destination.directory().unwrap(),
                        OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY),
                    )
                    .unwrap();
                    let operation = kitrove_windows_security::open_private_directory(
                        &history,
                        OsStr::new(&selected),
                    )
                    .unwrap();
                    crate::staging_policy::create_private_data_leaf(
                        &operation,
                        crate::staging_policy::OPERATION_RECORD,
                        bytes,
                    )
                    .unwrap();
                } else if after_move {
                    fs::write(archived.join("unknown-evidence"), b"preserve").unwrap();
                } else {
                    fs::create_dir(&archived).unwrap();
                }
                after_change = Some(crate::windows_test_support::snapshot_tree(
                    fixture.destination.path(),
                ));
            }
            Ok(())
        });
        assert_eq!(result.unwrap_err(), InstallerStageError::RecoveryRequired);
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            after_change.unwrap()
        );
        assert_eq!(operation.exists(), !after_move);
    }
    for stop in [0, 1, 2, 3, 4, 5, 6, 7] {
        let direction = ReplacementDirection::Upgrade;
        let fixture = Fixture::new(direction);
        prepare_stop(&fixture, direction, stop);
        let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
        assert!(
            history_tests::retire(&fixture, direction, |_| panic!(
                "nonterminal operation reached archival mutation"
            ))
            .is_err()
        );
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            before
        );
    }
}
