use super::*;
use crate::upgrade_transaction::windows_pair::{Layout, RETAINED_PRIOR, WindowsPair};
use crate::upgrade_transaction::windows_recovery_plan::{JournalStage, RecoveryStep};

/// Invoked by the existing dedicated standard-user case; never skipped as elevated.
pub(super) fn exercise_owned_pair_moves() {
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        for stop in 0..=4 {
            let fixture = Fixture::new(direction);
            let prepared = fixture.prepare(direction).unwrap();
            let operation = fixture
                .destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .join(prepared.staged.record.operation_id());
            let mut pair = WindowsPair::new(prepared).unwrap();
            for layout in [
                Layout::Gap,
                Layout::Published,
                Layout::Gap,
                Layout::Original,
            ]
            .into_iter()
            .take(stop)
            {
                let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
                assert!(
                    pair.move_with_hook(layout, &[], || Err(InstallerStageError::RecoveryRequired))
                        .is_err()
                );
                assert_eq!(
                    crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                    before
                );
                pair.move_to(layout, &[]).unwrap();
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
            }
            let journal = match stop {
                0 => JournalStage::Prepared,
                1 => JournalStage::PriorRetained,
                2 => JournalStage::Published,
                _ => JournalStage::RestoreRequested,
            };
            let expected = match stop {
                0 => RecoveryStep::Prepared,
                1 => RecoveryStep::RecordRestorationIntent,
                2 => RecoveryStep::ProbeCandidate,
                3 => RecoveryStep::RestorePrior,
                _ => RecoveryStep::CompleteRestoration,
            };
            assert_eq!(pair.recovery_step(journal, &[]).unwrap(), expected);
            drop(pair);
            let candidate = if stop == 2 {
                fixture.installed()
            } else {
                operation.join(crate::staging_policy::STAGED_EXECUTABLE)
            };
            let prior = if stop == 0 || stop == 4 {
                fixture.installed()
            } else {
                operation.join(RETAINED_PRIOR)
            };
            assert_eq!(fs::read(candidate).unwrap(), fixture.candidate.bytes());
            assert_eq!(
                fs::read(prior).unwrap(),
                fixture.material.executable().bytes()
            );
            if stop == 1 || stop == 3 {
                assert!(!fixture.installed().exists());
            }
            assert_eq!(
                fs::read(operation.join("rollback-kit/archive")).unwrap(),
                fixture.material.archive_bytes()
            );
            let authority =
                kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
            assert!(authority.try_lock_exclusive().is_ok());
        }
    }
    // Each move's target can be created after the last complete pair inspection.
    for movement in 0..4 {
        let fixture = Fixture::new(ReplacementDirection::Upgrade);
        let prepared = fixture.prepare(ReplacementDirection::Upgrade).unwrap();
        let operation = fixture
            .destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        let mut pair = WindowsPair::new(prepared).unwrap();
        let moves = [
            Layout::Gap,
            Layout::Published,
            Layout::Gap,
            Layout::Original,
        ];
        for &layout in moves.iter().take(movement) {
            pair.move_to(layout, &[]).unwrap();
        }
        let occupied = match movement {
            0 => operation.join(RETAINED_PRIOR),
            2 => operation.join(crate::staging_policy::STAGED_EXECUTABLE),
            _ => fixture.installed(),
        };
        let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
        assert!(
            pair.move_with_hook(moves[movement], &[], || {
                fs::write(&occupied, b"competing file").unwrap();
                Ok(())
            })
            .is_err()
        );
        drop(pair);
        assert_eq!(fs::read(&occupied).unwrap(), b"competing file");
        // Remove only the test-created competitor to compare the original evidence.
        fs::remove_file(&occupied).unwrap();
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            before
        );
    }
}
