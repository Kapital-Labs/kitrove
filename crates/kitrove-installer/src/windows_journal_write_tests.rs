use super::*;
use crate::staging_policy::create_private_data_leaf;
use crate::upgrade_transaction::windows_journal::writer::{JournaledPair, WriteBoundary};
use crate::upgrade_transaction::windows_journal_policy as policy;
use crate::upgrade_transaction::windows_pair::{Layout, WindowsPair};
use crate::upgrade_transaction::windows_recovery_plan::JournalStage;

fn before_phase<'a>(pair: WindowsPair<'a>, phase: JournalStage) -> JournaledPair<'a> {
    use JournalStage::*;
    let journal = JournaledPair::from_pair(pair)
        .unwrap()
        .move_to(Layout::Gap)
        .unwrap();
    match phase {
        PriorRetained | RestoreRequested => journal,
        Published => journal
            .record(PriorRetained)
            .unwrap()
            .move_to(Layout::Published)
            .unwrap(),
        RolledBack => journal
            .record(RestoreRequested)
            .unwrap()
            .move_to(Layout::Original)
            .unwrap(),
        _ => panic!("phase is outside placement writer authority"),
    }
}

/// Called by the dedicated native standard-user preparation case, not an elevated skip.
pub(super) fn exercise_journal_writes() {
    use JournalStage::*;
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        let fixture = Fixture::new(direction);
        let pair = WindowsPair::new(fixture.prepare(direction).unwrap()).unwrap();
        let operation = pair.operation().try_clone().unwrap();
        let binding = pair.journal_binding().unwrap();
        let journal = JournaledPair::from_pair(pair)
            .unwrap()
            .move_to(Layout::Gap)
            .unwrap()
            .record(PriorRetained)
            .unwrap()
            .move_to(Layout::Published)
            .unwrap()
            .record(Published)
            .unwrap()
            .record(RestoreRequested)
            .unwrap()
            .move_to(Layout::Gap)
            .unwrap()
            .move_to(Layout::Original)
            .unwrap()
            .record(RolledBack)
            .unwrap();
        assert!(
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                .unwrap()
                .try_lock_shared()
                .is_err()
        );
        drop(journal);
        for phase in [PriorRetained, Published, RestoreRequested, RolledBack] {
            let leaf = crate::staging_policy::read_private_data_leaf(
                &operation,
                &policy::name(phase, false).unwrap(),
                policy::MAX_RECORD_BYTES,
            )
            .unwrap();
            assert_eq!(leaf.bytes, binding.bytes(phase).unwrap());
            assert!(
                !crate::staging_policy::entry_exists(
                    &operation,
                    &policy::name(phase, true).unwrap()
                )
                .unwrap()
            );
        }
        assert_eq!(
            fs::read(fixture.installed()).unwrap(),
            fixture.material.executable().bytes()
        );
        assert!(
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                .unwrap()
                .try_lock_exclusive()
                .is_ok()
        );
    }
    for phase in [PriorRetained, Published, RestoreRequested, RolledBack] {
        for stop in [
            WriteBoundary::Created,
            WriteBoundary::Completed,
            WriteBoundary::BeforePublish,
            WriteBoundary::Published,
            WriteBoundary::Synced,
        ] {
            let fixture = Fixture::new(ReplacementDirection::Upgrade);
            let pair =
                WindowsPair::new(fixture.prepare(ReplacementDirection::Upgrade).unwrap()).unwrap();
            let operation = pair.operation().try_clone().unwrap();
            let binding = pair.journal_binding().unwrap();
            let journal = before_phase(pair, phase);
            let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
            let mut reached = false;
            assert!(
                journal
                    .record_with_hook(phase, |boundary| {
                        if boundary == stop {
                            reached = true;
                            Err(InstallerStageError::RecoveryRequired)
                        } else {
                            Ok(())
                        }
                    })
                    .is_err()
            );
            assert!(reached);
            let pending = !matches!(stop, WriteBoundary::Published | WriteBoundary::Synced);
            let name = policy::name(phase, pending).unwrap();
            let leaf = crate::staging_policy::read_pending_data_leaf(
                &operation,
                &name,
                policy::MAX_RECORD_BYTES,
            )
            .unwrap();
            let expected = if stop == WriteBoundary::Created {
                Vec::new()
            } else {
                binding.bytes(phase).unwrap()
            };
            assert_eq!(leaf.bytes, expected);
            let after = crate::windows_test_support::snapshot_tree(fixture.destination.path());
            assert_eq!(after.len(), before.len() + 1);
            for (path, content) in before {
                assert_eq!(after.get(&path), Some(&content));
            }
            assert!(
                kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                    .unwrap()
                    .try_lock_exclusive()
                    .is_ok()
            );
        }
    }
    for cut in 0..6 {
        let fixture = Fixture::new(ReplacementDirection::Upgrade);
        let mut pair =
            WindowsPair::new(fixture.prepare(ReplacementDirection::Upgrade).unwrap()).unwrap();
        pair.move_to(Layout::Gap, &[]).unwrap();
        let operation = pair.operation().try_clone().unwrap();
        let canonical = pair
            .journal_binding()
            .unwrap()
            .bytes(PriorRetained)
            .unwrap();
        let length = [
            0,
            1,
            canonical.len() / 2,
            canonical.len() - 1,
            canonical.len(),
            canonical.len() / 2,
        ][cut];
        let pending = policy::name(PriorRetained, true).unwrap();
        create_private_data_leaf(&operation, &pending, canonical[..length].to_vec()).unwrap();
        let journal = JournaledPair::from_pair(pair).unwrap();
        let journal = if cut == 5 {
            journal
                .record(RestoreRequested)
                .unwrap()
                .move_to(Layout::Original)
                .unwrap()
                .record(RolledBack)
                .unwrap()
        } else {
            journal.record(PriorRetained).unwrap()
        };
        drop(journal);
        if cut == 5 {
            let leaf = crate::staging_policy::read_pending_data_leaf(
                &operation,
                &pending,
                policy::MAX_RECORD_BYTES,
            )
            .unwrap();
            assert_eq!(leaf.bytes, canonical[..length]);
            assert_eq!(
                fs::read(fixture.installed()).unwrap(),
                fixture.material.executable().bytes()
            );
            continue;
        }
        assert!(!crate::staging_policy::entry_exists(&operation, &pending).unwrap());
        let leaf = crate::staging_policy::read_private_data_leaf(
            &operation,
            &policy::name(PriorRetained, false).unwrap(),
            policy::MAX_RECORD_BYTES,
        )
        .unwrap();
        assert_eq!(leaf.bytes, canonical);
    }
    let fixture = Fixture::new(ReplacementDirection::Upgrade);
    let pair = WindowsPair::new(fixture.prepare(ReplacementDirection::Upgrade).unwrap()).unwrap();
    let journal = before_phase(pair, Published);
    let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
    assert!(journal.record(Verified).is_err());
    assert_eq!(
        crate::windows_test_support::snapshot_tree(fixture.destination.path()),
        before
    );
    // Race after final full inspection, immediately before no-replace publication.
    let fixture = Fixture::new(ReplacementDirection::Upgrade);
    let pair = WindowsPair::new(fixture.prepare(ReplacementDirection::Upgrade).unwrap()).unwrap();
    let operation = pair.operation().try_clone().unwrap();
    let canonical = pair
        .journal_binding()
        .unwrap()
        .bytes(PriorRetained)
        .unwrap();
    let journal = before_phase(pair, PriorRetained);
    let name = policy::name(PriorRetained, false).unwrap();
    assert!(
        journal
            .record_with_hook(PriorRetained, |boundary| {
                if boundary == WriteBoundary::BeforePublish {
                    create_private_data_leaf(&operation, &name, b"competing record".to_vec())?;
                }
                Ok(())
            })
            .is_err()
    );
    let competitor =
        crate::staging_policy::read_private_data_leaf(&operation, &name, policy::MAX_RECORD_BYTES)
            .unwrap();
    assert_eq!(competitor.bytes, b"competing record");
    let pending = crate::staging_policy::read_pending_data_leaf(
        &operation,
        &policy::name(PriorRetained, true).unwrap(),
        policy::MAX_RECORD_BYTES,
    )
    .unwrap();
    assert_eq!(pending.bytes, canonical);
}
