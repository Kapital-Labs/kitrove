use super::*;

fn pending_restore(fixture: &Fixture) {
    let root =
        crate::windows_recovery::root::RecoveryRoot::open(fixture.destination.path()).unwrap();
    crate::staging_policy::create_private_data_leaf(
        &root.operation,
        &policy::name(JournalStage::RestoreRequested, true).unwrap(),
        Vec::new(),
    )
    .unwrap();
}

fn require_restored(fixture: &Fixture, operation: &Path) {
    assert_eq!(
        fs::read(fixture.installed()).unwrap(),
        fixture.material.executable().bytes()
    );
    assert_eq!(
        fs::read(operation.join(crate::staging_policy::STAGED_EXECUTABLE)).unwrap(),
        fixture.candidate.bytes()
    );
    assert!(
        !operation
            .join(crate::staging_policy::RETAINED_UPGRADE_PRIOR)
            .exists()
    );
    assert!(
        operation
            .join(policy::name(JournalStage::RolledBack, false).unwrap())
            .exists()
    );
}

pub(super) fn exercise_recovery() {
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        for stop in 0..=8 {
            let fixture = Fixture::new(direction);
            let operation = prepare_stop(&fixture, direction, stop);
            let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
            let expected = match stop {
                0 => "prepared",
                3 | 4 => "probe",
                _ => "restored",
            };
            run_in_child(&fixture, direction, "recover", expected);
            if expected == "restored" {
                require_restored(&fixture, &operation);
            } else {
                assert_eq!(
                    crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                    before
                );
            }
        }
    }
    // Interrupt every coordinator and journal-write boundary, then recover in another
    // fresh process. The pending intent must prevent the published candidate advancing.
    for cut in 0..17 {
        let direction = ReplacementDirection::Upgrade;
        let fixture = Fixture::new(direction);
        let operation = prepare_stop(&fixture, direction, 4);
        pending_restore(&fixture);
        run_in_child(&fixture, direction, "interrupt", &cut.to_string());
        run_in_child(&fixture, direction, "recover", "restored");
        require_restored(&fixture, &operation);
        let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
        with_reopened_at(fixture.destination.path(), &fixture.candidate, &fixture.material,
            std::slice::from_ref(&fixture.state), direction, |journal| {
                let (_, disposition) = journal.recover_placement()?;
                assert_eq!(disposition, crate::upgrade_transaction::windows_journal::writer::recovery::Disposition::Restored);
                Ok(())
            }).unwrap();
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            before
        );
    }
    let direction = ReplacementDirection::Upgrade;
    let fixture = Fixture::new(direction);
    let operation = prepare_stop(&fixture, direction, 2);
    let mut snapshot_after_collision = None;
    let result = with_reopened_at(
        fixture.destination.path(),
        &fixture.candidate,
        &fixture.material,
        std::slice::from_ref(&fixture.state),
        direction,
        |journal| {
            use crate::upgrade_transaction::windows_journal::writer::recovery::Boundary;
            use crate::upgrade_transaction::windows_recovery_plan::RecoveryStep;
            journal
                .recover_placement_with_hook(|point| {
                    assert!(
                        kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                            .unwrap()
                            .try_lock_shared()
                            .is_err()
                    );
                    if point == Boundary::Before(RecoveryStep::RestorePrior) {
                        fs::write(fixture.installed(), b"competing destination").unwrap();
                        snapshot_after_collision = Some(
                            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                        );
                    }
                    Ok(())
                })
                .map(|_| ())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        crate::windows_test_support::snapshot_tree(fixture.destination.path()),
        snapshot_after_collision.unwrap()
    );
    assert_eq!(
        fs::read(operation.join(crate::staging_policy::RETAINED_UPGRADE_PRIOR)).unwrap(),
        fixture.material.executable().bytes()
    );
}
