use super::*;
use crate::upgrade_transaction::windows_journal::writer::JournaledPair;
use crate::upgrade_transaction::windows_journal_policy as policy;
use crate::upgrade_transaction::windows_pair::{Layout, WindowsPair};
use crate::upgrade_transaction::windows_recovery_plan::JournalStage;

fn prepare_stop(fixture: &Fixture, direction: ReplacementDirection, stop: usize) -> PathBuf {
    use JournalStage::*;
    let prepared = fixture.prepare(direction).unwrap();
    let operation = fixture
        .destination
        .path()
        .join(crate::INSTALLER_STATE_DIRECTORY)
        .join(prepared.staged.record.operation_id());
    let mut journal = JournaledPair::from_pair(WindowsPair::new(prepared).unwrap()).unwrap();
    for step in 0..stop {
        journal = match step {
            0 => journal.move_to(Layout::Gap),
            1 => journal.record(PriorRetained),
            2 => journal.move_to(Layout::Published),
            3 => journal.record(Published),
            4 => journal.record(RestoreRequested),
            5 => journal.move_to(Layout::Gap),
            6 => journal.move_to(Layout::Original),
            7 => journal.record(RolledBack),
            _ => panic!("unknown stop"),
        }
        .unwrap();
    }
    drop(journal);
    operation
}

fn reopen_at(
    destination: &Path,
    candidate: &AuthenticatedApplicationExecutable,
    material: &AuthenticatedRecoveryMaterial,
    roots: &[PathBuf],
    direction: ReplacementDirection,
) -> Result<(), InstallerStageError> {
    with_reopened_at(
        destination,
        candidate,
        material,
        roots,
        direction,
        |journal| {
            drop(journal);
            Ok(())
        },
    )
}

fn with_reopened_at<R>(
    destination: &Path,
    candidate: &AuthenticatedApplicationExecutable,
    material: &AuthenticatedRecoveryMaterial,
    roots: &[PathBuf],
    direction: ReplacementDirection,
    action: impl FnOnce(JournaledPair<'_>) -> Result<R, InstallerStageError>,
) -> Result<R, InstallerStageError> {
    let expected = kitrove_release_provenance::ExpectedReleaseIdentity::new(
        material.executable().subject().release_tag(),
        material.executable().subject().source_commit(),
    )
    .unwrap();
    PreparedReplacement::with_reopened_windows_pair_impl(
        destination,
        candidate,
        roots,
        direction,
        |staged| {
            RetainedRollbackKit::reopen_material_with_test_subject(
                staged,
                &expected,
                material.executable().subject().archive_sha256(),
            )
        },
        |journal| {
            for root in roots {
                assert!(
                    kitrove_state_lifecycle::StateAuthority::open_existing(root)
                        .unwrap()
                        .try_lock_shared()
                        .is_err()
                );
            }
            action(journal)
        },
    )
}

#[test]
#[ignore = "child-only: invoked with synthetic inputs by the standard-user reopening fixture"]
fn fresh_process_child() {
    kitrove_windows_security::require_unelevated_process().unwrap();
    let destination = PathBuf::from(
        std::env::var_os("KITROVE_TEST_REOPEN_DESTINATION").expect("parent supplied destination"),
    );
    let direction = match std::env::var("KITROVE_TEST_REOPEN_DIRECTION")
        .unwrap()
        .as_str()
    {
        "upgrade" => ReplacementDirection::Upgrade,
        "rollback" => ReplacementDirection::Rollback,
        _ => panic!("unknown synthetic direction"),
    };
    // Construct fresh test subjects in this process; no retained parent capability is used.
    let (candidate, material) = crate::test_support::replacement_releases_with_bytes(
        b"old Windows executable",
        b"new Windows executable",
        direction,
    );
    with_reopened_at(
        &destination,
        &candidate,
        &material,
        &[destination.join("app-state")],
        direction,
        |journal| match std::env::var("KITROVE_TEST_REOPEN_ACTION")
            .unwrap()
            .as_str()
        {
            "inspect" => Ok(()),
            "recover" => {
                use crate::upgrade_transaction::windows_journal::writer::recovery::Disposition;
                let (retained, result) = journal.recover_placement()?;
                let expected = match std::env::var("KITROVE_TEST_REOPEN_EXPECTED")
                    .unwrap()
                    .as_str()
                {
                    "prepared" => Disposition::Prepared,
                    "probe" => Disposition::NeedsProbe,
                    "restored" => Disposition::Restored,
                    _ => panic!("unknown expected recovery disposition"),
                };
                assert_eq!(result, expected);
                drop(retained);
                Ok(())
            }
            "interrupt" => {
                let cut = std::env::var("KITROVE_TEST_REOPEN_EXPECTED")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                let mut observed = 0;
                let mut injected = false;
                let result = journal.recover_placement_with_hook(|_| {
                    if observed == cut {
                        injected = true;
                        return Err(InstallerStageError::RecoveryRequired);
                    }
                    observed += 1;
                    Ok(())
                });
                assert!(injected, "requested recovery boundary was not reached");
                assert!(result.is_err());
                Ok(())
            }
            "verify" => verification_tests::child(journal, &candidate),
            _ => panic!("unknown synthetic action"),
        },
    )
    .unwrap();
}

fn reopen_in_child(fixture: &Fixture, direction: ReplacementDirection) {
    run_in_child(fixture, direction, "inspect", "");
}

fn run_in_child(fixture: &Fixture, direction: ReplacementDirection, action: &str, expected: &str) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "upgrade_transaction::windows_tests::reopen_tests::fresh_process_child",
            "--ignored",
            "--nocapture",
        ])
        .env(
            "KITROVE_TEST_REOPEN_DESTINATION",
            fixture.destination.path(),
        )
        .env("KITROVE_TEST_REOPEN_ACTION", action)
        .env("KITROVE_TEST_REOPEN_EXPECTED", expected)
        .env(
            "KITROVE_TEST_REOPEN_DIRECTION",
            match direction {
                ReplacementDirection::Upgrade => "upgrade",
                ReplacementDirection::Rollback => "rollback",
            },
        )
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("fresh-process reopening exceeded its bounded runtime");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(test)]
#[path = "windows_placement_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "windows_verification_tests.rs"]
mod verification_tests;

#[cfg(test)]
#[path = "windows_replacement_history_tests.rs"]
mod history_tests;

#[cfg(test)]
#[path = "windows_replacement_retirement_tests.rs"]
mod retirement_tests;

pub(super) fn exercise_fresh_reopening() {
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        for stop in 0..=8 {
            let fixture = Fixture::new(direction);
            prepare_stop(&fixture, direction, stop);
            let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
            reopen_in_child(&fixture, direction);
            assert_eq!(
                crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                before
            );
            assert!(
                kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                    .unwrap()
                    .try_lock_exclusive()
                    .is_ok()
            );
        }
    }
    for (stop, phase) in [
        (1, JournalStage::PriorRetained),
        (4, JournalStage::RestoreRequested),
        (7, JournalStage::RolledBack),
    ] {
        let fixture = Fixture::new(ReplacementDirection::Upgrade);
        prepare_stop(&fixture, ReplacementDirection::Upgrade, stop);
        {
            let root =
                crate::windows_recovery::root::RecoveryRoot::open(fixture.destination.path())
                    .unwrap();
            crate::staging_policy::create_private_data_leaf(
                &root.operation,
                &policy::name(phase, true).unwrap(),
                Vec::new(),
            )
            .unwrap();
        }
        let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
        reopen_in_child(&fixture, ReplacementDirection::Upgrade);
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            before
        );
    }
    for alteration in 0..7 {
        let fixture = Fixture::new(ReplacementDirection::Upgrade);
        let operation = prepare_stop(&fixture, ReplacementDirection::Upgrade, 4);
        match alteration {
            0 => {
                fs::write(operation.join("rollback-kit/archive"), b"changed archive").unwrap();
            }
            1 => {
                fs::write(
                    operation.join(policy::name(JournalStage::Published, false).unwrap()),
                    b"foreign journal",
                )
                .unwrap();
            }
            2 => {
                let prior = operation.join(crate::staging_policy::RETAINED_UPGRADE_PRIOR);
                fs::rename(&prior, fixture.destination.path().join("preserved-prior")).unwrap();
                fs::write(prior, fixture.material.executable().bytes()).unwrap();
            }
            3 => {
                fs::write(operation.join("unknown-entry"), b"unmanaged").unwrap();
            }
            4 => {}
            5 => {
                fs::write(
                    fixture.state.join("state.json"),
                    String::from_utf8(crate::test_support::EMPTY_STATE.to_vec())
                        .unwrap()
                        .replace("test-machine", "different-test-machine"),
                )
                .unwrap();
            }
            6 => {}
            _ => unreachable!(),
        }
        let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
        let roots = if alteration == 4 {
            Vec::new()
        } else {
            vec![fixture.state.clone()]
        };
        let direction = if alteration == 6 {
            ReplacementDirection::Rollback
        } else {
            ReplacementDirection::Upgrade
        };
        assert!(
            reopen_at(
                fixture.destination.path(),
                &fixture.candidate,
                &fixture.material,
                &roots,
                direction
            )
            .is_err()
        );
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            before
        );
    }
    recovery_tests::exercise_recovery();
    verification_tests::exercise_verification();
    history_tests::exercise_history();
    retirement_tests::exercise_retirement();
}
