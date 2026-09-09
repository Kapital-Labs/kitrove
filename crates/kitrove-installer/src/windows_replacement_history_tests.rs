use super::*;
use crate::installation_history::replacement::{ArchivedReplacement, synchronization};
use crate::record::history::journal::HistoricalInstallOutcome;

pub(super) fn terminal_fixture(
    direction: ReplacementDirection,
    committed: bool,
) -> (Fixture, String, PathBuf) {
    let fixture = Fixture::new(direction);
    let operation = prepare_stop(&fixture, direction, 4);
    let selected = operation.file_name().unwrap().to_str().unwrap().to_owned();
    let result = with_reopened_at(
        fixture.destination.path(),
        &fixture.candidate,
        &fixture.material,
        std::slice::from_ref(&fixture.state),
        direction,
        |owner| {
            owner.finish_with_hooks(
                |_, _| {
                    if committed {
                        Ok(kitrove_model::ContentHash::digest(
                            fixture.candidate.bytes(),
                        ))
                    } else {
                        Err(InstallerStageError::VerificationFailed)
                    }
                },
                |_| Ok(()),
            )
        },
    );
    if committed {
        result.unwrap();
    } else {
        assert_eq!(result.unwrap_err(), InstallerStageError::VerificationFailed);
    }
    fs::write(
        fixture.state.join("state.json"),
        String::from_utf8(crate::test_support::EMPTY_STATE.to_vec())
            .unwrap()
            .replace("test-machine", "retirement-machine"),
    )
    .unwrap();
    (fixture, selected, operation)
}

pub(super) fn retire(
    fixture: &Fixture,
    direction: ReplacementDirection,
    boundary: impl FnMut(
        crate::upgrade_transaction::windows_retirement::Boundary,
    ) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    PreparedReplacement::retire_completed_with(
        fixture.destination.path(),
        &fixture.candidate,
        std::slice::from_ref(&fixture.state),
        direction,
        |operation| {
            RetainedRollbackKit::reopen_at_with_test_subject(
                operation,
                &fixture.expected(),
                fixture.material.executable().subject().archive_sha256(),
            )
        },
        boundary,
    )
}

fn archived_fixture(
    direction: ReplacementDirection,
    committed: bool,
) -> (Fixture, String, PathBuf) {
    let (fixture, selected, _) = terminal_fixture(direction, committed);
    let history = fixture
        .destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY);
    let archived = history.join(&selected);
    retire(&fixture, direction, |_| Ok(())).unwrap();
    (fixture, selected, archived)
}

pub(super) fn open(
    fixture: &Fixture,
    selected: &str,
    direction: ReplacementDirection,
) -> Result<ArchivedReplacement, InstallerStageError> {
    ArchivedReplacement::open_with_test_subject(
        fixture.destination.path(),
        selected,
        &fixture.candidate,
        &fixture.expected(),
        fixture.material.executable().subject().archive_sha256(),
        direction,
    )
}

pub(super) fn exercise_history() {
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        for committed in [false, true] {
            let (fixture, selected, _) = archived_fixture(direction, committed);
            fs::write(fixture.installed(), b"later installed application").unwrap();
            fs::write(
                fixture.state.join("state.json"),
                String::from_utf8(crate::test_support::EMPTY_STATE.to_vec())
                    .unwrap()
                    .replace("test-machine", "later-machine"),
            )
            .unwrap();
            let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
            let expected = if committed {
                HistoricalInstallOutcome::Committed
            } else {
                HistoricalInstallOutcome::RolledBack
            };
            assert_eq!(
                open(&fixture, &selected, direction)
                    .unwrap()
                    .outcome()
                    .unwrap(),
                expected
            );
            assert_eq!(
                crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                before
            );
            let outcome = synchronization::synchronize_test_archive(
                std::slice::from_ref(&fixture.state),
                || open(&fixture, &selected, direction),
                |_| {
                    assert!(
                        kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state)
                            .unwrap()
                            .try_lock_shared()
                            .is_err()
                    );
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(outcome, expected);
            assert_eq!(
                crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                before
            );
        }
    }
    for alteration in 0..5 {
        let direction = ReplacementDirection::Upgrade;
        let (fixture, selected, archived) = archived_fixture(direction, true);
        match alteration {
            0 => {
                fs::write(archived.join("unknown"), b"preserve").unwrap();
            }
            1 => {
                fs::write(archived.join("rollback-kit/archive"), b"changed").unwrap();
            }
            2 => {
                fs::write(
                    archived.join(policy::name(JournalStage::Committed, false).unwrap()),
                    b"foreign journal",
                )
                .unwrap();
            }
            3 => {
                fs::write(
                    archived.join(crate::staging_policy::RETAINED_UPGRADE_PRIOR),
                    b"changed prior",
                )
                .unwrap();
            }
            4 => {}
            _ => unreachable!(),
        }
        let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
        let supplied_direction = if alteration == 4 {
            ReplacementDirection::Rollback
        } else {
            direction
        };
        assert!(open(&fixture, &selected, supplied_direction).is_err());
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            before
        );
    }
}
