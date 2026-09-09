use super::*;

pub(super) fn child(
    owner: JournaledPair<'_>,
    candidate: &AuthenticatedApplicationExecutable,
) -> Result<(), InstallerStageError> {
    let request = std::env::var("KITROVE_TEST_REOPEN_EXPECTED").unwrap();
    let (mode, cut) = match request.split_once(':') {
        Some((mode, cut)) => (mode, Some(cut.parse::<usize>().unwrap())),
        None => (request.as_str(), None),
    };
    let mut observed = 0;
    let mut injected = false;
    let result = owner.finish_with_hooks(
        |_, _| match mode {
            "ok" => Ok(kitrove_model::ContentHash::digest(candidate.bytes())),
            "fail" => Err(InstallerStageError::VerificationFailed),
            "wrong-hash" => Ok(kitrove_model::ContentHash::digest(b"other executable")),
            "restored" => panic!("restoration intent must prevent probing"),
            _ => panic!("unknown verification mode"),
        },
        |_| {
            if Some(observed) == cut {
                injected = true;
                return Err(InstallerStageError::RecoveryRequired);
            }
            observed += 1;
            Ok(())
        },
    );
    if cut.is_some() {
        assert!(injected, "requested verification boundary not reached");
        assert_eq!(result.unwrap_err(), InstallerStageError::RecoveryRequired);
    } else if mode == "ok" {
        result.unwrap();
    } else {
        assert_eq!(result.unwrap_err(), InstallerStageError::VerificationFailed);
    }
    Ok(())
}

pub(super) fn exercise_verification() {
    use crate::upgrade_transaction::windows_journal::writer::verification::Boundary;
    for point in [
        Boundary::BeforeMove(Layout::Gap),
        Boundary::AfterMove(Layout::Gap),
        Boundary::BeforeMove(Layout::Published),
        Boundary::AfterMove(Layout::Published),
        Boundary::BeforeProbe,
        Boundary::AfterProbe,
    ] {
        let direction = ReplacementDirection::Upgrade;
        let fixture = Fixture::new(direction);
        let operation = prepare_stop(&fixture, direction, 0);
        let mut invoked = false;
        let mut after_change = None;
        let result = with_reopened_at(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.material,
            std::slice::from_ref(&fixture.state),
            direction,
            |owner| {
                owner.finish_with_hooks(
                    |_, _| {
                        invoked = true;
                        Ok(kitrove_model::ContentHash::digest(
                            fixture.candidate.bytes(),
                        ))
                    },
                    |boundary| {
                        if boundary == point {
                            fs::write(operation.join("unmanaged-evidence"), b"preserve me")
                                .unwrap();
                            after_change = Some(crate::windows_test_support::snapshot_tree(
                                fixture.destination.path(),
                            ));
                        }
                        Ok(())
                    },
                )
            },
        );
        assert_eq!(result.unwrap_err(), InstallerStageError::RecoveryRequired);
        assert_eq!(invoked, point == Boundary::AfterProbe);
        assert_eq!(
            crate::windows_test_support::snapshot_tree(fixture.destination.path()),
            after_change.unwrap()
        );
        assert!(
            !operation
                .join(policy::name(JournalStage::Verified, false).unwrap())
                .exists()
        );
    }
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        // Reopening untouched preparation must use the initial publication path;
        // its gap interruptions must still restore rather than publish forward.
        for cut in 0..9 {
            let fixture = Fixture::new(direction);
            let operation = prepare_stop(&fixture, direction, 0);
            run_in_child(&fixture, direction, "verify", &format!("ok:{cut}"));
            let mode = if cut == 0 || cut == 8 {
                "ok"
            } else {
                "restored"
            };
            run_in_child(&fixture, direction, "verify", mode);
            let (terminal, installed) = if mode == "ok" {
                (JournalStage::Committed, fixture.candidate.bytes())
            } else {
                (
                    JournalStage::RolledBack,
                    fixture.material.executable().bytes(),
                )
            };
            assert!(
                operation
                    .join(policy::name(terminal, false).unwrap())
                    .exists()
            );
            assert_eq!(fs::read(fixture.installed()).unwrap(), installed);
            // Neither path discards the opposite authenticated executable.
            let retained = if mode == "ok" {
                "prior-application"
            } else {
                "application"
            };
            let expected = if mode == "ok" {
                fixture.material.executable().bytes()
            } else {
                fixture.candidate.bytes()
            };
            assert_eq!(fs::read(operation.join(retained)).unwrap(), expected);
        }
        for mode in ["ok", "fail", "wrong-hash"] {
            let fixture = Fixture::new(direction);
            let operation = prepare_stop(&fixture, direction, 3);
            run_in_child(&fixture, direction, "verify", mode);
            if mode == "ok" {
                assert!(
                    operation
                        .join(policy::name(JournalStage::Committed, false).unwrap())
                        .exists()
                );
                assert_eq!(
                    fs::read(fixture.installed()).unwrap(),
                    fixture.candidate.bytes()
                );
                // Historical commit cannot suppress a fresh failing probe.
                run_in_child(&fixture, direction, "verify", "fail");
            }
            assert_eq!(
                fs::read(fixture.installed()).unwrap(),
                fixture.material.executable().bytes()
            );
            let before = crate::windows_test_support::snapshot_tree(fixture.destination.path());
            run_in_child(&fixture, direction, "verify", "restored");
            assert_eq!(
                crate::windows_test_support::snapshot_tree(fixture.destination.path()),
                before
            );
        }
    }
    for (mode, boundaries) in [("ok", 12), ("fail", 18)] {
        for cut in 0..boundaries {
            let direction = ReplacementDirection::Upgrade;
            let fixture = Fixture::new(direction);
            let operation = prepare_stop(&fixture, direction, 4);
            run_in_child(&fixture, direction, "verify", &format!("{mode}:{cut}"));
            run_in_child(&fixture, direction, "verify", mode);
            let terminal = if mode == "ok" {
                JournalStage::Committed
            } else {
                JournalStage::RolledBack
            };
            assert!(
                operation
                    .join(policy::name(terminal, false).unwrap())
                    .exists()
            );
        }
    }
    // The existing native probe fixture reports 1.2.3: rollback to that version
    // succeeds; an upgrade archive claiming 1.2.4 must restore after version mismatch.
    let current = std::env::current_dir().unwrap();
    let bytes = fs::read(current.join("application-probe-fixture.exe")).unwrap();
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        let (candidate, material) =
            crate::test_support::replacement_releases_with_bytes(&bytes, &bytes, direction);
        let fixture = Fixture::from_releases_in(candidate, material, &current);
        let result = fixture.prepare(direction).unwrap().install();
        if direction == ReplacementDirection::Rollback {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err(), InstallerStageError::VerificationFailed);
        }
        assert_eq!(fs::read(fixture.installed()).unwrap(), bytes);
    }
}
