use super::*;
use crate::install_phase::InstallPhase;
use crate::upgrade_transaction::unix::UpgradeBoundary;

fn rollback_fixture(old_bytes: &[u8]) -> Fixture {
    let (candidate, recovery) = crate::test_support::replacement_releases_with_bytes(
        old_bytes,
        b"current executable",
        ReplacementDirection::Rollback,
    );
    Fixture::with_releases(candidate, recovery)
}

fn prepare_rollback(fixture: &Fixture) -> PreparedReplacement<'_> {
    PreparedReplacement::prepare_rollback(
        fixture.destination.path(),
        &fixture.candidate,
        &fixture.rollback,
        std::slice::from_ref(&fixture.state),
    )
    .unwrap()
}

#[test]
fn preparation_reopening_preserves_explicit_direction_and_guards() {
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        let fixture = if direction == ReplacementDirection::Upgrade {
            Fixture::new()
        } else {
            rollback_fixture(b"old executable")
        };
        let prepared = PreparedReplacement::prepare_direction_with_hook(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.rollback,
            std::slice::from_ref(&fixture.state),
            direction,
            |_| Ok(()),
        )
        .unwrap();
        let record_path = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id())
            .join("upgrade.json");
        drop(prepared);
        let before = fs::read(&record_path).unwrap();
        for requested in [
            ReplacementDirection::Upgrade,
            ReplacementDirection::Rollback,
        ] {
            let result = fixture.recover_preparation_direction(requested, |mut prepared| {
                assert_eq!(requested, direction);
                prepared.revalidate()?;
                let authority = StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                Ok(())
            });
            assert_eq!(result.is_ok(), requested == direction);
            assert_eq!(fs::read(&record_path).unwrap(), before);
            assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
            let authority = StateAuthority::open_existing(&fixture.state).unwrap();
            let _guard = authority.try_lock_exclusive().unwrap();
        }
        assert!(
            PreparedReplacement::with_reopened_preparation(
                fixture.destination.path(),
                &fixture.candidate,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
                std::slice::from_ref(&fixture.state),
                direction,
                |_| -> Result<(), InstallerStageError> { panic!("synthetic provenance accepted") },
            )
            .is_err()
        );
    }
}

#[test]
fn rollback_preparation_reopening_preserves_changed_record_and_state() {
    for change in ["direction", "legacy", "state"] {
        let fixture = rollback_fixture(b"old executable");
        let prepared = prepare_rollback(&fixture);
        let record_path = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id())
            .join("upgrade.json");
        drop(prepared);
        let path = if change == "state" {
            fixture.state.join("state.json")
        } else {
            record_path
        };
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match change {
            "direction" => value["direction"] = serde_json::json!("upgrade"),
            "legacy" => {
                value["schema"] = serde_json::json!(2);
                value.as_object_mut().unwrap().remove("direction");
            }
            "state" => value["machine"]["active_profile"] = serde_json::json!("work"),
            _ => unreachable!(),
        }
        let changed = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &changed).unwrap();
        assert!(
            fixture
                .recover_preparation_direction(
                    ReplacementDirection::Rollback,
                    |_| -> Result<(), InstallerStageError> {
                        panic!("changed preparation accepted")
                    }
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), changed);
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
    }
}

#[test]
fn rollback_uses_fresh_current_state_and_the_shared_real_probe() {
    for (script, succeeds) in [
        (b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n".as_slice(), true),
        (b"#!/bin/sh\nprintf 'kitrove 9.9.9\\n'\n".as_slice(), false),
    ] {
        let fixture = rollback_fixture(script);
        let state =
            br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#;
        fs::write(fixture.state.join("state.json"), state).unwrap();
        let prepared = prepare_rollback(&fixture);
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(operation.join("upgrade.json")).unwrap()).unwrap();
        assert_eq!(record["schema"], 3);
        assert_eq!(record["direction"], "rollback");
        let result = prepared.install();
        if succeeds {
            result.unwrap();
            assert_eq!(fixture.prior_bytes(), script);
        } else {
            assert!(matches!(
                result,
                Err(InstallerStageError::VerificationFailed)
            ));
            assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        }
        assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), state);
    }
}

#[test]
fn wrong_requested_direction_is_a_nonmutating_refusal() {
    let rollback = rollback_fixture(b"old executable");
    assert!(rollback.prepare().is_err());
    assert!(!rollback.installer_state().exists());
    assert_eq!(
        rollback.prior_bytes(),
        rollback.rollback.executable().bytes()
    );
    let upgrade = Fixture::new();
    assert!(
        PreparedReplacement::prepare_rollback(
            upgrade.destination.path(),
            &upgrade.candidate,
            &upgrade.rollback,
            std::slice::from_ref(&upgrade.state)
        )
        .is_err()
    );
    assert!(!upgrade.installer_state().exists());
    assert_eq!(upgrade.prior_bytes(), upgrade.rollback.executable().bytes());
}

#[test]
fn rollback_recovery_cannot_change_direction_or_accept_legacy_preparation() {
    for change in ["request", "record", "legacy"] {
        let fixture = rollback_fixture(b"old executable");
        let prepared = prepare_rollback(&fixture);
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        prepared
            .install_with_hooks(
                |_, _| panic!("interrupted before probe"),
                |point| {
                    if point == UpgradeBoundary::Exchanged {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        let record_path = operation.join("upgrade.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        if change == "record" {
            record["direction"] = serde_json::json!("upgrade");
        }
        if change == "legacy" {
            record["schema"] = serde_json::json!(2);
            record.as_object_mut().unwrap().remove("direction");
        }
        if change != "request" {
            fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        let before = fs::read(&record_path).unwrap();
        let direction = if change == "request" {
            ReplacementDirection::Upgrade
        } else {
            ReplacementDirection::Rollback
        };
        assert!(
            fixture
                .recover_direction(direction, |_, _| panic!(
                    "invalid direction reached execution"
                ))
                .is_err()
        );
        assert_eq!(fs::read(record_path).unwrap(), before);
        assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
        assert_eq!(
            fs::read(operation.join("application")).unwrap(),
            fixture.rollback.executable().bytes()
        );
        if change == "request" {
            fixture
                .recover_direction(ReplacementDirection::Rollback, |_, _| {
                    Ok(kitrove_model::ContentHash::digest(
                        fixture.candidate.bytes(),
                    ))
                })
                .unwrap();
        }
    }
}

#[test]
fn explicit_rollback_recovers_pending_and_restored_boundaries() {
    for stop in [
        UpgradeBoundary::BeforeExchange,
        UpgradeBoundary::Exchanged,
        UpgradeBoundary::PhaseWritten(InstallPhase::Replaced),
        UpgradeBoundary::PhaseWritten(InstallPhase::Verified),
        UpgradeBoundary::PhaseWritten(InstallPhase::Committed),
        UpgradeBoundary::Restored,
        UpgradeBoundary::PhaseWritten(InstallPhase::RolledBack),
    ] {
        let fixture = rollback_fixture(b"old executable");
        let restoring = matches!(
            stop,
            UpgradeBoundary::Restored | UpgradeBoundary::PhaseWritten(InstallPhase::RolledBack)
        );
        let prepared = prepare_rollback(&fixture);
        prepared
            .install_with_hooks(
                |_, _| {
                    if restoring {
                        Err(InstallerStageError::VerificationFailed)
                    } else {
                        Ok(kitrove_model::ContentHash::digest(
                            fixture.candidate.bytes(),
                        ))
                    }
                },
                |point| {
                    if point == stop {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        for _ in 0..2 {
            let result = fixture.recover_direction(ReplacementDirection::Rollback, |_, _| {
                assert!(!restoring);
                Ok(kitrove_model::ContentHash::digest(
                    fixture.candidate.bytes(),
                ))
            });
            if restoring {
                assert!(matches!(
                    result,
                    Err(InstallerStageError::VerificationFailed)
                ));
                assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
            } else {
                result.unwrap();
                assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
            }
        }
    }
}

#[test]
fn late_state_changes_block_explicit_rollback_without_overwrite() {
    let fixture = rollback_fixture(b"old executable");
    let prepared = prepare_rollback(&fixture);
    let changed =
        br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"changed"}}"#;
    fs::write(fixture.state.join("state.json"), changed).unwrap();
    assert!(
        prepared
            .install_with_hooks(|_, _| panic!("changed state reached probe"), |_| Ok(()))
            .is_err()
    );
    assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), changed);
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
}
