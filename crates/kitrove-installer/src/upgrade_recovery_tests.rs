use super::*;

#[test]
fn real_probe_recovery_and_production_attestation_refusal_are_separate_evidence() {
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    let (candidate, rollback) = crate::test_support::upgrade_releases_with_bytes(
        b"prior executable",
        b"#!/bin/sh\nprintf 'kitrove 1.2.4\\n'\n",
    );
    let fixture = Fixture::with_releases(candidate, rollback);
    fixture
        .prepare()
        .unwrap()
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
    let result = PreparedReplacement::recover_upgrade(
        fixture.destination.path(),
        &fixture.candidate,
        &fixture.expected_prior(),
        fixture.rollback.executable().subject().archive_sha256(),
        std::slice::from_ref(&fixture.state),
    );
    assert!(matches!(
        result,
        Err(InstallerStageError::VerificationFailed)
    ));
    assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
    fixture
        .recover_transaction(crate::verify_installed_application)
        .unwrap();
    assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
}

#[test]
fn late_recovery_edits_and_wrong_checksums_never_reach_execution() {
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    for change in ["checksum", "state", "kit", "prior"] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
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
        let path = match change {
            "state" => fixture.state.join("state.json"),
            "kit" => operation.join("rollback-kit/archive"),
            _ => operation.join("application"),
        };
        let result = PreparedReplacement::recover_upgrade_with(
            fixture.destination.path(),
            &fixture.candidate,
            std::slice::from_ref(&fixture.state),
            |staged| {
                let reopened = RetainedRollbackKit::reopen_material_with_test_subject(
                    staged,
                    &fixture.expected_prior(),
                    if change == "checksum" {
                        [0; 32]
                    } else {
                        fixture.rollback.executable().subject().archive_sha256()
                    },
                )?;
                fs::write(&path, b"late edit").unwrap();
                Ok(reopened)
            },
            |_, _| panic!("late changed evidence reached execution"),
        );
        assert!(result.is_err(), "{change}");
        if change != "checksum" {
            assert_eq!(fs::read(path).unwrap(), b"late edit");
        }
        assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
        assert!(!operation.join("upgrade-replaced.json").exists());
    }
}

#[test]
fn fresh_transaction_recovery_handles_each_exchange_boundary_idempotently() {
    use crate::upgrade_transaction::unix::UpgradeBoundary::*;
    for stop in [
        BeforeExchange,
        Exchanged,
        ReplacedRecorded,
        VerifiedRecorded,
        CommittedRecorded,
        BeforeRestore,
        Restored,
        RolledBackRecorded,
    ] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        let restoring = matches!(stop, BeforeRestore | Restored | RolledBackRecorded);
        let result = prepared.install_with_hooks(
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
        );
        assert!(result.is_err());
        let restored = matches!(stop, Restored | RolledBackRecorded);
        for _ in 0..2 {
            let result = fixture.recover_transaction(|_, _| {
                assert!(!restored, "restored upgrade was executed again");
                let authority = StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                Ok(kitrove_model::ContentHash::digest(
                    fixture.candidate.bytes(),
                ))
            });
            if restored {
                assert!(
                    matches!(result, Err(InstallerStageError::VerificationFailed)),
                    "{stop:?}"
                );
                assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
                assert!(operation.join("upgrade-rolled-back.json").is_file());
            } else {
                result.unwrap();
                assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
                assert!(operation.join("upgrade-committed.json").is_file());
            }
            let authority = StateAuthority::open_existing(&fixture.state).unwrap();
            let _guard = authority.try_lock_exclusive().unwrap();
        }
    }
}

#[test]
fn freshly_recovered_failed_probe_restores_even_a_recorded_commit() {
    use crate::upgrade_transaction::unix::UpgradeBoundary::*;
    for stop in [
        Exchanged,
        ReplacedRecorded,
        VerifiedRecorded,
        CommittedRecorded,
    ] {
        let fixture = Fixture::new();
        fixture
            .prepare()
            .unwrap()
            .install_with_hooks(
                |_, _| {
                    Ok(kitrove_model::ContentHash::digest(
                        fixture.candidate.bytes(),
                    ))
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
        assert!(matches!(
            fixture.recover_transaction(|_, _| Err(InstallerStageError::VerificationFailed)),
            Err(InstallerStageError::VerificationFailed)
        ));
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        assert!(matches!(
            fixture.recover_transaction(|_, _| panic!("restored candidate executed")),
            Err(InstallerStageError::VerificationFailed)
        ));
    }
}

#[test]
fn transaction_recovery_rejects_tampered_or_pending_evidence_without_mutation() {
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    for change in [
        "phase",
        "pending",
        "record",
        "kit",
        "state",
        "candidate",
        "prior",
        "missing-replaced",
    ] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        let destination = fixture
            .destination
            .path()
            .join(prepared.staged.record.executable_name());
        prepared
            .install_with_hooks(
                |_, _| {
                    Ok(kitrove_model::ContentHash::digest(
                        fixture.candidate.bytes(),
                    ))
                },
                |point| {
                    if point == UpgradeBoundary::VerifiedRecorded {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        let path = match change {
            "phase" => operation.join("upgrade-verified.json"),
            "pending" => operation.join("upgrade-committed.pending"),
            "record" => operation.join("upgrade.json"),
            "kit" => operation.join("rollback-kit/archive"),
            "state" => fixture.state.join("state.json"),
            "candidate" => destination.clone(),
            "prior" => operation.join("application"),
            "missing-replaced" => operation.join("upgrade-replaced.json"),
            _ => unreachable!(),
        };
        if change == "missing-replaced" {
            fs::rename(&path, operation.join("saved-replaced")).unwrap();
        } else {
            fs::write(&path, b"changed").unwrap();
        }
        let installed = fs::read(&destination).unwrap();
        let retained = fs::read(operation.join("application")).unwrap();
        assert!(
            fixture
                .recover_transaction(|_, _| panic!("invalid recovery reached execution"))
                .is_err(),
            "{change}"
        );
        assert_eq!(fs::read(destination).unwrap(), installed);
        assert_eq!(fs::read(operation.join("application")).unwrap(), retained);
        if change != "missing-replaced" {
            assert_eq!(fs::read(path).unwrap(), b"changed");
        }
        assert!(!operation.join("upgrade-committed.json").exists());
    }
}
