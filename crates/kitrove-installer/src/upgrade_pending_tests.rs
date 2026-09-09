use super::*;
use crate::install_phase::InstallPhase;
use crate::upgrade_transaction::unix::UpgradeBoundary;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

fn stem(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::Replaced => "upgrade-replaced",
        InstallPhase::Verified => "upgrade-verified",
        InstallPhase::Committed => "upgrade-committed",
        InstallPhase::RolledBack => "upgrade-rolled-back",
    }
}

fn interrupt(fixture: &Fixture, phase: InstallPhase, stop: UpgradeBoundary) -> PathBuf {
    let prepared = fixture.prepare().unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    let result = prepared.install_with_hooks(
        |_, _| {
            if phase == InstallPhase::RolledBack {
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
    assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
    operation
}

#[test]
fn every_phase_write_boundary_recovers_without_replacing_the_record_identity() {
    for &phase in InstallPhase::all() {
        for stop in [
            UpgradeBoundary::PhaseCreated(phase),
            UpgradeBoundary::PhaseWritten(phase),
            UpgradeBoundary::PhasePublished(phase),
        ] {
            let fixture = Fixture::new();
            let operation = interrupt(&fixture, phase, stop);
            let pending = operation.join(format!("{}.pending", stem(phase)));
            let complete = operation.join(format!("{}.json", stem(phase)));
            let before = fs::metadata(if pending.exists() {
                &pending
            } else {
                &complete
            })
            .unwrap();
            let result = fixture.recover_transaction(|_, _| {
                assert_ne!(phase, InstallPhase::RolledBack);
                if matches!(
                    stop,
                    UpgradeBoundary::PhaseCreated(_) | UpgradeBoundary::PhaseWritten(_)
                ) && matches!(phase, InstallPhase::Verified | InstallPhase::Committed)
                {
                    assert!(!complete.exists(), "phase published before fresh probing");
                }
                Ok(kitrove_model::ContentHash::digest(
                    fixture.candidate.bytes(),
                ))
            });
            if phase == InstallPhase::RolledBack {
                assert!(matches!(
                    result,
                    Err(InstallerStageError::VerificationFailed)
                ));
                assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
            } else {
                result.unwrap();
                assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
            }
            let after = fs::metadata(&complete).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert!(!pending.exists());
        }
    }
}

#[test]
fn short_phase_prefixes_are_only_appended_and_are_idempotent() {
    for &phase in InstallPhase::all() {
        for length in [0, 1, 31, usize::MAX] {
            let fixture = Fixture::new();
            let operation = interrupt(&fixture, phase, UpgradeBoundary::PhaseWritten(phase));
            let pending = operation.join(format!("{}.pending", stem(phase)));
            let complete = operation.join(format!("{}.json", stem(phase)));
            let canonical = fs::read(&pending).unwrap();
            let length = length.min(canonical.len() - 1);
            fs::write(&pending, &canonical[..length]).unwrap();
            let before = fs::metadata(&pending).unwrap();
            for _ in 0..2 {
                let result = fixture.recover_transaction(|_, _| {
                    assert_ne!(phase, InstallPhase::RolledBack);
                    Ok(kitrove_model::ContentHash::digest(
                        fixture.candidate.bytes(),
                    ))
                });
                if phase == InstallPhase::RolledBack {
                    assert!(matches!(
                        result,
                        Err(InstallerStageError::VerificationFailed)
                    ));
                } else {
                    result.unwrap();
                }
                assert_eq!(fs::read(&complete).unwrap(), canonical);
                let after = fs::metadata(&complete).unwrap();
                assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            }
        }
    }
}

#[test]
fn failed_recovery_probe_preserves_earlier_pending_evidence_through_rollback() {
    for phase in [InstallPhase::Verified, InstallPhase::Committed] {
        let fixture = Fixture::new();
        let operation = interrupt(&fixture, phase, UpgradeBoundary::PhaseWritten(phase));
        let earlier = operation.join(format!("{}.pending", stem(phase)));
        let prefix = fs::read(&earlier).unwrap()[..31].to_vec();
        fs::write(&earlier, &prefix).unwrap();
        let result =
            fixture.recover_transaction(|_, _| Err(InstallerStageError::VerificationFailed));
        assert!(matches!(
            result,
            Err(InstallerStageError::VerificationFailed)
        ));
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        assert_eq!(fs::read(&earlier).unwrap(), prefix);
        // Reconstruct the atomic rename's pre-publication side to prove recovery
        // accepts both retained earlier evidence and an interrupted rollback marker.
        let rollback = operation.join("upgrade-rolled-back.json");
        let rollback_pending = operation.join("upgrade-rolled-back.pending");
        let canonical = fs::read(&rollback).unwrap();
        fs::rename(&rollback, &rollback_pending).unwrap();
        fs::write(&rollback_pending, &canonical[..31]).unwrap();
        assert!(matches!(
            fixture.recover_transaction(|_, _| panic!("restored binary re-executed")),
            Err(InstallerStageError::VerificationFailed)
        ));
        assert_eq!(fs::read(&rollback).unwrap(), canonical);
        assert_eq!(fs::read(&earlier).unwrap(), prefix);
    }
}

#[test]
fn foreign_or_contradictory_pending_records_are_preserved() {
    for change in [
        "non-prefix",
        "oversized",
        "mode",
        "hard-link",
        "duplicate",
        "impossible",
    ] {
        let fixture = Fixture::new();
        let operation = interrupt(
            &fixture,
            InstallPhase::Verified,
            UpgradeBoundary::PhaseWritten(InstallPhase::Verified),
        );
        let pending = operation.join("upgrade-verified.pending");
        match change {
            "non-prefix" => fs::write(&pending, b"foreign evidence").unwrap(),
            "oversized" => fs::write(&pending, vec![b'x'; 2049]).unwrap(),
            "mode" => fs::set_permissions(&pending, fs::Permissions::from_mode(0o644)).unwrap(),
            "hard-link" => {
                fs::hard_link(&pending, fixture.destination.path().join("external-copy")).unwrap()
            }
            "duplicate" => {
                fs::copy(&pending, operation.join("upgrade-verified.json")).unwrap();
            }
            "impossible" => {
                fs::rename(&pending, operation.join("upgrade-committed.pending")).unwrap()
            }
            _ => unreachable!(),
        }
        let observed = if change == "impossible" {
            operation.join("upgrade-committed.pending")
        } else {
            pending
        };
        let before = fs::read(&observed).unwrap();
        let mode = fs::metadata(&observed).unwrap().permissions().mode();
        assert!(
            fixture
                .recover_transaction(|_, _| panic!("untrusted pending evidence reached probing"))
                .is_err(),
            "{change}"
        );
        assert_eq!(fs::read(observed).unwrap(), before);
        assert_eq!(
            fs::metadata(if change == "impossible" {
                operation.join("upgrade-committed.pending")
            } else {
                operation.join("upgrade-verified.pending")
            })
            .unwrap()
            .permissions()
            .mode(),
            mode
        );
        assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
        assert_eq!(
            fs::read(operation.join("application")).unwrap(),
            fixture.rollback.executable().bytes()
        );
    }
}

#[test]
fn equal_byte_pending_namespace_replacements_are_never_published() {
    for stop in [
        UpgradeBoundary::PhaseCreated(InstallPhase::Replaced),
        UpgradeBoundary::PhaseWritten(InstallPhase::Replaced),
    ] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        let pending = operation.join("upgrade-replaced.pending");
        let retained = fixture.destination.path().join("saved-pending");
        let result = prepared.install_with_hooks(
            |_, _| panic!("raced pending evidence reached execution"),
            |point| {
                if point == stop {
                    let bytes = fs::read(&pending).unwrap();
                    fs::rename(&pending, &retained).unwrap();
                    fs::write(&pending, bytes).unwrap();
                    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
                }
                Ok(())
            },
        );
        assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
        assert_eq!(fs::read(pending).unwrap(), fs::read(retained).unwrap());
        assert!(!operation.join("upgrade-replaced.json").exists());
        assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
        assert_eq!(
            fs::read(operation.join("application")).unwrap(),
            fixture.rollback.executable().bytes()
        );
    }
}
