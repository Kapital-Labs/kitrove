use super::*;

#[test]
fn real_contained_probe_commits_correct_version_and_restores_wrong_version() {
    for (script, succeeds) in [
        (b"#!/bin/sh\nprintf 'kitrove 1.2.4\\n'\n".as_slice(), true),
        (b"#!/bin/sh\nprintf 'kitrove 9.9.9\\n'\n".as_slice(), false),
    ] {
        let (candidate, rollback) =
            crate::test_support::upgrade_releases_with_bytes(b"prior executable", script);
        let fixture = Fixture::with_releases(candidate, rollback);
        let result = fixture.prepare().unwrap().install();
        assert_eq!(result.is_ok(), succeeds);
        if succeeds {
            assert_eq!(fixture.prior_bytes(), script);
        } else {
            assert!(matches!(
                result,
                Err(InstallerStageError::VerificationFailed)
            ));
            assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        }
    }
}

#[test]
fn exchange_commits_candidate_and_retains_authenticated_prior() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    prepared
        .install_with_hooks(
            |_, _| {
                Ok(kitrove_model::ContentHash::digest(
                    fixture.candidate.bytes(),
                ))
            },
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
    assert_eq!(
        fs::read(operation.join("application")).unwrap(),
        fixture.rollback.executable().bytes()
    );
    assert!(operation.join("upgrade-committed.json").is_file());
    assert!(operation.join("rollback-kit/archive").is_file());
    let authority = StateAuthority::open_existing(&fixture.state).unwrap();
    let _guard = authority.try_lock_exclusive().unwrap();
}

#[test]
fn failed_verification_restores_prior_and_retains_candidate() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    let result = prepared.install_with_hooks(
        |_, _| Err(InstallerStageError::VerificationFailed),
        |_| Ok(()),
    );
    assert!(matches!(
        result,
        Err(InstallerStageError::VerificationFailed)
    ));
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
    assert_eq!(
        fs::read(operation.join("application")).unwrap(),
        fixture.candidate.bytes()
    );
    assert!(operation.join("upgrade-rolled-back.json").is_file());
    assert!(!operation.join("upgrade-committed.json").exists());
}

#[test]
fn interrupted_exchange_boundaries_preserve_both_executables() {
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
        assert!(
            matches!(result, Err(InstallerStageError::RecoveryRequired)),
            "{stop:?}"
        );
        let original_layout = matches!(stop, BeforeExchange | Restored | RolledBackRecorded);
        let (installed, retained) = if original_layout {
            (
                fixture.rollback.executable().bytes(),
                fixture.candidate.bytes(),
            )
        } else {
            (
                fixture.candidate.bytes(),
                fixture.rollback.executable().bytes(),
            )
        };
        assert_eq!(fixture.prior_bytes(), installed, "{stop:?}");
        assert_eq!(
            fs::read(operation.join("application")).unwrap(),
            retained,
            "{stop:?}"
        );
    }
}

#[test]
fn foreign_file_displaced_by_exchange_is_preserved_without_execution() {
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    let installed = fixture
        .destination
        .path()
        .join(prepared.staged.record.executable_name());
    let backup = fixture.destination.path().join("manual-backup");
    let result = prepared.install_with_hooks(
        |_, _| panic!("unvalidated displaced file reached execution"),
        |point| {
            if point == UpgradeBoundary::BeforeExchange {
                fs::rename(&installed, &backup).unwrap();
                fs::write(&installed, b"foreign").unwrap();
                fs::set_permissions(&installed, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Ok(())
        },
    );
    assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
    assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
    assert_eq!(fs::read(operation.join("application")).unwrap(), b"foreign");
    assert_eq!(
        fs::read(backup).unwrap(),
        fixture.rollback.executable().bytes()
    );
}

#[test]
fn changed_transaction_evidence_blocks_commit_and_preserves_all_bytes() {
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    for change in ["kit", "state", "phase", "record", "unknown"] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare().unwrap();
        let operation = fixture
            .installer_state()
            .join(prepared.staged.record.operation_id());
        let path = match change {
            "kit" => operation.join("rollback-kit/archive"),
            "state" => fixture.state.join("state.json"),
            "phase" => operation.join("upgrade-replaced.json"),
            "record" => operation.join("upgrade.json"),
            "unknown" => operation.join("foreign"),
            _ => unreachable!(),
        };
        let result = prepared.install_with_hooks(
            |_, _| panic!("changed evidence reached execution"),
            |point| {
                if point == UpgradeBoundary::ReplacedRecorded {
                    fs::write(&path, b"changed evidence").unwrap();
                }
                Ok(())
            },
        );
        assert!(
            matches!(result, Err(InstallerStageError::RecoveryRequired)),
            "{change}"
        );
        assert_eq!(fs::read(path).unwrap(), b"changed evidence");
        assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
        assert_eq!(
            fs::read(operation.join("application")).unwrap(),
            fixture.rollback.executable().bytes()
        );
        assert!(!operation.join("upgrade-committed.json").exists());
    }
}

#[test]
fn changed_installed_candidate_blocks_automatic_restore_without_overwrite() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    let result = prepared.install_with_hooks(
        |path, _| {
            fs::write(path, b"user edit").unwrap();
            Err(InstallerStageError::VerificationFailed)
        },
        |_| Ok(()),
    );
    assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
    assert_eq!(fixture.prior_bytes(), b"user edit");
    assert_eq!(
        fs::read(operation.join("application")).unwrap(),
        fixture.rollback.executable().bytes()
    );
    assert!(!operation.join("upgrade-rolled-back.json").exists());
}
