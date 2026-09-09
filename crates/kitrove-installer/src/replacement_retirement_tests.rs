use super::*;
use crate::upgrade_transaction::unix::RetirementBoundary;

#[cfg(test)]
#[path = "replacement_history_tests.rs"]
mod inspection;

fn finish(fixture: &Fixture, succeeds: bool) -> PathBuf {
    let prepared = fixture.prepare().unwrap();
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    let result = prepared.install_with_hooks(
        |_, _| {
            if succeeds {
                Ok(kitrove_model::ContentHash::digest(
                    fixture.candidate.bytes(),
                ))
            } else {
                Err(InstallerStageError::VerificationFailed)
            }
        },
        |_| Ok(()),
    );
    assert_eq!(result.is_ok(), succeeds);
    operation
}

fn retire(
    fixture: &Fixture,
    boundary: impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    PreparedReplacement::retire_completed_with(
        fixture.destination.path(),
        &fixture.candidate,
        std::slice::from_ref(&fixture.state),
        ReplacementDirection::Upgrade,
        |staged| {
            RetainedRollbackKit::reopen_material_with_test_subject(
                staged,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
            )
        },
        boundary,
    )
}

fn history(fixture: &Fixture, operation: &Path) -> PathBuf {
    fixture
        .destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY)
        .join(operation.file_name().unwrap())
}

#[test]
fn completed_history_preserves_changed_state_and_allows_fresh_rollback() {
    let fixture = Fixture::new();
    let operation = finish(&fixture, true);
    let original_record = fs::read(operation.join("upgrade.json")).unwrap();
    let state = br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#;
    fs::write(fixture.state.join("state.json"), state).unwrap();
    assert!(
        fixture
            .recover_transaction(|_, _| panic!("stale state must refuse"))
            .is_err()
    );
    retire(&fixture, |_| Ok(())).unwrap();
    let archived = history(&fixture, &operation);
    assert!(!operation.exists());
    assert_eq!(
        fs::read(archived.join("upgrade.json")).unwrap(),
        original_record
    );
    assert_eq!(
        fs::read(archived.join("application")).unwrap(),
        fixture.rollback.executable().bytes()
    );
    assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
    let (candidate, material) = crate::test_support::replacement_releases_with_bytes(
        fixture.rollback.executable().bytes(),
        fixture.candidate.bytes(),
        ReplacementDirection::Rollback,
    );
    PreparedReplacement::prepare_rollback(
        fixture.destination.path(),
        &candidate,
        &material,
        std::slice::from_ref(&fixture.state),
    )
    .unwrap()
    .install_with_hooks(
        |_, _| Ok(kitrove_model::ContentHash::digest(candidate.bytes())),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
    assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), state);
    assert_eq!(
        fs::read(archived.join("upgrade.json")).unwrap(),
        original_record
    );
}

#[test]
fn failed_probe_history_preserves_candidate_and_allows_retry() {
    let fixture = Fixture::new();
    let operation = finish(&fixture, false);
    retire(&fixture, |_| Ok(())).unwrap();
    let archived = history(&fixture, &operation);
    assert_eq!(
        fs::read(archived.join("application")).unwrap(),
        fixture.candidate.bytes()
    );
    assert!(archived.join("upgrade-rolled-back.json").is_file());
    fixture.prepare().unwrap();
}

#[test]
fn nonterminal_retirement_refuses_before_creating_history() {
    let fixture = Fixture::new();
    let operation = fixture.retained_operation();
    assert!(retire(&fixture, |_| panic!("not terminal")).is_err());
    assert!(operation.is_dir());
    assert!(
        !fixture
            .destination
            .path()
            .join(crate::INSTALLER_HISTORY_DIRECTORY)
            .exists()
    );
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
}

#[test]
fn interrupted_retirement_preserves_evidence_on_exactly_one_side() {
    use RetirementBoundary::*;
    for point in [HistoryReady, BeforeMove, Moved, HistorySynced, SourceSynced] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, false);
        let record = fs::read(operation.join("upgrade.json")).unwrap();
        assert!(
            retire(&fixture, |seen| {
                if seen == point {
                    Err(InstallerStageError::RecoveryRequired)
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        let archived = history(&fixture, &operation);
        let moved = matches!(point, Moved | HistorySynced | SourceSynced);
        assert_eq!(archived.exists(), moved);
        assert_eq!(operation.exists(), !moved);
        let retained = if moved { &archived } else { &operation };
        assert_eq!(fs::read(retained.join("upgrade.json")).unwrap(), record);
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        if moved {
            fixture.prepare().unwrap();
        } else {
            retire(&fixture, |_| Ok(())).unwrap();
        }
    }
}

#[test]
fn conflicting_history_is_never_overwritten() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    let operation = finish(&fixture, true);
    let archived = history(&fixture, &operation);
    fs::create_dir(archived.parent().unwrap()).unwrap();
    fs::set_permissions(
        archived.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::create_dir(&archived).unwrap();
    fs::write(archived.join("unmanaged"), b"preserve").unwrap();
    assert!(retire(&fixture, |_| Ok(())).is_err());
    assert!(operation.join("upgrade-committed.json").exists());
    assert_eq!(fs::read(archived.join("unmanaged")).unwrap(), b"preserve");
}

#[test]
fn late_state_change_blocks_retirement_without_executable_mutation() {
    let fixture = Fixture::new();
    let operation = finish(&fixture, true);
    assert!(
        retire(&fixture, |point| {
            if point == RetirementBoundary::BeforeMove {
                fs::write(fixture.state.join("state.json"), EMPTY_STATE).unwrap();
                fs::write(fixture.state.join("unexpected"), b"preserve").unwrap();
            }
            Ok(())
        })
        .is_err()
    );
    assert!(operation.is_dir());
    assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
    assert_eq!(
        fs::read(fixture.state.join("unexpected")).unwrap(),
        b"preserve"
    );
}

#[test]
fn production_retirement_requires_real_attestation() {
    let fixture = Fixture::new();
    let operation = finish(&fixture, true);
    assert!(
        PreparedReplacement::retire_completed(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.expected_prior(),
            fixture.rollback.executable().subject().archive_sha256(),
            std::slice::from_ref(&fixture.state),
            ReplacementDirection::Upgrade,
        )
        .is_err()
    );
    assert!(operation.is_dir());
    assert!(!history(&fixture, &operation).exists());
}

#[test]
fn unsafe_history_is_not_repaired_or_followed() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for link in [false, true] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, true);
        let history_root = history(&fixture, &operation)
            .parent()
            .unwrap()
            .to_path_buf();
        let other = private_tempdir();
        if link {
            symlink(other.path(), &history_root).unwrap();
        } else {
            fs::create_dir(&history_root).unwrap();
            fs::set_permissions(&history_root, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(retire(&fixture, |_| Ok(())).is_err());
        assert!(operation.is_dir());
        assert_eq!(fs::read_dir(other.path()).unwrap().count(), 0);
        if link {
            assert!(fs::symlink_metadata(&history_root).unwrap().is_symlink());
        } else {
            assert_eq!(
                fs::metadata(&history_root).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
}

#[test]
fn substituted_history_parent_is_rejected_before_and_after_move() {
    use std::os::unix::fs::PermissionsExt as _;
    for point in [
        RetirementBoundary::BeforeMove,
        RetirementBoundary::SourceSynced,
    ] {
        let fixture = Fixture::new();
        let operation = finish(&fixture, true);
        let history_root = history(&fixture, &operation)
            .parent()
            .unwrap()
            .to_path_buf();
        let displaced = fixture.destination.path().join("displaced-history");
        assert!(
            retire(&fixture, |seen| {
                if seen == point {
                    fs::rename(&history_root, &displaced).unwrap();
                    fs::create_dir(&history_root).unwrap();
                    fs::set_permissions(&history_root, fs::Permissions::from_mode(0o700)).unwrap();
                }
                Ok(())
            })
            .is_err()
        );
        let retained = if point == RetirementBoundary::BeforeMove {
            operation
        } else {
            displaced.join(operation.file_name().unwrap())
        };
        assert!(retained.join("upgrade-committed.json").is_file());
        assert_eq!(fs::read_dir(&history_root).unwrap().count(), 0);
        assert_eq!(fixture.prior_bytes(), fixture.candidate.bytes());
    }
}

#[test]
fn historical_state_shapes_are_bounded_without_opening_paths() {
    use crate::state_preflight::StateRootRecord;
    let valid =
        serde_json::json!({"path_hex":"2f6d697373696e67", "tree_fingerprint":"a".repeat(64)});
    let record: StateRootRecord = serde_json::from_value(valid.clone()).unwrap();
    StateRootRecord::validate_history(std::slice::from_ref(&record)).unwrap();
    assert!(StateRootRecord::validate_history(&[record.clone(), record.clone()]).is_err());
    assert!(StateRootRecord::validate_history(&vec![record; 17]).is_err());
    for (field, value) in [
        ("path_hex", "".to_owned()),
        ("path_hex", "a".to_owned()),
        ("path_hex", "GG".to_owned()),
        ("path_hex", "aa".repeat(2049)),
        ("tree_fingerprint", "a".repeat(63)),
        ("tree_fingerprint", "A".repeat(64)),
    ] {
        let mut bad = valid.clone();
        bad[field] = value.into();
        let record: StateRootRecord = serde_json::from_value(bad).unwrap();
        assert!(StateRootRecord::validate_history(&[record]).is_err());
    }
}

#[test]
fn terminal_rollback_retains_earlier_pending_evidence() {
    use crate::install_phase::InstallPhase;
    use crate::upgrade_transaction::unix::UpgradeBoundary;
    for phase in [InstallPhase::Verified, InstallPhase::Committed] {
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
                |point| {
                    if point == UpgradeBoundary::PhaseWritten(phase) {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
        let name = match phase {
            InstallPhase::Verified => "upgrade-verified.pending",
            InstallPhase::Committed => "upgrade-committed.pending",
            _ => unreachable!(),
        };
        let prefix = fs::read(operation.join(name)).unwrap()[..31].to_vec();
        fs::write(operation.join(name), &prefix).unwrap();
        assert!(matches!(
            fixture.recover_transaction(|_, _| Err(InstallerStageError::VerificationFailed)),
            Err(InstallerStageError::VerificationFailed)
        ));
        retire(&fixture, |_| Ok(())).unwrap();
        assert_eq!(
            fs::read(history(&fixture, &operation).join(name)).unwrap(),
            prefix
        );
        fixture.prepare().unwrap();
    }
}
