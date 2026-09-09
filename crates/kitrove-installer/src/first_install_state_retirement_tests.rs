use super::*;
use crate::installation_state::recovery::ClosedInstallation;
use crate::unix_history::RetirementBoundary;

#[cfg(test)]
#[path = "installation_history_tests.rs"]
mod history_tests;

fn archive(fixture: &Fixture) -> PathBuf {
    fixture
        .destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY)
        .join(fixture.operation.file_name().unwrap())
}

fn retire(fixture: &Fixture) -> Result<(), InstallerStageError> {
    ClosedInstallation::retire(
        fixture.destination.path(),
        &fixture.executable,
        std::slice::from_ref(&fixture.state),
    )
}

#[test]
fn historical_records_require_exact_schema_binding_and_bounded_canonical_shape() {
    for change in [
        "schema",
        "candidate",
        "unknown",
        "newline",
        "duplicate",
        "path",
        "fingerprint",
        "too-many",
    ] {
        let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
        let path = fixture.operation.join(INSTALL_STATE_RECORD);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match change {
            "schema" => value["schema"] = serde_json::json!(2),
            "candidate" => value["candidate_record_sha256"] = serde_json::json!("0".repeat(64)),
            "duplicate" => {
                let root = value["state_roots"][0].clone();
                value["state_roots"].as_array_mut().unwrap().push(root);
            }
            "path" => value["state_roots"][0]["path_hex"] = serde_json::json!("not-hex"),
            "fingerprint" => value["state_roots"][0]["tree_fingerprint"] = serde_json::json!("bad"),
            "too-many" => {
                let root = value["state_roots"][0].clone();
                value["state_roots"] = serde_json::json!(
                    (1..=17)
                        .map(|index| {
                            let mut distinct = root.clone();
                            distinct["path_hex"] = serde_json::json!(format!("{index:02x}"));
                            distinct
                        })
                        .collect::<Vec<_>>()
                );
            }
            _ => {}
        }
        // Keep canonical field order so shape/binding failures are not hidden by
        // an unrelated map-key ordering refusal.
        let typed: crate::installation_state::InstallStateEvidence =
            serde_json::from_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&typed).unwrap();
        if change == "unknown" {
            assert_eq!(bytes.pop(), Some(b'}'));
            bytes.extend_from_slice(b",\"unknown\":true}");
        }
        if change == "newline" {
            bytes.push(b'\n');
        }
        fs::write(&path, &bytes).unwrap();
        assert!(retire(&fixture).is_err(), "accepted {change}");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(
            !fixture
                .destination
                .path()
                .join(crate::INSTALLER_HISTORY_DIRECTORY)
                .exists()
        );
    }
}

#[test]
fn a_pending_current_rollback_cannot_be_retired_as_completed_history() {
    let fixture = Fixture::interrupted(ExecutionBoundary::BeforeProbe);
    assert!(
        fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |point| {
                    if point == RecoveryBoundary::PhaseCreated(InstallPhase::RolledBack) {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
    );
    let before = fixture.snapshot();
    assert!(retire(&fixture).is_err());
    assert_eq!(fixture.snapshot(), before);
    assert!(
        !fixture
            .destination
            .path()
            .join(crate::INSTALLER_HISTORY_DIRECTORY)
            .exists()
    );
}

#[test]
fn completed_history_is_retained_after_current_state_changes_without_recovering() {
    let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
    let before = fixture.snapshot();
    fs::write(
        fixture.state.join("state.json"),
        br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#,
    )
    .unwrap();
    assert!(fixture.reopen().is_err());
    retire(&fixture).unwrap();
    assert!(!fixture.operation.exists());
    for (name, bytes) in before {
        assert_eq!(fs::read(archive(&fixture).join(name)).unwrap(), bytes);
    }
    assert_eq!(
        fs::read(
            fixture
                .destination
                .path()
                .join(fixture.executable.subject().spec().executable_name())
        )
        .unwrap(),
        fixture.executable.bytes()
    );
    let next =
        crate::stage_authenticated_application(fixture.destination.path(), &fixture.executable)
            .unwrap();
    assert_ne!(
        next.record.operation_id(),
        fixture.operation.file_name().unwrap().to_str().unwrap()
    );
    assert!(archive(&fixture).exists());
}

#[test]
fn historical_root_paths_are_not_opened_for_retirement() {
    let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
    fs::rename(
        &fixture.state,
        fixture.state.with_file_name("historical-state"),
    )
    .unwrap();
    let (_current_parent, current) = initialized_state(EMPTY_STATE);
    ClosedInstallation::retire(fixture.destination.path(), &fixture.executable, &[current])
        .unwrap();
    assert!(archive(&fixture).exists());
    assert!(!fixture.state.exists());
}

#[test]
fn existing_history_entries_are_never_replaced() {
    let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
    let history = fixture
        .destination
        .path()
        .join(crate::INSTALLER_HISTORY_DIRECTORY);
    fs::create_dir(&history).unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    let conflicting = archive(&fixture);
    fs::create_dir(&conflicting).unwrap();
    fs::set_permissions(&conflicting, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(conflicting.join("foreign"), b"unmanaged history").unwrap();
    let before = fixture.snapshot();
    assert!(retire(&fixture).is_err());
    assert_eq!(fixture.snapshot(), before);
    assert_eq!(
        fs::read(conflicting.join("foreign")).unwrap(),
        b"unmanaged history"
    );
}

#[test]
fn foreign_pre_failure_pending_bytes_block_terminal_retention() {
    let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
        InstallPhase::Committed,
        unix_install::PhaseWriteBoundary::FileSynced,
    ));
    assert_eq!(
        fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |_| Ok(())
            )
            .unwrap_err(),
        InstallerStageError::VerificationFailed
    );
    let pending = fixture
        .operation
        .join(InstallPhase::Committed.pending_file_name());
    fs::write(&pending, b"foreign historical bytes").unwrap();
    let before = fixture.snapshot();
    assert!(retire(&fixture).is_err());
    assert_eq!(fixture.snapshot(), before);
    assert!(
        !fixture
            .destination
            .path()
            .join(crate::INSTALLER_HISTORY_DIRECTORY)
            .exists()
    );
}

#[test]
fn completed_rollback_archives_earlier_pending_bytes_without_completing_them() {
    use std::os::unix::fs::MetadataExt as _;
    let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
        InstallPhase::Committed,
        unix_install::PhaseWriteBoundary::FileSynced,
    ));
    assert_eq!(
        fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |_| Ok(())
            )
            .unwrap_err(),
        InstallerStageError::VerificationFailed
    );
    let pending = fixture
        .operation
        .join(InstallPhase::Committed.pending_file_name());
    let bytes = fs::read(&pending).unwrap();
    let identity = fs::metadata(&pending).unwrap().ino();
    retire(&fixture).unwrap();
    let historical_pending = archive(&fixture).join(InstallPhase::Committed.pending_file_name());
    assert_eq!(fs::read(&historical_pending).unwrap(), bytes);
    assert_eq!(fs::metadata(&historical_pending).unwrap().ino(), identity);
    assert!(
        archive(&fixture)
            .join(InstallPhase::RolledBack.file_name())
            .exists()
    );
    assert!(
        !fixture
            .destination
            .path()
            .join(fixture.executable.subject().spec().executable_name())
            .exists()
    );
}

#[test]
fn nonterminal_operations_are_refused_before_history_creation() {
    for stop in [
        ExecutionBoundary::BeforePublication,
        ExecutionBoundary::Published,
        ExecutionBoundary::BeforeProbe,
        ExecutionBoundary::Verified,
    ] {
        let fixture = Fixture::interrupted(stop);
        let before = fixture.snapshot();
        assert!(retire(&fixture).is_err());
        assert_eq!(fixture.snapshot(), before);
        assert!(
            !fixture
                .destination
                .path()
                .join(crate::INSTALLER_HISTORY_DIRECTORY)
                .exists()
        );
    }
}

#[test]
fn retirement_keeps_current_state_locked_and_refuses_late_writers() {
    let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
    assert!(
        ClosedInstallation::retire_with(
            fixture.destination.path(),
            &fixture.executable,
            std::slice::from_ref(&fixture.state),
            |point| {
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                if point == RetirementBoundary::BeforeMove {
                    fs::write(fixture.state.join("state.json"), b"late writer").unwrap();
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert!(fixture.operation.exists());
    assert!(!archive(&fixture).exists());
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        b"late writer"
    );
}

#[test]
fn archival_interruptions_preserve_every_record_on_exactly_one_side() {
    for stop in [
        RetirementBoundary::HistoryReady,
        RetirementBoundary::BeforeMove,
        RetirementBoundary::Moved,
        RetirementBoundary::HistorySynced,
        RetirementBoundary::SourceSynced,
    ] {
        let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
        let before = fixture.snapshot();
        assert!(
            ClosedInstallation::retire_with(
                fixture.destination.path(),
                &fixture.executable,
                std::slice::from_ref(&fixture.state),
                |point| {
                    if point == stop {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_ne!(fixture.operation.exists(), archive(&fixture).exists());
        let retained = if fixture.operation.exists() {
            fixture.operation.clone()
        } else {
            archive(&fixture)
        };
        for (name, bytes) in before {
            assert_eq!(fs::read(retained.join(name)).unwrap(), bytes);
        }
        if fixture.operation.exists() {
            retire(&fixture).unwrap();
        } else {
            crate::stage_authenticated_application(fixture.destination.path(), &fixture.executable)
                .unwrap();
        }
    }
}
