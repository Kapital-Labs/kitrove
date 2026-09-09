use super::*;
use crate::installation_history::ArchivedInstallation;
use crate::record::history::journal::HistoricalInstallOutcome;
use std::os::unix::fs::symlink;

#[cfg(test)]
#[path = "history_sync_tests.rs"]
mod sync_tests;

fn inspect(fixture: &Fixture) -> Result<ArchivedInstallation, InstallerStageError> {
    ArchivedInstallation::open(
        fixture.destination.path(),
        fixture.operation.file_name().unwrap().to_str().unwrap(),
        &fixture.executable,
    )
}

fn completed_history(rollback: bool) -> Fixture {
    let fixture = Fixture::interrupted(ExecutionBoundary::Committed);
    if rollback {
        assert!(
            fixture
                .reopen()
                .unwrap()
                .recover_with(
                    |_, _| Err(InstallerStageError::VerificationFailed),
                    |_| Ok(())
                )
                .is_err()
        );
    }
    retire(&fixture).unwrap();
    fixture
}

fn history_snapshot(fixture: &Fixture) -> kitrove_testkit::FilesystemSnapshot {
    kitrove_testkit::FilesystemSnapshot::capture(&archive(fixture)).unwrap()
}

#[test]
fn archived_inspection_survives_later_active_binary_and_state_changes_without_mutation() {
    for rollback in [false, true] {
        let fixture = completed_history(rollback);
        let before = history_snapshot(&fixture);
        let installed = fixture
            .destination
            .path()
            .join(fixture.executable.subject().spec().executable_name());
        // Neither current executable contents nor saved historical root paths select authority.
        fs::write(&installed, b"a later active version").unwrap();
        let old_state = fixture.state.with_extension("unavailable");
        fs::rename(&fixture.state, old_state).unwrap();
        let destination_before =
            kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap();
        let history = inspect(&fixture).unwrap();
        assert_eq!(
            history.outcome().unwrap(),
            if rollback {
                HistoricalInstallOutcome::RolledBack
            } else {
                HistoricalInstallOutcome::Committed
            }
        );
        assert_eq!(history_snapshot(&fixture), before);
        assert_eq!(
            kitrove_testkit::FilesystemSnapshot::capture(fixture.destination.path()).unwrap(),
            destination_before
        );
        assert_eq!(fs::read(&installed).unwrap(), b"a later active version");
        assert_eq!(
            inspect(&fixture)
                .err()
                .map(|error| error == InstallerStageError::Conflict),
            Some(true)
        );
        drop(history);
        inspect(&fixture).unwrap();
    }
}

#[test]
fn archived_inspection_refuses_every_altered_retained_leaf_without_repair() {
    for name in [
        "operation.json",
        INSTALL_STATE_RECORD,
        "replaced.json",
        "verified.json",
        "committed.json",
        "application",
        "failed-application",
    ] {
        let fixture = completed_history(true);
        let path = archive(&fixture).join(name);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(&path, &bytes).unwrap();
        let before = history_snapshot(&fixture);
        assert!(inspect(&fixture).is_err(), "accepted {name}");
        assert_eq!(history_snapshot(&fixture), before);
    }
}

#[test]
fn archived_inspection_requires_exact_selection_private_inventory_and_original_identities() {
    for change in [
        "unknown",
        "missing",
        "symlink",
        "hardlink",
        "mode",
        "directory",
        "equal-file",
    ] {
        let fixture = completed_history(false);
        let history = archive(&fixture);
        let leaf = history.join(INSTALL_STATE_RECORD);
        match change {
            "unknown" => fs::write(history.join("unknown"), b"preserve").unwrap(),
            "missing" => fs::rename(
                history.join("verified.json"),
                fixture.destination.path().join("saved-marker"),
            )
            .unwrap(),
            "symlink" => {
                let saved = fixture.destination.path().join("saved-state");
                fs::rename(&leaf, &saved).unwrap();
                symlink(saved, &leaf).unwrap();
            }
            "hardlink" => fs::hard_link(&leaf, fixture.destination.path().join("alias")).unwrap(),
            "mode" => fs::set_permissions(&history, fs::Permissions::from_mode(0o755)).unwrap(),
            "directory" => {
                let saved = fixture.destination.path().join("saved-operation");
                fs::rename(&history, &saved).unwrap();
                fs::create_dir(&history).unwrap();
                fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
                for entry in fs::read_dir(&saved).unwrap() {
                    let entry = entry.unwrap();
                    fs::rename(entry.path(), history.join(entry.file_name())).unwrap();
                }
            }
            "equal-file" => {
                let staged = history.join("application");
                let bytes = fs::read(&staged).unwrap();
                fs::rename(
                    &staged,
                    fixture.destination.path().join("saved-application"),
                )
                .unwrap();
                fs::write(&staged, bytes).unwrap();
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
            }
            _ => unreachable!(),
        }
        let before = history_snapshot(&fixture);
        assert!(inspect(&fixture).is_err(), "accepted {change}");
        assert_eq!(history_snapshot(&fixture), before);
        if change == "mode" {
            assert_eq!(
                fs::metadata(&history).unwrap().permissions().mode() & 0o7777,
                0o755
            );
        }
    }
    let fixture = completed_history(false);
    let before = history_snapshot(&fixture);
    for selected in [
        "",
        "..",
        "../other",
        "A0000000000000000000000000000000",
        "00000000000000000000000000000000",
    ] {
        assert!(
            ArchivedInstallation::open(fixture.destination.path(), selected, &fixture.executable)
                .is_err()
        );
    }
    let (_, other) = upgrade_releases();
    assert!(
        ArchivedInstallation::open(
            fixture.destination.path(),
            fixture.operation.file_name().unwrap().to_str().unwrap(),
            other.executable()
        )
        .is_err()
    );
    assert_eq!(history_snapshot(&fixture), before);
}

#[test]
fn archived_inspection_revalidates_retained_leaf_and_namespace_changes() {
    for change in [
        "bytes",
        "equal-file",
        "history-parent",
        "operation-parent",
        "unknown",
    ] {
        let fixture = completed_history(false);
        let retained = inspect(&fixture).unwrap();
        let archive = archive(&fixture);
        let leaf = archive.join(INSTALL_STATE_RECORD);
        match change {
            "bytes" => fs::write(&leaf, b"changed").unwrap(),
            "equal-file" => {
                let bytes = fs::read(&leaf).unwrap();
                fs::rename(&leaf, fixture.destination.path().join("saved-state")).unwrap();
                fs::write(&leaf, bytes).unwrap();
                fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "history-parent" => fs::rename(
                archive.parent().unwrap(),
                fixture.destination.path().join("moved-history"),
            )
            .unwrap(),
            "operation-parent" => {
                fs::rename(&archive, fixture.destination.path().join("moved-operation")).unwrap()
            }
            "unknown" => fs::write(archive.join("unknown"), b"preserve").unwrap(),
            _ => unreachable!(),
        }
        assert!(retained.outcome().is_err(), "accepted {change}");
    }
}

#[test]
fn archived_inspection_preserves_pre_failure_pending_evidence() {
    let fixture = Fixture::interrupted(ExecutionBoundary::PhaseWrite(
        InstallPhase::Committed,
        unix_install::PhaseWriteBoundary::FileSynced,
    ));
    let pending = fixture
        .operation
        .join(InstallPhase::Committed.pending_file_name());
    let bytes = fs::read(&pending).unwrap();
    fs::write(&pending, &bytes[..bytes.len() / 2]).unwrap();
    assert!(
        fixture
            .reopen()
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |_| Ok(())
            )
            .is_err()
    );
    retire(&fixture).unwrap();
    let before = history_snapshot(&fixture);
    assert_eq!(
        inspect(&fixture).unwrap().outcome().unwrap(),
        HistoricalInstallOutcome::RolledBack
    );
    assert_eq!(history_snapshot(&fixture), before);
}
