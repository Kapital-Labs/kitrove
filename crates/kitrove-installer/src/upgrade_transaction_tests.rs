use super::*;
use crate::test_support::{
    EMPTY_STATE, TestDestination, initialized_state, private_tempdir, upgrade_releases,
};
use kitrove_state_lifecycle::StateAuthority;
use std::fs;
use std::io::Write as _;

struct Fixture {
    destination: TestDestination,
    candidate: AuthenticatedApplicationExecutable,
    rollback: AuthenticatedRecoveryMaterial,
    _state_parent: TestDestination,
    state: PathBuf,
}

impl Fixture {
    fn retained_operation(&self) -> PathBuf {
        let prepared = self.prepare().unwrap();
        self.installer_state()
            .join(prepared.staged.record.operation_id())
    }

    fn expected_prior(&self) -> kitrove_release_provenance::ExpectedReleaseIdentity {
        kitrove_release_provenance::ExpectedReleaseIdentity::new(
            self.rollback.executable().subject().release_tag(),
            self.rollback.executable().subject().source_commit(),
        )
        .unwrap()
    }

    fn recover<R>(
        &self,
        action: impl FnOnce(PreparedReplacement<'_>) -> Result<R, InstallerStageError>,
    ) -> Result<R, InstallerStageError> {
        self.recover_preparation_direction(ReplacementDirection::Upgrade, action)
    }

    fn recover_preparation_direction<R>(
        &self,
        direction: ReplacementDirection,
        action: impl FnOnce(PreparedReplacement<'_>) -> Result<R, InstallerStageError>,
    ) -> Result<R, InstallerStageError> {
        PreparedReplacement::with_reopened_impl(
            self.destination.path(),
            &self.candidate,
            std::slice::from_ref(&self.state),
            direction,
            |staged| {
                RetainedRollbackKit::reopen_with_test_subject(
                    staged,
                    &self.expected_prior(),
                    self.rollback.executable().subject().archive_sha256(),
                )
            },
            action,
        )
    }

    fn recover_transaction(
        &self,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
    ) -> Result<crate::InstalledApplication, InstallerStageError> {
        self.recover_direction(ReplacementDirection::Upgrade, verify)
    }

    fn recover_direction(
        &self,
        direction: ReplacementDirection,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
    ) -> Result<crate::InstalledApplication, InstallerStageError> {
        PreparedReplacement::recover_direction_with(
            self.destination.path(),
            &self.candidate,
            std::slice::from_ref(&self.state),
            direction,
            |staged| {
                RetainedRollbackKit::reopen_material_with_test_subject(
                    staged,
                    &self.expected_prior(),
                    self.rollback.executable().subject().archive_sha256(),
                )
            },
            verify,
        )
    }

    fn new() -> Self {
        let (candidate, rollback) = upgrade_releases();
        Self::with_releases(candidate, rollback)
    }

    fn with_releases(
        candidate: AuthenticatedApplicationExecutable,
        rollback: AuthenticatedRecoveryMaterial,
    ) -> Self {
        let destination = private_tempdir();
        let directory = crate::unix_staging::open_destination(destination.path()).unwrap();
        let mut prior = crate::unix_staging::create_private_file(
            directory.directory(),
            std::ffi::OsStr::new(rollback.executable().subject().spec().executable_name()),
            0o700,
        )
        .unwrap();
        prior.write_all(rollback.executable().bytes()).unwrap();
        prior.sync_all().unwrap();
        let (parent, state) = initialized_state(EMPTY_STATE);
        Self {
            destination,
            candidate,
            rollback,
            _state_parent: parent,
            state,
        }
    }

    fn prepare(&self) -> Result<PreparedReplacement<'_>, InstallerStageError> {
        PreparedReplacement::prepare(
            self.destination.path(),
            &self.candidate,
            &self.rollback,
            std::slice::from_ref(&self.state),
        )
    }

    fn prior_bytes(&self) -> Vec<u8> {
        fs::read(
            self.destination.path().join(
                self.rollback
                    .executable()
                    .subject()
                    .spec()
                    .executable_name(),
            ),
        )
        .unwrap()
    }

    fn installer_state(&self) -> PathBuf {
        self.destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
    }
}

#[cfg(test)]
#[path = "upgrade_exchange_tests.rs"]
mod exchange;
#[cfg(test)]
#[path = "upgrade_recovery_tests.rs"]
mod recovery;

#[cfg(test)]
#[path = "upgrade_pending_tests.rs"]
mod pending;

#[cfg(test)]
#[path = "replacement_direction_tests.rs"]
mod direction;

#[cfg(test)]
#[path = "replacement_retirement_tests.rs"]
mod retirement;

#[test]
fn fresh_reopening_retains_guards_and_reconstructs_the_complete_record() {
    let fixture = Fixture::new();
    let operation = fixture.retained_operation();
    let record = fs::read(operation.join(crate::upgrade_record::UPGRADE_RECORD)).unwrap();
    for _ in 0..2 {
        fixture
            .recover(|mut prepared| {
                prepared.revalidate()?;
                let authority = StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                assert_eq!(
                    prepared.prior.rollback().archive_bytes(),
                    fixture.rollback.archive_bytes()
                );
                Ok(())
            })
            .unwrap();
        let authority = StateAuthority::open_existing(&fixture.state).unwrap();
        let _guard = authority.try_lock_exclusive().unwrap();
    }
    assert_eq!(
        fs::read(operation.join(crate::upgrade_record::UPGRADE_RECORD)).unwrap(),
        record
    );
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
}

#[test]
fn production_reopening_requires_real_offline_attestation_and_the_expected_checksum() {
    let fixture = Fixture::new();
    fixture.retained_operation();
    for checksum in [
        [0; 32],
        fixture.rollback.executable().subject().archive_sha256(),
    ] {
        let result = PreparedReplacement::with_reopened_preparation(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.expected_prior(),
            checksum,
            std::slice::from_ref(&fixture.state),
            ReplacementDirection::Upgrade,
            |_| -> Result<(), InstallerStageError> {
                panic!("synthetic attestation became recovery authority")
            },
        );
        assert_eq!(result, Err(InstallerStageError::VerificationFailed));
    }
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
}

#[test]
fn changed_recovery_evidence_is_preserved_and_never_reaches_the_action() {
    for change in ["archive", "bundle", "record", "state", "unknown", "pending"] {
        let fixture = Fixture::new();
        let operation = fixture.retained_operation();
        let path = match change {
            "archive" => operation.join("rollback-kit/archive"),
            "bundle" => operation.join("rollback-kit/attestation.json"),
            "record" => operation.join(crate::upgrade_record::UPGRADE_RECORD),
            "state" => fixture.state.join("state.json"),
            "unknown" => operation.join("foreign"),
            "pending" => {
                operation.join(crate::install_phase::InstallPhase::Replaced.pending_file_name())
            }
            _ => unreachable!(),
        };
        fs::write(&path, b"changed").unwrap();
        if change == "pending" {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(
            fixture
                .recover(|_| -> Result<(), InstallerStageError> {
                    panic!("changed evidence reached recovery action")
                })
                .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), b"changed");
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
    }
}

#[test]
fn late_changes_after_kit_verification_block_recovery_without_repair() {
    for change in ["kit", "state", "prior"] {
        let fixture = Fixture::new();
        let operation = fixture.retained_operation();
        let path = match change {
            "kit" => operation.join("rollback-kit/archive"),
            "state" => fixture.state.join("state.json"),
            "prior" => fixture.destination.path().join(
                fixture
                    .rollback
                    .executable()
                    .subject()
                    .spec()
                    .executable_name(),
            ),
            _ => unreachable!(),
        };
        let result = PreparedReplacement::with_reopened_impl(
            fixture.destination.path(),
            &fixture.candidate,
            std::slice::from_ref(&fixture.state),
            ReplacementDirection::Upgrade,
            |staged| {
                let material = RetainedRollbackKit::reopen_with_test_subject(
                    staged,
                    &fixture.expected_prior(),
                    fixture.rollback.executable().subject().archive_sha256(),
                )?;
                fs::write(&path, b"late edit").unwrap();
                Ok(material)
            },
            |_| -> Result<(), InstallerStageError> { panic!("late change accepted") },
        );
        assert!(result.is_err());
        assert_eq!(fs::read(path).unwrap(), b"late edit");
    }
}

#[test]
fn omitted_roots_and_noncanonical_records_are_not_recovered() {
    let fixture = Fixture::new();
    let operation = fixture.retained_operation();
    let result = PreparedReplacement::with_reopened_impl(
        fixture.destination.path(),
        &fixture.candidate,
        &[],
        ReplacementDirection::Upgrade,
        |staged| {
            RetainedRollbackKit::reopen_with_test_subject(
                staged,
                &fixture.expected_prior(),
                fixture.rollback.executable().subject().archive_sha256(),
            )
        },
        |_| -> Result<(), InstallerStageError> { panic!("omitted state roots accepted") },
    );
    assert!(result.is_err());
    let path = operation.join(crate::upgrade_record::UPGRADE_RECORD);
    let mut record = fs::read(&path).unwrap();
    record.push(b'\n');
    fs::write(&path, &record).unwrap();
    assert!(
        fixture
            .recover(|_| -> Result<(), InstallerStageError> {
                panic!("noncanonical record accepted")
            })
            .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), record);
}

#[test]
fn preparation_owns_all_guards_and_preserves_the_prior_executable() {
    let fixture = Fixture::new();
    let mut prepared = fixture.prepare().unwrap();
    prepared.revalidate().unwrap();
    let authority = StateAuthority::open_existing(&fixture.state).unwrap();
    assert!(authority.try_lock_shared().is_err());
    assert_eq!(fixture.prepare().err(), Some(InstallerStageError::Conflict));
    assert_eq!(
        PreparedReplacement::prepare(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.rollback,
            &[]
        )
        .err(),
        Some(InstallerStageError::Conflict)
    );
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
    let operation = fixture
        .installer_state()
        .join(prepared.staged.record.operation_id());
    let record: serde_json::Value = serde_json::from_slice(
        &fs::read(operation.join(crate::upgrade_record::UPGRADE_RECORD)).unwrap(),
    )
    .unwrap();
    assert_eq!(record["phase"], "state_preflight_retained");
    assert_eq!(record["state_roots"].as_array().unwrap().len(), 1);
    assert_eq!(
        fs::read(operation.join("rollback-kit/archive")).unwrap(),
        fixture.rollback.archive_bytes()
    );
    assert!(!format!("{prepared:?}").contains("executable"));
    drop(prepared);
    let guard = authority.try_lock_exclusive().unwrap();
    drop(guard);
    // Ordinary first-install recovery must not consume upgrade preparation.
    assert!(
        crate::resume_authenticated_application_staging(
            fixture.destination.path(),
            &fixture.candidate
        )
        .is_err()
    );
    assert!(
        operation
            .join(crate::upgrade_record::UPGRADE_RECORD)
            .exists()
    );
}

#[test]
fn failed_preflight_does_not_start_installer_mutation() {
    let fixture = Fixture::new();
    let authority = StateAuthority::open_existing(&fixture.state).unwrap();
    let guard = authority.try_lock_shared().unwrap();
    assert_eq!(fixture.prepare().err(), Some(InstallerStageError::Conflict));
    assert!(!fixture.installer_state().exists());
    drop(guard);
    fs::write(fixture.state.join("state.json"), b"unsupported").unwrap();
    assert_eq!(
        fixture.prepare().err(),
        Some(InstallerStageError::UnsafeState)
    );
    assert!(!fixture.installer_state().exists());
    assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
}

#[test]
fn every_interrupted_preparation_preserves_existing_authority_and_releases_guards() {
    for stop in [
        PreparationBoundary::StatesLocked,
        PreparationBoundary::Staged,
        PreparationBoundary::KitRetained,
        PreparationBoundary::RecordRetained,
    ] {
        let fixture = Fixture::new();
        let result = PreparedReplacement::prepare_with_hook(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.rollback,
            std::slice::from_ref(&fixture.state),
            |boundary| {
                if boundary == stop {
                    Err(InstallerStageError::WriteFailed)
                } else {
                    Ok(())
                }
            },
        );
        let expected = if stop == PreparationBoundary::StatesLocked {
            InstallerStageError::WriteFailed
        } else {
            InstallerStageError::RecoveryRequired
        };
        assert_eq!(result.err(), Some(expected));
        assert_eq!(
            fixture.installer_state().exists(),
            stop != PreparationBoundary::StatesLocked
        );
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            EMPTY_STATE
        );
        let authority = StateAuthority::open_existing(&fixture.state).unwrap();
        let _guard = authority.try_lock_exclusive().unwrap();
    }
}

#[test]
fn changed_prior_at_each_write_boundary_is_preserved_for_recovery() {
    for change in [
        PreparationBoundary::Staged,
        PreparationBoundary::KitRetained,
        PreparationBoundary::RecordRetained,
    ] {
        let fixture = Fixture::new();
        let prior_path = fixture.destination.path().join(
            fixture
                .rollback
                .executable()
                .subject()
                .spec()
                .executable_name(),
        );
        let result = PreparedReplacement::prepare_with_hook(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.rollback,
            std::slice::from_ref(&fixture.state),
            |boundary| {
                if boundary == change {
                    fs::write(&prior_path, b"foreign edit").unwrap();
                }
                Ok(())
            },
        );
        assert_eq!(result.err(), Some(InstallerStageError::RecoveryRequired));
        assert_eq!(fixture.prior_bytes(), b"foreign edit");
        assert!(fixture.installer_state().exists());
    }
}

#[test]
fn uncooperative_state_changes_at_preparation_boundaries_never_replace_the_prior() {
    for change in [
        PreparationBoundary::Staged,
        PreparationBoundary::KitRetained,
        PreparationBoundary::RecordRetained,
    ] {
        let fixture = Fixture::new();
        let result = PreparedReplacement::prepare_with_hook(
            fixture.destination.path(),
            &fixture.candidate,
            &fixture.rollback,
            std::slice::from_ref(&fixture.state),
            |boundary| {
                if boundary == change {
                    fs::write(fixture.state.join("state.json"), b"uncooperative").unwrap();
                }
                Ok(())
            },
        );
        assert_eq!(result.err(), Some(InstallerStageError::RecoveryRequired));
        assert_eq!(fixture.prior_bytes(), fixture.rollback.executable().bytes());
        assert_eq!(
            fs::read(fixture.state.join("state.json")).unwrap(),
            b"uncooperative"
        );
        assert!(fixture.installer_state().exists());
    }
}
