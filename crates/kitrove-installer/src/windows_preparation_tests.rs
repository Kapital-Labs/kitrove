use super::*;
use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;

struct Fixture {
    destination: crate::windows_test_support::TestDestination,
    candidate: AuthenticatedApplicationExecutable,
    material: AuthenticatedRecoveryMaterial,
    state: PathBuf,
}

impl Fixture {
    fn new(direction: ReplacementDirection) -> Self {
        Self::new_in(direction, &std::env::current_dir().unwrap())
    }

    fn new_in(direction: ReplacementDirection, parent: &Path) -> Self {
        let (candidate, material) = crate::test_support::replacement_releases_with_bytes(
            b"old Windows executable",
            b"new Windows executable",
            direction,
        );
        Self::from_releases_in(candidate, material, parent)
    }

    fn from_releases_in(
        candidate: AuthenticatedApplicationExecutable,
        material: AuthenticatedRecoveryMaterial,
        parent: &Path,
    ) -> Self {
        // The standard-user runner supplies its own profile-owned working directory.
        let destination = crate::windows_test_support::destination_in(parent);
        {
            let directory =
                kitrove_windows_security::validate_install_directory(destination.path()).unwrap();
            let mut file = kitrove_windows_security::create_private_file(
                directory.directory().unwrap(),
                OsStr::new(material.executable().subject().spec().executable_name()),
            )
            .unwrap();
            file.write_all(material.executable().bytes()).unwrap();
            file.sync_all().unwrap();
        }
        let state = destination.path().join("app-state");
        let (authority, guard) =
            kitrove_state_lifecycle::StateAuthority::initialize_absent(&state).unwrap();
        authority
            .exclusive_access(&guard)
            .unwrap()
            .create_initial_state(crate::test_support::EMPTY_STATE)
            .unwrap();
        Self {
            destination,
            candidate,
            material,
            state,
        }
    }

    fn prepare(
        &self,
        direction: ReplacementDirection,
    ) -> Result<PreparedReplacement<'_>, InstallerStageError> {
        PreparedReplacement::prepare_direction_with_hook(
            self.destination.path(),
            &self.candidate,
            &self.material,
            std::slice::from_ref(&self.state),
            direction,
            |_| Ok(()),
        )
    }

    fn recover(&self, direction: ReplacementDirection) -> Result<(), InstallerStageError> {
        let expected = self.expected();
        PreparedReplacement::with_reopened_impl(
            self.destination.path(),
            &self.candidate,
            std::slice::from_ref(&self.state),
            direction,
            |staged| {
                RetainedRollbackKit::reopen_with_test_subject(
                    staged,
                    &expected,
                    self.material.executable().subject().archive_sha256(),
                )
            },
            |mut prepared| {
                assert_eq!(prepared.prior.direction(), direction);
                prepared.revalidate()?;
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&self.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                Ok(())
            },
        )
    }

    fn expected(&self) -> kitrove_release_provenance::ExpectedReleaseIdentity {
        kitrove_release_provenance::ExpectedReleaseIdentity::new(
            self.material.executable().subject().release_tag(),
            self.material.executable().subject().source_commit(),
        )
        .unwrap()
    }

    fn installed(&self) -> PathBuf {
        self.destination.path().join(
            self.material
                .executable()
                .subject()
                .spec()
                .executable_name(),
        )
    }
}

#[test]
fn elevated_replacement_preparation_is_nonmutating() {
    if !kitrove_windows_security::current_process_is_elevated().unwrap() {
        return;
    }
    let fixture = Fixture::new_in(ReplacementDirection::Upgrade, &std::env::temp_dir());
    assert!(matches!(
        fixture.prepare(ReplacementDirection::Upgrade),
        Err(InstallerStageError::UnsafeDestination)
    ));
    assert!(
        !fixture
            .destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .exists()
    );
    assert_eq!(
        fs::read(fixture.installed()).unwrap(),
        fixture.material.executable().bytes()
    );
}

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_preparation_and_recovery() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    pair_tests::exercise_owned_pair_moves();
    journal_tests::exercise_journal_writes();
    reopen_tests::exercise_fresh_reopening();
    for direction in [
        ReplacementDirection::Upgrade,
        ReplacementDirection::Rollback,
    ] {
        let fixture = Fixture::new(direction);
        let mut prepared = fixture.prepare(direction).unwrap();
        let operation = fixture
            .destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        prepared.revalidate().unwrap();
        assert!(fs::write(fixture.installed(), b"blocked writer").is_err());
        let authority =
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
        assert!(authority.try_lock_exclusive().is_err());
        drop(authority);
        drop(prepared);
        let record_bytes = fs::read(operation.join("upgrade.json")).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&record_bytes).unwrap();
        assert_eq!(
            record["direction"],
            serde_json::to_value(direction).unwrap()
        );
        assert_eq!(
            fs::read(operation.join("rollback-kit/archive")).unwrap(),
            fixture.material.archive_bytes()
        );
        assert_eq!(
            fs::read(fixture.installed()).unwrap(),
            fixture.material.executable().bytes()
        );
        fixture.recover(direction).unwrap();
        for wrong_direction in [
            ReplacementDirection::Upgrade,
            ReplacementDirection::Rollback,
        ] {
            if wrong_direction != direction {
                assert!(fixture.recover(wrong_direction).is_err());
            }
        }
        assert_eq!(
            fs::read(operation.join("upgrade.json")).unwrap(),
            record_bytes
        );
        assert_eq!(
            fs::read(fixture.installed()).unwrap(),
            fixture.material.executable().bytes()
        );
        assert!(
            PreparedReplacement::with_reopened_preparation(
                fixture.destination.path(),
                &fixture.candidate,
                &fixture.expected(),
                fixture.material.executable().subject().archive_sha256(),
                std::slice::from_ref(&fixture.state),
                direction,
                |_| -> Result<(), InstallerStageError> {
                    panic!("synthetic attestation cannot authorize production recovery")
                }
            )
            .is_err()
        );
    }
    for point in [
        PreparationBoundary::StatesLocked,
        PreparationBoundary::Staged,
        PreparationBoundary::KitRetained,
        PreparationBoundary::RecordRetained,
    ] {
        let fixture = Fixture::new(ReplacementDirection::Upgrade);
        assert!(
            PreparedReplacement::prepare_with_hook(
                fixture.destination.path(),
                &fixture.candidate,
                &fixture.material,
                std::slice::from_ref(&fixture.state),
                |seen| {
                    if seen == point {
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_eq!(
            fs::read(fixture.installed()).unwrap(),
            fixture.material.executable().bytes()
        );
        assert_eq!(
            fixture
                .destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .exists(),
            point != PreparationBoundary::StatesLocked
        );
        let authority =
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
        let _guard = authority.try_lock_exclusive().unwrap();
    }
    for change in ["record", "state"] {
        let fixture = Fixture::new(ReplacementDirection::Upgrade);
        let prepared = fixture.prepare(ReplacementDirection::Upgrade).unwrap();
        let operation = fixture
            .destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        drop(prepared);
        let path = if change == "record" {
            operation.join("upgrade.json")
        } else {
            fixture.state.join("state.json")
        };
        let bytes = if change == "record" {
            b"foreign record".as_slice()
        } else {
            br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":"work"}}"#
        };
        fs::write(&path, bytes).unwrap();
        assert!(fixture.recover(ReplacementDirection::Upgrade).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
        assert_eq!(
            fs::read(fixture.installed()).unwrap(),
            fixture.material.executable().bytes()
        );
    }
}

#[cfg(test)]
#[path = "windows_pair_tests.rs"]
mod pair_tests;

#[cfg(test)]
#[path = "windows_journal_write_tests.rs"]
mod journal_tests;

#[cfg(test)]
#[path = "windows_reopen_tests.rs"]
mod reopen_tests;
