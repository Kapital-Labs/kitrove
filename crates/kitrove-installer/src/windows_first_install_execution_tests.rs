use super::*;
use crate::windows_test_support::{TestDestination, destination_in, initialized_state};

#[cfg(test)]
#[path = "windows_first_install_recovery_tests.rs"]
mod recovery_tests;

struct Fixture {
    destination: TestDestination,
    state: PathBuf,
    executable: AuthenticatedApplicationExecutable,
}

impl Fixture {
    fn new() -> Self {
        let destination = destination_in(&std::env::current_dir().unwrap());
        let state = initialized_state(destination.path());
        let (executable, _) = crate::test_support::replacement_releases_with_bytes(
            b"prior executable",
            b"candidate executable",
            crate::replacement_direction::ReplacementDirection::Upgrade,
        );
        Self {
            destination,
            state,
            executable,
        }
    }

    fn prepare(&self) -> PreparedInstallation {
        PreparedInstallation::prepare(
            self.destination.path(),
            &self.executable,
            std::slice::from_ref(&self.state),
        )
        .unwrap()
    }

    fn operation(&self, prepared: &PreparedInstallation) -> PathBuf {
        self.destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id())
    }
}

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_state_guarded_installation() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    for succeeds in [true, false] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        let operation = fixture
            .destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(prepared.staged.record.operation_id());
        let hash = prepared.staged.executable_content_hash.clone();
        let name = prepared.staged.record.executable_name().to_owned();
        let result = prepared.install_with(
            |_, _| {
                if succeeds {
                    Ok(hash)
                } else {
                    Err(InstallerStageError::VerificationFailed)
                }
            },
            |_| {
                let authority =
                    kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
                assert!(authority.try_lock_shared().is_err());
                assert!(std::fs::write(operation.join(INSTALL_STATE_RECORD), b"foreign").is_err());
                Ok(())
            },
        );
        if succeeds {
            let installed = result.unwrap();
            assert_eq!(
                std::fs::read(installed.path).unwrap(),
                fixture.executable.bytes()
            );
            assert!(operation.join(InstallPhase::Committed.file_name()).exists());
        } else {
            assert_eq!(result.unwrap_err(), InstallerStageError::VerificationFailed);
            assert!(!fixture.destination.path().join(name).exists());
            assert_eq!(
                std::fs::read(operation.join(crate::install_phase::FAILED_EXECUTABLE)).unwrap(),
                fixture.executable.bytes()
            );
            assert!(
                operation
                    .join(InstallPhase::RolledBack.file_name())
                    .exists()
            );
        }
    }
    for phase in InstallPhase::all() {
        for point in [
            PhaseWriteBoundary::Created,
            PhaseWriteBoundary::FileSynced,
            PhaseWriteBoundary::Published,
        ] {
            let fixture = Fixture::new();
            let prepared = fixture.prepare();
            let operation = fixture
                .destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .join(prepared.staged.record.operation_id());
            let hash = prepared.staged.executable_content_hash.clone();
            let mut hit = false;
            let result = prepared.install_with(
                |_, _| {
                    if *phase == InstallPhase::RolledBack {
                        Err(InstallerStageError::VerificationFailed)
                    } else {
                        Ok(hash)
                    }
                },
                |boundary| {
                    if boundary == ExecutionBoundary::PhaseWrite(*phase, point) {
                        hit = true;
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(hit);
            assert_eq!(result.unwrap_err(), InstallerStageError::RecoveryRequired);
            let leaf = if point == PhaseWriteBoundary::Published {
                phase.file_name()
            } else {
                phase.pending_file_name()
            };
            let bytes = std::fs::read(operation.join(leaf)).unwrap();
            assert_eq!(bytes.is_empty(), point == PhaseWriteBoundary::Created);
            assert!(operation.join(INSTALL_STATE_RECORD).exists());
        }
    }
    for stop in [
        ExecutionBoundary::BeforePublication,
        ExecutionBoundary::Published,
        ExecutionBoundary::BeforeProbe,
        ExecutionBoundary::Probed,
        ExecutionBoundary::Restored,
    ] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        let hash = prepared.staged.executable_content_hash.clone();
        let mut hit = false;
        assert!(
            prepared
                .install_with(
                    |_, _| if stop == ExecutionBoundary::Restored {
                        Err(InstallerStageError::VerificationFailed)
                    } else {
                        Ok(hash)
                    },
                    |point| {
                        if point == stop {
                            hit = true;
                            std::fs::write(fixture.state.join("late-writer"), b"unmanaged")
                                .unwrap();
                        }
                        Ok(())
                    },
                )
                .is_err()
        );
        assert!(hit);
        assert_eq!(
            std::fs::read(fixture.state.join("late-writer")).unwrap(),
            b"unmanaged"
        );
    }
    // A new unrecognized entry invalidates the inventory before pending bytes are written.
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let operation = fixture
        .destination
        .path()
        .join(crate::INSTALLER_STATE_DIRECTORY)
        .join(prepared.staged.record.operation_id());
    assert_eq!(
        prepared
            .install_with(
                |_, _| panic!("invalid inventory reached the probe"),
                |point| {
                    if point
                        == ExecutionBoundary::PhaseWrite(
                            InstallPhase::Replaced,
                            PhaseWriteBoundary::Created,
                        )
                    {
                        std::fs::write(operation.join("foreign"), b"unmanaged").unwrap();
                    }
                    Ok(())
                },
            )
            .unwrap_err(),
        InstallerStageError::RecoveryRequired
    );
    assert!(
        std::fs::read(operation.join(InstallPhase::Replaced.pending_file_name()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read(operation.join("foreign")).unwrap(),
        b"unmanaged"
    );
}
