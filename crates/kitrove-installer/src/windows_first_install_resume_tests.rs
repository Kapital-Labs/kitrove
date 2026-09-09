use super::*;
use crate::installation_state::recovery::RecoveryBoundary;

pub(super) fn interrupted(stop: ExecutionBoundary, fail: bool) -> (Fixture, PathBuf) {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let operation = fixture.operation(&prepared);
    let hash = prepared.staged.executable_content_hash.clone();
    let mut hit = false;
    assert!(
        prepared
            .install_with(
                |_, _| if fail {
                    Err(InstallerStageError::VerificationFailed)
                } else {
                    Ok(hash)
                },
                |point| if point == stop {
                    hit = true;
                    Err(InstallerStageError::RecoveryRequired)
                } else {
                    Ok(())
                },
            )
            .is_err()
    );
    assert!(hit);
    (fixture, operation)
}

fn forward(fixture: &Fixture) {
    let mut probed = false;
    let installed = reopen(fixture)
        .unwrap()
        .recover_with(
            |_, _| {
                probed = true;
                Ok(kitrove_model::ContentHash::digest(
                    fixture.executable.bytes(),
                ))
            },
            |_| Ok(()),
        )
        .unwrap();
    assert!(probed);
    assert_eq!(
        std::fs::read(installed.path).unwrap(),
        fixture.executable.bytes()
    );
}

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_first_install_recovery_execution() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    let mut stops = vec![
        ExecutionBoundary::BeforePublication,
        ExecutionBoundary::Published,
        ExecutionBoundary::BeforeProbe,
        ExecutionBoundary::Probed,
    ];
    for phase in [
        InstallPhase::Replaced,
        InstallPhase::Verified,
        InstallPhase::Committed,
    ] {
        for point in [
            PhaseWriteBoundary::Created,
            PhaseWriteBoundary::FileSynced,
            PhaseWriteBoundary::Published,
        ] {
            stops.push(ExecutionBoundary::PhaseWrite(phase, point));
        }
    }
    for stop in stops {
        let (fixture, _) = interrupted(stop, false);
        forward(&fixture);
        forward(&fixture);
    }
    for phase in [InstallPhase::Verified, InstallPhase::Committed] {
        for stop in [
            RecoveryBoundary::PhaseCreated(phase),
            RecoveryBoundary::PhaseCompleted(phase),
            RecoveryBoundary::PhasePublished(phase),
        ] {
            let (fixture, _) = interrupted(ExecutionBoundary::BeforeProbe, false);
            let mut hit = false;
            assert!(
                reopen(&fixture)
                    .unwrap()
                    .recover_with(
                        |_, _| Ok(kitrove_model::ContentHash::digest(
                            fixture.executable.bytes()
                        )),
                        |point| if point == stop {
                            hit = true;
                            Err(InstallerStageError::RecoveryRequired)
                        } else {
                            Ok(())
                        },
                    )
                    .is_err()
            );
            assert!(hit);
            forward(&fixture);
        }
    }
    for stop in [
        RecoveryBoundary::Restored,
        RecoveryBoundary::PhaseCreated(InstallPhase::RolledBack),
        RecoveryBoundary::PhaseCompleted(InstallPhase::RolledBack),
        RecoveryBoundary::PhasePublished(InstallPhase::RolledBack),
    ] {
        let (fixture, operation) = interrupted(
            ExecutionBoundary::PhaseWrite(InstallPhase::Committed, PhaseWriteBoundary::FileSynced),
            false,
        );
        let pending = operation.join(InstallPhase::Committed.pending_file_name());
        let bytes = std::fs::read(&pending).unwrap();
        let mut hit = false;
        assert!(
            reopen(&fixture)
                .unwrap()
                .recover_with(
                    |_, _| Err(InstallerStageError::VerificationFailed),
                    |point| if point == stop {
                        hit = true;
                        Err(InstallerStageError::RecoveryRequired)
                    } else {
                        Ok(())
                    },
                )
                .is_err()
        );
        assert!(hit);
        assert_eq!(
            reopen(&fixture)
                .unwrap()
                .recover_with(|_, _| panic!("restored candidate executed"), |_| Ok(()),)
                .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert_eq!(std::fs::read(pending).unwrap(), bytes);
    }
    let (fixture, operation) = interrupted(
        ExecutionBoundary::PhaseWrite(InstallPhase::Replaced, PhaseWriteBoundary::FileSynced),
        false,
    );
    let pending = operation.join(InstallPhase::Replaced.pending_file_name());
    let identity =
        kitrove_windows_security::file_identity(&std::fs::File::open(&pending).unwrap()).unwrap();
    forward(&fixture);
    assert_eq!(
        kitrove_windows_security::file_identity(
            &std::fs::File::open(operation.join(InstallPhase::Replaced.file_name())).unwrap()
        )
        .unwrap(),
        identity
    );

    // A second read-only lease prevents write reopening; failure leaves all bytes intact.
    let (fixture, operation) = interrupted(
        ExecutionBoundary::PhaseWrite(InstallPhase::Replaced, PhaseWriteBoundary::FileSynced),
        false,
    );
    let directory = kitrove_windows_security::validate_install_directory(&operation).unwrap();
    let other = kitrove_windows_security::open_private_file(
        directory.directory().unwrap(),
        OsStr::new(InstallPhase::Replaced.pending_file_name()),
    )
    .unwrap();
    let before = snapshot(&operation);
    assert!(
        reopen(&fixture)
            .unwrap()
            .recover_with(|_, _| unreachable!(), |_| Ok(()))
            .is_err()
    );
    assert_eq!(snapshot(&operation), before);
    drop(other);
    forward(&fixture);

    for stop in [
        RecoveryBoundary::Synced,
        RecoveryBoundary::Probed,
        RecoveryBoundary::PhaseCreated(InstallPhase::Verified),
        RecoveryBoundary::PhaseCompleted(InstallPhase::Verified),
        RecoveryBoundary::PhasePublished(InstallPhase::Verified),
        RecoveryBoundary::PhaseCreated(InstallPhase::Committed),
        RecoveryBoundary::PhaseCompleted(InstallPhase::Committed),
        RecoveryBoundary::PhasePublished(InstallPhase::Committed),
    ] {
        let (fixture, _) = interrupted(ExecutionBoundary::BeforeProbe, false);
        let mut hit = false;
        assert!(
            reopen(&fixture)
                .unwrap()
                .recover_with(
                    |_, _| Ok(kitrove_model::ContentHash::digest(
                        fixture.executable.bytes()
                    )),
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
    let (fixture, operation) = interrupted(
        ExecutionBoundary::PhaseWrite(InstallPhase::Committed, PhaseWriteBoundary::Published),
        false,
    );
    assert_eq!(
        reopen(&fixture)
            .unwrap()
            .recover_with(
                |_, _| Err(InstallerStageError::VerificationFailed),
                |_| Ok(())
            )
            .unwrap_err(),
        InstallerStageError::VerificationFailed
    );
    for phase in [
        InstallPhase::Verified,
        InstallPhase::Committed,
        InstallPhase::RolledBack,
    ] {
        assert!(operation.join(phase.file_name()).exists());
    }
    assert_eq!(
        reopen(&fixture)
            .unwrap()
            .recover_with(|_, _| panic!("restored candidate executed"), |_| Ok(()))
            .unwrap_err(),
        InstallerStageError::VerificationFailed
    );
}
