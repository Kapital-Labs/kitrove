use super::*;
use crate::installation_state::recovery::ReopenedInstallation;

#[cfg(test)]
#[path = "windows_first_install_resume_tests.rs"]
mod execution_tests;

#[cfg(test)]
#[path = "windows_first_install_retirement_tests.rs"]
mod retirement_tests;

fn snapshot(operation: &Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut files = std::fs::read_dir(operation)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read(entry.path()).unwrap())
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn reopen(fixture: &Fixture) -> Result<ReopenedInstallation, InstallerStageError> {
    ReopenedInstallation::reopen(
        fixture.destination.path(),
        &fixture.executable,
        std::slice::from_ref(&fixture.state),
    )
}

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_read_only_first_install_recovery() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    let mut stops = vec![
        (ExecutionBoundary::BeforePublication, false),
        (ExecutionBoundary::Published, false),
        (ExecutionBoundary::BeforeProbe, false),
        (ExecutionBoundary::Probed, false),
        (ExecutionBoundary::Restored, true),
    ];
    for &phase in InstallPhase::all() {
        for point in [
            PhaseWriteBoundary::Created,
            PhaseWriteBoundary::FileSynced,
            PhaseWriteBoundary::Published,
        ] {
            stops.push((
                ExecutionBoundary::PhaseWrite(phase, point),
                phase == InstallPhase::RolledBack,
            ));
        }
    }
    for (stop, fail_probe) in stops {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        let operation = fixture.operation(&prepared);
        let hash = prepared.staged.executable_content_hash.clone();
        let mut hit = false;
        assert!(
            prepared
                .install_with(
                    |_, _| if fail_probe {
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
        let before = snapshot(&operation);
        assert!(
            ReopenedInstallation::reopen(fixture.destination.path(), &fixture.executable, &[])
                .is_err()
        );
        assert_eq!(snapshot(&operation), before);
        let mut recovered = reopen(&fixture).unwrap();
        recovered.revalidate().unwrap();
        assert_eq!(snapshot(&operation), before);
        let authority =
            kitrove_state_lifecycle::StateAuthority::open_existing(&fixture.state).unwrap();
        assert!(authority.try_lock_shared().is_err());
        drop(recovered);
        assert!(authority.try_lock_shared().is_ok());

        // Every layout refuses stale selected state without reconciling journal evidence.
        std::fs::write(fixture.state.join("late-writer"), b"unmanaged").unwrap();
        assert!(reopen(&fixture).is_err());
        assert_eq!(snapshot(&operation), before);
    }

    // Empty, partial and complete canonical pending prefixes remain unchanged; foreign
    // bytes and a pending phase that overlaps a complete record cannot become authority.
    for partial in [true, false] {
        let fixture = Fixture::new();
        let prepared = fixture.prepare();
        let operation = fixture.operation(&prepared);
        assert!(
            prepared
                .install_with(
                    |_, _| unreachable!(),
                    |point| {
                        if point
                            == ExecutionBoundary::PhaseWrite(
                                InstallPhase::Replaced,
                                PhaseWriteBoundary::FileSynced,
                            )
                        {
                            Err(InstallerStageError::RecoveryRequired)
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        let path = operation.join(InstallPhase::Replaced.pending_file_name());
        let canonical = std::fs::read(&path).unwrap();
        let bytes = if partial {
            &canonical[..canonical.len() / 2]
        } else {
            &canonical[..]
        };
        kitrove_windows_security::write_current_user_owned_file_for_tests(&path, bytes).unwrap();
        let recovered = reopen(&fixture).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        drop(recovered);
        kitrove_windows_security::write_current_user_owned_file_for_tests(&path, b"foreign")
            .unwrap();
        let before = snapshot(&operation);
        assert!(reopen(&fixture).is_err());
        assert_eq!(snapshot(&operation), before);
        kitrove_windows_security::write_current_user_owned_file_for_tests(&path, &canonical)
            .unwrap();
        kitrove_windows_security::write_current_user_owned_file_for_tests(
            &operation.join(InstallPhase::Replaced.file_name()),
            &canonical,
        )
        .unwrap();
        let before = snapshot(&operation);
        assert!(reopen(&fixture).is_err());
        assert_eq!(snapshot(&operation), before);
    }
}
