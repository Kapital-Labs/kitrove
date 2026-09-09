use std::ffi::OsStr;
use std::io::Write as _;
use std::path::Path;

use semver::Version;
use sha2::{Digest as _, Sha256};

use crate::install_phase::{
    FAILED_EXECUTABLE, InstallPhase, InstallPhaseRecord, InstallRecoveryPhase,
};
use crate::staging_policy::{OPERATION_RECORD, STAGED_EXECUTABLE};
use crate::windows_staging::{
    file_identity, native_identity, reopen_private_file_with_identity, require_exact_inventory,
    require_file_contents, require_identity, require_named_directory_identity,
    require_named_file_identity, revalidate_control_boundary,
};
use crate::{InstalledApplication, InstallerStageError, StagedApplication};

pub(crate) fn install(
    staged: StagedApplication,
) -> Result<InstalledApplication, InstallerStageError> {
    install_impl(staged, crate::verify_installed_application)
}

pub(crate) fn recover(
    destination_parent: &Path,
    input: &crate::StagingInput<'_>,
) -> Result<InstalledApplication, InstallerStageError> {
    kitrove_windows_security::require_unelevated_process()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    recover_after_security_preflight(
        destination_parent,
        input,
        crate::verify_installed_application,
    )
}

fn recover_after_security_preflight<F>(
    destination_parent: &Path,
    input: &crate::StagingInput<'_>,
    verify_version: F,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    let (mut staged, phase) =
        crate::windows_recovery::resume_detected_phase_after_security_preflight(
            destination_parent,
            input,
            None,
            || Ok(()),
        )?;
    match phase {
        InstallRecoveryPhase::Prepared => install_impl(staged, verify_version),
        InstallRecoveryPhase::ReplacedUnrecorded => {
            write_phase_record(&mut staged, InstallPhase::Replaced)?;
            complete_replaced_install(staged, verify_version, |_| Ok(()))
        }
        InstallRecoveryPhase::Replaced => {
            complete_replaced_install(staged, verify_version, |_| Ok(()))
        }
        InstallRecoveryPhase::Verified => {
            write_phase_record(&mut staged, InstallPhase::Committed)?;
            finish_committed(staged)
        }
        InstallRecoveryPhase::Committed => finish_committed(staged),
        InstallRecoveryPhase::RolledBack => Err(InstallerStageError::VerificationFailed),
        InstallRecoveryPhase::RolledBackUnrecorded => {
            write_phase_record(&mut staged, InstallPhase::RolledBack)?;
            revalidate_stage(&staged, InstallRecoveryPhase::RolledBack, None)?;
            Err(InstallerStageError::VerificationFailed)
        }
    }
}

fn install_impl<F>(
    staged: StagedApplication,
    verify_version: F,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    install_with_phase_hook(staged, verify_version, |_| Ok(()))
}

fn install_with_phase_hook<F>(
    mut staged: StagedApplication,
    verify_version: F,
    mut after_phase: impl FnMut(InstallPhase) -> Result<(), InstallerStageError>,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    revalidate_stage(&staged, InstallRecoveryPhase::Prepared, None)?;
    publish_retained_executable(&mut staged)?;
    write_phase_record(&mut staged, InstallPhase::Replaced)?;
    after_phase(InstallPhase::Replaced)?;
    complete_replaced_install(staged, verify_version, after_phase)
}

/// The caller validates the complete operation and selected state before this move.
pub(crate) fn publish_retained_executable(
    staged: &mut StagedApplication,
) -> Result<(), InstallerStageError> {
    let executable_name = staged.record.executable_name().to_owned();
    let staged_identity = kitrove_windows_security::file_identity(staged._retained.executable()?)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if native_identity(staged_identity) != *staged.record.staged_identity() {
        return Err(InstallerStageError::UnsafeState);
    }

    // Release the read-only no-delete-sharing handle before the guarded move opens DELETE access.
    // The move independently binds the source identity; reopening must bind that same identity.
    drop(staged._retained.executable.take());
    match kitrove_windows_security::move_owned_file(
        &staged._retained.operation,
        OsStr::new(STAGED_EXECUTABLE),
        staged
            ._retained
            .destination
            .directory()
            .map_err(|_| InstallerStageError::UnsafeDestination)?,
        OsStr::new(&executable_name),
        OsStr::new(FAILED_EXECUTABLE),
        staged_identity,
    ) {
        Ok(()) => {}
        Err(kitrove_windows_security::OwnedObjectPromotionError::Failed)
            if require_named_file_identity(
                &staged._retained.operation,
                OsStr::new(STAGED_EXECUTABLE),
                *staged.record.staged_identity(),
                false,
            )
            .is_ok()
                && staged
                    ._retained
                    .destination
                    .path()
                    .join(&executable_name)
                    .symlink_metadata()
                    .is_ok() =>
        {
            return Err(InstallerStageError::DestinationOccupied);
        }
        Err(_) => return Err(InstallerStageError::RecoveryRequired),
    }

    staged._retained.executable = Some(
        reopen_private_file_with_identity(
            staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            OsStr::new(&executable_name),
            native_identity(staged_identity),
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );

    Ok(())
}

fn complete_replaced_install<F>(
    mut staged: StagedApplication,
    verify_version: F,
    mut after_phase: impl FnMut(InstallPhase) -> Result<(), InstallerStageError>,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    let executable_name = staged.record.executable_name().to_owned();
    revalidate_stage(
        &staged,
        InstallRecoveryPhase::Replaced,
        Some(&executable_name),
    )?;

    let installed_path = staged._retained.destination.path().join(&executable_name);
    if verify_version(&installed_path, staged.manifest.release_version()).as_ref()
        != Ok(&staged.executable_content_hash)
    {
        rollback_failed_install(&mut staged, &executable_name)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        return Err(InstallerStageError::VerificationFailed);
    }

    revalidate_stage(
        &staged,
        InstallRecoveryPhase::Replaced,
        Some(&executable_name),
    )?;
    write_phase_record(&mut staged, InstallPhase::Verified)?;
    after_phase(InstallPhase::Verified)?;
    revalidate_stage(
        &staged,
        InstallRecoveryPhase::Verified,
        Some(&executable_name),
    )?;
    write_phase_record(&mut staged, InstallPhase::Committed)?;
    after_phase(InstallPhase::Committed)?;
    finish_committed(staged)
}

fn finish_committed(
    staged: StagedApplication,
) -> Result<InstalledApplication, InstallerStageError> {
    let executable_name = staged.record.executable_name().to_owned();
    let installed_path = staged._retained.destination.path().join(&executable_name);
    revalidate_stage(
        &staged,
        InstallRecoveryPhase::Committed,
        Some(&executable_name),
    )?;

    Ok(InstalledApplication {
        record: staged.record,
        manifest: staged.manifest,
        path: installed_path,
    })
}

fn rollback_failed_install(
    staged: &mut StagedApplication,
    executable_name: &str,
) -> Result<(), InstallerStageError> {
    revalidate_stage(
        staged,
        InstallRecoveryPhase::Replaced,
        Some(executable_name),
    )?;
    restore_install_absence(staged, executable_name)?;
    write_phase_record(staged, InstallPhase::RolledBack)?;
    revalidate_stage(staged, InstallRecoveryPhase::RolledBack, None)
}

/// Moves only the retained installed identity; never overwrites a failed-copy name.
pub(crate) fn restore_install_absence(
    staged: &mut StagedApplication,
    executable_name: &str,
) -> Result<(), InstallerStageError> {
    let identity = kitrove_windows_security::file_identity(staged._retained.executable()?)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    drop(staged._retained.executable.take());
    kitrove_windows_security::move_owned_file(
        staged
            ._retained
            .destination
            .directory()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
        OsStr::new(executable_name),
        &staged._retained.operation,
        OsStr::new(FAILED_EXECUTABLE),
        OsStr::new(FAILED_EXECUTABLE),
        identity,
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    staged._retained.executable = Some(
        reopen_private_file_with_identity(
            &staged._retained.operation,
            OsStr::new(FAILED_EXECUTABLE),
            native_identity(identity),
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseWriteBoundary {
    Created,
    FileSynced,
    Published,
}

fn write_phase_record(
    staged: &mut StagedApplication,
    phase: InstallPhase,
) -> Result<(), InstallerStageError> {
    write_phase_record_with_validation(staged, phase, |_, _| Ok(()))
}

pub(crate) fn write_phase_record_with_validation(
    staged: &mut StagedApplication,
    phase: InstallPhase,
    mut validate: impl FnMut(&StagedApplication, PhaseWriteBoundary) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    let bytes = expected_phase_record(staged, phase)?.to_json()?;
    if bytes.len() > crate::install_phase::MAX_PHASE_RECORD_BYTES {
        return Err(InstallerStageError::WriteFailed);
    }
    let pending_name = OsStr::new(phase.pending_file_name());
    let final_name = OsStr::new(phase.file_name());
    let mut marker =
        kitrove_windows_security::create_private_file(&staged._retained.operation, pending_name)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
    let marker_identity = kitrove_windows_security::file_identity(&marker)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    validate(staged, PhaseWriteBoundary::Created)?;
    marker
        .write_all(&bytes)
        .and_then(|()| marker.sync_all())
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    validate(staged, PhaseWriteBoundary::FileSynced)?;
    drop(marker);
    kitrove_windows_security::promote_owned_file(
        &staged._retained.operation,
        pending_name,
        final_name,
        OsStr::new("phase-record.rollback"),
        marker_identity,
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    let marker = reopen_private_file_with_identity(
        &staged._retained.operation,
        final_name,
        native_identity(marker_identity),
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_file_contents(&marker, bytes.len() as u64, Sha256::digest(&bytes).into())?;
    require_named_file_identity(
        &staged._retained.operation,
        final_name,
        native_identity(marker_identity),
        false,
    )?;
    staged._retained.phase_markers.push(marker);
    validate(staged, PhaseWriteBoundary::Published)
}

fn expected_phase_record(
    staged: &StagedApplication,
    phase: InstallPhase,
) -> Result<InstallPhaseRecord, InstallerStageError> {
    InstallPhaseRecord::new(
        phase,
        &staged.record,
        *staged.record.staged_identity(),
        staged.manifest.executable_sha256(),
    )
}

pub(crate) fn revalidate_stage(
    staged: &StagedApplication,
    phase: InstallRecoveryPhase,
    installed_name: Option<&str>,
) -> Result<(), InstallerStageError> {
    revalidate_stage_with_extra_entries(staged, phase, installed_name, &[])
}

/// Validates ordinary stage authority; the caller separately authenticates every extra entry.
pub(crate) fn revalidate_stage_with_extra_entries(
    staged: &StagedApplication,
    phase: InstallRecoveryPhase,
    installed_name: Option<&str>,
    extra_entries: &[&OsStr],
) -> Result<(), InstallerStageError> {
    revalidate_stage_namespace(staged)?;
    revalidate_stage_contents_with_extra_entries(staged, phase, installed_name, extra_entries)
}

pub(crate) fn revalidate_stage_namespace(
    staged: &StagedApplication,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    revalidate_control_boundary(
        &retained.destination,
        &retained.state,
        *staged.record.state_identity(),
        &retained.lock,
    )?;
    require_named_directory_identity(
        &retained.state,
        OsStr::new(staged.record.operation_id()),
        *staged.record.operation_identity(),
    )?;
    Ok(())
}

/// Authenticates retained contents independently of their active or historical parent.
/// The caller must separately retain and validate the operation's namespace authority.
pub(crate) fn revalidate_stage_contents_with_extra_entries(
    staged: &StagedApplication,
    phase: InstallRecoveryPhase,
    installed_name: Option<&str>,
    extra_entries: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    require_identity(&retained.operation, *staged.record.operation_identity())?;
    require_identity(retained.executable()?, *staged.record.staged_identity())?;
    let mut inventory = phase.inventory();
    inventory.extend_from_slice(extra_entries);
    require_exact_inventory(&retained.operation, &inventory)?;

    revalidate_operation_record(staged)?;
    require_file_contents(
        retained.executable()?,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )?;

    for (marker_phase, marker) in phase.marker_phases().iter().zip(&retained.phase_markers) {
        let marker_bytes = expected_phase_record(staged, *marker_phase)?.to_json()?;
        let marker_identity = file_identity(marker)?;
        require_named_file_identity(
            &retained.operation,
            OsStr::new(marker_phase.file_name()),
            marker_identity,
            false,
        )?;
        require_file_contents(
            marker,
            marker_bytes.len() as u64,
            Sha256::digest(&marker_bytes).into(),
        )?;
    }
    if retained.phase_markers.len() != phase.marker_phases().len() {
        return Err(InstallerStageError::UnsafeState);
    }

    if matches!(
        phase,
        InstallRecoveryPhase::RolledBack | InstallRecoveryPhase::RolledBackUnrecorded
    ) {
        let parent = cap_std::fs::Dir::from_std_file(
            retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?
                .try_clone()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
        );
        match parent.symlink_metadata(staged.record.executable_name()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(InstallerStageError::RecoveryRequired),
        }
    }

    let executable_link = match phase {
        InstallRecoveryPhase::Prepared => Some(STAGED_EXECUTABLE),
        InstallRecoveryPhase::RolledBack | InstallRecoveryPhase::RolledBackUnrecorded => {
            Some(FAILED_EXECUTABLE)
        }
        _ => installed_name,
    };
    if let Some(name) = executable_link {
        let parent = if installed_name.is_some() {
            retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::UnsafeDestination)?
        } else {
            &retained.operation
        };
        require_named_file_identity(
            parent,
            OsStr::new(name),
            *staged.record.staged_identity(),
            false,
        )?;
    }
    Ok(())
}

/// Shared exact record validation; executable placement and inventory are separate.
pub(crate) fn revalidate_operation_record(
    staged: &StagedApplication,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let record_identity = file_identity(&retained.record)?;
    require_named_file_identity(
        &retained.operation,
        OsStr::new(OPERATION_RECORD),
        record_identity,
        false,
    )?;
    let record_bytes = staged
        .record
        .to_json()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_file_contents(
        &retained.record,
        record_bytes.len() as u64,
        Sha256::digest(&record_bytes).into(),
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::StagingInput;
    use crate::windows_staging::stage_after_security_preflight_for_tests;
    use crate::windows_test_support::{authenticated_executable, destination, inventory};

    #[test]
    fn rollback_recovery_preserves_a_newly_occupied_destination() {
        for unrecorded in [false, true] {
            let destination = destination();
            let executable = authenticated_executable();
            let input = StagingInput::from(&executable);
            let staged =
                stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
            let operation = destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .join(staged.record.operation_id());
            assert_eq!(
                install_impl(staged, |_, _| Err(InstallerStageError::VerificationFailed)),
                Err(InstallerStageError::VerificationFailed)
            );
            if unrecorded {
                std::fs::remove_file(operation.join(InstallPhase::RolledBack.file_name())).unwrap();
            }
            let before = inventory(&operation);
            let candidate = std::fs::read(operation.join(FAILED_EXECUTABLE)).unwrap();
            let occupied = destination.path().join("kitrove.exe");
            std::fs::write(&occupied, b"foreign").unwrap();
            assert_eq!(
                recover_after_security_preflight(destination.path(), &input, |_, _| unreachable!()),
                Err(InstallerStageError::RecoveryRequired)
            );
            assert_eq!(std::fs::read(occupied).unwrap(), b"foreign");
            assert_eq!(
                std::fs::read(operation.join(FAILED_EXECUTABLE)).unwrap(),
                candidate
            );
            assert_eq!(inventory(&operation), before);
        }
    }

    #[test]
    fn recovery_records_an_identity_bound_move_without_a_phase_marker() {
        for rolled_back in [false, true] {
            let destination = destination();
            let executable = authenticated_executable();
            let input = StagingInput::from(&executable);
            let staged =
                stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
            let expected_hash = staged.executable_content_hash.clone();
            let operation = destination
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .join(staged.record.operation_id());
            let marker = if rolled_back {
                assert_eq!(
                    install_impl(staged, |_, _| Err(InstallerStageError::VerificationFailed)),
                    Err(InstallerStageError::VerificationFailed)
                );
                InstallPhase::RolledBack
            } else {
                assert_eq!(
                    install_with_phase_hook(
                        staged,
                        |_, _| unreachable!(),
                        |_| { Err(InstallerStageError::RecoveryRequired) }
                    ),
                    Err(InstallerStageError::RecoveryRequired)
                );
                InstallPhase::Replaced
            };
            // Recreate the exact namespace at the move/phase-write boundary, after
            // all retained handles from the interrupted invocation have been dropped.
            std::fs::remove_file(operation.join(marker.file_name())).unwrap();
            let pending = operation.join(marker.pending_file_name());
            kitrove_windows_security::write_current_user_owned_file_for_tests(
                &pending,
                b"{partial",
            )
            .unwrap();
            let result = recover_after_security_preflight(destination.path(), &input, |_, _| {
                assert!(!rolled_back);
                Ok(expected_hash)
            });
            if rolled_back {
                assert_eq!(result, Err(InstallerStageError::VerificationFailed));
                assert!(!destination.path().join("kitrove.exe").exists());
                assert!(operation.join(FAILED_EXECUTABLE).is_file());
            } else {
                assert_eq!(
                    result.unwrap().path(),
                    destination.path().join("kitrove.exe")
                );
            }
            assert!(operation.join(marker.file_name()).is_file());
            assert!(!pending.exists());
        }
    }

    #[test]
    fn unrecorded_move_recovery_preserves_a_changed_candidate() {
        let destination = destination();
        let executable = authenticated_executable();
        let input = StagingInput::from(&executable);
        let staged = stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record.operation_id());
        assert_eq!(
            install_with_phase_hook(
                staged,
                |_, _| unreachable!(),
                |_| { Err(InstallerStageError::RecoveryRequired) }
            ),
            Err(InstallerStageError::RecoveryRequired)
        );
        std::fs::remove_file(operation.join(InstallPhase::Replaced.file_name())).unwrap();
        let candidate = destination.path().join("kitrove.exe");
        std::fs::write(&candidate, b"changed").unwrap();
        assert!(
            recover_after_security_preflight(destination.path(), &input, |_, _| unreachable!())
                .is_err()
        );
        assert_eq!(std::fs::read(candidate).unwrap(), b"changed");
        assert_eq!(
            inventory(&operation),
            vec![OsString::from(OPERATION_RECORD)]
        );
    }

    #[test]
    fn durable_install_phases_rebind_the_original_executable() {
        for (stop, recovery) in [
            (InstallPhase::Replaced, InstallRecoveryPhase::Replaced),
            (InstallPhase::Verified, InstallRecoveryPhase::Verified),
            (InstallPhase::Committed, InstallRecoveryPhase::Committed),
        ] {
            let destination = destination();
            let executable = authenticated_executable();
            let input = StagingInput::from(&executable);
            let staged =
                stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
            let original_identity = *staged.record.staged_identity();
            let expected_hash = staged.executable_content_hash.clone();
            let mut reached = false;
            assert_eq!(
                install_with_phase_hook(
                    staged,
                    |_, _| Ok(expected_hash),
                    |phase| {
                        if phase == stop {
                            reached = true;
                            Err(InstallerStageError::RecoveryRequired)
                        } else {
                            Ok(())
                        }
                    }
                ),
                Err(InstallerStageError::RecoveryRequired)
            );
            assert!(reached);
            let resumed = crate::windows_recovery::resume_phase_after_security_preflight(
                destination.path(),
                &input,
                recovery,
                || Ok(()),
            )
            .unwrap();
            assert_eq!(*resumed.record.staged_identity(), original_identity);
            assert_eq!(
                resumed._retained.phase_markers.len(),
                recovery.marker_phases().len()
            );
            let expected_hash = resumed.executable_content_hash.clone();
            drop(resumed);
            let mut probed = false;
            let installed = recover_after_security_preflight(destination.path(), &input, |_, _| {
                probed = true;
                Ok(expected_hash)
            })
            .unwrap();
            assert_eq!(probed, stop == InstallPhase::Replaced);
            assert_eq!(installed.path(), destination.path().join("kitrove.exe"));
        }
    }

    #[test]
    fn rolled_back_phase_rebinds_the_quarantined_candidate() {
        let destination = destination();
        let executable = authenticated_executable();
        let input = StagingInput::from(&executable);
        let staged = stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
        let original_identity = *staged.record.staged_identity();
        assert_eq!(
            install_impl(staged, |_, _| Err(InstallerStageError::VerificationFailed)),
            Err(InstallerStageError::VerificationFailed)
        );
        let resumed = crate::windows_recovery::resume_phase_after_security_preflight(
            destination.path(),
            &input,
            InstallRecoveryPhase::RolledBack,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(*resumed.record.staged_identity(), original_identity);
        assert!(!destination.path().join("kitrove.exe").exists());
        drop(resumed);
        assert_eq!(
            recover_after_security_preflight(destination.path(), &input, |_, _| unreachable!()),
            Err(InstallerStageError::VerificationFailed)
        );
    }

    #[test]
    fn recovery_rolls_back_an_unverified_replacement_when_the_probe_fails() {
        let destination = destination();
        let executable = authenticated_executable();
        let input = StagingInput::from(&executable);
        let staged = stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
        assert_eq!(
            install_with_phase_hook(
                staged,
                |_, _| unreachable!(),
                |_| { Err(InstallerStageError::RecoveryRequired) }
            ),
            Err(InstallerStageError::RecoveryRequired)
        );
        let mut probed = false;
        assert_eq!(
            recover_after_security_preflight(destination.path(), &input, |_, _| {
                probed = true;
                Err(InstallerStageError::VerificationFailed)
            }),
            Err(InstallerStageError::VerificationFailed)
        );
        assert!(probed);
        assert!(!destination.path().join("kitrove.exe").exists());
    }

    #[test]
    fn recovery_rejects_a_corrupted_phase_marker_without_removing_the_candidate() {
        let destination = destination();
        let executable = authenticated_executable();
        let input = StagingInput::from(&executable);
        let staged = stage_after_security_preflight_for_tests(destination.path(), &input).unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record.operation_id());
        assert_eq!(
            install_with_phase_hook(
                staged,
                |_, _| unreachable!(),
                |_| { Err(InstallerStageError::RecoveryRequired) }
            ),
            Err(InstallerStageError::RecoveryRequired)
        );
        let candidate = destination.path().join("kitrove.exe");
        let original_bytes = std::fs::read(&candidate).unwrap();
        std::fs::write(operation.join(InstallPhase::Replaced.file_name()), b"{}").unwrap();
        assert!(
            crate::windows_recovery::resume_phase_after_security_preflight(
                destination.path(),
                &input,
                InstallRecoveryPhase::Replaced,
                || Ok(()),
            )
            .is_err()
        );
        assert_eq!(std::fs::read(candidate).unwrap(), original_bytes);
        assert_eq!(
            std::fs::read(operation.join(InstallPhase::Replaced.file_name())).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn publishes_and_commits_an_absent_destination() {
        let destination = destination();
        let executable = authenticated_executable();
        let staged = stage_after_security_preflight_for_tests(
            destination.path(),
            &StagingInput::from(&executable),
        )
        .unwrap();
        let expected_hash = staged.executable_content_hash.clone();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record.operation_id());

        let installed = install_impl(staged, |path, _| {
            assert!(path.is_file());
            Ok(expected_hash)
        })
        .unwrap();

        assert_eq!(installed.path(), destination.path().join("kitrove.exe"));
        assert_eq!(
            inventory(&operation),
            vec![
                OsString::from(InstallPhase::Committed.file_name()),
                OsString::from(OPERATION_RECORD),
                OsString::from(InstallPhase::Replaced.file_name()),
                OsString::from(InstallPhase::Verified.file_name()),
            ]
        );
    }

    #[test]
    fn verification_failure_restores_an_absent_destination() {
        let destination = destination();
        let executable = authenticated_executable();
        let staged = stage_after_security_preflight_for_tests(
            destination.path(),
            &StagingInput::from(&executable),
        )
        .unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record.operation_id());

        assert_eq!(
            install_impl(staged, |_, _| Err(InstallerStageError::VerificationFailed)),
            Err(InstallerStageError::VerificationFailed)
        );
        assert!(!destination.path().join("kitrove.exe").exists());
        assert_eq!(
            inventory(&operation),
            vec![
                OsString::from(FAILED_EXECUTABLE),
                OsString::from(OPERATION_RECORD),
                OsString::from(InstallPhase::Replaced.file_name()),
                OsString::from(InstallPhase::RolledBack.file_name()),
            ]
        );
    }

    #[test]
    fn destination_collision_preserves_both_files() {
        let destination = destination();
        let executable = authenticated_executable();
        let staged = stage_after_security_preflight_for_tests(
            destination.path(),
            &StagingInput::from(&executable),
        )
        .unwrap();
        std::fs::write(destination.path().join("kitrove.exe"), b"occupied").unwrap();

        assert_eq!(
            install_impl(staged, |_, _| unreachable!()),
            Err(InstallerStageError::DestinationOccupied)
        );
        assert_eq!(
            std::fs::read(destination.path().join("kitrove.exe")).unwrap(),
            b"occupied"
        );
    }

    #[test]
    fn rollback_authority_change_preserves_the_installed_candidate_for_recovery() {
        let destination = destination();
        let executable = authenticated_executable();
        let staged = stage_after_security_preflight_for_tests(
            destination.path(),
            &StagingInput::from(&executable),
        )
        .unwrap();
        let operation = destination
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record.operation_id());

        assert_eq!(
            install_impl(staged, |_, _| {
                std::fs::write(operation.join("unexpected"), b"conflict").unwrap();
                Err(InstallerStageError::VerificationFailed)
            }),
            Err(InstallerStageError::RecoveryRequired)
        );
        assert!(destination.path().join("kitrove.exe").is_file());
        assert_eq!(
            std::fs::read(operation.join("unexpected")).unwrap(),
            b"conflict"
        );
    }
}
