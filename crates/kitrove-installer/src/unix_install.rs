use std::ffi::{OsStr, OsString};
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

use semver::Version;

#[cfg(test)]
use crate::install_phase::COMMITTED_RECORD;
use crate::install_phase::{
    DetectedInstallPhase, FAILED_EXECUTABLE, InstallPhase, InstallPhaseRecord, InstallRecoveryPhase,
};
use crate::record::MAX_OPERATION_RECORD_BYTES;
use crate::staging_policy::require_absent_entry as require_absent_destination;
use crate::unix_recovery::{
    detect_install_phase, open_exact_private_file, resume, resume_install_phase,
};
use crate::unix_staging::{
    INSTALLER_LOCK, OPERATION_RECORD, STAGED_EXECUTABLE, create_private_file, metadata_identity,
    read_bounded_file, require_exact_inventory, require_named_directory_identity,
    require_named_file_identity, require_named_file_identity_with_link_count,
    revalidate_control_boundary, sync_directory, verify_sha256_contents,
};
use crate::{InstalledApplication, InstallerStageError, StagedApplication, StagingInput};

#[path = "first_install_retirement.rs"]
mod retirement;

pub(crate) fn install(
    staged: StagedApplication,
) -> Result<InstalledApplication, InstallerStageError> {
    install_impl(staged, crate::verify_installed_application)
}

pub(crate) fn recover(
    destination_parent: &Path,
    input: &StagingInput<'_>,
) -> Result<InstalledApplication, InstallerStageError> {
    recover_impl(
        destination_parent,
        input,
        crate::verify_installed_application,
    )
}

fn install_impl<F>(
    staged: StagedApplication,
    verify_version: F,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    let mut staged = staged;
    revalidate_prepared_stage(&staged)?;
    let executable_name = staged.record.executable_name().to_owned();
    require_absent_destination(staged._retained.destination.directory(), &executable_name)?;
    if let Err(error) = publish_retained_executable(&mut staged, &executable_name) {
        return match staged
            ._retained
            .destination
            .directory()
            .symlink_metadata(&executable_name)
        {
            Err(probe) if probe.kind() == std::io::ErrorKind::NotFound => Err(error),
            _ => Err(InstallerStageError::RecoveryRequired),
        };
    }
    write_phase_record(&mut staged, InstallPhase::Replaced)?;

    complete_replaced_install(staged, verify_version)
}

fn complete_replaced_install<F>(
    staged: StagedApplication,
    verify_version: F,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    let mut staged = staged;
    let installed_path = destination_executable_path(&staged);
    if revalidate_replaced_stage(&staged).is_err() {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let observed_probe_hash = verify_version(&installed_path, staged.manifest.release_version());
    if observed_probe_hash.as_ref() != Ok(&staged.executable_content_hash) {
        return rollback_failed_install(&mut staged)
            .and(Err(InstallerStageError::VerificationFailed));
    }
    if revalidate_replaced_stage(&staged).is_err() {
        return Err(InstallerStageError::RecoveryRequired);
    }
    write_phase_record(&mut staged, InstallPhase::Verified)?;
    revalidate_verified_stage(&staged).map_err(|_| InstallerStageError::RecoveryRequired)?;
    write_phase_record(&mut staged, InstallPhase::Committed)?;
    revalidate_committed_stage(&staged).map_err(|_| InstallerStageError::RecoveryRequired)?;

    Ok(InstalledApplication {
        record: staged.record,
        manifest: staged.manifest,
        path: installed_path,
    })
}

fn recover_impl<F>(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    verify_version: F,
) -> Result<InstalledApplication, InstallerStageError>
where
    F: FnOnce(&Path, &Version) -> Result<kitrove_model::ContentHash, InstallerStageError>,
{
    match detect_install_phase(destination_parent, input)? {
        DetectedInstallPhase::Prepared => {
            install_impl(resume(destination_parent, input)?, verify_version)
        }
        DetectedInstallPhase::Replaced => complete_replaced_install(
            resume_install_phase(destination_parent, input, InstallRecoveryPhase::Replaced)?,
            verify_version,
        ),
        DetectedInstallPhase::Verified => {
            let mut staged =
                resume_install_phase(destination_parent, input, InstallRecoveryPhase::Verified)?;
            revalidate_verified_stage(&staged)?;
            write_phase_record(&mut staged, InstallPhase::Committed)?;
            finish_committed(staged)
        }
        DetectedInstallPhase::Committed => finish_committed(resume_install_phase(
            destination_parent,
            input,
            InstallRecoveryPhase::Committed,
        )?),
        DetectedInstallPhase::RollbackHandoff => {
            let staged = resume_install_phase(
                destination_parent,
                input,
                InstallRecoveryPhase::RollbackHandoff,
            )?;
            complete_rollback_handoff(staged)
        }
        DetectedInstallPhase::ReplacedUnrecorded => {
            let mut staged = resume(destination_parent, input)?;
            attach_installed_application(&mut staged)?;
            persist_recovered_replacement(&mut staged)?;
            complete_replaced_install(staged, verify_version)
        }
        DetectedInstallPhase::RollingBack => {
            let _ = verify_version;
            let mut staged =
                resume_install_phase(destination_parent, input, InstallRecoveryPhase::RollingBack)?;
            persist_recovered_rollback(&mut staged)?;
            revalidate_rolled_back_stage(&staged)?;
            Err(InstallerStageError::VerificationFailed)
        }
        DetectedInstallPhase::RolledBack => {
            let _ = verify_version;
            let staged =
                resume_install_phase(destination_parent, input, InstallRecoveryPhase::RolledBack)?;
            revalidate_rolled_back_stage(&staged)?;
            Err(InstallerStageError::VerificationFailed)
        }
    }
}

fn complete_rollback_handoff(
    mut staged: StagedApplication,
) -> Result<InstalledApplication, InstallerStageError> {
    revalidate_rollback_handoff_stage(&staged)?;
    sync_retained_installed(&staged)?;
    sync_directory(&staged._retained.operation)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    revalidate_rollback_handoff_stage(&staged)?;
    remove_rollback_handoff_name(&staged, &[])?;
    sync_directory(staged._retained.destination.directory())
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    revalidate_rolling_back_stage(&staged)?;
    persist_recovered_rollback(&mut staged)?;
    revalidate_rolled_back_stage(&staged)?;
    Err(InstallerStageError::VerificationFailed)
}

pub(crate) fn remove_rollback_handoff_name(
    staged: &StagedApplication,
    extra: &[&OsStr],
) -> Result<(), InstallerStageError> {
    revalidate_rollback_handoff_with_extra_entries(staged, extra)?;
    staged
        ._retained
        .destination
        .directory()
        .remove_file(staged.record.executable_name())
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryDurabilityBoundary {
    Leaf,
    DestinationDirectory,
    OperationDirectory,
}

fn persist_recovered_replacement(
    staged: &mut StagedApplication,
) -> Result<(), InstallerStageError> {
    persist_recovered_replacement_impl(staged, |_| Ok(()))
}

fn persist_recovered_replacement_impl<F>(
    staged: &mut StagedApplication,
    mut boundary: F,
) -> Result<(), InstallerStageError>
where
    F: FnMut(RecoveryDurabilityBoundary) -> Result<(), InstallerStageError>,
{
    sync_retained_installed(staged)?;
    boundary(RecoveryDurabilityBoundary::Leaf)?;
    sync_directory(staged._retained.destination.directory())
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    boundary(RecoveryDurabilityBoundary::DestinationDirectory)?;
    revalidate_prepared_stage(staged)?;
    revalidate_installed_leaf(staged)?;
    write_phase_record(staged, InstallPhase::Replaced)
}

fn persist_recovered_rollback(staged: &mut StagedApplication) -> Result<(), InstallerStageError> {
    persist_recovered_rollback_impl(staged, |_| Ok(()))
}

fn persist_recovered_rollback_impl<F>(
    staged: &mut StagedApplication,
    mut boundary: F,
) -> Result<(), InstallerStageError>
where
    F: FnMut(RecoveryDurabilityBoundary) -> Result<(), InstallerStageError>,
{
    sync_retained_installed(staged)?;
    boundary(RecoveryDurabilityBoundary::Leaf)?;
    sync_directory(&staged._retained.operation)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    boundary(RecoveryDurabilityBoundary::OperationDirectory)?;
    sync_directory(staged._retained.destination.directory())
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    boundary(RecoveryDurabilityBoundary::DestinationDirectory)?;
    revalidate_rolling_back_stage(staged)?;
    write_phase_record(staged, InstallPhase::RolledBack)
}

fn sync_retained_installed(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    staged
        ._retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?
        .sync_all()
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

fn finish_committed(
    staged: StagedApplication,
) -> Result<InstalledApplication, InstallerStageError> {
    revalidate_committed_stage(&staged)?;
    Ok(InstalledApplication {
        path: destination_executable_path(&staged),
        record: staged.record,
        manifest: staged.manifest,
    })
}

#[cfg(target_vendor = "apple")]
fn publish_native_executable(
    staged: &StagedApplication,
    executable_name: &str,
) -> Result<(), InstallerStageError> {
    rustix::fs::fclonefileat(
        &staged._retained.executable,
        staged._retained.destination.directory(),
        executable_name,
        rustix::fs::CloneFlags::empty(),
    )
    .map_err(publication_error)
}

#[cfg(target_os = "linux")]
fn publish_native_executable(
    staged: &StagedApplication,
    executable_name: &str,
) -> Result<(), InstallerStageError> {
    use cap_fs_ext::OsMetadataExt as _;
    use cap_std::fs::PermissionsExt as _;
    use std::os::fd::AsRawFd as _;

    let temporary = rustix::fs::openat(
        staged._retained.destination.directory(),
        ".",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::TMPFILE,
        rustix::fs::Mode::from_raw_mode(0o700),
    )
    .map_err(publication_error)?;
    let mut temporary = cap_std::fs::File::from_std(std::fs::File::from(temporary));
    temporary
        .set_permissions(cap_std::fs::Permissions::from_mode(0o700))
        .map_err(|_| InstallerStageError::WriteFailed)?;
    let mut staged_reader = staged
        ._retained
        .executable
        .try_clone()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    staged_reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallerStageError::WriteFailed)?;
    let expected_size = staged.record.executable_size();
    let copied = std::io::copy(&mut staged_reader.take(expected_size + 1), &mut temporary)
        .map_err(|_| InstallerStageError::WriteFailed)?;
    if copied != expected_size {
        return Err(InstallerStageError::WriteFailed);
    }
    temporary
        .flush()
        .and_then(|()| temporary.sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)?;
    verify_sha256_contents(
        &temporary,
        expected_size,
        staged.manifest.executable_sha256(),
    )?;
    let metadata = temporary
        .metadata()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    let current_user = u64::from(rustix::process::geteuid().as_raw());
    if !metadata.is_file()
        || metadata.is_symlink()
        || u64::from(metadata.uid()) != current_user
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.len() != expected_size
        || metadata.nlink() != 0
    {
        return Err(InstallerStageError::WriteFailed);
    }
    let source = format!("/proc/self/fd/{}", temporary.as_raw_fd());
    rustix::fs::linkat(
        rustix::fs::CWD,
        source,
        staged._retained.destination.directory(),
        executable_name,
        rustix::fs::AtFlags::SYMLINK_FOLLOW,
    )
    .map_err(publication_error)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn publish_native_executable(
    _staged: &StagedApplication,
    _executable_name: &str,
) -> Result<(), InstallerStageError> {
    Err(InstallerStageError::UnsupportedPlatform)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationBoundary {
    Published,
    FileSynced,
    DirectorySynced,
}

pub(crate) fn publish_retained_executable(
    staged: &mut StagedApplication,
    executable_name: &str,
) -> Result<(), InstallerStageError> {
    publish_retained_executable_impl(staged, executable_name, |_| Ok(()))
}

fn publish_retained_executable_impl<F>(
    staged: &mut StagedApplication,
    executable_name: &str,
    mut boundary: F,
) -> Result<(), InstallerStageError>
where
    F: FnMut(PublicationBoundary) -> Result<(), InstallerStageError>,
{
    publish_native_executable(staged, executable_name)?;
    boundary(PublicationBoundary::Published)?;
    attach_installed_application(staged)?;
    staged
        ._retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?
        .sync_all()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    boundary(PublicationBoundary::FileSynced)?;
    sync_directory(staged._retained.destination.directory())
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    boundary(PublicationBoundary::DirectorySynced)
}

fn publication_error(error: rustix::io::Errno) -> InstallerStageError {
    if error == rustix::io::Errno::EXIST {
        InstallerStageError::DestinationOccupied
    } else {
        InstallerStageError::WriteFailed
    }
}

pub(crate) fn attach_installed_application(
    staged: &mut StagedApplication,
) -> Result<(), InstallerStageError> {
    let installed = open_exact_private_file(
        staged._retained.destination.directory(),
        staged.record.executable_name(),
        0o700,
        staged.record.executable_size(),
    )?;
    staged._retained.installed = Some(installed.file);
    revalidate_installed_leaf(staged)
}

pub(crate) fn revalidate_installed_leaf(
    staged: &StagedApplication,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let installed = retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    let identity = metadata_identity(
        &installed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    require_named_file_identity(
        retained.destination.directory(),
        staged.record.executable_name(),
        installed,
        identity,
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        installed,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )
}

fn write_phase_record(
    staged: &mut StagedApplication,
    phase: InstallPhase,
) -> Result<(), InstallerStageError> {
    write_phase_record_impl(staged, phase, |_| Ok(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseWriteBoundary {
    Created,
    FileSynced,
    Published,
    DirectorySynced,
}

/// The current marker is pending until its no-replace publication succeeds.
pub(crate) fn require_phase_write_inventory(
    staged: &StagedApplication,
    phase: InstallPhase,
    point: PhaseWriteBoundary,
    extra: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let mut inventory = phase.inventory();
    if matches!(
        point,
        PhaseWriteBoundary::Created | PhaseWriteBoundary::FileSynced
    ) {
        for name in &mut inventory {
            if *name == OsStr::new(phase.file_name()) {
                *name = OsStr::new(phase.pending_file_name());
            }
        }
    }
    inventory.extend_from_slice(extra);
    require_exact_inventory(&staged._retained.operation, &inventory)
}

fn write_phase_record_impl<F>(
    staged: &mut StagedApplication,
    phase: InstallPhase,
    mut boundary: F,
) -> Result<(), InstallerStageError>
where
    F: FnMut(PhaseWriteBoundary) -> Result<(), InstallerStageError>,
{
    write_phase_record_with_validation(staged, phase, |_, point| boundary(point))
}

pub(crate) fn write_phase_record_with_validation(
    staged: &mut StagedApplication,
    phase: InstallPhase,
    mut boundary: impl FnMut(&StagedApplication, PhaseWriteBoundary) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let installed = retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    let installed_identity = metadata_identity(
        &installed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    let phase_record = InstallPhaseRecord::new(
        phase,
        &staged.record,
        installed_identity,
        staged.manifest.executable_sha256(),
    )?;
    let bytes = phase_record.to_json()?;
    let pending_name = phase.pending_file_name();
    let mut marker = create_private_file(&retained.operation, OsStr::new(pending_name), 0o600)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    let publish = (|| {
        boundary(staged, PhaseWriteBoundary::Created)?;
        marker
            .write_all(&bytes)
            .and_then(|()| marker.sync_all())
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        boundary(staged, PhaseWriteBoundary::FileSynced)?;
        let metadata = marker
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        require_named_file_identity(
            &retained.operation,
            pending_name,
            &marker,
            metadata_identity(&metadata),
            0o600,
            bytes.len() as u64,
        )?;
        if read_bounded_file(&marker, crate::install_phase::MAX_PHASE_RECORD_BYTES)? != bytes {
            return Err(InstallerStageError::RecoveryRequired);
        }
        rename_noreplace(
            &retained.operation,
            OsStr::new(pending_name),
            &retained.operation,
            OsStr::new(phase.file_name()),
        )?;
        boundary(staged, PhaseWriteBoundary::Published)?;
        sync_directory(&retained.operation)?;
        boundary(staged, PhaseWriteBoundary::DirectorySynced)?;
        require_named_file_identity(
            &retained.operation,
            phase.file_name(),
            &marker,
            metadata_identity(&metadata),
            0o600,
            bytes.len() as u64,
        )
    })();
    publish.map_err(|_| InstallerStageError::RecoveryRequired)?;
    staged._retained.phase_markers.push(marker);
    Ok(())
}

fn require_phase_records(
    staged: &StagedApplication,
    highest: InstallPhase,
    installed_identity: crate::NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let phases = highest.chain();
    if retained.phase_markers.len() != phases.len() {
        return Err(InstallerStageError::RecoveryRequired);
    }
    for (phase, marker) in phases.iter().zip(&retained.phase_markers) {
        let metadata = marker
            .metadata()
            .map_err(|_| InstallerStageError::UnsafeState)?;
        let size = metadata.len();
        if size == 0 || size > crate::install_phase::MAX_PHASE_RECORD_BYTES as u64 {
            return Err(InstallerStageError::UnsafeState);
        }
        require_named_file_identity(
            &retained.operation,
            phase.file_name(),
            marker,
            metadata_identity(&metadata),
            0o600,
            size,
        )?;
        let bytes = read_bounded_file(marker, crate::install_phase::MAX_PHASE_RECORD_BYTES)?;
        let observed = InstallPhaseRecord::parse_canonical(&bytes)?;
        let expected = InstallPhaseRecord::new(
            *phase,
            &staged.record,
            installed_identity,
            staged.manifest.executable_sha256(),
        )?;
        observed.require_matches(&expected)?;
    }
    Ok(())
}

fn revalidate_prepared_stage(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    revalidate_prepared_stage_with_extra_entries(staged, &[])
}

/// Validates ordinary staging authority; the caller must separately authenticate any extra entry.
pub(crate) fn revalidate_prepared_stage_with_extra_entries(
    staged: &StagedApplication,
    extra_entries: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    revalidate_common(staged)?;
    let mut inventory = vec![OsStr::new(STAGED_EXECUTABLE), OsStr::new(OPERATION_RECORD)];
    inventory.extend_from_slice(extra_entries);
    require_exact_inventory(&retained.operation, &inventory)?;
    revalidate_staged_leaf(staged)
}

pub(crate) fn revalidate_staged_leaf(
    staged: &StagedApplication,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    require_named_file_identity(
        &retained.operation,
        STAGED_EXECUTABLE,
        &retained.executable,
        *staged.record.staged_identity(),
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        &retained.executable,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )
    .map_err(|_| InstallerStageError::UnsafeState)
}

fn revalidate_replaced_stage(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    revalidate_phase_stage(staged, InstallPhase::Replaced)
}

fn revalidate_verified_stage(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    revalidate_phase_stage(staged, InstallPhase::Verified)
}

fn revalidate_committed_stage(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    revalidate_phase_stage(staged, InstallPhase::Committed)
}

fn revalidate_rolled_back_stage(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    revalidate_rollback_stage(
        staged,
        InstallRecoveryPhase::RolledBack,
        InstallPhase::RolledBack,
    )
}

fn revalidate_rolling_back_stage(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    revalidate_rollback_stage(
        staged,
        InstallRecoveryPhase::RollingBack,
        InstallPhase::Replaced,
    )
}

fn revalidate_rollback_handoff_stage(
    staged: &StagedApplication,
) -> Result<(), InstallerStageError> {
    revalidate_rollback_handoff_with_extra_entries(staged, &[])
}

pub(crate) fn revalidate_rollback_handoff_with_extra_entries(
    staged: &StagedApplication,
    extra: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    revalidate_common(staged)?;
    let mut inventory = InstallRecoveryPhase::RollbackHandoff.inventory();
    inventory.extend_from_slice(extra);
    require_exact_inventory(&retained.operation, &inventory)?;
    require_named_file_identity(
        &retained.operation,
        STAGED_EXECUTABLE,
        &retained.executable,
        *staged.record.staged_identity(),
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        &retained.executable,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )?;
    let failed = retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    let failed_identity = metadata_identity(
        &failed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    require_named_file_identity_with_link_count(
        &retained.operation,
        FAILED_EXECUTABLE,
        failed,
        failed_identity,
        0o700,
        staged.record.executable_size(),
        2,
    )?;
    let destination = crate::unix_recovery::open_exact_private_file_with_link_count(
        retained.destination.directory(),
        staged.record.executable_name(),
        0o700,
        staged.record.executable_size(),
        2,
    )?;
    if destination.identity != failed_identity {
        return Err(InstallerStageError::UnsafeState);
    }
    verify_sha256_contents(
        failed,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )?;
    require_phase_records(staged, InstallPhase::Replaced, failed_identity)
}

fn revalidate_rollback_stage(
    staged: &StagedApplication,
    recovery_phase: InstallRecoveryPhase,
    highest_record: InstallPhase,
) -> Result<(), InstallerStageError> {
    revalidate_common(staged)?;
    revalidate_rollback_contents(staged, recovery_phase, highest_record)
}

fn revalidate_rollback_contents(
    staged: &StagedApplication,
    recovery_phase: InstallRecoveryPhase,
    highest_record: InstallPhase,
) -> Result<(), InstallerStageError> {
    revalidate_rollback_contents_with_extra_entries(staged, recovery_phase, highest_record, &[])
}

pub(crate) fn revalidate_rollback_contents_with_extra_entries(
    staged: &StagedApplication,
    recovery_phase: InstallRecoveryPhase,
    highest_record: InstallPhase,
    extra: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let mut inventory = recovery_phase.inventory();
    inventory.extend_from_slice(extra);
    require_exact_inventory(&retained.operation, &inventory)?;
    require_absent_destination(
        retained.destination.directory(),
        staged.record.executable_name(),
    )?;
    let failed = retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    let identity = metadata_identity(
        &failed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    require_named_file_identity(
        &retained.operation,
        FAILED_EXECUTABLE,
        failed,
        identity,
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        failed,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )?;
    require_phase_records(staged, highest_record, identity)
}

fn revalidate_phase_stage(
    staged: &StagedApplication,
    phase: InstallPhase,
) -> Result<(), InstallerStageError> {
    revalidate_common(staged)?;
    revalidate_phase_contents(staged, phase)
}

fn revalidate_phase_contents(
    staged: &StagedApplication,
    phase: InstallPhase,
) -> Result<(), InstallerStageError> {
    revalidate_phase_contents_with_extra_entries(staged, phase, &[])
}

pub(crate) fn revalidate_phase_contents_with_extra_entries(
    staged: &StagedApplication,
    phase: InstallPhase,
    extra: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let mut inventory = phase.inventory();
    inventory.extend_from_slice(extra);
    require_exact_inventory(&retained.operation, &inventory)?;
    require_named_file_identity(
        &retained.operation,
        STAGED_EXECUTABLE,
        &retained.executable,
        *staged.record.staged_identity(),
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        &retained.executable,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )
    .map_err(|_| InstallerStageError::UnsafeState)?;
    let installed = retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    let installed_identity = metadata_identity(
        &installed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    require_named_file_identity(
        retained.destination.directory(),
        staged.record.executable_name(),
        installed,
        installed_identity,
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        installed,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_phase_records(staged, phase, installed_identity)
}

/// Revalidates retained containers and the candidate record, not executable placement.
pub(crate) fn revalidate_common(staged: &StagedApplication) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    revalidate_control_boundary(
        &retained.destination,
        &retained.state,
        *staged.record.state_identity(),
        &retained.lock,
    )?;
    require_named_directory_identity(
        &retained.state,
        staged.record.operation_id(),
        &retained.operation,
        *staged.record.operation_identity(),
    )?;
    require_exact_inventory(
        &retained.state,
        &[
            OsStr::new(INSTALLER_LOCK),
            OsStr::new(staged.record.operation_id()),
        ],
    )?;
    revalidate_operation_record(staged)
}

/// Operation-record leaf validation without assuming the active operation's parent.
pub(crate) fn revalidate_operation_record(
    staged: &StagedApplication,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    let canonical = staged
        .record
        .to_json()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let record_identity = retained
        .record
        .metadata()
        .map(|metadata| metadata_identity(&metadata))
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_named_file_identity(
        &retained.operation,
        OPERATION_RECORD,
        &retained.record,
        record_identity,
        0o600,
        canonical.len() as u64,
    )?;
    if read_bounded_file(&retained.record, MAX_OPERATION_RECORD_BYTES)? == canonical {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

fn rollback_failed_install(staged: &mut StagedApplication) -> Result<(), InstallerStageError> {
    rollback_failed_install_with_state(staged, &[], |_| Ok(()))
}

pub(crate) fn rollback_failed_install_with_state(
    staged: &mut StagedApplication,
    extra: &[&OsStr],
    mut validate_state: impl FnMut(&StagedApplication) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    revalidate_common(staged)?;
    revalidate_phase_contents_with_extra_entries(staged, InstallPhase::Replaced, extra)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    validate_state(staged)?;
    let retained = &staged._retained;
    rename_noreplace(
        retained.destination.directory(),
        OsStr::new(staged.record.executable_name()),
        &retained.operation,
        OsStr::new(FAILED_EXECUTABLE),
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    sync_directory(&retained.operation)
        .and_then(|()| sync_directory(retained.destination.directory()))
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_absent_destination(
        retained.destination.directory(),
        staged.record.executable_name(),
    )?;
    let failed = retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    let failed_identity = metadata_identity(
        &failed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    require_named_file_identity(
        &retained.operation,
        FAILED_EXECUTABLE,
        failed,
        failed_identity,
        0o700,
        staged.record.executable_size(),
    )?;
    verify_sha256_contents(
        failed,
        staged.record.executable_size(),
        staged.manifest.executable_sha256(),
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    validate_state(staged)?;
    write_phase_record_with_validation(staged, InstallPhase::RolledBack, |staged, point| {
        revalidate_common(staged)?;
        require_phase_write_inventory(staged, InstallPhase::RolledBack, point, extra)?;
        validate_state(staged)
    })
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    revalidate_common(staged)?;
    revalidate_rollback_contents_with_extra_entries(
        staged,
        InstallRecoveryPhase::RolledBack,
        InstallPhase::RolledBack,
        extra,
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    validate_state(staged)
}

pub(crate) fn destination_executable_path(staged: &StagedApplication) -> PathBuf {
    let parent = PathBuf::from(OsString::from_vec(
        staged._retained.destination.path_bytes().to_vec(),
    ));
    parent.join(staged.record.executable_name())
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
pub(crate) fn rename_noreplace(
    source_parent: &cap_std::fs::Dir,
    source_name: &OsStr,
    destination_parent: &cap_std::fs::Dir,
    destination_name: &OsStr,
) -> Result<(), InstallerStageError> {
    rustix::fs::renameat_with(
        source_parent,
        source_name,
        destination_parent,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            InstallerStageError::DestinationOccupied
        } else {
            InstallerStageError::WriteFailed
        }
    })
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
pub(crate) fn rename_noreplace(
    _source_parent: &cap_std::fs::Dir,
    _source_name: &OsStr,
    _destination_parent: &cap_std::fs::Dir,
    _destination_name: &OsStr,
) -> Result<(), InstallerStageError> {
    Err(InstallerStageError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::test_support::{private_tempdir, staging_input};
    use crate::unix_staging::stage;

    const EXECUTABLE: &[u8] = b"authenticated executable";
    const VERSIONED_EXECUTABLE: &[u8] = b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n";

    fn probe_hash() -> kitrove_model::ContentHash {
        kitrove_model::ContentHash::digest(EXECUTABLE)
    }

    fn publish_for_test(staged: &mut StagedApplication) {
        let executable_name = staged.record.executable_name().to_owned();
        publish_retained_executable(staged, &executable_name).unwrap();
    }

    #[test]
    fn installs_into_an_absent_destination_and_commits_after_version_evidence() {
        let root = private_tempdir();
        let staged = stage(root.path(), &staging_input(EXECUTABLE)).unwrap();
        let operation_id = staged.record().operation_id().to_owned();
        let installed = install_impl(staged, |_, expected| {
            assert_eq!(expected, &Version::new(1, 2, 3));
            Ok(probe_hash())
        })
        .unwrap();

        assert_eq!(
            fs::read(installed.path()).unwrap(),
            b"authenticated executable"
        );
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(operation_id);
        assert!(operation.join(COMMITTED_RECORD).is_file());
        assert!(operation.join(OPERATION_RECORD).is_file());
        assert!(operation.join(STAGED_EXECUTABLE).is_file());
    }

    #[test]
    fn real_version_probe_commits_the_published_application() {
        let root = private_tempdir();
        let input = staging_input(VERSIONED_EXECUTABLE);
        let staged = stage(root.path(), &input).unwrap();

        let installed = install(staged).unwrap();

        assert_eq!(fs::read(installed.path()).unwrap(), VERSIONED_EXECUTABLE);
    }

    #[test]
    fn occupied_destination_is_preserved_without_moving_the_stage() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        fs::write(root.path().join(input.executable_name), b"unmanaged").unwrap();
        let staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());

        assert_eq!(
            install_impl(staged, |_, _| Ok(probe_hash())).unwrap_err(),
            InstallerStageError::DestinationOccupied
        );
        assert_eq!(
            fs::read(root.path().join(input.executable_name)).unwrap(),
            b"unmanaged"
        );
        assert_eq!(
            fs::read(operation.join(STAGED_EXECUTABLE)).unwrap(),
            b"authenticated executable"
        );
    }

    #[test]
    fn failed_version_evidence_restores_the_absent_precondition() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());

        assert_eq!(
            install_impl(staged, |_, _| Err(InstallerStageError::VerificationFailed)).unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert!(!root.path().join(input.executable_name).exists());
        assert_eq!(
            fs::read(operation.join(STAGED_EXECUTABLE)).unwrap(),
            b"authenticated executable"
        );
        assert!(!operation.join(COMMITTED_RECORD).exists());
        assert!(operation.join(FAILED_EXECUTABLE).is_file());
    }

    #[test]
    fn recovery_completes_each_durable_first_install_phase() {
        for phase in [
            DetectedInstallPhase::Prepared,
            DetectedInstallPhase::Replaced,
            DetectedInstallPhase::Verified,
            DetectedInstallPhase::Committed,
        ] {
            let root = private_tempdir();
            let input = staging_input(EXECUTABLE);
            let mut staged = stage(root.path(), &input).unwrap();
            let operation = root
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .join(staged.record().operation_id());
            match phase {
                DetectedInstallPhase::Prepared => drop(staged),
                DetectedInstallPhase::Replaced | DetectedInstallPhase::Verified => {
                    publish_for_test(&mut staged);
                    write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                    if phase == DetectedInstallPhase::Verified {
                        write_phase_record(&mut staged, InstallPhase::Verified).unwrap();
                    }
                    drop(staged);
                }
                DetectedInstallPhase::Committed => {
                    install_impl(staged, |_, _| Ok(probe_hash())).unwrap();
                }
                DetectedInstallPhase::ReplacedUnrecorded
                | DetectedInstallPhase::RollbackHandoff
                | DetectedInstallPhase::RollingBack
                | DetectedInstallPhase::RolledBack => unreachable!(),
            }

            let installed = recover_impl(root.path(), &input, |_, _| Ok(probe_hash()))
                .unwrap_or_else(|error| panic!("failed to recover {phase:?}: {error:?}"));
            assert_eq!(
                fs::read(installed.path()).unwrap(),
                b"authenticated executable"
            );
            assert!(operation.join(COMMITTED_RECORD).is_file());
            assert!(operation.join(STAGED_EXECUTABLE).is_file());
        }
    }

    #[test]
    fn recovery_rolls_back_a_replaced_candidate_that_fails_its_probe() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let mut staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());
        publish_for_test(&mut staged);
        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
        drop(staged);

        assert_eq!(
            recover_impl(root.path(), &input, |_, _| {
                Err(InstallerStageError::VerificationFailed)
            })
            .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert!(!root.path().join(input.executable_name).exists());
        assert_eq!(
            fs::read(operation.join(STAGED_EXECUTABLE)).unwrap(),
            b"authenticated executable"
        );
    }

    #[test]
    fn recovery_records_a_replacement_interrupted_before_its_phase_write() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let mut staged = stage(root.path(), &input).unwrap();
        publish_for_test(&mut staged);
        drop(staged);

        let installed = recover_impl(root.path(), &input, |_, _| Ok(probe_hash())).unwrap();
        assert_eq!(fs::read(installed.path()).unwrap(), EXECUTABLE);
    }

    #[test]
    fn recovery_finishes_and_authenticates_an_interrupted_rollback() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let mut staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());
        publish_for_test(&mut staged);
        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
        rename_noreplace(
            staged._retained.destination.directory(),
            OsStr::new(input.executable_name),
            &staged._retained.operation,
            OsStr::new(FAILED_EXECUTABLE),
        )
        .unwrap();
        drop(staged);

        assert_eq!(
            recover_impl(root.path(), &input, |_, _| Ok(probe_hash())).unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert!(
            operation
                .join(crate::install_phase::ROLLED_BACK_RECORD)
                .is_file()
        );
        assert_eq!(
            recover_impl(root.path(), &input, |_, _| Ok(probe_hash())).unwrap_err(),
            InstallerStageError::VerificationFailed
        );
    }

    #[test]
    fn probe_evidence_must_bind_the_authenticated_bytes() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let staged = stage(root.path(), &input).unwrap();

        assert_eq!(
            install_impl(staged, |_, _| {
                Ok(kitrove_model::ContentHash::digest(b"other"))
            })
            .unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert!(!root.path().join(input.executable_name).exists());
    }

    #[test]
    fn namespace_replacement_never_publishes_foreign_bytes() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let mut staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());
        revalidate_prepared_stage(&staged).unwrap();
        fs::rename(
            operation.join(STAGED_EXECUTABLE),
            operation.join("retained-source"),
        )
        .unwrap();
        fs::write(operation.join(STAGED_EXECUTABLE), b"foreign").unwrap();
        fs::set_permissions(
            operation.join(STAGED_EXECUTABLE),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        publish_retained_executable(&mut staged, input.executable_name).unwrap();
        assert_eq!(
            fs::read(root.path().join(input.executable_name)).unwrap(),
            EXECUTABLE
        );
    }

    #[test]
    fn recovery_completes_after_every_publication_boundary() {
        for boundary in [
            PublicationBoundary::Published,
            PublicationBoundary::FileSynced,
            PublicationBoundary::DirectorySynced,
        ] {
            let root = private_tempdir();
            let input = staging_input(EXECUTABLE);
            let mut staged = stage(root.path(), &input).unwrap();
            let executable_name = staged.record.executable_name().to_owned();
            assert_eq!(
                publish_retained_executable_impl(&mut staged, &executable_name, |observed| {
                    if observed == boundary {
                        Err(InstallerStageError::WriteFailed)
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err(),
                InstallerStageError::WriteFailed
            );
            drop(staged);

            let installed = recover_impl(root.path(), &input, |_, _| Ok(probe_hash()))
                .unwrap_or_else(|error| panic!("failed recovery after {boundary:?}: {error:?}"));
            assert_eq!(fs::read(installed.path()).unwrap(), EXECUTABLE);
        }
    }

    #[test]
    fn replacement_recovery_survives_a_second_crash_at_every_sync_boundary() {
        for boundary in [
            RecoveryDurabilityBoundary::Leaf,
            RecoveryDurabilityBoundary::DestinationDirectory,
        ] {
            let root = private_tempdir();
            let input = staging_input(EXECUTABLE);
            let staged = stage(root.path(), &input).unwrap();
            publish_native_executable(&staged, input.executable_name).unwrap();
            drop(staged);

            let mut recovered = resume(root.path(), &input).unwrap();
            attach_installed_application(&mut recovered).unwrap();
            assert_eq!(
                persist_recovered_replacement_impl(&mut recovered, |observed| {
                    if observed == boundary {
                        Err(InstallerStageError::WriteFailed)
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err(),
                InstallerStageError::WriteFailed
            );
            drop(recovered);

            let installed = recover_impl(root.path(), &input, |_, _| Ok(probe_hash()))
                .unwrap_or_else(|error| {
                    panic!("failed second recovery after {boundary:?}: {error:?}")
                });
            assert_eq!(fs::read(installed.path()).unwrap(), EXECUTABLE);
        }
    }

    #[test]
    fn rollback_recovery_survives_a_second_crash_at_every_sync_boundary() {
        for boundary in [
            RecoveryDurabilityBoundary::Leaf,
            RecoveryDurabilityBoundary::OperationDirectory,
            RecoveryDurabilityBoundary::DestinationDirectory,
        ] {
            let root = private_tempdir();
            let input = staging_input(EXECUTABLE);
            let mut staged = stage(root.path(), &input).unwrap();
            publish_for_test(&mut staged);
            write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
            rename_noreplace(
                staged._retained.destination.directory(),
                OsStr::new(input.executable_name),
                &staged._retained.operation,
                OsStr::new(FAILED_EXECUTABLE),
            )
            .unwrap();
            drop(staged);

            let mut recovered =
                resume_install_phase(root.path(), &input, InstallRecoveryPhase::RollingBack)
                    .unwrap();
            let mut observed_boundaries = Vec::new();
            assert_eq!(
                persist_recovered_rollback_impl(&mut recovered, |observed| {
                    observed_boundaries.push(observed);
                    if observed == boundary {
                        Err(InstallerStageError::WriteFailed)
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err(),
                InstallerStageError::WriteFailed
            );
            let expected_boundaries = match boundary {
                RecoveryDurabilityBoundary::Leaf => vec![RecoveryDurabilityBoundary::Leaf],
                RecoveryDurabilityBoundary::OperationDirectory => vec![
                    RecoveryDurabilityBoundary::Leaf,
                    RecoveryDurabilityBoundary::OperationDirectory,
                ],
                RecoveryDurabilityBoundary::DestinationDirectory => vec![
                    RecoveryDurabilityBoundary::Leaf,
                    RecoveryDurabilityBoundary::OperationDirectory,
                    RecoveryDurabilityBoundary::DestinationDirectory,
                ],
            };
            assert_eq!(observed_boundaries, expected_boundaries);
            drop(recovered);

            assert_eq!(
                recover_impl(root.path(), &input, |_, _| Ok(probe_hash())).unwrap_err(),
                InstallerStageError::VerificationFailed,
                "failed second rollback recovery after {boundary:?}"
            );
        }
    }

    #[test]
    fn recovery_completes_a_same_identity_dual_name_rollback_handoff() {
        let root = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let mut staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());
        publish_for_test(&mut staged);
        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
        fs::hard_link(
            root.path().join(input.executable_name),
            operation.join(FAILED_EXECUTABLE),
        )
        .unwrap();
        drop(staged);

        assert_eq!(
            recover_impl(root.path(), &input, |_, _| Ok(probe_hash())).unwrap_err(),
            InstallerStageError::VerificationFailed
        );
        assert!(!root.path().join(input.executable_name).exists());
        assert_eq!(
            fs::read(operation.join(FAILED_EXECUTABLE)).unwrap(),
            EXECUTABLE
        );
        assert!(
            operation
                .join(crate::install_phase::ROLLED_BACK_RECORD)
                .is_file()
        );
    }

    #[test]
    fn recovery_preserves_distinct_dual_name_rollback_leaves() {
        let root = private_tempdir();
        let aliases = private_tempdir();
        let input = staging_input(EXECUTABLE);
        let mut staged = stage(root.path(), &input).unwrap();
        let operation = root
            .path()
            .join(crate::INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());
        publish_for_test(&mut staged);
        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
        let failed = operation.join(FAILED_EXECUTABLE);
        fs::write(&failed, EXECUTABLE).unwrap();
        fs::set_permissions(&failed, fs::Permissions::from_mode(0o700)).unwrap();
        fs::hard_link(
            root.path().join(input.executable_name),
            aliases.path().join("installed-alias"),
        )
        .unwrap();
        fs::hard_link(&failed, aliases.path().join("failed-alias")).unwrap();
        let installed_leaf = crate::unix_recovery::open_exact_private_file_with_link_count(
            staged._retained.destination.directory(),
            input.executable_name,
            0o700,
            EXECUTABLE.len() as u64,
            2,
        )
        .unwrap();
        let failed_leaf = crate::unix_recovery::open_exact_private_file_with_link_count(
            &staged._retained.operation,
            FAILED_EXECUTABLE,
            0o700,
            EXECUTABLE.len() as u64,
            2,
        )
        .unwrap();
        assert_ne!(installed_leaf.identity, failed_leaf.identity);
        drop(staged);

        assert_eq!(
            recover_impl(root.path(), &input, |_, _| Ok(probe_hash())).unwrap_err(),
            InstallerStageError::UnsafeState
        );
        assert!(root.path().join(input.executable_name).is_file());
        assert!(failed.is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_publication_normalizes_a_restrictive_process_umask() {
        if std::env::var_os("KITROVE_RESTRICTIVE_UMASK_HELPER").is_some() {
            let root = private_tempdir();
            let input = staging_input(EXECUTABLE);
            let staged = stage(root.path(), &input).unwrap();
            rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));

            let installed = install_impl(staged, |_, _| Ok(probe_hash())).unwrap();
            assert_eq!(
                fs::metadata(installed.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("unix_install::tests::linux_publication_normalizes_a_restrictive_process_umask")
            .arg("--exact")
            .arg("--nocapture")
            .env("KITROVE_RESTRICTIVE_UMASK_HELPER", "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn recovery_discards_every_non_authoritative_partial_phase_write() {
        for &interrupted in InstallPhase::all() {
            let root = private_tempdir();
            let input = staging_input(EXECUTABLE);
            let mut staged = stage(root.path(), &input).unwrap();
            let operation = root
                .path()
                .join(crate::INSTALLER_STATE_DIRECTORY)
                .join(staged.record().operation_id());
            publish_for_test(&mut staged);
            match interrupted {
                InstallPhase::Replaced => {}
                InstallPhase::Verified => {
                    write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                }
                InstallPhase::Committed => {
                    write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                    write_phase_record(&mut staged, InstallPhase::Verified).unwrap();
                }
                InstallPhase::RolledBack => {
                    write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                    rename_noreplace(
                        staged._retained.destination.directory(),
                        OsStr::new(input.executable_name),
                        &staged._retained.operation,
                        OsStr::new(FAILED_EXECUTABLE),
                    )
                    .unwrap();
                }
            }
            let pending = create_private_file(
                &staged._retained.operation,
                OsStr::new(interrupted.pending_file_name()),
                0o600,
            )
            .unwrap();
            pending.sync_all().unwrap();
            sync_directory(&staged._retained.operation).unwrap();
            drop(staged);

            let result = recover_impl(root.path(), &input, |_, _| Ok(probe_hash()));
            if interrupted == InstallPhase::RolledBack {
                assert_eq!(result.unwrap_err(), InstallerStageError::VerificationFailed);
            } else {
                assert!(result.is_ok(), "failed to recover {interrupted:?}");
            }
            assert!(!operation.join(interrupted.pending_file_name()).exists());
            assert!(operation.join(interrupted.file_name()).is_file());
        }
    }

    #[test]
    fn recovery_handles_every_phase_write_boundary() {
        for &interrupted in InstallPhase::all() {
            for boundary in [
                PhaseWriteBoundary::Created,
                PhaseWriteBoundary::FileSynced,
                PhaseWriteBoundary::Published,
                PhaseWriteBoundary::DirectorySynced,
            ] {
                let root = private_tempdir();
                let input = staging_input(EXECUTABLE);
                let mut staged = stage(root.path(), &input).unwrap();
                publish_for_test(&mut staged);
                match interrupted {
                    InstallPhase::Replaced => {}
                    InstallPhase::Verified => {
                        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                    }
                    InstallPhase::Committed => {
                        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                        write_phase_record(&mut staged, InstallPhase::Verified).unwrap();
                    }
                    InstallPhase::RolledBack => {
                        write_phase_record(&mut staged, InstallPhase::Replaced).unwrap();
                        rename_noreplace(
                            staged._retained.destination.directory(),
                            OsStr::new(input.executable_name),
                            &staged._retained.operation,
                            OsStr::new(FAILED_EXECUTABLE),
                        )
                        .unwrap();
                    }
                }
                assert_eq!(
                    write_phase_record_impl(&mut staged, interrupted, |observed| {
                        if observed == boundary {
                            Err(InstallerStageError::WriteFailed)
                        } else {
                            Ok(())
                        }
                    })
                    .unwrap_err(),
                    InstallerStageError::RecoveryRequired
                );
                drop(staged);

                let result = recover_impl(root.path(), &input, |_, _| Ok(probe_hash()));
                if interrupted == InstallPhase::RolledBack {
                    assert_eq!(result.unwrap_err(), InstallerStageError::VerificationFailed);
                } else {
                    assert!(
                        result.is_ok(),
                        "failed {interrupted:?} recovery after {boundary:?}"
                    );
                }
            }
        }
    }
}
