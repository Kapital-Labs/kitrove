use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use std::ffi::{OsStr, OsString};

use crate::install_phase::{
    DetectedInstallPhase, FAILED_EXECUTABLE, InstallPhase, InstallRecoveryPhase,
    MAX_PHASE_RECORD_BYTES, classify_operation,
};
use crate::record::{MAX_OPERATION_RECORD_BYTES, PreparedFilesystemEvidence};
use crate::staging_policy::{OpenedLeaf, RecoveryKind};
use crate::unix_staging::{
    INSTALLER_LOCK, OPERATION_RECORD, OpenedDestination, RetainedStage, STAGED_EXECUTABLE,
    acquire_existing_installer_lock, directory_identity, metadata_identity, open_destination,
    open_private_child, read_bounded_file, require_exact_inventory,
    require_named_directory_identity, require_named_file_identity,
    require_private_file_with_link_count, require_unprivileged_process,
    revalidate_control_boundary, revalidate_destination, verify_executable_contents,
};
use crate::{
    INSTALLER_STATE_DIRECTORY, InstallerOperationRecord, InstallerStageError, NativeFileIdentity,
    StagedApplication, StagingInput,
};

struct InterruptedPhaseWrite {
    name: &'static str,
    file: cap_std::fs::File,
    identity: NativeFileIdentity,
    size: u64,
}

pub(crate) struct RecoveryRoot {
    pub(crate) destination: OpenedDestination,
    pub(crate) state: Dir,
    pub(crate) operation: Dir,
    pub(crate) lock: crate::unix_staging::InstallerLock,
    pub(crate) operation_id: String,
    pub(crate) state_identity: NativeFileIdentity,
    pub(crate) operation_identity: NativeFileIdentity,
}

/// Opens existing authority only, holding the installer lock before operation inspection.
pub(crate) fn open_recovery_root(
    path: &std::path::Path,
) -> Result<RecoveryRoot, InstallerStageError> {
    require_unprivileged_process()?;
    let destination = open_destination(path)?;
    revalidate_destination(&destination)?;
    let state = open_private_child(
        destination.directory(),
        OsStr::new(INSTALLER_STATE_DIRECTORY),
    )?;
    let state_identity = directory_identity(&state)?;
    let lock = acquire_existing_installer_lock(&state)?;
    revalidate_control_boundary(&destination, &state, state_identity, &lock)?;
    let name = retained_operation_name(&state)?;
    let operation_id = name
        .to_str()
        .ok_or(InstallerStageError::RecoveryRequired)?
        .to_owned();
    let operation = open_private_child(&state, &name)?;
    let operation_identity = directory_identity(&operation)?;
    require_named_directory_identity(&state, &operation_id, &operation, operation_identity)?;
    require_exact_inventory(
        &state,
        &[OsStr::new(INSTALLER_LOCK), OsStr::new(&operation_id)],
    )?;
    Ok(RecoveryRoot {
        destination,
        state,
        operation,
        lock,
        operation_id,
        state_identity,
        operation_identity,
    })
}

pub(crate) fn resume(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    resume_impl(
        destination_parent,
        input,
        InstallRecoveryPhase::Prepared,
        |_, _, _, _, _, _| Ok(()),
    )
}

pub(crate) fn resume_install_phase(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
    location: InstallRecoveryPhase,
) -> Result<StagedApplication, InstallerStageError> {
    resume_impl(destination_parent, input, location, |_, _, _, _, _, _| {
        Ok(())
    })
}

pub(crate) fn detect_install_phase(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
) -> Result<DetectedInstallPhase, InstallerStageError> {
    detect_install_phase_with_kind(destination_parent, input, RecoveryKind::Installation)
}

pub(crate) fn detect_state_bound_install_phase(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
) -> Result<DetectedInstallPhase, InstallerStageError> {
    detect_install_phase_with_kind(
        destination_parent,
        input,
        RecoveryKind::StateBoundInstallation,
    )
}

fn detect_install_phase_with_kind(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
    kind: RecoveryKind,
) -> Result<DetectedInstallPhase, InstallerStageError> {
    let root = open_recovery_root(destination_parent)?;
    let operation = &root.operation;
    let destination = &root.destination;
    let state_bound = kind == RecoveryKind::StateBoundInstallation;
    let pending = if state_bound {
        None
    } else {
        open_interrupted_phase_write(operation)?
    };
    let extra = kind.extra_entries();
    let mut names =
        operation_entry_names(operation, if state_bound { 12 } else { 6 + extra.len() })?;
    for name in extra {
        if !names.iter().any(|observed| observed == name) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        names.retain(|observed| observed != name);
    }
    if let Some(pending) = &pending {
        names.retain(|name| name != OsStr::new(pending.name));
    }
    names.sort();
    let installed = entry_exists(destination.directory(), input.executable_name)?;
    let failed = entry_exists(operation, FAILED_EXECUTABLE)?;

    if state_bound {
        names.retain(|name| {
            !InstallPhase::all()
                .iter()
                .any(|phase| name == OsStr::new(phase.pending_file_name()))
        });
        if failed {
            names.retain(|name| {
                ![InstallPhase::Verified, InstallPhase::Committed]
                    .iter()
                    .any(|phase| name == OsStr::new(phase.file_name()))
            });
        }
    }

    classify_operation(&names, installed, failed)
}

fn open_interrupted_phase_write(
    operation: &Dir,
) -> Result<Option<InterruptedPhaseWrite>, InstallerStageError> {
    let pending_names = InstallPhase::all()
        .iter()
        .filter_map(|phase| {
            let name = phase.pending_file_name();
            match operation.symlink_metadata(name) {
                Ok(_) => Some(Ok(name)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => Some(Err(InstallerStageError::RecoveryRequired)),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if pending_names.len() > 1 {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let Some(name) = pending_names.first().copied() else {
        return Ok(None);
    };
    let pending = open_pending_private_file(operation, name, MAX_PHASE_RECORD_BYTES as u64)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_named_file_identity(
        operation,
        name,
        &pending.file,
        pending.identity,
        0o600,
        pending.size,
    )?;
    Ok(Some(InterruptedPhaseWrite {
        name,
        file: pending.file,
        identity: pending.identity,
        size: pending.size,
    }))
}

fn discard_interrupted_phase_write(
    operation: &Dir,
    pending: &InterruptedPhaseWrite,
) -> Result<(), InstallerStageError> {
    require_named_file_identity(
        operation,
        pending.name,
        &pending.file,
        pending.identity,
        0o600,
        pending.size,
    )?;
    operation
        .remove_file(pending.name)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    crate::unix_staging::sync_directory(operation)
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

fn operation_entry_names(
    operation: &Dir,
    maximum: usize,
) -> Result<Vec<OsString>, InstallerStageError> {
    let mut names = Vec::with_capacity(maximum);
    let mut entries = operation
        .entries()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    for _ in 0..=maximum {
        let Some(entry) = entries.next() else {
            return Ok(names);
        };
        names.push(
            entry
                .map_err(|_| InstallerStageError::RecoveryRequired)?
                .file_name(),
        );
    }
    Err(InstallerStageError::RecoveryRequired)
}

fn entry_exists(parent: &Dir, name: &str) -> Result<bool, InstallerStageError> {
    match parent.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(InstallerStageError::RecoveryRequired),
    }
}

fn resume_impl<F>(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
    location: InstallRecoveryPhase,
    before_final_rebind: F,
) -> Result<StagedApplication, InstallerStageError>
where
    F: FnOnce(
        &OpenedDestination,
        &Dir,
        &Dir,
        &str,
        &OpenedLeaf,
        &OpenedLeaf,
    ) -> Result<(), InstallerStageError>,
{
    resume_with_kind(
        destination_parent,
        input,
        location,
        RecoveryKind::Installation,
        before_final_rebind,
    )
}

pub(crate) fn resume_prepared_upgrade(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    resume_with_kind(
        destination_parent,
        input,
        InstallRecoveryPhase::Prepared,
        RecoveryKind::UpgradePreparation,
        |_, _, _, _, _, _| Ok(()),
    )
}

/// Read-only filesystem rebinding. The caller must also authenticate retained state
/// and the complete phase/layout evidence before using this as execution authority.
pub(crate) fn resume_state_bound_install(
    destination: &std::path::Path,
    input: &StagingInput<'_>,
    location: InstallRecoveryPhase,
) -> Result<StagedApplication, InstallerStageError> {
    resume_with_kind(
        destination,
        input,
        location,
        RecoveryKind::StateBoundInstallation,
        |_, _, _, _, _, _| Ok(()),
    )
}

/// Retention never reconciles or discards incomplete first-install phase writes.
pub(crate) fn resume_terminal_install(
    destination: &std::path::Path,
    input: &StagingInput<'_>,
    location: InstallRecoveryPhase,
) -> Result<StagedApplication, InstallerStageError> {
    if !matches!(
        location,
        InstallRecoveryPhase::Committed | InstallRecoveryPhase::RolledBack
    ) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    resume_with_kind(
        destination,
        input,
        location,
        RecoveryKind::TerminalInstallation,
        |_, _, _, _, _, _| Ok(()),
    )
}

fn resume_with_kind<F>(
    destination_parent: &std::path::Path,
    input: &StagingInput<'_>,
    location: InstallRecoveryPhase,
    kind: RecoveryKind,
    before_final_rebind: F,
) -> Result<StagedApplication, InstallerStageError>
where
    F: FnOnce(
        &OpenedDestination,
        &Dir,
        &Dir,
        &str,
        &OpenedLeaf,
        &OpenedLeaf,
    ) -> Result<(), InstallerStageError>,
{
    let RecoveryRoot {
        destination,
        state,
        operation,
        lock,
        operation_id,
        state_identity,
        operation_identity,
    } = open_recovery_root(destination_parent)?;
    let operation_id = operation_id.as_str();
    let pending = if kind == RecoveryKind::StateBoundInstallation {
        None
    } else {
        open_interrupted_phase_write(&operation)?
    };
    if kind == RecoveryKind::TerminalInstallation && pending.is_some() {
        return Err(InstallerStageError::RecoveryRequired);
    }
    if kind == RecoveryKind::UpgradePreparation
        && (pending.is_some() || location != InstallRecoveryPhase::Prepared)
    {
        return Err(InstallerStageError::RecoveryRequired);
    }
    require_operation_inventory_with_pending(&operation, location, pending.as_ref(), kind)?;
    let record_leaf = open_bounded_private_file(
        &operation,
        OPERATION_RECORD,
        0o600,
        MAX_OPERATION_RECORD_BYTES as u64,
    )?;
    let record_bytes = read_bounded_file(&record_leaf.file, MAX_OPERATION_RECORD_BYTES)?;
    let unverified = InstallerOperationRecord::parse_untrusted(&record_bytes).map_err(|error| {
        if error.is_legacy_schema() {
            InstallerStageError::RecoveryRequired
        } else {
            InstallerStageError::UnsafeState
        }
    })?;
    if unverified.operation_id() != operation_id {
        return Err(InstallerStageError::UnsafeState);
    }
    let installed_name = unverified.executable_name().to_owned();
    let installed_size = unverified.executable_size();
    let executable_name = STAGED_EXECUTABLE.to_owned();
    let executable_parent = &operation;
    let executable = open_exact_private_file(
        executable_parent,
        &executable_name,
        0o700,
        unverified.executable_size(),
    )?;

    let ancestry_identities = destination.identities();
    let record = unverified
        .authenticate_prepared(
            input,
            PreparedFilesystemEvidence {
                destination_path: destination.path_bytes(),
                ancestry_identities: &ancestry_identities,
                state_identity,
                lock_identity: lock.identity(),
                operation_identity,
                staged_identity: executable.identity,
            },
        )
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let canonical_record = record
        .to_json()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if record_bytes != canonical_record {
        return Err(InstallerStageError::UnsafeState);
    }

    verify_executable_contents(&executable.file, input)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if read_bounded_file(&record_leaf.file, MAX_OPERATION_RECORD_BYTES)? != record_bytes {
        return Err(InstallerStageError::UnsafeState);
    }
    if let Some(pending) = &pending {
        revalidate_control_boundary(&destination, &state, state_identity, &lock)?;
        require_named_directory_identity(&state, operation_id, &operation, operation_identity)?;
        require_exact_inventory(
            &state,
            &[OsStr::new(INSTALLER_LOCK), OsStr::new(operation_id)],
        )?;
        require_operation_inventory_with_pending(&operation, location, Some(pending), kind)?;
        if kind != RecoveryKind::StateBoundInstallation {
            discard_interrupted_phase_write(&operation, pending)?;
        }
    }
    before_final_rebind(
        &destination,
        &state,
        &operation,
        operation_id,
        &executable,
        &record_leaf,
    )?;
    revalidate_control_boundary(&destination, &state, state_identity, &lock)?;
    require_named_directory_identity(&state, operation_id, &operation, operation_identity)?;
    require_exact_inventory(
        &state,
        &[OsStr::new(INSTALLER_LOCK), OsStr::new(operation_id)],
    )?;
    let retained_pending = if kind == RecoveryKind::StateBoundInstallation {
        pending.as_ref()
    } else {
        None
    };
    require_operation_inventory_with_pending(&operation, location, retained_pending, kind)?;
    require_named_file_identity(
        executable_parent,
        &executable_name,
        &executable.file,
        executable.identity,
        0o700,
        input.executable_bytes.len() as u64,
    )?;
    require_named_file_identity(
        &operation,
        OPERATION_RECORD,
        &record_leaf.file,
        record_leaf.identity,
        0o600,
        record_leaf.size,
    )?;
    verify_executable_contents(&executable.file, input)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if read_bounded_file(&record_leaf.file, MAX_OPERATION_RECORD_BYTES)? != canonical_record {
        return Err(InstallerStageError::UnsafeState);
    }

    let mut retained = RetainedStage::new(
        destination,
        state,
        operation,
        executable.file,
        record_leaf.file,
        lock,
    );
    if location != InstallRecoveryPhase::Prepared {
        let installed = match location {
            InstallRecoveryPhase::RollbackHandoff => {
                let destination_leaf = open_exact_private_file_with_link_count(
                    retained.destination.directory(),
                    &installed_name,
                    0o700,
                    installed_size,
                    2,
                )?;
                let failed = open_exact_private_file_with_link_count(
                    &retained.operation,
                    FAILED_EXECUTABLE,
                    0o700,
                    installed_size,
                    2,
                )?;
                if destination_leaf.identity != failed.identity {
                    return Err(InstallerStageError::UnsafeState);
                }
                failed
            }
            InstallRecoveryPhase::RollingBack | InstallRecoveryPhase::RolledBack => {
                open_exact_private_file(
                    &retained.operation,
                    FAILED_EXECUTABLE,
                    0o700,
                    installed_size,
                )?
            }
            _ => open_exact_private_file(
                retained.destination.directory(),
                &installed_name,
                0o700,
                installed_size,
            )?,
        };
        retained = retained.with_installed(installed.file);
        for phase in location.marker_phases() {
            let marker_name = phase.file_name();
            let marker = open_bounded_private_file(
                &retained.operation,
                marker_name,
                0o600,
                crate::install_phase::MAX_PHASE_RECORD_BYTES as u64,
            )?;
            retained = retained.with_phase_marker(marker.file);
        }
    }
    Ok(StagedApplication {
        record,
        manifest: input.manifest.clone(),
        executable_content_hash: kitrove_model::ContentHash::digest(input.executable_bytes),
        _retained: retained,
    })
}

pub(crate) fn retained_operation_name(state: &Dir) -> Result<OsString, InstallerStageError> {
    let entries = state
        .entries()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    crate::staging_policy::retained_operation_name(
        entries.map(|entry| entry.map(|entry| entry.file_name())),
    )
}

fn require_operation_inventory_with_pending(
    operation: &Dir,
    location: InstallRecoveryPhase,
    pending: Option<&InterruptedPhaseWrite>,
    kind: RecoveryKind,
) -> Result<(), InstallerStageError> {
    let mut inventory = location.inventory();
    inventory.extend(kind.extra_entries());
    if kind == RecoveryKind::StateBoundInstallation {
        let names = operation_entry_names(operation, 12)?;
        for &phase in InstallPhase::all() {
            if names
                .iter()
                .any(|name| name == OsStr::new(phase.pending_file_name()))
            {
                inventory.push(OsStr::new(phase.pending_file_name()));
            }
            if !location.marker_phases().contains(&phase)
                && names
                    .iter()
                    .any(|name| name == OsStr::new(phase.file_name()))
            {
                inventory.push(OsStr::new(phase.file_name()));
            }
        }
    }
    if let Some(pending) = pending {
        inventory.push(OsStr::new(pending.name));
    }
    require_exact_inventory(operation, &inventory)
}

pub(crate) fn open_exact_private_file(
    parent: &Dir,
    name: &str,
    mode: u32,
    size: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    open_exact_private_file_with_link_count(parent, name, mode, size, 1)
}

pub(crate) fn open_exact_private_file_with_link_count(
    parent: &Dir,
    name: &str,
    mode: u32,
    size: u64,
    link_count: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    let leaf = open_bounded_private_file_with_link_count(parent, name, mode, size, link_count)?;
    if leaf.size == size {
        Ok(leaf)
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

pub(crate) fn open_bounded_private_file(
    parent: &Dir,
    name: &str,
    mode: u32,
    maximum_size: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    open_bounded_private_file_with_link_count(parent, name, mode, maximum_size, 1)
}

fn open_bounded_private_file_with_link_count(
    parent: &Dir,
    name: &str,
    mode: u32,
    maximum_size: u64,
    link_count: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    open_bounded_private_file_with_hook(parent, name, mode, maximum_size, link_count, || {})
}

fn open_bounded_private_file_with_hook(
    parent: &Dir,
    name: &str,
    mode: u32,
    maximum_size: u64,
    link_count: u64,
    before_open: impl FnOnce(),
) -> Result<OpenedLeaf, InstallerStageError> {
    open_private_file_with_hook(
        parent,
        name,
        mode,
        1..=maximum_size,
        link_count,
        before_open,
    )
}

pub(crate) fn open_pending_private_file(
    parent: &Dir,
    name: &str,
    maximum_size: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    open_private_file_with_hook(parent, name, 0o600, 0..=maximum_size, 1, || {})
}

fn open_private_file_with_hook(
    parent: &Dir,
    name: &str,
    mode: u32,
    sizes: std::ops::RangeInclusive<u64>,
    link_count: u64,
    before_open: impl FnOnce(),
) -> Result<OpenedLeaf, InstallerStageError> {
    use cap_std::fs::OpenOptionsExt as _;

    let before = parent
        .symlink_metadata(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_bounded_private_file_with_link_count(&before, mode, &sizes, link_count)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .follow(FollowSymlinks::No)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    before_open();
    let file = parent
        .open_with(name, &options)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let after = file
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_bounded_private_file_with_link_count(&after, mode, &sizes, link_count)?;
    let identity = metadata_identity(&after);
    if identity != metadata_identity(&before) || before.len() != after.len() {
        return Err(InstallerStageError::UnsafeState);
    }
    Ok(OpenedLeaf {
        file,
        identity,
        size: after.len(),
    })
}

fn require_bounded_private_file_with_link_count(
    metadata: &Metadata,
    mode: u32,
    sizes: &std::ops::RangeInclusive<u64>,
    link_count: u64,
) -> Result<(), InstallerStageError> {
    let size = metadata.len();
    if !sizes.contains(&size) {
        return Err(InstallerStageError::UnsafeState);
    }
    require_private_file_with_link_count(metadata, mode, size, link_count)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Seek as _, SeekFrom, Write as _};

    use super::*;
    use crate::test_support::{private_tempdir, staging_input as input};
    use crate::unix_staging::stage;

    #[test]
    fn empty_pending_record_inspection_cannot_block_on_a_late_fifo() {
        let destination = private_tempdir();
        let root = open_destination(destination.path()).unwrap();
        let file = crate::unix_staging::create_private_file(
            root.directory(),
            OsStr::new("pending"),
            0o600,
        )
        .unwrap();
        drop(file);
        let result =
            open_private_file_with_hook(root.directory(), "pending", 0o600, 0..=1024, 1, || {
                fs::rename(
                    destination.path().join("pending"),
                    destination.path().join("retained"),
                )
                .unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(destination.path().join("pending"))
                        .status()
                        .unwrap()
                        .success()
                );
            });
        assert!(result.is_err());
        assert_eq!(fs::read(destination.path().join("retained")).unwrap(), b"");
    }

    #[test]
    fn fifo_substitution_cannot_block_private_recovery_inspection() {
        let destination = private_tempdir();
        let root = open_destination(destination.path()).unwrap();
        let mut file =
            crate::unix_staging::create_private_file(root.directory(), OsStr::new("prior"), 0o700)
                .unwrap();
        file.write_all(b"prior").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let result =
            open_bounded_private_file_with_hook(root.directory(), "prior", 0o700, 5, 1, || {
                fs::rename(
                    destination.path().join("prior"),
                    destination.path().join("retained"),
                )
                .unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(destination.path().join("prior"))
                        .status()
                        .expect("mkfifo must be available on supported Unix test hosts")
                        .success()
                );
            });
        assert_eq!(result.err(), Some(InstallerStageError::UnsafeState));
        assert_eq!(
            fs::read(destination.path().join("retained")).unwrap(),
            b"prior"
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RecoveryFault {
        ReplaceState,
        ReplaceOperation,
        ReplaceLock,
        MutateExecutable,
        MutateRecord,
        ReplaceExecutable,
        ReplaceRecord,
        AddStateEntry,
        AddOperationEntry,
    }

    fn resume_with_fault(
        destination: &std::path::Path,
        input: &StagingInput<'_>,
        fault: RecoveryFault,
    ) -> Result<StagedApplication, InstallerStageError> {
        resume_impl(
            destination,
            input,
            InstallRecoveryPhase::Prepared,
            |destination, state, operation, operation_id, executable, record| {
                apply_recovery_fault(
                    destination,
                    state,
                    operation,
                    operation_id,
                    executable,
                    record,
                    fault,
                )
            },
        )
    }

    fn apply_recovery_fault(
        destination: &OpenedDestination,
        state: &Dir,
        operation: &Dir,
        operation_id: &str,
        executable: &OpenedLeaf,
        record: &OpenedLeaf,
        fault: RecoveryFault,
    ) -> Result<(), InstallerStageError> {
        match fault {
            RecoveryFault::ReplaceState => {
                destination
                    .directory()
                    .rename(
                        INSTALLER_STATE_DIRECTORY,
                        destination.directory(),
                        "moved-state",
                    )
                    .map_err(|_| InstallerStageError::WriteFailed)?;
                destination
                    .directory()
                    .create_dir(INSTALLER_STATE_DIRECTORY)
                    .map_err(|_| InstallerStageError::WriteFailed)
            }
            RecoveryFault::ReplaceOperation => {
                state
                    .rename(operation_id, state, "moved-operation")
                    .map_err(|_| InstallerStageError::WriteFailed)?;
                state
                    .create_dir(operation_id)
                    .map_err(|_| InstallerStageError::WriteFailed)
            }
            RecoveryFault::ReplaceLock => {
                replace_leaf(state, INSTALLER_LOCK, "moved-lock", 0o600, 0)
            }
            RecoveryFault::MutateExecutable => {
                overwrite_named_prefix(operation, STAGED_EXECUTABLE, b"X")
            }
            RecoveryFault::MutateRecord => {
                overwrite_named_prefix(operation, OPERATION_RECORD, b"[")
            }
            RecoveryFault::ReplaceExecutable => replace_leaf(
                operation,
                STAGED_EXECUTABLE,
                "moved-application",
                0o700,
                executable.size,
            ),
            RecoveryFault::ReplaceRecord => replace_leaf(
                operation,
                OPERATION_RECORD,
                "moved-record",
                0o600,
                record.size,
            ),
            RecoveryFault::AddStateEntry => destination
                .directory()
                .open_dir(INSTALLER_STATE_DIRECTORY)
                .and_then(|live_state| live_state.create_dir("unexpected-operation"))
                .map_err(|_| InstallerStageError::WriteFailed),
            RecoveryFault::AddOperationEntry => operation
                .create_dir("unexpected-child")
                .map_err(|_| InstallerStageError::WriteFailed),
        }
    }

    fn overwrite_named_prefix(
        parent: &Dir,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), InstallerStageError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let mut writer = parent
            .open_with(name, &options)
            .map_err(|_| InstallerStageError::WriteFailed)?;
        writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| writer.write_all(bytes))
            .and_then(|()| writer.sync_all())
            .map_err(|_| InstallerStageError::WriteFailed)
    }

    fn replace_leaf(
        parent: &Dir,
        name: &str,
        moved_name: &str,
        mode: u32,
        size: u64,
    ) -> Result<(), InstallerStageError> {
        use cap_std::fs::OpenOptionsExt as _;

        parent
            .rename(name, parent, moved_name)
            .map_err(|_| InstallerStageError::WriteFailed)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode)
            .follow(FollowSymlinks::No);
        let replacement = parent
            .open_with(name, &options)
            .map_err(|_| InstallerStageError::WriteFailed)?;
        replacement
            .set_len(size)
            .and_then(|()| replacement.sync_all())
            .map_err(|_| InstallerStageError::WriteFailed)
    }

    fn operation_path(root: &tempfile::TempDir, staged: &StagedApplication) -> std::path::PathBuf {
        root.path()
            .join(INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id())
    }

    fn write_pending_phase(operation: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = operation.join(InstallPhase::Replaced.pending_file_name());
        fs::write(&path, b"interrupted phase record").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn resumes_one_exact_authenticated_prepared_operation() {
        let root = private_tempdir();
        let input = input(b"authenticated executable");
        let staged = stage(root.path(), &input).unwrap();
        let operation_id = staged.record().operation_id().to_owned();
        drop(staged);

        let resumed = resume(root.path(), &input).unwrap();

        assert_eq!(resumed.record().operation_id(), operation_id);
        assert_eq!(
            resumed.record().phase(),
            crate::InstallerOperationPhase::Prepared
        );
    }

    #[test]
    fn live_guard_blocks_resume_and_wrong_authority_never_rebinds() {
        let root = private_tempdir();
        let first = input(b"first authenticated executable");
        let staged = stage(root.path(), &first).unwrap();
        assert_eq!(
            resume(root.path(), &first).unwrap_err(),
            InstallerStageError::Conflict
        );
        drop(staged);

        let second = input(b"other authenticated executable");
        assert_eq!(
            resume(root.path(), &second).unwrap_err(),
            InstallerStageError::UnsafeState
        );
    }

    #[test]
    fn pending_phase_write_is_preserved_until_operation_authority_is_authenticated() {
        let wrong_input_root = private_tempdir();
        let expected = input(b"authenticated executable");
        let staged = stage(wrong_input_root.path(), &expected).unwrap();
        let operation = operation_path(&wrong_input_root, &staged);
        drop(staged);
        let pending = write_pending_phase(&operation);
        let pending_bytes = fs::read(&pending).unwrap();

        let wrong = input(b"different authenticated executable");
        assert_eq!(
            resume(wrong_input_root.path(), &wrong).unwrap_err(),
            InstallerStageError::UnsafeState
        );
        assert_eq!(fs::read(&pending).unwrap(), pending_bytes);

        let tampered_root = private_tempdir();
        let staged = stage(tampered_root.path(), &expected).unwrap();
        let operation = operation_path(&tampered_root, &staged);
        drop(staged);
        let pending = write_pending_phase(&operation);
        let pending_bytes = fs::read(&pending).unwrap();
        fs::write(operation.join(OPERATION_RECORD), b"not a record").unwrap();
        assert_eq!(
            resume(tampered_root.path(), &expected).unwrap_err(),
            InstallerStageError::UnsafeState
        );
        assert_eq!(fs::read(&pending).unwrap(), pending_bytes);

        let extra_root = private_tempdir();
        let staged = stage(extra_root.path(), &expected).unwrap();
        let operation = operation_path(&extra_root, &staged);
        drop(staged);
        let pending = write_pending_phase(&operation);
        let pending_bytes = fs::read(&pending).unwrap();
        fs::write(operation.join("unexpected"), b"foreign").unwrap();
        assert_eq!(
            resume(extra_root.path(), &expected).unwrap_err(),
            InstallerStageError::RecoveryRequired
        );
        assert_eq!(fs::read(&pending).unwrap(), pending_bytes);
    }

    #[test]
    fn incomplete_or_extra_inventory_is_preserved_for_cleanup() {
        let root = private_tempdir();
        let input = input(b"authenticated executable");
        let staged = stage(root.path(), &input).unwrap();
        let operation = operation_path(&root, &staged);
        drop(staged);
        fs::remove_file(operation.join(OPERATION_RECORD)).unwrap();

        assert_eq!(
            resume(root.path(), &input).unwrap_err(),
            InstallerStageError::RecoveryRequired
        );
        assert!(operation.join(STAGED_EXECUTABLE).exists());

        let extra = root
            .path()
            .join(INSTALLER_STATE_DIRECTORY)
            .join("unexpected");
        fs::create_dir(&extra).unwrap();
        assert_eq!(
            resume(root.path(), &input).unwrap_err(),
            InstallerStageError::RecoveryRequired
        );
        assert!(extra.exists());
    }

    #[test]
    fn prior_schema_operation_is_classified_as_retained_legacy_state() {
        for schema in [1, 2] {
            let root = private_tempdir();
            let input = input(b"authenticated executable");
            let staged = stage(root.path(), &input).unwrap();
            let operation = operation_path(&root, &staged);
            drop(staged);

            let record_path = operation.join(OPERATION_RECORD);
            let mut record: serde_json::Value =
                serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
            record["schema"] = serde_json::json!(schema);
            let legacy_identity = serde_json::json!({"device": 1, "file": 1});
            for identity in record["ancestry_identities"].as_array_mut().unwrap() {
                *identity = legacy_identity.clone();
            }
            for field in [
                "state_identity",
                "lock_identity",
                "operation_identity",
                "staged_identity",
            ] {
                record[field] = legacy_identity.clone();
            }
            if schema == 1 {
                for field in [
                    "release_manifest_sha256",
                    "application_state_schema",
                    "lifecycle_lock_protocol",
                ] {
                    record.as_object_mut().unwrap().remove(field);
                }
            }
            fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();

            assert_eq!(
                resume(root.path(), &input).unwrap_err(),
                InstallerStageError::RecoveryRequired
            );
            assert!(record_path.exists());
            assert!(operation.join(STAGED_EXECUTABLE).exists());
        }
    }

    #[test]
    fn changed_staged_bytes_and_record_bytes_never_rebind() {
        let executable_root = private_tempdir();
        let input = input(b"authenticated executable");
        let staged = stage(executable_root.path(), &input).unwrap();
        let operation = operation_path(&executable_root, &staged);
        drop(staged);
        let mut executable = fs::OpenOptions::new()
            .write(true)
            .open(operation.join(STAGED_EXECUTABLE))
            .unwrap();
        executable.seek(SeekFrom::Start(0)).unwrap();
        executable.write_all(b"X").unwrap();
        executable.sync_all().unwrap();
        assert_eq!(
            resume(executable_root.path(), &input).unwrap_err(),
            InstallerStageError::UnsafeState
        );

        let record_root = private_tempdir();
        let staged = stage(record_root.path(), &input).unwrap();
        let operation = operation_path(&record_root, &staged);
        drop(staged);
        let mut record = fs::OpenOptions::new()
            .write(true)
            .open(operation.join(OPERATION_RECORD))
            .unwrap();
        record.seek(SeekFrom::Start(0)).unwrap();
        record.write_all(b"[").unwrap();
        record.sync_all().unwrap();
        assert_eq!(
            resume(record_root.path(), &input).unwrap_err(),
            InstallerStageError::UnsafeState
        );
    }

    #[test]
    fn final_rebind_refuses_every_namespace_and_content_race_without_cleanup() {
        for fault in [
            RecoveryFault::ReplaceState,
            RecoveryFault::ReplaceOperation,
            RecoveryFault::ReplaceLock,
            RecoveryFault::MutateExecutable,
            RecoveryFault::MutateRecord,
            RecoveryFault::ReplaceExecutable,
            RecoveryFault::ReplaceRecord,
            RecoveryFault::AddStateEntry,
            RecoveryFault::AddOperationEntry,
        ] {
            let root = private_tempdir();
            let input = input(b"authenticated executable");
            let staged = stage(root.path(), &input).unwrap();
            let operation_id = staged.record().operation_id().to_owned();
            drop(staged);

            let error = resume_with_fault(root.path(), &input, fault).unwrap_err();

            assert!(
                matches!(
                    error,
                    InstallerStageError::UnsafeDestination
                        | InstallerStageError::UnsafeState
                        | InstallerStageError::RecoveryRequired
                ),
                "unexpected result for {fault:?}: {error:?}"
            );
            let state = root.path().join(INSTALLER_STATE_DIRECTORY);
            let operation = state.join(&operation_id);
            match fault {
                RecoveryFault::ReplaceState => {
                    assert!(root.path().join("moved-state").join(&operation_id).exists());
                }
                RecoveryFault::ReplaceOperation => {
                    assert!(state.join("moved-operation").exists());
                }
                RecoveryFault::ReplaceLock => assert!(state.join("moved-lock").exists()),
                RecoveryFault::MutateExecutable => {
                    assert!(operation.join(STAGED_EXECUTABLE).exists());
                }
                RecoveryFault::MutateRecord => {
                    assert!(operation.join(OPERATION_RECORD).exists());
                }
                RecoveryFault::ReplaceExecutable => {
                    assert!(operation.join("moved-application").exists());
                }
                RecoveryFault::ReplaceRecord => {
                    assert!(operation.join("moved-record").exists());
                }
                RecoveryFault::AddStateEntry => {
                    assert!(state.join("unexpected-operation").exists());
                }
                RecoveryFault::AddOperationEntry => {
                    assert!(operation.join("unexpected-child").exists());
                }
            }
        }
    }
}
