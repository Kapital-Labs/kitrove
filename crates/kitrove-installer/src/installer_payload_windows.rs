//! Native bindings for the shared installer-payload staging sequence.
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

use crate::windows_staging as staging;
use crate::{InstallerStageError, NativeFileIdentity};

pub(super) use staging::{
    create_written_private_file as create_synced_private_file, file_identity,
    file_identity as directory_identity, require_exact_inventory,
    require_file_contents as verify_sha256_contents,
};

pub(super) struct OpenedDestination {
    validated: kitrove_windows_security::ValidatedInstallDirectory,
    directory: File,
}

impl OpenedDestination {
    pub(super) fn directory(&self) -> &File {
        &self.directory
    }
}

pub(super) fn require_unprivileged_process() -> Result<(), InstallerStageError> {
    kitrove_windows_security::require_unelevated_process()
        .map_err(|_| InstallerStageError::UnsafeDestination)
}

pub(super) fn open_destination(path: &Path) -> Result<OpenedDestination, InstallerStageError> {
    let validated = kitrove_windows_security::validate_install_directory(path)
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    let directory = validated
        .directory()
        .map_err(|_| InstallerStageError::UnsafeDestination)?
        .try_clone()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    Ok(OpenedDestination {
        validated,
        directory,
    })
}

pub(super) fn revalidate_destination(
    parent: &OpenedDestination,
) -> Result<(), InstallerStageError> {
    parent
        .validated
        .revalidate()
        .map_err(|_| InstallerStageError::UnsafeDestination)
}

pub(super) fn create_private_child(
    parent: &File,
    name: &OsStr,
) -> Result<File, InstallerStageError> {
    kitrove_windows_security::create_private_directory(parent, name)
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

pub(super) fn require_named_directory_identity(
    parent: &File,
    name: &str,
    directory: &File,
    identity: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    kitrove_windows_security::inspect_private_directory(directory)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    staging::require_identity(directory, identity)?;
    staging::require_named_directory_identity(parent, OsStr::new(name), identity)
}

pub(super) fn require_named_file_identity(
    parent: &File,
    name: &str,
    file: &File,
    identity: NativeFileIdentity,
    unix_mode: u32,
    size: u64,
) -> Result<(), InstallerStageError> {
    if unix_mode != 0o600 {
        return Err(InstallerStageError::UnsafeState);
    }
    kitrove_windows_security::inspect_private_single_link_file(file)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    staging::require_identity(file, identity)?;
    if file
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?
        .len()
        != size
    {
        return Err(InstallerStageError::UnsafeState);
    }
    staging::require_named_file_identity(parent, OsStr::new(name), identity, false)
}

pub(super) fn sync_stage(
    parent: &OpenedDestination,
    directory: &File,
) -> Result<(), InstallerStageError> {
    staging::sync_directory(parent.directory(), OsStr::new(super::DIRECTORY), directory)?;
    parent
        .validated
        .flush()
        .map_err(|_| InstallerStageError::RecoveryRequired)
}
