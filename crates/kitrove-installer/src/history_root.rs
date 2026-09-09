use std::ffi::OsStr;
use std::path::Path;

use crate::staging_policy::{INSTALLER_LOCK, InstallerDirectory, OpenedLeaf};
use crate::{
    INSTALLER_HISTORY_DIRECTORY, INSTALLER_STATE_DIRECTORY, InstallerStageError, NativeFileIdentity,
};

#[cfg(unix)]
use crate::unix_staging::{InstallerLock, OpenedDestination as Destination};
#[cfg(windows)]
use crate::windows_staging::InstallerLock;
#[cfg(windows)]
use kitrove_windows_security::ValidatedInstallDirectory as Destination;

pub(crate) enum HistoryDirectory {
    Operation,
    History,
    Source,
}

#[cfg(windows)]
pub(crate) struct HistoryIdentities {
    pub(crate) state: NativeFileIdentity,
    pub(crate) history: NativeFileIdentity,
    pub(crate) operation: NativeFileIdentity,
}

/// Existing private namespaces only. No creation, permission repair or recorded-path traversal.
pub(crate) struct HistoryRoot {
    pub(crate) operation: InstallerDirectory,
    history: InstallerDirectory,
    state: InstallerDirectory,
    destination: Destination,
    selected: String,
    operation_identity: NativeFileIdentity,
    history_identity: NativeFileIdentity,
    state_identity: NativeFileIdentity,
    // Every retained child is released before the transaction lock.
    lock: InstallerLock,
}

impl HistoryRoot {
    pub(crate) fn selected(&self) -> &str {
        &self.selected
    }

    #[cfg(windows)]
    pub(crate) fn from_moved(
        destination: Destination,
        state: InstallerDirectory,
        lock: InstallerLock,
        history: InstallerDirectory,
        selected: String,
        identities: HistoryIdentities,
    ) -> Result<Self, InstallerStageError> {
        if !crate::record::is_operation_id(&selected) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let operation = open_child(&history, &selected)?;
        let HistoryIdentities {
            state: state_identity,
            history: history_identity,
            operation: operation_identity,
        } = identities;
        let root = Self {
            operation,
            history,
            state,
            destination,
            selected,
            operation_identity,
            history_identity,
            state_identity,
            lock,
        };
        root.revalidate(operation_identity)?;
        Ok(root)
    }

    pub(crate) fn synchronize_directory(
        &self,
        directory: HistoryDirectory,
    ) -> Result<(), InstallerStageError> {
        use HistoryDirectory::*;
        self.revalidate(self.operation_identity)?;
        match directory {
            Operation => sync_child(&self.history, &self.selected, &self.operation)?,
            History => sync_child(
                destination_directory(&self.destination)?,
                INSTALLER_HISTORY_DIRECTORY,
                &self.history,
            )?,
            Source => {
                sync_child(
                    destination_directory(&self.destination)?,
                    INSTALLER_STATE_DIRECTORY,
                    &self.state,
                )?;
                #[cfg(unix)]
                crate::unix_staging::sync_directory(self.destination.directory())?;
                #[cfg(windows)]
                self.destination
                    .flush()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?;
            }
        }
        self.revalidate(self.operation_identity)
    }

    pub(super) fn open(path: &Path, selected: &str) -> Result<Self, InstallerStageError> {
        if !crate::record::is_operation_id(selected) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        #[cfg(unix)]
        let destination = crate::unix_staging::open_destination(path)?;
        #[cfg(windows)]
        let destination = kitrove_windows_security::validate_install_directory(path)
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        let parent = destination_directory(&destination)?;
        let state = open_child(parent, INSTALLER_STATE_DIRECTORY)?;
        let state_identity = directory_identity(&state)?;
        #[cfg(unix)]
        let lock = crate::unix_staging::acquire_existing_installer_lock(&state)?;
        #[cfg(windows)]
        let lock = crate::windows_staging::acquire_existing_installer_lock(&state)?;
        require_exact_inventory(&state, &[OsStr::new(INSTALLER_LOCK)])?;
        let history = open_child(parent, INSTALLER_HISTORY_DIRECTORY)?;
        let history_identity = directory_identity(&history)?;
        let operation = open_child(&history, selected)?;
        let operation_identity = directory_identity(&operation)?;
        let root = Self {
            operation,
            history,
            state,
            destination,
            selected: selected.to_owned(),
            operation_identity,
            history_identity,
            state_identity,
            lock,
        };
        root.revalidate(operation_identity)?;
        Ok(root)
    }

    pub(super) fn revalidate(
        &self,
        recorded_identity: NativeFileIdentity,
    ) -> Result<(), InstallerStageError> {
        #[cfg(unix)]
        crate::unix_staging::revalidate_control_boundary(
            &self.destination,
            &self.state,
            self.state_identity,
            &self.lock,
        )?;
        #[cfg(windows)]
        crate::windows_staging::revalidate_control_boundary(
            &self.destination,
            &self.state,
            self.state_identity,
            &self.lock,
        )?;
        require_exact_inventory(&self.state, &[OsStr::new(INSTALLER_LOCK)])?;
        require_child(
            destination_directory(&self.destination)?,
            INSTALLER_HISTORY_DIRECTORY,
            &self.history,
            self.history_identity,
        )?;
        require_child(
            &self.history,
            &self.selected,
            &self.operation,
            self.operation_identity,
        )?;
        if recorded_identity != self.operation_identity {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(())
    }
}

fn sync_child(
    parent: &InstallerDirectory,
    name: &str,
    child: &InstallerDirectory,
) -> Result<(), InstallerStageError> {
    let expected = directory_identity(child)?;
    require_child(parent, name, child, expected)?;
    #[cfg(unix)]
    crate::unix_staging::sync_directory(child)?;
    #[cfg(windows)]
    crate::windows_staging::sync_directory(parent, OsStr::new(name), child)?;
    require_child(parent, name, child, expected)
}

#[cfg(unix)]
pub(super) fn synchronize_executable(leaf: &OpenedLeaf) -> Result<(), InstallerStageError> {
    crate::unix_staging::sync_file(&leaf.file)
}

#[cfg(windows)]
pub(super) fn synchronize_executable(
    parent: &InstallerDirectory,
    name: &str,
    leaf: OpenedLeaf,
    size: u64,
    sha256: [u8; 32],
) -> Result<OpenedLeaf, InstallerStageError> {
    let file = crate::windows_staging::flush_retained_private_file(
        parent,
        OsStr::new(name),
        leaf.file,
        size,
        sha256,
    )?;
    Ok(OpenedLeaf {
        file,
        identity: leaf.identity,
        size: leaf.size,
    })
}

fn destination_directory(
    destination: &Destination,
) -> Result<&InstallerDirectory, InstallerStageError> {
    #[cfg(unix)]
    {
        Ok(destination.directory())
    }
    #[cfg(windows)]
    {
        destination
            .directory()
            .map_err(|_| InstallerStageError::UnsafeDestination)
    }
}

fn open_child(
    parent: &InstallerDirectory,
    name: &str,
) -> Result<InstallerDirectory, InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::open_private_child(parent, OsStr::new(name))
    }
    #[cfg(windows)]
    {
        kitrove_windows_security::open_private_directory(parent, OsStr::new(name))
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

fn directory_identity(
    directory: &InstallerDirectory,
) -> Result<NativeFileIdentity, InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::directory_identity(directory)
    }
    #[cfg(windows)]
    {
        crate::windows_staging::file_identity(directory)
    }
}

fn require_child(
    parent: &InstallerDirectory,
    name: &str,
    child: &InstallerDirectory,
    expected: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::require_named_directory_identity(parent, name, child, expected)
    }
    #[cfg(windows)]
    {
        crate::windows_staging::require_identity(child, expected)?;
        crate::windows_staging::require_named_directory_identity(parent, OsStr::new(name), expected)
    }
}

pub(super) fn require_exact_inventory(
    parent: &InstallerDirectory,
    expected: &[&OsStr],
) -> Result<(), InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::require_exact_inventory(parent, expected)
    }
    #[cfg(windows)]
    {
        crate::windows_staging::require_exact_inventory(parent, expected)
    }
}

pub(super) fn open_executable(
    parent: &InstallerDirectory,
    name: &str,
    size: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_recovery::open_exact_private_file(parent, name, 0o700, size)
    }
    #[cfg(windows)]
    {
        crate::windows_recovery::open_bounded_private_file(parent, OsStr::new(name), size)
    }
}

pub(super) fn require_executable(
    parent: &InstallerDirectory,
    name: &str,
    leaf: &OpenedLeaf,
    identity: NativeFileIdentity,
    size: u64,
    sha256: [u8; 32],
) -> Result<(), InstallerStageError> {
    if leaf.identity != identity || leaf.size != size {
        return Err(InstallerStageError::RecoveryRequired);
    }
    #[cfg(unix)]
    {
        crate::unix_staging::require_named_file_identity(
            parent, name, &leaf.file, identity, 0o700, size,
        )?;
        crate::unix_staging::verify_sha256_contents(&leaf.file, size, sha256)?;
        crate::unix_staging::require_named_file_identity(
            parent, name, &leaf.file, identity, 0o700, size,
        )
    }
    #[cfg(windows)]
    {
        crate::windows_staging::require_identity(&leaf.file, identity)?;
        crate::windows_staging::require_named_file_identity(
            parent,
            OsStr::new(name),
            identity,
            false,
        )?;
        crate::windows_staging::require_file_contents(&leaf.file, size, sha256)?;
        crate::windows_staging::require_named_file_identity(
            parent,
            OsStr::new(name),
            identity,
            false,
        )
    }
}
