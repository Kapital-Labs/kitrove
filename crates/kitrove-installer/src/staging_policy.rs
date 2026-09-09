use std::ffi::{OsStr, OsString};

use crate::InstallerStageError;
use crate::record::{encode_operation_id, is_operation_id};

#[cfg(windows)]
pub(crate) const RETAINED_UPGRADE_PRIOR: &str = "prior-application";

#[cfg(unix)]
pub(crate) type InstallerFile = cap_std::fs::File;
#[cfg(windows)]
pub(crate) type InstallerFile = std::fs::File;
#[cfg(unix)]
pub(crate) type InstallerDirectory = cap_std::fs::Dir;
#[cfg(windows)]
pub(crate) type InstallerDirectory = std::fs::File;

/// Presence only, without following the entry. Callers validate type, identity and contents.
pub(crate) fn entry_exists(
    parent: &InstallerDirectory,
    name: &str,
) -> Result<bool, InstallerStageError> {
    #[cfg(windows)]
    let parent = cap_std::fs::Dir::from_std_file(
        parent
            .try_clone()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    match parent.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(InstallerStageError::RecoveryRequired),
    }
}

pub(crate) struct OpenedLeaf {
    pub(crate) file: InstallerFile,
    pub(crate) identity: crate::NativeFileIdentity,
    pub(crate) size: u64,
}

/// Bounded private bytes and their retained identity; not parsed or authenticated authority.
pub(crate) struct PrivateDataLeaf {
    pub(crate) file: InstallerFile,
    pub(crate) identity: crate::NativeFileIdentity,
    pub(crate) bytes: Vec<u8>,
}

impl PrivateDataLeaf {
    #[cfg(unix)]
    pub(crate) fn sync(
        &self,
        parent: &InstallerDirectory,
        name: &str,
    ) -> Result<(), InstallerStageError> {
        self.require_contents(parent, name, &self.bytes)?;
        crate::unix_staging::sync_file(&self.file)?;
        self.require_contents(parent, name, &self.bytes)
    }

    #[cfg(windows)]
    pub(crate) fn complete_prefix_owned(
        mut self,
        parent: &InstallerDirectory,
        name: &str,
        canonical: &[u8],
    ) -> Result<Self, InstallerStageError> {
        self.require_prefix(parent, name, canonical)?;
        self.file = crate::windows_staging::complete_private_file_prefix(
            parent,
            OsStr::new(name),
            self.file,
            &self.bytes,
            canonical,
        )?;
        self.bytes = canonical.to_vec();
        self.require_contents(parent, name, canonical)?;
        Ok(self)
    }

    #[cfg(windows)]
    pub(crate) fn sync_owned(
        mut self,
        parent: &InstallerDirectory,
        name: &str,
    ) -> Result<Self, InstallerStageError> {
        use sha2::{Digest as _, Sha256};
        self.require_contents(parent, name, &self.bytes)?;
        self.file = crate::windows_staging::flush_retained_private_file(
            parent,
            OsStr::new(name),
            self.file,
            self.bytes.len() as u64,
            Sha256::digest(&self.bytes).into(),
        )?;
        self.require_contents(parent, name, &self.bytes)?;
        Ok(self)
    }

    #[cfg(unix)]
    pub(crate) fn complete_prefix(
        &mut self,
        parent: &InstallerDirectory,
        name: &str,
        canonical: &[u8],
    ) -> Result<(), InstallerStageError> {
        self.require_prefix(parent, name, canonical)?;
        crate::unix_staging::complete_private_file_prefix(
            parent,
            name,
            &self.file,
            self.identity,
            &self.bytes,
            canonical,
        )?;
        self.bytes = canonical.to_vec();
        self.require_contents(parent, name, canonical)
    }

    pub(crate) fn require_prefix(
        &self,
        parent: &InstallerDirectory,
        name: &str,
        canonical: &[u8],
    ) -> Result<(), InstallerStageError> {
        if !canonical.starts_with(&self.bytes) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.require_contents(parent, name, &self.bytes)
    }

    /// Exact bytes and namespace identity, without interpreting record contents.
    pub(crate) fn require_contents(
        &self,
        parent: &InstallerDirectory,
        name: &str,
        expected: &[u8],
    ) -> Result<(), InstallerStageError> {
        if self.bytes != expected {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.require_identity(parent, name, expected.len())?;
        #[cfg(unix)]
        let observed = crate::unix_staging::read_bounded_file(&self.file, expected.len())?;
        #[cfg(windows)]
        let observed = crate::windows_recovery::read_pending_file(&self.file, expected.len())?;
        if observed != expected {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.require_identity(parent, name, expected.len())
    }

    fn require_identity(
        &self,
        parent: &InstallerDirectory,
        name: &str,
        size: usize,
    ) -> Result<(), InstallerStageError> {
        #[cfg(unix)]
        {
            crate::unix_staging::require_named_file_identity(
                parent,
                name,
                &self.file,
                self.identity,
                0o600,
                size as u64,
            )
        }
        #[cfg(windows)]
        {
            kitrove_windows_security::inspect_private_single_link_file(&self.file)
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            crate::windows_staging::require_identity(&self.file, self.identity)?;
            if self
                .file
                .metadata()
                .map_err(|_| InstallerStageError::RecoveryRequired)?
                .len()
                != size as u64
            {
                return Err(InstallerStageError::RecoveryRequired);
            }
            crate::windows_staging::require_named_file_identity(
                parent,
                OsStr::new(name),
                self.identity,
                false,
            )
        }
    }
}

/// Creates an exact private record through the existing platform write boundary.
pub(crate) fn create_private_data_leaf(
    parent: &InstallerDirectory,
    name: &str,
    bytes: Vec<u8>,
) -> Result<PrivateDataLeaf, InstallerStageError> {
    #[cfg(unix)]
    let file = crate::unix_staging::create_synced_private_file(parent, OsStr::new(name), &bytes)?;
    #[cfg(windows)]
    let file =
        crate::windows_staging::create_written_private_file(parent, OsStr::new(name), &bytes)?;
    #[cfg(unix)]
    let identity = crate::unix_staging::metadata_identity(
        &file
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    #[cfg(windows)]
    let identity = crate::windows_staging::file_identity(&file)?;
    let leaf = PrivateDataLeaf {
        file,
        identity,
        bytes,
    };
    leaf.require_contents(parent, name, &leaf.bytes)?;
    #[cfg(unix)]
    crate::unix_staging::sync_directory(parent)?;
    Ok(leaf)
}

pub(crate) fn require_absent_entry(
    parent: &InstallerDirectory,
    name: &str,
) -> Result<(), InstallerStageError> {
    #[cfg(windows)]
    let parent = cap_std::fs::Dir::from_std_file(
        parent
            .try_clone()
            .map_err(|_| InstallerStageError::UnsafeDestination)?,
    );
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(InstallerStageError::DestinationOccupied),
        Err(_) => Err(InstallerStageError::UnsafeDestination),
    }
}

pub(crate) fn read_private_data_leaf(
    parent: &InstallerDirectory,
    name: &str,
    maximum: usize,
) -> Result<PrivateDataLeaf, InstallerStageError> {
    #[cfg(unix)]
    let leaf =
        crate::unix_recovery::open_bounded_private_file(parent, name, 0o600, maximum as u64)?;
    #[cfg(windows)]
    let leaf = crate::windows_recovery::open_bounded_private_file(
        parent,
        OsStr::new(name),
        maximum as u64,
    )?;
    capture_opened_leaf(leaf)
}

pub(crate) fn read_pending_data_leaf(
    parent: &InstallerDirectory,
    name: &str,
    maximum: usize,
) -> Result<PrivateDataLeaf, InstallerStageError> {
    #[cfg(unix)]
    let leaf = crate::unix_recovery::open_pending_private_file(parent, name, maximum as u64)?;
    #[cfg(windows)]
    let leaf = crate::windows_recovery::open_pending_private_file(
        parent,
        OsStr::new(name),
        maximum as u64,
    )?;
    capture_opened_leaf(leaf)
}

fn capture_opened_leaf(leaf: OpenedLeaf) -> Result<PrivateDataLeaf, InstallerStageError> {
    // Allocate for the observed bounded leaf, not the maximum archive budget.
    let size = usize::try_from(leaf.size).map_err(|_| InstallerStageError::RecoveryRequired)?;
    #[cfg(unix)]
    let bytes = crate::unix_staging::read_bounded_file(&leaf.file, size)?;
    #[cfg(windows)]
    let bytes = crate::windows_recovery::read_pending_file(&leaf.file, size)?;
    if bytes.len() as u64 != leaf.size {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(PrivateDataLeaf {
        file: leaf.file,
        identity: leaf.identity,
        bytes,
    })
}

pub(crate) const INSTALLER_LOCK: &str = "operation.lock";
pub(crate) const STAGED_EXECUTABLE: &str = "application";
pub(crate) const OPERATION_RECORD: &str = "operation.json";

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RecoveryKind {
    Installation,
    #[cfg(unix)]
    TerminalInstallation,
    StateBoundInstallation,
    UpgradePreparation,
}

impl RecoveryKind {
    pub(crate) fn extra_entries(self) -> Vec<&'static OsStr> {
        match self {
            Self::Installation => Vec::new(),
            #[cfg(unix)]
            Self::TerminalInstallation => Vec::new(),
            Self::StateBoundInstallation => {
                vec![OsStr::new(crate::installation_state::INSTALL_STATE_RECORD)]
            }
            Self::UpgradePreparation => vec![
                OsStr::new(crate::rollback_kit::ROLLBACK_DIRECTORY),
                OsStr::new(crate::upgrade_record::UPGRADE_RECORD),
            ],
        }
    }
}

pub(crate) fn retained_operation_name(
    entries: impl Iterator<Item = std::io::Result<OsString>>,
) -> Result<OsString, InstallerStageError> {
    let names = entries
        .take(3)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    let lock = OsStr::new(INSTALLER_LOCK);
    if names.len() != 2 || !names.iter().any(|name| name == lock) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    names
        .into_iter()
        .find(|name| name.to_str().is_some_and(is_operation_id))
        .ok_or(InstallerStageError::RecoveryRequired)
}

pub(crate) fn lock_error(error: std::io::Error) -> InstallerStageError {
    if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
        InstallerStageError::Conflict
    } else {
        InstallerStageError::UnsafeState
    }
}

pub(crate) fn inventory_matches(mut observed: Vec<OsString>, expected: &[&OsStr]) -> bool {
    observed.sort();
    let mut expected = expected
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    observed == expected
}

pub(crate) fn random_operation_id() -> Result<String, InstallerStageError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| InstallerStageError::WriteFailed)?;
    Ok(encode_operation_id(random))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_inventory_requires_one_lock_and_one_operation() {
        let operation = encode_operation_id([1; 16]);
        for names in [
            vec![INSTALLER_LOCK, operation.as_str()],
            vec![operation.as_str(), INSTALLER_LOCK],
        ] {
            assert_eq!(
                retained_operation_name(names.into_iter().map(|name| Ok(OsString::from(name)))),
                Ok(OsString::from(&operation))
            );
        }
        for names in [
            vec![],
            vec![INSTALLER_LOCK],
            vec![operation.as_str(), operation.as_str()],
            vec![INSTALLER_LOCK, "unknown"],
            vec![INSTALLER_LOCK, operation.as_str(), "extra"],
        ] {
            assert_eq!(
                retained_operation_name(names.into_iter().map(|name| Ok(OsString::from(name)))),
                Err(InstallerStageError::RecoveryRequired)
            );
        }
        assert_eq!(
            retained_operation_name(std::iter::once(Err(std::io::Error::other(
                "enumeration failed"
            )))),
            Err(InstallerStageError::RecoveryRequired)
        );
    }

    #[test]
    fn recovery_inventory_reads_at_most_three_entries() {
        let mut reads = 0;
        let entries = std::iter::from_fn(|| {
            reads += 1;
            assert!(reads <= 3);
            Some(Ok(OsString::from(INSTALLER_LOCK)))
        });
        assert_eq!(
            retained_operation_name(entries),
            Err(InstallerStageError::RecoveryRequired)
        );
        assert_eq!(reads, 3);
    }

    #[test]
    fn only_platform_lock_contention_is_a_conflict() {
        assert_eq!(
            lock_error(fs2::lock_contended_error()),
            InstallerStageError::Conflict
        );
        assert_eq!(
            lock_error(std::io::Error::other("unexpected failure")),
            InstallerStageError::UnsafeState
        );
    }

    #[test]
    fn inventory_comparison_is_exact_and_order_independent() {
        assert!(inventory_matches(
            vec![OsString::from("b"), OsString::from("a")],
            &[OsStr::new("a"), OsStr::new("b")],
        ));
        assert!(!inventory_matches(
            vec![OsString::from("a"), OsString::from("foreign")],
            &[OsStr::new("a")],
        ));
    }
}
