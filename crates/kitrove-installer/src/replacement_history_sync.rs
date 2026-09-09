use std::path::PathBuf;

use super::*;
use crate::installation_history::synchronization::{HistoricalArchive, synchronize_archive};

/// Retry archival durability using fresh release authentication and current selected state.
/// Historical paths never select live state; no executable is replaced or history removed.
pub(crate) fn synchronize(
    destination: &Path,
    selected: &str,
    candidate: &AuthenticatedApplicationExecutable,
    prior: &ExpectedReleaseIdentity,
    archive_sha256: [u8; 32],
    roots: &[PathBuf],
    direction: ReplacementDirection,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    crate::require_compiled_target(candidate)?;
    crate::require_current_user_installation()?;
    synchronize_archive(
        roots,
        || {
            ArchivedReplacement::open(
                destination,
                selected,
                candidate,
                prior,
                archive_sha256,
                direction,
            )
        },
        |_| Ok(()),
    )
}

impl HistoricalArchive for ArchivedReplacement {
    fn revalidate(&self) -> Result<(), InstallerStageError> {
        ArchivedReplacement::revalidate(self)
    }

    fn root(&self) -> &filesystem::HistoryRoot {
        &self.root
    }

    fn outcome(&self) -> Result<HistoricalInstallOutcome, InstallerStageError> {
        ArchivedReplacement::outcome(self)
    }

    fn sync_files(mut self) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        #[cfg(unix)]
        {
            self.operation_leaf
                .sync(&self.root.operation, OPERATION_RECORD)?;
            self.upgrade_leaf
                .sync(&self.root.operation, UPGRADE_RECORD)?;
            filesystem::synchronize_executable(&self.displaced.leaf)?;
            self.kit.sync_material()?;
        }
        #[cfg(windows)]
        {
            self.operation_leaf = self
                .operation_leaf
                .sync_owned(&self.root.operation, OPERATION_RECORD)?;
            self.upgrade_leaf = self
                .upgrade_leaf
                .sync_owned(&self.root.operation, UPGRADE_RECORD)?;
            self.displaced.leaf = filesystem::synchronize_executable(
                &self.root.operation,
                self.displaced.name,
                self.displaced.leaf,
                self.displaced_size,
                self.displaced_sha256,
            )?;
            self.kit = self
                .kit
                .sync_material_owned(&self.root.operation, &self.material)?;
        }
        self.phases = journal::synchronize(self.phases, &self.root.operation)?;
        self.revalidate()?;
        Ok(self)
    }
}

#[cfg(test)]
pub(crate) fn synchronize_test_archive(
    roots: &[PathBuf],
    open: impl FnOnce() -> Result<ArchivedReplacement, InstallerStageError>,
    boundary: impl FnMut(
        crate::installation_history::synchronization::HistorySyncBoundary,
    ) -> Result<(), InstallerStageError>,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    synchronize_archive(roots, open, boundary)
}
