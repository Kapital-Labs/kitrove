use std::path::{Path, PathBuf};

use super::*;
use crate::state_preflight::InspectedStateRoots;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistorySyncBoundary {
    Inspected,
    FilesSynced,
    OperationSynced,
    HistorySynced,
    SourceSynced,
}

/// Explicit retry after archival movement. Only current caller-selected roots are locked.
/// No executable is installed, no pending write is completed, and no history is removed.
pub(crate) fn synchronize(
    destination: &Path,
    selected: &str,
    executable: &AuthenticatedApplicationExecutable,
    roots: &[PathBuf],
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    synchronize_with(destination, selected, executable, roots, |_| Ok(()))
}

pub(crate) fn synchronize_with(
    destination: &Path,
    selected: &str,
    executable: &AuthenticatedApplicationExecutable,
    roots: &[PathBuf],
    boundary: impl FnMut(HistorySyncBoundary) -> Result<(), InstallerStageError>,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    crate::require_compiled_target(executable)?;
    crate::require_current_user_installation()?;
    synchronize_archive(
        roots,
        || ArchivedInstallation::open(destination, selected, executable),
        boundary,
    )
}

/// Retained, revalidated historical evidence. Implementations preserve all leaves on error.
pub(crate) trait HistoricalArchive: Sized {
    fn revalidate(&self) -> Result<(), InstallerStageError>;
    fn sync_files(self) -> Result<Self, InstallerStageError>;
    fn root(&self) -> &filesystem::HistoryRoot;
    fn outcome(&self) -> Result<HistoricalInstallOutcome, InstallerStageError>;
}

pub(super) fn synchronize_archive<H: HistoricalArchive>(
    roots: &[PathBuf],
    open: impl FnOnce() -> Result<H, InstallerStageError>,
    boundary: impl FnMut(HistorySyncBoundary) -> Result<(), InstallerStageError>,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    let mut states = InspectedStateRoots::capture(roots)?;
    // Reverse local drop order releases the history leaves and installer lock before state guards.
    let history = open()?;
    synchronize_locked_archive(&mut states, history, boundary)
}

pub(crate) fn synchronize_locked_archive<H: HistoricalArchive>(
    states: &mut InspectedStateRoots,
    history: H,
    mut boundary: impl FnMut(HistorySyncBoundary) -> Result<(), InstallerStageError>,
) -> Result<HistoricalInstallOutcome, InstallerStageError> {
    let check = |history: &H, states: &mut InspectedStateRoots| {
        states.revalidate()?;
        history.revalidate()?;
        states.revalidate()
    };
    // Once inspection succeeds, every interruption or uncertainty retains all evidence for retry.
    (|| -> Result<HistoricalInstallOutcome, InstallerStageError> {
        boundary(HistorySyncBoundary::Inspected)?;
        check(&history, states)?;
        let history = history.sync_files()?;
        boundary(HistorySyncBoundary::FilesSynced)?;
        check(&history, states)?;
        for (directory, point) in [
            (
                filesystem::HistoryDirectory::Operation,
                HistorySyncBoundary::OperationSynced,
            ),
            (
                filesystem::HistoryDirectory::History,
                HistorySyncBoundary::HistorySynced,
            ),
            (
                filesystem::HistoryDirectory::Source,
                HistorySyncBoundary::SourceSynced,
            ),
        ] {
            history.root().synchronize_directory(directory)?;
            boundary(point)?;
            check(&history, states)?;
        }
        let outcome = history.outcome()?;
        check(&history, states)?;
        Ok(outcome)
    })()
    .map_err(|_| InstallerStageError::RecoveryRequired)
}

impl HistoricalArchive for ArchivedInstallation {
    fn revalidate(&self) -> Result<(), InstallerStageError> {
        ArchivedInstallation::revalidate(self)
    }

    fn root(&self) -> &filesystem::HistoryRoot {
        &self.root
    }

    fn outcome(&self) -> Result<HistoricalInstallOutcome, InstallerStageError> {
        ArchivedInstallation::outcome(self)
    }

    fn sync_files(self) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        #[cfg(unix)]
        {
            self.record_leaf
                .sync(&self.root.operation, OPERATION_RECORD)?;
            self.state_leaf
                .sync(&self.root.operation, INSTALL_STATE_RECORD)?;
            for phase in &self.phases {
                phase.leaf.sync(&self.root.operation, phase.name())?;
            }
            for executable in &self.executables {
                filesystem::synchronize_executable(&executable.leaf)?;
            }
            self.revalidate()?;
            Ok(self)
        }
        #[cfg(windows)]
        {
            // Keep the aggregate owner intact so errors close remaining leaves before the lock.
            let mut history = self;
            history.record_leaf = history
                .record_leaf
                .sync_owned(&history.root.operation, OPERATION_RECORD)?;
            history.state_leaf = history
                .state_leaf
                .sync_owned(&history.root.operation, INSTALL_STATE_RECORD)?;
            history.phases = history
                .phases
                .into_iter()
                .map(|phase| {
                    let name = phase.name();
                    Ok(JournalLeaf {
                        phase: phase.phase,
                        pending: phase.pending,
                        name,
                        leaf: phase.leaf.sync_owned(&history.root.operation, name)?,
                    })
                })
                .collect::<Result<Vec<_>, InstallerStageError>>()?;
            history.executables = history
                .executables
                .into_iter()
                .map(|executable| {
                    let leaf = filesystem::synchronize_executable(
                        &history.root.operation,
                        executable.name,
                        executable.leaf,
                        history.executable_size,
                        history.executable_sha256,
                    )?;
                    Ok(ExecutableLeaf {
                        name: executable.name,
                        identity: executable.identity,
                        leaf,
                    })
                })
                .collect::<Result<Vec<_>, InstallerStageError>>()?;
            history.revalidate()?;
            Ok(history)
        }
    }
}
