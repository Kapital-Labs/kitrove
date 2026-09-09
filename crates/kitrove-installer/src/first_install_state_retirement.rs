use super::*;
use crate::unix_history::{RetirementBoundary, TerminalOperation};

impl ClosedInstallation {
    pub(crate) fn retire(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
    ) -> Result<(), InstallerStageError> {
        Self::retire_with(destination, executable, roots, |_| Ok(()))
    }

    pub(in crate::installation_state) fn retire_with(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
        boundary: impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        let mut closed = Self::reopen(destination, executable, roots)?;
        closed.require_terminal()?;
        crate::unix_history::retire(&mut closed, boundary)
    }

    fn require_terminal(&self) -> Result<(), InstallerStageError> {
        if matches!(
            self.phase,
            DetectedInstallPhase::Committed | DetectedInstallPhase::RolledBack
        ) {
            Ok(())
        } else {
            Err(InstallerStageError::RecoveryRequired)
        }
    }
}

impl TerminalOperation for ClosedInstallation {
    fn staged(&self) -> &StagedApplication {
        &self.installation.staged
    }

    fn revalidate_contents(&mut self) -> Result<(), InstallerStageError> {
        self.require_terminal()?;
        InspectedInstallation::revalidate_contents(self)
    }

    fn sync_files(&self) -> Result<(), InstallerStageError> {
        InspectedInstallation::sync_files(self)
    }
}
