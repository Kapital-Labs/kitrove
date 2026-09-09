use std::path::{Path, PathBuf};

use kitrove_release_provenance::AuthenticatedApplicationExecutable;

use crate::install_phase::{DetectedInstallPhase, InstallPhase, InstallRecoveryPhase};
use crate::state_preflight::InspectedStateRoots;
use crate::unix_history::{RetirementBoundary, TerminalOperation};
use crate::{InstallerStageError, StagedApplication, StagingInput};

struct ClosedInstallation {
    staged: StagedApplication,
    phase: InstallPhase,
    // State guards outlive retained executable and journal handles.
    states: InspectedStateRoots,
}

impl StagedApplication {
    pub(crate) fn retire_completed_install(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        state_roots: &[PathBuf],
    ) -> Result<(), InstallerStageError> {
        crate::require_compiled_target(executable)?;
        retire_with(
            destination,
            &StagingInput::from(executable),
            state_roots,
            |_| Ok(()),
        )
    }
}

fn retire_with(
    destination: &Path,
    input: &StagingInput<'_>,
    state_roots: &[PathBuf],
    boundary: impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    crate::require_current_user_installation()?;
    let states = InspectedStateRoots::capture(state_roots)?;
    let (phase, location) = match crate::unix_recovery::detect_install_phase(destination, input)? {
        DetectedInstallPhase::Committed => {
            (InstallPhase::Committed, InstallRecoveryPhase::Committed)
        }
        DetectedInstallPhase::RolledBack => {
            (InstallPhase::RolledBack, InstallRecoveryPhase::RolledBack)
        }
        _ => return Err(InstallerStageError::RecoveryRequired),
    };
    let staged = crate::unix_recovery::resume_terminal_install(destination, input, location)?;
    crate::unix_history::retire(
        &mut ClosedInstallation {
            staged,
            phase,
            states,
        },
        boundary,
    )
}

impl TerminalOperation for ClosedInstallation {
    fn staged(&self) -> &StagedApplication {
        &self.staged
    }

    fn revalidate_contents(&mut self) -> Result<(), InstallerStageError> {
        match self.phase {
            InstallPhase::Committed => super::revalidate_phase_contents(&self.staged, self.phase)?,
            InstallPhase::RolledBack => {
                super::revalidate_rollback_contents(
                    &self.staged,
                    InstallRecoveryPhase::RolledBack,
                    self.phase,
                )?;
                // The failed-install validator checks the displaced copy; archival also
                // preserves the independently staged executable from initial preparation.
                let retained = &self.staged._retained;
                crate::unix_staging::require_named_file_identity(
                    &retained.operation,
                    crate::staging_policy::STAGED_EXECUTABLE,
                    &retained.executable,
                    *self.staged.record.staged_identity(),
                    0o700,
                    self.staged.record.executable_size(),
                )?;
                crate::unix_staging::verify_sha256_contents(
                    &retained.executable,
                    self.staged.record.executable_size(),
                    self.staged.manifest.executable_sha256(),
                )?;
            }
            _ => return Err(InstallerStageError::RecoveryRequired),
        }
        self.states.revalidate()
    }

    fn sync_files(&self) -> Result<(), InstallerStageError> {
        let retained = &self.staged._retained;
        let installed = retained
            .installed
            .as_ref()
            .ok_or(InstallerStageError::RecoveryRequired)?;
        for file in [&retained.executable, &retained.record, installed]
            .into_iter()
            .chain(&retained.phase_markers)
        {
            file.sync_all()
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
        }
        crate::unix_staging::sync_directory(&retained.operation)
    }
}

#[cfg(test)]
#[path = "first_install_retirement_tests.rs"]
mod tests;
