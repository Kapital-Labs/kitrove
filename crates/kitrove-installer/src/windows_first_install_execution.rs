use super::*;
use crate::InstalledApplication;
use crate::install_phase::{InstallPhase, InstallRecoveryPhase};
use crate::windows_install::{self, PhaseWriteBoundary};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionBoundary {
    BeforePublication,
    Published,
    BeforeProbe,
    Probed,
    Restored,
    PhaseWrite(InstallPhase, PhaseWriteBoundary),
}

impl PreparedInstallation {
    pub(crate) fn install(self) -> Result<InstalledApplication, InstallerStageError> {
        self.install_with_probe(crate::verify_installed_application)
    }

    pub(super) fn install_with_probe(
        self,
        probe: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        self.install_with(probe, |_| Ok(()))
    }

    fn install_with(
        mut self,
        probe: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
        mut boundary: impl FnMut(ExecutionBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        boundary(ExecutionBoundary::BeforePublication)?;
        self.revalidate()?;
        windows_install::publish_retained_executable(&mut self.staged)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        boundary(ExecutionBoundary::Published)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.write_phase(InstallPhase::Replaced, &mut boundary)?;

        let name = self.staged.record.executable_name().to_owned();
        let path = self.staged._retained.destination.path().join(&name);
        boundary(ExecutionBoundary::BeforeProbe)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.validate_phase(InstallRecoveryPhase::Replaced)?;
        let observed = probe(&path, self.staged.manifest.release_version());
        boundary(ExecutionBoundary::Probed).map_err(|_| InstallerStageError::RecoveryRequired)?;
        // Even automatic restoration requires the same freshly validated state authority.
        self.validate_phase(InstallRecoveryPhase::Replaced)?;
        if observed.as_ref() != Ok(&self.staged.executable_content_hash) {
            windows_install::restore_install_absence(&mut self.staged, &name)?;
            boundary(ExecutionBoundary::Restored)
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            self.write_phase(InstallPhase::RolledBack, &mut boundary)?;
            return Err(InstallerStageError::VerificationFailed);
        }
        self.write_phase(InstallPhase::Verified, &mut boundary)?;
        self.write_phase(InstallPhase::Committed, &mut boundary)?;
        self.validate_phase(InstallRecoveryPhase::Committed)?;
        Ok(InstalledApplication {
            record: self.staged.record,
            manifest: self.staged.manifest,
            path,
        })
    }

    fn validate_phase(&mut self, phase: InstallRecoveryPhase) -> Result<(), InstallerStageError> {
        validate(&self.staged, &self.record, &mut self.states, phase, &[])
    }

    fn write_phase(
        &mut self,
        phase: InstallPhase,
        boundary: &mut impl FnMut(ExecutionBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        let (before, after) = match phase {
            InstallPhase::Replaced => (
                InstallRecoveryPhase::ReplacedUnrecorded,
                InstallRecoveryPhase::Replaced,
            ),
            InstallPhase::Verified => (
                InstallRecoveryPhase::Replaced,
                InstallRecoveryPhase::Verified,
            ),
            InstallPhase::Committed => (
                InstallRecoveryPhase::Verified,
                InstallRecoveryPhase::Committed,
            ),
            InstallPhase::RolledBack => (
                InstallRecoveryPhase::RolledBackUnrecorded,
                InstallRecoveryPhase::RolledBack,
            ),
        };
        self.validate_phase(before)?;
        windows_install::write_phase_record_with_validation(
            &mut self.staged,
            phase,
            |staged, point| {
                boundary(ExecutionBoundary::PhaseWrite(phase, point))?;
                let pending = [OsStr::new(phase.pending_file_name())];
                let (location, extra) = if point == PhaseWriteBoundary::Published {
                    (after, &[][..])
                } else {
                    (before, &pending[..])
                };
                validate(staged, &self.record, &mut self.states, location, extra)
            },
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

fn validate(
    staged: &StagedApplication,
    record: &RetainedInstallState,
    states: &mut InspectedStateRoots,
    phase: InstallRecoveryPhase,
    pending: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let installed = match phase {
        InstallRecoveryPhase::Prepared
        | InstallRecoveryPhase::RolledBack
        | InstallRecoveryPhase::RolledBackUnrecorded => None,
        _ => Some(staged.record.executable_name()),
    };
    let mut extra = vec![OsStr::new(INSTALL_STATE_RECORD)];
    extra.extend_from_slice(pending);
    windows_install::revalidate_stage_with_extra_entries(staged, phase, installed, &extra)?;
    record.revalidate(&staged._retained.operation, &staged.record, states)?;
    windows_install::revalidate_stage_with_extra_entries(staged, phase, installed, &extra)
}

#[cfg(test)]
#[path = "windows_first_install_execution_tests.rs"]
mod tests;
