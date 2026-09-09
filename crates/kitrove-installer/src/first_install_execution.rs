use super::*;
use crate::InstalledApplication;
use crate::install_phase::InstallPhase;
use crate::unix_install;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionBoundary {
    BeforePublication,
    Published,
    BeforeProbe,
    Probed,
    Verified,
    Committed,
    PhaseWrite(InstallPhase, unix_install::PhaseWriteBoundary),
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
        let name = self.staged.record.executable_name().to_owned();
        // Errors from publication may follow a successful native write. Preserve the
        // operation and require recovery; never infer an absent destination on error.
        unix_install::publish_retained_executable(&mut self.staged, &name)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        boundary(ExecutionBoundary::Published)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.validate_state()?;
        self.write_phase(InstallPhase::Replaced, &mut boundary)?;
        self.validate_phase(InstallPhase::Replaced)?;

        let installed_path = unix_install::destination_executable_path(&self.staged);
        boundary(ExecutionBoundary::BeforeProbe)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.validate_phase(InstallPhase::Replaced)?;
        let observed = probe(&installed_path, self.staged.manifest.release_version());
        boundary(ExecutionBoundary::Probed).map_err(|_| InstallerStageError::RecoveryRequired)?;
        // A changed state tree blocks even automatic rollback. The saved evidence
        // cannot authorize a new mutation after an uncooperative state writer.
        self.validate_phase(InstallPhase::Replaced)?;
        if observed.as_ref() != Ok(&self.staged.executable_content_hash) {
            unix_install::rollback_failed_install_with_state(
                &mut self.staged,
                &[OsStr::new(INSTALL_STATE_RECORD)],
                |staged| {
                    self.record.revalidate(
                        &staged._retained.operation,
                        &staged.record,
                        &mut self.states,
                    )
                },
            )?;
            return Err(InstallerStageError::VerificationFailed);
        }
        self.write_phase(InstallPhase::Verified, &mut boundary)?;
        boundary(ExecutionBoundary::Verified).map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.validate_phase(InstallPhase::Verified)?;
        self.write_phase(InstallPhase::Committed, &mut boundary)?;
        boundary(ExecutionBoundary::Committed)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.validate_phase(InstallPhase::Committed)?;
        Ok(InstalledApplication {
            record: self.staged.record,
            manifest: self.staged.manifest,
            path: installed_path,
        })
    }

    fn validate_state(&mut self) -> Result<(), InstallerStageError> {
        unix_install::revalidate_common(&self.staged)?;
        self.record.revalidate(
            &self.staged._retained.operation,
            &self.staged.record,
            &mut self.states,
        )
    }

    fn validate_phase(&mut self, phase: InstallPhase) -> Result<(), InstallerStageError> {
        self.validate_state()?;
        unix_install::revalidate_phase_contents_with_extra_entries(
            &self.staged,
            phase,
            &[OsStr::new(INSTALL_STATE_RECORD)],
        )?;
        self.validate_state()
    }

    fn write_phase(
        &mut self,
        phase: InstallPhase,
        boundary: &mut impl FnMut(ExecutionBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        match phase {
            InstallPhase::Replaced => {
                self.validate_state()?;
                unix_install::revalidate_prepared_stage_with_extra_entries(
                    &self.staged,
                    &[OsStr::new(INSTALL_STATE_RECORD)],
                )?;
                unix_install::revalidate_installed_leaf(&self.staged)?;
            }
            InstallPhase::Verified => self.validate_phase(InstallPhase::Replaced)?,
            InstallPhase::Committed => self.validate_phase(InstallPhase::Verified)?,
            InstallPhase::RolledBack => return Err(InstallerStageError::RecoveryRequired),
        }
        unix_install::write_phase_record_with_validation(
            &mut self.staged,
            phase,
            |staged, point| {
                boundary(ExecutionBoundary::PhaseWrite(phase, point))?;
                unix_install::revalidate_common(staged)?;
                unix_install::require_phase_write_inventory(
                    staged,
                    phase,
                    point,
                    &[OsStr::new(INSTALL_STATE_RECORD)],
                )?;
                self.record.revalidate(
                    &staged._retained.operation,
                    &staged.record,
                    &mut self.states,
                )
            },
        )
    }
}

#[cfg(debug_assertions)]
#[cfg(test)]
#[path = "first_install_execution_tests.rs"]
mod tests;

#[cfg(debug_assertions)]
#[cfg(test)]
#[path = "first_install_recovery_tests.rs"]
mod recovery_tests;
