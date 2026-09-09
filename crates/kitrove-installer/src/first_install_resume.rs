use super::*;
use crate::InstalledApplication;
#[cfg(unix)]
use crate::unix_staging::sync_directory;

#[cfg(windows)]
#[path = "windows_first_install_resume.rs"]
mod windows;

impl ReopenedInstallation {
    pub(crate) fn recover(self) -> Result<InstalledApplication, InstallerStageError> {
        self.recover_with(crate::verify_installed_application, |_| Ok(()))
    }

    pub(in crate::installation_state) fn recover_with(
        mut self,
        probe: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
        mut boundary: impl FnMut(RecoveryBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        self.revalidate()?;
        if self.phase == DetectedInstallPhase::Prepared {
            return self.installation.install_with_probe(probe);
        }
        self = self.sync(&mut boundary)?;
        #[cfg(unix)]
        if self.phase == DetectedInstallPhase::RollbackHandoff {
            let extra = self.extra_names();
            unix_install::remove_rollback_handoff_name(&self.installation.staged, &extra)?;
            self.phase = DetectedInstallPhase::RollingBack;
            boundary(RecoveryBoundary::HandoffRemoved)?;
            self = self.sync(&mut boundary)?;
        }
        if matches!(
            self.phase,
            DetectedInstallPhase::RollingBack | DetectedInstallPhase::RolledBack
        ) {
            if self.phase != DetectedInstallPhase::RolledBack {
                self.write_marker(InstallPhase::RolledBack, &mut boundary)?;
            }
            self.revalidate()?;
            return Err(InstallerStageError::VerificationFailed);
        }
        if self.phase == DetectedInstallPhase::ReplacedUnrecorded {
            self.write_marker(InstallPhase::Replaced, &mut boundary)?;
        }
        self.revalidate()?;
        #[cfg(unix)]
        let path = unix_install::destination_executable_path(&self.installation.staged);
        #[cfg(windows)]
        let path = self
            .installation
            .staged
            ._retained
            .destination
            .path()
            .join(self.installation.staged.record.executable_name());
        let observed = probe(&path, self.installation.staged.manifest.release_version());
        boundary(RecoveryBoundary::Probed)?;
        self.revalidate()?;
        if observed.as_ref() != Ok(&self.installation.staged.executable_content_hash) {
            self.restore_absence(&mut boundary)?;
            return Err(InstallerStageError::VerificationFailed);
        }
        if self.phase == DetectedInstallPhase::Replaced {
            self.write_marker(InstallPhase::Verified, &mut boundary)?;
        }
        if self.phase == DetectedInstallPhase::Verified {
            self.write_marker(InstallPhase::Committed, &mut boundary)?;
        }
        self.revalidate()?;
        Ok(InstalledApplication {
            record: self.installation.staged.record,
            manifest: self.installation.staged.manifest,
            path,
        })
    }

    fn sync(
        mut self,
        boundary: &mut impl FnMut(RecoveryBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        #[cfg(unix)]
        self.sync_files()?;
        #[cfg(windows)]
        {
            self = self.sync_windows()?;
        }
        boundary(RecoveryBoundary::Synced)?;
        self.revalidate()?;
        Ok(self)
    }

    fn write_marker(
        &mut self,
        phase: InstallPhase,
        boundary: &mut impl FnMut(RecoveryBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        self.revalidate()?;
        let expected_phase = match self.phase {
            DetectedInstallPhase::ReplacedUnrecorded => InstallPhase::Replaced,
            DetectedInstallPhase::Replaced => InstallPhase::Verified,
            DetectedInstallPhase::Verified => InstallPhase::Committed,
            DetectedInstallPhase::RollingBack => InstallPhase::RolledBack,
            _ => return Err(InstallerStageError::RecoveryRequired),
        };
        if phase != expected_phase {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let index =
            if let Some(index) = self.pending.iter().position(|record| record.phase == phase) {
                index
            } else {
                let leaf = create_private_data_leaf(
                    &self.installation.staged._retained.operation,
                    phase.pending_file_name(),
                    Vec::new(),
                )?;
                self.pending.push(InstallJournalRecord { phase, leaf });
                boundary(RecoveryBoundary::PhaseCreated(phase))?;
                self.pending.len() - 1
            };
        self.revalidate()?;
        let bytes = phase_bytes(&self.installation.staged, phase)?;
        #[cfg(unix)]
        self.pending[index].leaf.complete_prefix(
            &self.installation.staged._retained.operation,
            phase.pending_file_name(),
            &bytes,
        )?;
        #[cfg(windows)]
        {
            let record = self.pending.remove(index);
            let leaf = record.leaf.complete_prefix_owned(
                &self.installation.staged._retained.operation,
                phase.pending_file_name(),
                &bytes,
            )?;
            self.pending
                .insert(index, InstallJournalRecord { phase, leaf });
        }
        boundary(RecoveryBoundary::PhaseCompleted(phase))?;
        self.revalidate()?;
        #[cfg(unix)]
        unix_install::rename_noreplace(
            &self.installation.staged._retained.operation,
            OsStr::new(phase.pending_file_name()),
            &self.installation.staged._retained.operation,
            OsStr::new(phase.file_name()),
        )?;
        #[cfg(unix)]
        let record = self.pending.remove(index);
        #[cfg(unix)]
        let marker = record.leaf.file;
        #[cfg(windows)]
        let marker = self.publish_windows_marker(index, phase)?;
        self.installation
            .staged
            ._retained
            .phase_markers
            .push(marker);
        self.phase = match phase {
            InstallPhase::Replaced => DetectedInstallPhase::Replaced,
            InstallPhase::Verified => DetectedInstallPhase::Verified,
            InstallPhase::Committed => DetectedInstallPhase::Committed,
            InstallPhase::RolledBack => DetectedInstallPhase::RolledBack,
        };
        boundary(RecoveryBoundary::PhasePublished(phase))?;
        #[cfg(unix)]
        sync_directory(&self.installation.staged._retained.operation)?;
        self.revalidate()
    }

    fn restore_absence(
        mut self,
        boundary: &mut impl FnMut(RecoveryBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        let mut prior = Vec::new();
        for &phase in location(self.phase).marker_phases() {
            if phase != InstallPhase::Replaced {
                prior.push(InstallJournalRecord {
                    phase,
                    leaf: read_private_data_leaf(
                        &self.installation.staged._retained.operation,
                        phase.file_name(),
                        MAX_PHASE_RECORD_BYTES,
                    )?,
                });
            }
        }
        self.revalidate()?;
        #[cfg(unix)]
        let staged = &self.installation.staged;
        #[cfg(unix)]
        unix_install::rename_noreplace(
            staged._retained.destination.directory(),
            OsStr::new(staged.record.executable_name()),
            &staged._retained.operation,
            OsStr::new(crate::install_phase::FAILED_EXECUTABLE),
        )?;
        #[cfg(windows)]
        {
            let name = self.installation.staged.record.executable_name().to_owned();
            crate::windows_install::restore_install_absence(&mut self.installation.staged, &name)?;
        }
        // Retain all earlier evidence, while the active rollback chain uses its own
        // exact marker set. No old complete or pending journal leaf is removed.
        self.prior = prior;
        self.installation.staged._retained.phase_markers.truncate(1);
        self.phase = DetectedInstallPhase::RollingBack;
        boundary(RecoveryBoundary::Restored)?;
        self = self.sync(boundary)?;
        self.write_marker(InstallPhase::RolledBack, boundary)?;
        Ok(self)
    }
}
