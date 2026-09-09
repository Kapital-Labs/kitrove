use super::*;
use crate::windows_staging::{
    flush_retained_private_file, native_identity, reopen_private_file_with_identity,
    require_file_contents,
};
use sha2::Sha256;

impl<R: InstallationStateRecord> InspectedInstallation<R> {
    /// Writable leases are temporary and consumed; state locks outlive every rebind.
    pub(in crate::installation_state::recovery) fn sync_windows(
        mut self,
    ) -> Result<Self, InstallerStageError> {
        self.installation.record = self
            .installation
            .record
            .sync_owned(&self.installation.staged._retained.operation)?;
        let file = self
            .installation
            .staged
            ._retained
            .executable
            .take()
            .ok_or(InstallerStageError::RecoveryRequired)?;
        let (parent, name) = if self.phase.is_restored() {
            (
                &self.installation.staged._retained.operation,
                crate::install_phase::FAILED_EXECUTABLE,
            )
        } else {
            (
                self.installation
                    .staged
                    ._retained
                    .destination
                    .directory()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
                self.installation.staged.record.executable_name(),
            )
        };
        self.installation.staged._retained.executable = Some(flush_retained_private_file(
            parent,
            OsStr::new(name),
            file,
            self.installation.staged.record.executable_size(),
            self.installation.staged.manifest.executable_sha256(),
        )?);
        let operation_bytes = self
            .installation
            .staged
            .record
            .to_json()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.installation.staged._retained.record = flush_retained_private_file(
            &self.installation.staged._retained.operation,
            OsStr::new(crate::staging_policy::OPERATION_RECORD),
            self.installation.staged._retained.record,
            operation_bytes.len() as u64,
            Sha256::digest(&operation_bytes).into(),
        )?;
        let phases = location(self.phase).marker_phases();
        let expected = phases
            .iter()
            .map(|phase| phase_bytes(&self.installation.staged, *phase))
            .collect::<Result<Vec<_>, _>>()?;
        let mut markers = Vec::new();
        for ((file, phase), bytes) in self
            .installation
            .staged
            ._retained
            .phase_markers
            .into_iter()
            .zip(phases)
            .zip(expected)
        {
            markers.push(flush_retained_private_file(
                &self.installation.staged._retained.operation,
                OsStr::new(phase.file_name()),
                file,
                bytes.len() as u64,
                Sha256::digest(&bytes).into(),
            )?);
        }
        self.installation.staged._retained.phase_markers = markers;
        self.pending = self
            .pending
            .into_iter()
            .map(|record| {
                let leaf = record.leaf.sync_owned(
                    &self.installation.staged._retained.operation,
                    record.phase.pending_file_name(),
                )?;
                Ok(InstallJournalRecord {
                    phase: record.phase,
                    leaf,
                })
            })
            .collect::<Result<_, InstallerStageError>>()?;
        self.prior = self
            .prior
            .into_iter()
            .map(|record| {
                let leaf = record.leaf.sync_owned(
                    &self.installation.staged._retained.operation,
                    record.phase.file_name(),
                )?;
                Ok(InstallJournalRecord {
                    phase: record.phase,
                    leaf,
                })
            })
            .collect::<Result<_, InstallerStageError>>()?;
        Ok(self)
    }
}

impl ReopenedInstallation {
    pub(super) fn publish_windows_marker(
        &mut self,
        index: usize,
        phase: InstallPhase,
    ) -> Result<std::fs::File, InstallerStageError> {
        let record = self.pending.remove(index);
        let identity = kitrove_windows_security::file_identity(&record.leaf.file)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        drop(record.leaf.file);
        let parent = &self.installation.staged._retained.operation;
        kitrove_windows_security::promote_owned_file(
            parent,
            OsStr::new(phase.pending_file_name()),
            OsStr::new(phase.file_name()),
            OsStr::new("phase-record.rollback"),
            identity,
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let marker = reopen_private_file_with_identity(
            parent,
            OsStr::new(phase.file_name()),
            native_identity(identity),
        )?;
        let marker = flush_retained_private_file(
            parent,
            OsStr::new(phase.file_name()),
            marker,
            record.leaf.bytes.len() as u64,
            Sha256::digest(&record.leaf.bytes).into(),
        )?;
        require_file_contents(
            &marker,
            record.leaf.bytes.len() as u64,
            Sha256::digest(&record.leaf.bytes).into(),
        )?;
        Ok(marker)
    }
}
