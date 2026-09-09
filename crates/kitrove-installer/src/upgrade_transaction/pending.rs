use cap_std::fs::Dir;
use std::ffi::OsStr;

use super::{
    Exchange, MAX_UPGRADE_PHASE_BYTES, Marker, UpgradeBoundary, marker_name, pending_name,
};
use crate::InstallerStageError;
use crate::install_phase::InstallPhase;
pub(super) use crate::replacement_phase::require_phase_order;
use crate::staging_policy::{PrivateDataLeaf, read_pending_data_leaf};
use crate::unix_staging::metadata_identity;

pub(super) struct PendingMarker {
    pub(super) phase: InstallPhase,
    leaf: PrivateDataLeaf,
}

impl PendingMarker {
    pub(super) fn sync(&self) -> Result<(), InstallerStageError> {
        self.leaf
            .file
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }
    pub(super) fn open(
        parent: &Dir,
        phase: InstallPhase,
        canonical: &[u8],
    ) -> Result<Self, InstallerStageError> {
        let leaf = read_pending_data_leaf(parent, pending_name(phase), MAX_UPGRADE_PHASE_BYTES)?;
        let pending = Self { phase, leaf };
        pending.revalidate(parent, canonical)?;
        Ok(pending)
    }

    pub(super) fn revalidate(
        &self,
        parent: &Dir,
        canonical: &[u8],
    ) -> Result<(), InstallerStageError> {
        self.leaf
            .require_prefix(parent, pending_name(self.phase), canonical)
    }

    fn complete(&mut self, parent: &Dir, canonical: &[u8]) -> Result<(), InstallerStageError> {
        self.leaf
            .complete_prefix(parent, pending_name(self.phase), canonical)
    }
}

impl Exchange<'_> {
    pub(super) fn write_marker(&mut self, phase: InstallPhase) -> Result<(), InstallerStageError> {
        self.write_marker_with_hook(phase, &mut |_| Ok(()))
    }

    pub(super) fn write_marker_with_hook(
        &mut self,
        phase: InstallPhase,
        boundary: &mut impl FnMut(UpgradeBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        self.revalidate()?;
        if self.has_marker(phase) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let mut planned_pending = self
            .pending
            .iter()
            .map(|pending| pending.phase)
            .collect::<Vec<_>>();
        if !planned_pending.contains(&phase) {
            planned_pending.push(phase);
        }
        require_phase_order(
            &self
                .markers
                .iter()
                .map(|marker| marker.phase)
                .collect::<Vec<_>>(),
            &planned_pending,
            self.layout,
        )?;
        let bytes = self.phase_bytes(phase)?;
        let index = if let Some(index) = self
            .pending
            .iter()
            .position(|pending| pending.phase == phase)
        {
            index
        } else {
            let file = crate::unix_staging::create_private_file(
                &self.prepared.staged._retained.operation,
                OsStr::new(pending_name(phase)),
                0o600,
            )?;
            let identity = metadata_identity(
                &file
                    .metadata()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
            );
            self.pending.push(PendingMarker {
                phase,
                leaf: PrivateDataLeaf {
                    file,
                    identity,
                    bytes: Vec::new(),
                },
            });
            boundary(UpgradeBoundary::PhaseCreated(phase))?;
            self.pending.len() - 1
        };
        self.revalidate()?;
        self.pending[index].complete(&self.prepared.staged._retained.operation, &bytes)?;
        boundary(UpgradeBoundary::PhaseWritten(phase))?;
        self.revalidate()?;
        crate::unix_install::rename_noreplace(
            &self.prepared.staged._retained.operation,
            OsStr::new(pending_name(phase)),
            &self.prepared.staged._retained.operation,
            OsStr::new(marker_name(phase)),
        )?;
        let pending = self.pending.remove(index);
        self.markers.push(Marker {
            phase,
            file: pending.leaf.file,
            identity: pending.leaf.identity,
        });
        boundary(UpgradeBoundary::PhasePublished(phase))?;
        crate::unix_staging::sync_directory(&self.prepared.staged._retained.operation)?;
        self.revalidate()
    }
}
