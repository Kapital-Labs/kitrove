use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity,
};

use super::{
    Layout, MAX_UPGRADE_PHASE_BYTES, Marker, PendingMarker, PreparedReplacement,
    RetirementBoundary, encode_phase_evidence, marker_name, pending_name, phase_inventory,
    require_pair,
};
use crate::install_phase::InstallPhase;
use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::RetainedRollbackKit;
use crate::state_preflight::InspectedStateRoots;
use crate::unix_history::TerminalOperation;
use crate::unix_staging::{require_exact_inventory, sync_directory};
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::upgrade_record::TerminalUpgradeRecord;
use crate::{InstallerStageError, StagedApplication, StagingInput};

/// Its historical record cannot be converted into live replacement authority.
struct ClosedReplacement<'a> {
    markers: Vec<Marker>,
    pending: Vec<PendingMarker>,
    record: TerminalUpgradeRecord,
    kit: RetainedRollbackKit,
    prior: ReplacementPrecondition<'a>,
    staged: StagedApplication,
    layout: Layout,
    states: InspectedStateRoots,
}

impl PreparedReplacement<'_> {
    pub(crate) fn retire_completed(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
    ) -> Result<(), InstallerStageError> {
        Self::retire_completed_with(
            destination,
            candidate,
            state_roots,
            direction,
            |staged| {
                RetainedRollbackKit::reopen_material(
                    staged,
                    expected_prior,
                    expected_archive_sha256,
                )
            },
            |_| Ok(()),
        )
    }

    pub(in crate::upgrade_transaction) fn retire_completed_with(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
        reopen_kit: impl FnOnce(
            &StagedApplication,
        ) -> Result<
            (RetainedRollbackKit, AuthenticatedRecoveryMaterial),
            InstallerStageError,
        >,
        boundary: impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let states = InspectedStateRoots::capture(state_roots)?;
        let (staged, layout, phases) =
            super::recovery::reopen_stage(destination, &StagingInput::from(candidate))?;
        let terminal = match layout {
            Layout::Exchanged => InstallPhase::Committed,
            Layout::Restored => InstallPhase::RolledBack,
        };
        if !phases.complete.contains(&terminal) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let (kit, material) = reopen_kit(&staged)?;
        let prior = ReplacementPrecondition::reopen_at(
            destination,
            &staged,
            candidate,
            &material,
            layout == Layout::Exchanged,
            direction,
        )?;
        let record = TerminalUpgradeRecord::reopen(&staged, &prior, &kit)?;
        let mut closed = ClosedReplacement {
            markers: Vec::new(),
            pending: Vec::new(),
            record,
            kit,
            prior,
            staged,
            layout,
            states,
        };
        for phase in phases.complete {
            let leaf = crate::staging_policy::read_private_data_leaf(
                &closed.staged._retained.operation,
                marker_name(phase),
                MAX_UPGRADE_PHASE_BYTES,
            )?;
            if leaf.bytes != closed.phase_bytes(phase)? {
                return Err(InstallerStageError::RecoveryRequired);
            }
            closed.markers.push(Marker {
                phase,
                file: leaf.file,
                identity: leaf.identity,
            });
        }
        for phase in phases.pending {
            closed.pending.push(PendingMarker::open(
                &closed.staged._retained.operation,
                phase,
                &closed.phase_bytes(phase)?,
            )?);
        }
        crate::unix_history::retire(&mut closed, boundary)
    }
}

impl ClosedReplacement<'_> {
    fn phase_bytes(&self, phase: InstallPhase) -> Result<Vec<u8>, InstallerStageError> {
        encode_phase_evidence(
            phase,
            self.record.binding_digest()?,
            *self.staged.record.staged_identity(),
            self.prior.prior_identity(),
        )
    }
}

impl TerminalOperation for ClosedReplacement<'_> {
    fn staged(&self) -> &StagedApplication {
        &self.staged
    }

    fn revalidate_contents(&mut self) -> Result<(), InstallerStageError> {
        self.prior.bind_stage_identity(&self.staged)?;
        let complete = self
            .markers
            .iter()
            .map(|marker| marker.phase)
            .collect::<Vec<_>>();
        let pending = self
            .pending
            .iter()
            .map(|marker| marker.phase)
            .collect::<Vec<_>>();
        super::pending::require_phase_order(&complete, &pending, self.layout)?;
        let terminal = match self.layout {
            Layout::Exchanged => InstallPhase::Committed,
            Layout::Restored => InstallPhase::RolledBack,
        };
        if !complete.contains(&terminal) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let mut inventory = phase_inventory(complete.into_iter());
        inventory.extend(
            pending
                .into_iter()
                .map(|phase| OsStr::new(pending_name(phase))),
        );
        require_exact_inventory(&self.staged._retained.operation, &inventory)?;
        require_pair(&self.staged, &self.prior, self.layout)?;
        self.kit
            .revalidate_material(&self.staged, self.prior.rollback())?;
        self.record
            .revalidate(&self.staged, &self.prior, &self.kit)?;
        for marker in &self.markers {
            marker.revalidate(
                &self.staged._retained.operation,
                &self.phase_bytes(marker.phase)?,
            )?;
        }
        for pending in &self.pending {
            pending.revalidate(
                &self.staged._retained.operation,
                &self.phase_bytes(pending.phase)?,
            )?;
        }
        require_pair(&self.staged, &self.prior, self.layout)?;
        require_exact_inventory(&self.staged._retained.operation, &inventory)?;
        self.states.revalidate()
    }

    fn sync_files(&self) -> Result<(), InstallerStageError> {
        self.staged
            ._retained
            .executable
            .sync_all()
            .and_then(|()| self.staged._retained.record.sync_all())
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.prior.sync_prior()?;
        self.record.sync()?;
        self.kit.sync_material()?;
        for marker in &self.markers {
            marker
                .file
                .sync_all()
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
        }
        for pending in &self.pending {
            pending.sync()?;
        }
        sync_directory(&self.staged._retained.operation)
    }
}
