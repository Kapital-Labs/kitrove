//! Owned Windows executable pair, below the journal coordinator.
//! Journal policy and fresh recovery mediate every replacement entry point.

use std::ffi::OsStr;
use std::fs::File;

use super::PreparedReplacement;
use super::windows_recovery_plan::{self, JournalStage, RecoveryStep};
use crate::staging_policy::{OPERATION_RECORD, STAGED_EXECUTABLE};
use crate::windows_staging as filesystem;
use crate::{InstallerStageError, NativeFileIdentity};

pub(super) use super::windows_recovery_plan::Layout;
pub(super) use crate::staging_policy::RETAINED_UPGRADE_PRIOR as RETAINED_PRIOR;

#[path = "windows_pair_files.rs"]
pub(super) mod files;

pub(super) fn inventory<'a>(layout: Layout, markers: &[&'a OsStr]) -> Vec<&'a OsStr> {
    let mut names = vec![
        OsStr::new(OPERATION_RECORD),
        OsStr::new(crate::upgrade_record::UPGRADE_RECORD),
        OsStr::new(crate::rollback_kit::ROLLBACK_DIRECTORY),
    ];
    if layout != Layout::Published {
        names.push(OsStr::new(STAGED_EXECUTABLE));
    }
    if layout != Layout::Original {
        names.push(OsStr::new(RETAINED_PRIOR));
    }
    names.extend_from_slice(markers);
    names
}

/// All file leases are dropped before preparation releases the lifecycle locks.
pub(super) struct WindowsPair<'a> {
    prior_file: Option<File>,
    prepared: PreparedReplacement<'a>,
    layout: Layout,
}

impl<'a> WindowsPair<'a> {
    pub(super) fn from_reopened(
        prepared: PreparedReplacement<'a>,
        prior_file: File,
        layout: Layout,
        markers: &[&OsStr],
    ) -> Result<Self, InstallerStageError> {
        let mut pair = Self {
            prior_file: Some(prior_file),
            prepared,
            layout,
        };
        pair.revalidate(markers)?;
        Ok(pair)
    }
    pub(super) fn layout(&self) -> Layout {
        self.layout
    }

    pub(super) fn candidate_metadata(
        &self,
    ) -> Result<crate::InstalledApplication, InstallerStageError> {
        if self.layout != Layout::Published {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let staged = &self.prepared.staged;
        Ok(crate::InstalledApplication {
            record: staged.record.clone(),
            manifest: staged.manifest.clone(),
            path: staged
                ._retained
                .destination
                .path()
                .join(staged.record.executable_name()),
        })
    }

    pub(super) fn candidate_content_hash(&self) -> &kitrove_model::ContentHash {
        &self.prepared.staged.executable_content_hash
    }

    pub(super) fn operation(&self) -> &File {
        &self.prepared.staged._retained.operation
    }

    pub(super) fn journal_binding(
        &self,
    ) -> Result<super::windows_journal_policy::Binding, InstallerStageError> {
        super::windows_journal_policy::Binding::new(
            self.prepared.record.binding_digest()?,
            self.evidence(true).0,
            self.evidence(false).0,
        )
    }

    pub(super) fn sync_operation(&self) -> Result<(), InstallerStageError> {
        let staged = &self.prepared.staged;
        filesystem::sync_directory(
            &staged._retained.state,
            OsStr::new(staged.record.operation_id()),
            &staged._retained.operation,
        )
    }

    /// Reopened bytes must be durable before a phase can certify their placement.
    /// Callers consume the owning journal on error, preserving any uncertain layout.
    pub(super) fn sync_pair(&mut self, markers: &[&OsStr]) -> Result<(), InstallerStageError> {
        self.revalidate(markers)?;
        files::synchronize(
            &mut self.prepared.staged,
            &self.prepared.prior,
            &mut self.prior_file,
            self.layout,
        )?;
        self.sync_operation()?;
        self.prepared
            .staged
            ._retained
            .destination
            .flush()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.revalidate(markers)
    }

    pub(super) fn new(mut prepared: PreparedReplacement<'a>) -> Result<Self, InstallerStageError> {
        prepared.revalidate()?;
        let prior_file = Some(prepared.prior.take_windows_file()?);
        let mut pair = Self {
            prior_file,
            prepared,
            layout: Layout::Original,
        };
        pair.revalidate(&[])?;
        Ok(pair)
    }

    /// Journal authority must be independently reconstructed by the coordinator.
    pub(super) fn recovery_step(
        &mut self,
        journal: JournalStage,
        markers: &[&OsStr],
    ) -> Result<RecoveryStep, InstallerStageError> {
        self.revalidate(markers)?;
        windows_recovery_plan::next_step_for_layout(self.layout, journal)
    }

    pub(super) fn revalidate(&mut self, markers: &[&OsStr]) -> Result<(), InstallerStageError> {
        self.prepared.states.revalidate()?;
        let staged = &self.prepared.staged;
        self.prepared.prior.bind_stage_identity(staged)?;
        crate::windows_install::revalidate_stage_namespace(staged)?;
        filesystem::require_identity(
            &staged._retained.operation,
            *staged.record.operation_identity(),
        )?;
        crate::windows_install::revalidate_operation_record(staged)?;
        filesystem::require_exact_inventory(
            &staged._retained.operation,
            &inventory(self.layout, markers),
        )?;
        self.require_pair()?;
        self.prepared
            .kit
            .revalidate_material(staged, self.prepared.prior.rollback())?;
        self.prepared.record.revalidate_evidence(
            staged,
            &self.prepared.prior,
            &self.prepared.kit,
            &mut self.prepared.states,
        )?;
        self.require_pair()?;
        crate::windows_install::revalidate_stage_namespace(&self.prepared.staged)?;
        self.prepared.states.revalidate()
    }

    fn location(
        &self,
        candidate: bool,
        layout: Layout,
    ) -> Result<(&File, &str), InstallerStageError> {
        files::location(&self.prepared.staged, candidate, layout)
    }

    fn evidence(&self, candidate: bool) -> (NativeFileIdentity, u64, [u8; 32]) {
        files::evidence(&self.prepared.staged, &self.prepared.prior, candidate)
    }

    fn require_pair(&self) -> Result<(), InstallerStageError> {
        files::require(
            &self.prepared.staged,
            &self.prepared.prior,
            self.prior_file.as_ref(),
            self.layout,
        )
    }

    /// One no-replace move only. The journal coordinator must durably record the
    /// required intent/phase before requesting publication or restoration.
    pub(super) fn move_to(
        &mut self,
        next: Layout,
        markers: &[&OsStr],
    ) -> Result<(), InstallerStageError> {
        self.move_with_hook(next, markers, || Ok(()))
    }

    pub(super) fn move_with_hook(
        &mut self,
        next: Layout,
        markers: &[&OsStr],
        before_move: impl FnOnce() -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        self.move_impl(next, markers, before_move)
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    fn move_impl(
        &mut self,
        next: Layout,
        markers: &[&OsStr],
        before_move: impl FnOnce() -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        let candidate = match (self.layout, next) {
            (Layout::Original, Layout::Gap) | (Layout::Gap, Layout::Original) => false,
            (Layout::Gap, Layout::Published) | (Layout::Published, Layout::Gap) => true,
            _ => return Err(InstallerStageError::RecoveryRequired),
        };
        self.revalidate(markers)?;
        before_move()?;
        self.prepared.states.revalidate()?;
        let (identity, size, digest) = self.evidence(candidate);
        let held = if candidate {
            self.prepared.staged._retained.executable.take()
        } else {
            self.prior_file.take()
        }
        .ok_or(InstallerStageError::RecoveryRequired)?;
        let native = kitrove_windows_security::file_identity(&held)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        // These leases deny DELETE sharing. The move rechecks identity after release.
        drop(held);
        let (source_parent, source) = self.location(candidate, self.layout)?;
        let (target_parent, target) = self.location(candidate, next)?;
        kitrove_windows_security::move_owned_file(
            source_parent,
            OsStr::new(source),
            target_parent,
            OsStr::new(target),
            OsStr::new("replacement-move-uncertain"),
            native,
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let reopened = filesystem::reopen_private_file_with_identity(
            target_parent,
            OsStr::new(target),
            identity,
        )?;
        let reopened = filesystem::flush_retained_private_file(
            target_parent,
            OsStr::new(target),
            reopened,
            size,
            digest,
        )?;
        if candidate {
            self.prepared.staged._retained.executable = Some(reopened);
        } else {
            self.prior_file = Some(reopened);
        }
        self.layout = next;
        self.revalidate(markers)?;
        let staged = &self.prepared.staged;
        self.sync_operation()?;
        staged
            ._retained
            .destination
            .flush()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.revalidate(markers)
    }
}
