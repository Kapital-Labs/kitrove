//! Terminal retention cannot become live replacement authority.

use super::{
    PreparedReplacement,
    windows_journal::RetainedJournal,
    windows_journal_policy as policy,
    windows_pair::{self, Layout, files},
    windows_reopen,
};
use crate::installation_history::{
    filesystem::HistoryRoot,
    replacement::{ArchivedReplacement, RetirementEvidence},
    synchronization::{HistorySyncBoundary, synchronize_locked_archive},
};
use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::RetainedRollbackKit;
use crate::state_preflight::InspectedStateRoots;
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::upgrade_record::TerminalUpgradeRecord;
use crate::windows_staging as filesystem;
use crate::{InstallerStageError, NativeFileIdentity, StagedApplication};
use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity,
};
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Boundary {
    HistoryReady,
    BeforeMove,
    Moved,
    Sync(HistorySyncBoundary),
}

struct ClosedReplacement<'a> {
    journal: RetainedJournal,
    record: TerminalUpgradeRecord,
    prior_file: Option<File>,
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
        roots: &[PathBuf],
        direction: ReplacementDirection,
    ) -> Result<(), InstallerStageError> {
        Self::retire_completed_with(
            destination,
            candidate,
            roots,
            direction,
            |operation| {
                RetainedRollbackKit::reopen_at(operation, expected_prior, expected_archive_sha256)
            },
            |_| Ok(()),
        )
    }

    pub(super) fn retire_completed_with(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
        direction: ReplacementDirection,
        authenticate: impl Fn(
            &File,
        ) -> Result<
            (RetainedRollbackKit, AuthenticatedRecoveryMaterial),
            InstallerStageError,
        >,
        mut boundary: impl FnMut(Boundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let states = InspectedStateRoots::capture(roots)?;
        let (staged, layout, _) = windows_reopen::reopen_candidate(destination, candidate)?;
        let (kit, material) = authenticate(&staged._retained.operation)?;
        let (prior, prior_file) = ReplacementPrecondition::reopen_windows_pair(
            destination,
            &staged,
            candidate,
            &material,
            layout != Layout::Original,
            direction,
        )?;
        let record = TerminalUpgradeRecord::reopen(&staged, &prior, &kit)?;
        let binding = policy::Binding::new(
            record.binding_digest()?,
            *staged.record.staged_identity(),
            prior.prior_identity(),
        )?;
        let journal = RetainedJournal::open(&staged._retained.operation, binding)?;
        let mut closed = ClosedReplacement {
            journal,
            record,
            prior_file: Some(prior_file),
            kit,
            prior,
            staged,
            layout,
            states,
        };
        closed.revalidate()?;
        (|| -> Result<(), InstallerStageError> {
            let parent = closed
                .staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            let name = OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY);
            let history = match kitrove_windows_security::open_private_directory(parent, name) {
                Ok(history) => history,
                Err(_) => kitrove_windows_security::create_private_directory(parent, name)
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
            };
            let history_identity = filesystem::file_identity(&history)?;
            boundary(Boundary::HistoryReady)?;
            closed = closed.synchronize()?;
            filesystem::sync_directory(
                closed
                    .staged
                    ._retained
                    .destination
                    .directory()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
                name,
                &history,
            )?;
            closed.revalidate()?;
            let RetirementHandoff {
                mut states,
                live,
                root,
                evidence,
            } = closed.move_to_history(history, history_identity, &mut boundary)?;
            let archive = ArchivedReplacement::open_root(root, candidate, direction, authenticate)?;
            synchronize_locked_archive(
                &mut states,
                RetirementArchive {
                    live,
                    archive,
                    evidence,
                },
                |point| boundary(Boundary::Sync(point)),
            )?;
            Ok(())
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

impl ClosedReplacement<'_> {
    fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        self.states.revalidate()?;
        if policy::terminal_layout(&self.journal.phases(false), &self.journal.phases(true))?
            != self.layout
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.prior.bind_stage_identity(&self.staged)?;
        crate::windows_install::revalidate_stage_namespace(&self.staged)?;
        crate::windows_install::revalidate_operation_record(&self.staged)?;
        filesystem::require_exact_inventory(
            &self.staged._retained.operation,
            &windows_pair::inventory(self.layout, &self.journal.names()),
        )?;
        files::require(
            &self.staged,
            &self.prior,
            self.prior_file.as_ref(),
            self.layout,
        )?;
        self.kit
            .revalidate_material(&self.staged, self.prior.rollback())?;
        self.record
            .revalidate(&self.staged, &self.prior, &self.kit)?;
        self.journal.revalidate(&self.staged._retained.operation)?;
        files::require(
            &self.staged,
            &self.prior,
            self.prior_file.as_ref(),
            self.layout,
        )?;
        self.states.revalidate()
    }

    fn synchronize(mut self) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        files::synchronize(
            &mut self.staged,
            &self.prior,
            &mut self.prior_file,
            self.layout,
        )?;
        self.journal = self.journal.synchronize(&self.staged._retained.operation)?;
        self.record = self
            .record
            .sync_owned(&self.staged, &self.prior, &self.kit)?;
        self.kit = self
            .kit
            .sync_material_owned(&self.staged._retained.operation, self.prior.rollback())?;
        let bytes = self
            .staged
            .record
            .to_json()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        use sha2::Digest as _;
        self.staged._retained.record = filesystem::flush_retained_private_file(
            &self.staged._retained.operation,
            OsStr::new(crate::staging_policy::OPERATION_RECORD),
            self.staged._retained.record,
            bytes.len() as u64,
            sha2::Sha256::digest(&bytes).into(),
        )?;
        filesystem::sync_directory(
            &self.staged._retained.state,
            OsStr::new(self.staged.record.operation_id()),
            &self.staged._retained.operation,
        )?;
        filesystem::sync_directory(
            self.staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            OsStr::new(crate::INSTALLER_STATE_DIRECTORY),
            &self.staged._retained.state,
        )?;
        self.staged
            ._retained
            .destination
            .flush()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.revalidate()?;
        Ok(self)
    }

    fn move_to_history(
        self,
        history: File,
        history_identity: NativeFileIdentity,
        boundary: &mut impl FnMut(Boundary) -> Result<(), InstallerStageError>,
    ) -> Result<RetirementHandoff, InstallerStageError> {
        // Bind guards first so all subsequently bound artifact capabilities drop first.
        let Self {
            mut states,
            journal,
            record: terminal,
            prior_file,
            kit,
            prior,
            staged,
            layout,
        } = self;
        let history = history;
        let (identity, size, digest) =
            files::evidence(&staged, &prior, layout == Layout::Published);
        let name = staged.record.executable_name().to_owned();
        let parent = staged
            ._retained
            .destination
            .directory()
            .map_err(|_| InstallerStageError::RecoveryRequired)?
            .try_clone()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let evidence = RetirementEvidence {
            operation_identity: filesystem::file_identity(&staged._retained.record)?,
            operation_bytes: staged
                .record
                .to_json()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            upgrade_identity: terminal.leaf_identity(),
            upgrade_digest: terminal.binding_digest()?,
            journal: journal.release(),
        };
        drop(terminal);
        drop(kit);
        drop(prior);
        let StagedApplication {
            record, _retained, ..
        } = staged;
        let crate::windows_staging::RetainedStage {
            destination,
            state,
            operation,
            executable,
            record: record_file,
            phase_markers,
            lock,
        } = _retained;
        drop(record_file);
        drop(phase_markers);
        let installed = if layout == Layout::Published {
            drop(prior_file);
            executable
        } else {
            drop(executable);
            prior_file
        }
        .ok_or(InstallerStageError::RecoveryRequired)?;
        let live = LiveExecutable {
            file: installed,
            parent,
            name,
            identity,
            size,
            digest,
        };
        let operation_identity = kitrove_windows_security::file_identity(&operation)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        drop(operation);
        boundary(Boundary::BeforeMove)?;
        states.revalidate()?;
        live.revalidate()?;
        filesystem::revalidate_control_boundary(
            &destination,
            &state,
            *record.state_identity(),
            &lock,
        )?;
        filesystem::require_named_directory_identity(
            destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY),
            history_identity,
        )?;
        kitrove_windows_security::move_owned_directory(
            &state,
            OsStr::new(record.operation_id()),
            &history,
            OsStr::new(record.operation_id()),
            OsStr::new("replacement-retirement-uncertain"),
            operation_identity,
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        boundary(Boundary::Moved)?;
        let root = HistoryRoot::from_moved(
            destination,
            state,
            lock,
            history,
            record.operation_id().to_owned(),
            crate::installation_history::filesystem::HistoryIdentities {
                state: *record.state_identity(),
                history: history_identity,
                operation: *record.operation_identity(),
            },
        )?;
        states.revalidate()?;
        live.revalidate()?;
        Ok(RetirementHandoff {
            root,
            live,
            states,
            evidence,
        })
    }
}

struct RetirementHandoff {
    live: LiveExecutable,
    root: HistoryRoot,
    states: InspectedStateRoots,
    evidence: RetirementEvidence,
}

struct RetirementArchive {
    live: LiveExecutable,
    archive: ArchivedReplacement,
    evidence: RetirementEvidence,
}

impl crate::installation_history::synchronization::HistoricalArchive for RetirementArchive {
    fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.live.revalidate()?;
        self.archive.require_handoff(&self.evidence)?;
        self.live.revalidate()
    }

    fn sync_files(mut self) -> Result<Self, InstallerStageError> {
        self.revalidate()?;
        self.archive = self.archive.sync_files()?;
        self.revalidate()?;
        Ok(self)
    }

    fn root(&self) -> &HistoryRoot {
        self.archive.root()
    }

    fn outcome(
        &self,
    ) -> Result<crate::record::history::journal::HistoricalInstallOutcome, InstallerStageError>
    {
        self.revalidate()?;
        self.archive.outcome()
    }
}

struct LiveExecutable {
    file: File,
    parent: File,
    name: String,
    identity: NativeFileIdentity,
    size: u64,
    digest: [u8; 32],
}
impl LiveExecutable {
    fn revalidate(&self) -> Result<(), InstallerStageError> {
        files::require_leaf(
            &self.parent,
            &self.name,
            &self.file,
            self.identity,
            self.size,
            self.digest,
        )
    }
}
