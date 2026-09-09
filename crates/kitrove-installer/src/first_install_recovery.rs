use super::*;
use crate::StagingInput;
use crate::install_phase::{
    DetectedInstallPhase, InstallPhase, InstallPhaseRecord, InstallRecoveryPhase,
    MAX_PHASE_RECORD_BYTES,
};
use crate::staging_policy::{
    PrivateDataLeaf, entry_exists, read_pending_data_leaf, read_private_data_leaf,
};
#[cfg(unix)]
use crate::{unix_install, unix_recovery};

/// Retained recovery authority. Reopening alone is read-only, not a completed installation.
pub(crate) struct InspectedInstallation<R> {
    pending: Vec<InstallJournalRecord>,
    prior: Vec<InstallJournalRecord>,
    installation: Installation<R>,
    phase: DetectedInstallPhase,
}

pub(crate) type ReopenedInstallation = InspectedInstallation<RetainedInstallState>;
pub(crate) type ClosedInstallation = InspectedInstallation<TerminalInstallState>;

struct InstallJournalRecord {
    phase: InstallPhase,
    leaf: PrivateDataLeaf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryBoundary {
    Synced,
    Probed,
    Restored,
    HandoffRemoved,
    PhaseCreated(InstallPhase),
    PhaseCompleted(InstallPhase),
    PhasePublished(InstallPhase),
}

#[path = "first_install_resume.rs"]
mod resume;

#[cfg(unix)]
#[path = "first_install_state_retirement.rs"]
mod retirement;

#[cfg(windows)]
#[path = "windows_first_install_retirement.rs"]
pub(super) mod retirement;

impl<R: InstallationStateRecord> InspectedInstallation<R> {
    pub(crate) fn reopen(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
    ) -> Result<Self, InstallerStageError> {
        crate::require_compiled_target(executable)?;
        crate::require_current_user_installation()?;
        let mut states = InspectedStateRoots::capture(roots)?;
        let input = StagingInput::from(executable);
        #[cfg(unix)]
        let phase = unix_recovery::detect_state_bound_install_phase(destination, &input)?;
        #[cfg(unix)]
        let mut staged =
            unix_recovery::resume_state_bound_install(destination, &input, location(phase))?;
        #[cfg(windows)]
        let (staged, native_phase) =
            crate::windows_recovery::resume_state_bound_install(destination, &input)?;
        #[cfg(windows)]
        let phase = detected_windows_phase(native_phase);
        let record = R::reopen(&staged._retained.operation, &staged.record, &mut states)?;
        #[cfg(unix)]
        if phase == DetectedInstallPhase::ReplacedUnrecorded {
            unix_install::attach_installed_application(&mut staged)?;
        }
        let mut pending = Vec::new();
        let mut prior = Vec::new();
        for &candidate in InstallPhase::all() {
            if !location(phase).marker_phases().contains(&candidate)
                && entry_exists(&staged._retained.operation, candidate.file_name())?
            {
                prior.push(InstallJournalRecord {
                    phase: candidate,
                    leaf: read_private_data_leaf(
                        &staged._retained.operation,
                        candidate.file_name(),
                        MAX_PHASE_RECORD_BYTES,
                    )?,
                });
            }
            if !entry_exists(&staged._retained.operation, candidate.pending_file_name())? {
                continue;
            }
            pending.push(InstallJournalRecord {
                phase: candidate,
                leaf: read_pending_data_leaf(
                    &staged._retained.operation,
                    candidate.pending_file_name(),
                    MAX_PHASE_RECORD_BYTES,
                )?,
            });
        }
        let mut reopened = Self {
            pending,
            prior,
            installation: Installation {
                record,
                staged,
                states,
            },
            phase,
        };
        reopened.revalidate()?;
        Ok(reopened)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        #[cfg(unix)]
        unix_install::revalidate_common(&self.installation.staged)?;
        #[cfg(windows)]
        crate::windows_install::revalidate_stage_namespace(&self.installation.staged)?;
        self.revalidate_contents()?;
        #[cfg(unix)]
        unix_install::revalidate_common(&self.installation.staged)?;
        #[cfg(windows)]
        crate::windows_install::revalidate_stage_namespace(&self.installation.staged)?;
        Ok(())
    }

    fn revalidate_contents(&mut self) -> Result<(), InstallerStageError> {
        self.require_journal_order()?;
        let extra = self.extra_names();
        let Installation {
            record,
            staged,
            states,
        } = &mut self.installation;
        record.revalidate(&staged._retained.operation, &staged.record, states)?;
        for pending in &self.pending {
            let canonical = phase_bytes(staged, pending.phase)?;
            pending.leaf.require_prefix(
                &staged._retained.operation,
                pending.phase.pending_file_name(),
                &canonical,
            )?;
        }
        for prior in &self.prior {
            let canonical = phase_bytes(staged, prior.phase)?;
            prior.leaf.require_contents(
                &staged._retained.operation,
                prior.phase.file_name(),
                &canonical,
            )?;
        }
        #[cfg(unix)]
        {
            use DetectedInstallPhase::*;
            match self.phase {
                Prepared | ReplacedUnrecorded => {
                    unix_install::revalidate_prepared_stage_with_extra_entries(staged, &extra)?;
                    if self.phase == Prepared {
                        require_absent_entry(
                            staged._retained.destination.directory(),
                            staged.record.executable_name(),
                        )?;
                    } else {
                        unix_install::revalidate_installed_leaf(staged)?;
                    }
                }
                Replaced | Verified | Committed => {
                    let highest = match self.phase {
                        Replaced => InstallPhase::Replaced,
                        Verified => InstallPhase::Verified,
                        _ => InstallPhase::Committed,
                    };
                    unix_install::revalidate_phase_contents_with_extra_entries(
                        staged, highest, &extra,
                    )?;
                }
                RollingBack | RolledBack => {
                    unix_install::revalidate_staged_leaf(staged)?;
                    unix_install::revalidate_rollback_contents_with_extra_entries(
                        staged,
                        location(self.phase),
                        if self.phase == RolledBack {
                            InstallPhase::RolledBack
                        } else {
                            InstallPhase::Replaced
                        },
                        &extra,
                    )?;
                }
                RollbackHandoff => {
                    unix_install::revalidate_rollback_handoff_with_extra_entries(staged, &extra)?
                }
            }
        }
        #[cfg(windows)]
        {
            let installed = if matches!(
                self.phase,
                DetectedInstallPhase::Prepared
                    | DetectedInstallPhase::RollingBack
                    | DetectedInstallPhase::RolledBack
            ) {
                None
            } else {
                Some(staged.record.executable_name())
            };
            crate::windows_install::revalidate_stage_contents_with_extra_entries(
                staged,
                location(self.phase),
                installed,
                &extra,
            )?;
            if self.phase == DetectedInstallPhase::Prepared {
                require_absent_entry(
                    staged
                        ._retained
                        .destination
                        .directory()
                        .map_err(|_| InstallerStageError::RecoveryRequired)?,
                    staged.record.executable_name(),
                )?;
            }
        }
        record.revalidate(&staged._retained.operation, &staged.record, states)
    }

    fn extra_names(&self) -> Vec<&'static OsStr> {
        let mut extra = vec![OsStr::new(INSTALL_STATE_RECORD)];
        extra.extend(
            self.prior
                .iter()
                .map(|record| OsStr::new(record.phase.file_name())),
        );
        extra.extend(
            self.pending
                .iter()
                .map(|record| OsStr::new(record.phase.pending_file_name())),
        );
        extra
    }

    #[cfg(unix)]
    fn sync_files(&self) -> Result<(), InstallerStageError> {
        let retained = &self.installation.staged._retained;
        retained
            .installed
            .as_ref()
            .ok_or(InstallerStageError::RecoveryRequired)?
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        self.installation.record.sync()?;
        for file in [&retained.executable, &retained.record]
            .into_iter()
            .chain(&retained.phase_markers)
            .chain(self.pending.iter().map(|record| &record.leaf.file))
            .chain(self.prior.iter().map(|record| &record.leaf.file))
        {
            file.sync_all()
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
        }
        crate::unix_staging::sync_directory(retained.destination.directory())?;
        crate::unix_staging::sync_directory(&retained.operation)
    }

    fn require_journal_order(&self) -> Result<(), InstallerStageError> {
        self.phase.require_journal_order(
            &self
                .pending
                .iter()
                .map(|record| record.phase)
                .collect::<Vec<_>>(),
            &self
                .prior
                .iter()
                .map(|record| record.phase)
                .collect::<Vec<_>>(),
        )
    }
}

fn phase_bytes(
    staged: &StagedApplication,
    phase: InstallPhase,
) -> Result<Vec<u8>, InstallerStageError> {
    #[cfg(unix)]
    let installed = staged
        ._retained
        .installed
        .as_ref()
        .ok_or(InstallerStageError::RecoveryRequired)?;
    #[cfg(unix)]
    let identity = crate::unix_staging::metadata_identity(
        &installed
            .metadata()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    #[cfg(windows)]
    let identity = crate::windows_staging::file_identity(staged._retained.executable()?)?;
    InstallPhaseRecord::new(
        phase,
        &staged.record,
        identity,
        staged.manifest.executable_sha256(),
    )?
    .to_json()
}

fn location(phase: DetectedInstallPhase) -> InstallRecoveryPhase {
    phase.recovery_phase()
}

#[cfg(windows)]
fn detected_windows_phase(phase: InstallRecoveryPhase) -> DetectedInstallPhase {
    match phase {
        InstallRecoveryPhase::Prepared => DetectedInstallPhase::Prepared,
        InstallRecoveryPhase::ReplacedUnrecorded => DetectedInstallPhase::ReplacedUnrecorded,
        InstallRecoveryPhase::Replaced => DetectedInstallPhase::Replaced,
        InstallRecoveryPhase::Verified => DetectedInstallPhase::Verified,
        InstallRecoveryPhase::Committed => DetectedInstallPhase::Committed,
        InstallRecoveryPhase::RolledBackUnrecorded => DetectedInstallPhase::RollingBack,
        InstallRecoveryPhase::RolledBack => DetectedInstallPhase::RolledBack,
    }
}
