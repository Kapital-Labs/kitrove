use super::*;
use crate::windows_staging::{
    file_identity, reopen_private_file_with_identity, require_exact_inventory,
    require_named_directory_identity, revalidate_control_boundary,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::installation_state) enum RetirementBoundary {
    HistoryReady,
    BeforeMove,
    Moved,
    OperationSynced,
    HistorySynced,
    SourceSynced,
    Validated,
}

impl ClosedInstallation {
    pub(crate) fn retire(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
    ) -> Result<(), InstallerStageError> {
        Self::retire_with(destination, executable, roots, |_| Ok(()))
    }

    pub(in crate::installation_state) fn retire_with(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
        mut boundary: impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        let mut closed = Self::reopen(destination, executable, roots)?;
        if !matches!(
            closed.phase,
            DetectedInstallPhase::Committed | DetectedInstallPhase::RolledBack
        ) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        // Any uncertainty after history creation preserves both namespaces.
        (|| {
            let parent = closed
                .installation
                .staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            let name = OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY);
            let history = match kitrove_windows_security::open_private_directory(parent, name) {
                Ok(directory) => directory,
                Err(_) => kitrove_windows_security::create_private_directory(parent, name)
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
            };
            let history_identity = file_identity(&history)?;
            boundary(RetirementBoundary::HistoryReady)?;
            closed.revalidate()?;
            closed = closed.sync_windows()?;
            closed.revalidate()?;
            {
                let retained = &closed.installation.staged._retained;
                crate::windows_staging::sync_directory(
                    &retained.state,
                    OsStr::new(closed.installation.staged.record.operation_id()),
                    &retained.operation,
                )?;
                sync_control_child(
                    &closed.installation.staged,
                    crate::INSTALLER_STATE_DIRECTORY,
                    &retained.state,
                )?;
                sync_control_child(
                    &closed.installation.staged,
                    crate::INSTALLER_HISTORY_DIRECTORY,
                    &history,
                )?;
                retained
                    .destination
                    .flush()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?;
            }
            closed.revalidate()?;
            let mut archived = move_to_history(closed, &history, history_identity, &mut boundary)?;
            archived.revalidate_history(&history, history_identity)?;
            crate::windows_staging::sync_directory(
                &history,
                OsStr::new(archived.installation.staged.record.operation_id()),
                &archived.installation.staged._retained.operation,
            )?;
            boundary(RetirementBoundary::OperationSynced)?;
            archived.revalidate_history(&history, history_identity)?;
            sync_control_child(
                &archived.installation.staged,
                crate::INSTALLER_HISTORY_DIRECTORY,
                &history,
            )?;
            boundary(RetirementBoundary::HistorySynced)?;
            archived.revalidate_history(&history, history_identity)?;
            sync_control_child(
                &archived.installation.staged,
                crate::INSTALLER_STATE_DIRECTORY,
                &archived.installation.staged._retained.state,
            )?;
            archived
                .installation
                .staged
                ._retained
                .destination
                .flush()
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            boundary(RetirementBoundary::SourceSynced)?;
            archived.revalidate_history(&history, history_identity)?;
            boundary(RetirementBoundary::Validated)?;
            archived.revalidate_history(&history, history_identity)
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    fn revalidate_history(
        &mut self,
        history: &std::fs::File,
        history_identity: crate::NativeFileIdentity,
    ) -> Result<(), InstallerStageError> {
        require_history_location(&self.installation.staged, history, history_identity)?;
        self.revalidate_contents()?;
        require_history_location(&self.installation.staged, history, history_identity)
    }
}

fn sync_control_child(
    staged: &StagedApplication,
    name: &str,
    child: &std::fs::File,
) -> Result<(), InstallerStageError> {
    crate::windows_staging::sync_directory(
        staged
            ._retained
            .destination
            .directory()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
        OsStr::new(name),
        child,
    )
}

fn require_history_location(
    staged: &StagedApplication,
    history: &std::fs::File,
    history_identity: crate::NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    let retained = &staged._retained;
    revalidate_control_boundary(
        &retained.destination,
        &retained.state,
        *staged.record.state_identity(),
        &retained.lock,
    )?;
    require_named_directory_identity(
        retained
            .destination
            .directory()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
        OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY),
        history_identity,
    )?;
    require_named_directory_identity(
        history,
        OsStr::new(staged.record.operation_id()),
        *staged.record.operation_identity(),
    )?;
    require_exact_inventory(
        &retained.state,
        &[OsStr::new(crate::staging_policy::INSTALLER_LOCK)],
    )
}

/// Only identity is carried across the closed-handle interval. Shared content validation
/// must authenticate every reopened byte before the archival operation can succeed.
fn release_file(file: std::fs::File) -> Result<crate::NativeFileIdentity, InstallerStageError> {
    file_identity(&file)
}

struct ReleasedLeaf {
    identity: crate::NativeFileIdentity,
    bytes: Vec<u8>,
}

impl ReleasedLeaf {
    fn release(leaf: PrivateDataLeaf) -> Self {
        Self {
            identity: leaf.identity,
            bytes: leaf.bytes,
        }
    }

    fn reopen(
        self,
        parent: &std::fs::File,
        name: &str,
    ) -> Result<PrivateDataLeaf, InstallerStageError> {
        let leaf = PrivateDataLeaf {
            file: reopen_private_file_with_identity(parent, OsStr::new(name), self.identity)?,
            identity: self.identity,
            bytes: self.bytes,
        };
        leaf.require_contents(parent, name, &leaf.bytes)?;
        Ok(leaf)
    }
}

fn move_to_history(
    closed: ClosedInstallation,
    history: &std::fs::File,
    history_identity: crate::NativeFileIdentity,
    boundary: &mut impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
) -> Result<ClosedInstallation, InstallerStageError> {
    let InspectedInstallation {
        pending,
        prior,
        installation,
        phase,
    } = closed;
    // Keep current state guards alive across every capability release and reconstruction.
    let Installation {
        record: state_record,
        staged,
        mut states,
    } = installation;
    let StagedApplication {
        record,
        manifest,
        executable_content_hash,
        _retained,
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
    let state_leaf = ReleasedLeaf::release(state_record.leaf);
    let pending = pending
        .into_iter()
        .map(|record| (record.phase, ReleasedLeaf::release(record.leaf)))
        .collect::<Vec<_>>();
    let prior = prior
        .into_iter()
        .map(|record| (record.phase, ReleasedLeaf::release(record.leaf)))
        .collect::<Vec<_>>();
    let record_identity = release_file(record_file)?;
    let marker_identities = phase_markers
        .into_iter()
        .map(release_file)
        .collect::<Result<Vec<_>, _>>()?;
    let executable_identity =
        release_file(executable.ok_or(InstallerStageError::RecoveryRequired)?)?;
    let operation_identity = kitrove_windows_security::file_identity(&operation)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    drop(operation);
    boundary(RetirementBoundary::BeforeMove)?;
    states.revalidate()?;
    revalidate_control_boundary(&destination, &state, *record.state_identity(), &lock)?;
    require_named_directory_identity(
        destination
            .directory()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
        OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY),
        history_identity,
    )?;
    kitrove_windows_security::move_owned_directory(
        &state,
        OsStr::new(record.operation_id()),
        history,
        OsStr::new(record.operation_id()),
        OsStr::new("retirement-rollback"),
        operation_identity,
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    boundary(RetirementBoundary::Moved)?;
    let operation = kitrove_windows_security::open_private_directory(
        history,
        OsStr::new(record.operation_id()),
    )
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    crate::windows_staging::require_identity(&operation, *record.operation_identity())?;
    let state_record = TerminalInstallState {
        leaf: state_leaf.reopen(&operation, INSTALL_STATE_RECORD)?,
        roots: state_record.roots,
    };
    let pending = pending
        .into_iter()
        .map(|(phase, leaf)| {
            Ok(InstallJournalRecord {
                phase,
                leaf: leaf.reopen(&operation, phase.pending_file_name())?,
            })
        })
        .collect::<Result<Vec<_>, InstallerStageError>>()?;
    let prior = prior
        .into_iter()
        .map(|(phase, leaf)| {
            Ok(InstallJournalRecord {
                phase,
                leaf: leaf.reopen(&operation, phase.file_name())?,
            })
        })
        .collect::<Result<Vec<_>, InstallerStageError>>()?;
    let record_file = reopen_private_file_with_identity(
        &operation,
        OsStr::new(crate::staging_policy::OPERATION_RECORD),
        record_identity,
    )?;
    let phase_markers = location(phase)
        .marker_phases()
        .iter()
        .zip(marker_identities)
        .map(|(phase, identity)| {
            reopen_private_file_with_identity(&operation, OsStr::new(phase.file_name()), identity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (parent, name) = if phase.is_restored() {
        (&operation, crate::install_phase::FAILED_EXECUTABLE)
    } else {
        (
            destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            record.executable_name(),
        )
    };
    let executable = Some(reopen_private_file_with_identity(
        parent,
        OsStr::new(name),
        executable_identity,
    )?);
    Ok(InspectedInstallation {
        pending,
        prior,
        phase,
        installation: Installation {
            record: state_record,
            states,
            staged: StagedApplication {
                record,
                manifest,
                executable_content_hash,
                _retained: crate::windows_staging::RetainedStage {
                    destination,
                    state,
                    operation,
                    executable,
                    record: record_file,
                    phase_markers,
                    lock,
                },
            },
        },
    })
}
