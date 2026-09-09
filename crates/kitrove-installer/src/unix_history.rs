use std::ffi::OsStr;

use cap_std::fs::Dir;

use crate::unix_staging::{
    directory_identity, require_exact_inventory, require_named_directory_identity, sync_directory,
};
use crate::{InstallerStageError, NativeFileIdentity, StagedApplication};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetirementBoundary {
    HistoryReady,
    BeforeMove,
    Moved,
    HistorySynced,
    SourceSynced,
}

/// Implementations retain terminal evidence and all guards until archival completes.
pub(crate) trait TerminalOperation {
    fn staged(&self) -> &StagedApplication;
    fn revalidate_contents(&mut self) -> Result<(), InstallerStageError>;
    fn sync_files(&self) -> Result<(), InstallerStageError>;
}

pub(crate) fn retire(
    operation: &mut impl TerminalOperation,
    mut boundary: impl FnMut(RetirementBoundary) -> Result<(), InstallerStageError>,
) -> Result<(), InstallerStageError> {
    revalidate(operation, None)?;
    // After history creation, uncertainty preserves both namespaces for reconciliation.
    (|| {
        let history = crate::unix_staging::open_or_create_private_directory(
            operation.staged()._retained.destination.directory(),
            OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY),
        )?;
        let identity = directory_identity(&history)?;
        boundary(RetirementBoundary::HistoryReady)?;
        require_history(operation.staged(), &history, identity)?;
        revalidate(operation, None)?;
        operation.sync_files()?;
        boundary(RetirementBoundary::BeforeMove)?;
        require_history(operation.staged(), &history, identity)?;
        revalidate(operation, None)?;
        crate::unix_install::rename_noreplace(
            &operation.staged()._retained.state,
            OsStr::new(operation.staged().record.operation_id()),
            &history,
            OsStr::new(operation.staged().record.operation_id()),
        )?;
        boundary(RetirementBoundary::Moved)?;
        revalidate(operation, Some((&history, identity)))?;
        sync_directory(&history)?;
        boundary(RetirementBoundary::HistorySynced)?;
        sync_directory(&operation.staged()._retained.state)?;
        sync_directory(operation.staged()._retained.destination.directory())?;
        boundary(RetirementBoundary::SourceSynced)?;
        revalidate(operation, Some((&history, identity)))
    })()
    .map_err(|_| InstallerStageError::RecoveryRequired)
}

fn revalidate(
    operation: &mut impl TerminalOperation,
    archived: Option<(&Dir, NativeFileIdentity)>,
) -> Result<(), InstallerStageError> {
    revalidate_location(operation.staged(), archived)?;
    operation.revalidate_contents()?;
    revalidate_location(operation.staged(), archived)
}

fn require_history(
    staged: &StagedApplication,
    history: &Dir,
    identity: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    require_named_directory_identity(
        staged._retained.destination.directory(),
        crate::INSTALLER_HISTORY_DIRECTORY,
        history,
        identity,
    )
}

fn revalidate_location(
    staged: &StagedApplication,
    archived: Option<(&Dir, NativeFileIdentity)>,
) -> Result<(), InstallerStageError> {
    if let Some((history, identity)) = archived {
        require_history(staged, history, identity)?;
        crate::unix_staging::revalidate_control_boundary(
            &staged._retained.destination,
            &staged._retained.state,
            *staged.record.state_identity(),
            &staged._retained.lock,
        )?;
        require_exact_inventory(
            &staged._retained.state,
            &[OsStr::new(crate::staging_policy::INSTALLER_LOCK)],
        )?;
        require_named_directory_identity(
            history,
            staged.record.operation_id(),
            &staged._retained.operation,
            *staged.record.operation_identity(),
        )?;
        crate::unix_install::revalidate_operation_record(staged)
    } else {
        crate::unix_install::revalidate_common(staged)
    }
}
