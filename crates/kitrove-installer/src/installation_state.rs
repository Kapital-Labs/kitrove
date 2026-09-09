use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kitrove_release_provenance::AuthenticatedApplicationExecutable;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::staging_policy::{
    InstallerDirectory, PrivateDataLeaf, create_private_data_leaf, read_private_data_leaf,
    require_absent_entry,
};
use crate::state_preflight::{InspectedStateRoots, StateRootRecord};
use crate::{InstallerOperationRecord, InstallerStageError, StagedApplication};

pub(crate) const INSTALL_STATE_RECORD: &str = "install-state.json";
pub(crate) const MAX_INSTALL_STATE_BYTES: usize = 128 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallStateEvidence {
    schema: u32,
    candidate_record_sha256: String,
    state_roots: Vec<StateRootRecord>,
}

/// State evidence only. The recovery caller must authenticate operation/layout authority
/// before invoking any mutation; saved record bytes never select roots or release inputs.
pub(crate) struct RetainedInstallState {
    leaf: PrivateDataLeaf,
}

/// Static evidence policy: historical records have no conversion to live state authority.
pub(crate) trait InstallationStateRecord: Sized {
    fn reopen(
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError>;
    fn revalidate(
        &self,
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<(), InstallerStageError>;
    #[cfg(unix)]
    fn sync(&self) -> Result<(), InstallerStageError>;
    #[cfg(windows)]
    fn sync_owned(self, operation: &InstallerDirectory) -> Result<Self, InstallerStageError>;
}

impl InstallationStateRecord for RetainedInstallState {
    #[cfg(windows)]
    fn sync_owned(mut self, operation: &InstallerDirectory) -> Result<Self, InstallerStageError> {
        self.leaf = self.leaf.sync_owned(operation, INSTALL_STATE_RECORD)?;
        Ok(self)
    }

    fn reopen(
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        Self::reopen(operation, record, states)
    }
    fn revalidate(
        &self,
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<(), InstallerStageError> {
        self.revalidate(operation, record, states)
    }
    #[cfg(unix)]
    fn sync(&self) -> Result<(), InstallerStageError> {
        self.leaf
            .file
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

pub(crate) struct TerminalInstallState {
    leaf: PrivateDataLeaf,
    roots: Vec<StateRootRecord>,
}

impl InstallationStateRecord for TerminalInstallState {
    #[cfg(windows)]
    fn sync_owned(mut self, operation: &InstallerDirectory) -> Result<Self, InstallerStageError> {
        self.leaf = self.leaf.sync_owned(operation, INSTALL_STATE_RECORD)?;
        Ok(self)
    }

    fn reopen(
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        let leaf =
            read_private_data_leaf(operation, INSTALL_STATE_RECORD, MAX_INSTALL_STATE_BYTES)?;
        let record_bytes = record
            .to_json()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let roots =
            parse_historical_state_evidence(&leaf.bytes, Sha256::digest(record_bytes).into())?;
        let retained = Self { leaf, roots };
        retained.revalidate(operation, record, states)?;
        Ok(retained)
    }
    fn revalidate(
        &self,
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<(), InstallerStageError> {
        let expected = serialize_evidence(record, self.roots.clone())?;
        self.leaf
            .require_contents(operation, INSTALL_STATE_RECORD, &expected)?;
        states.revalidate()
    }
    #[cfg(unix)]
    fn sync(&self) -> Result<(), InstallerStageError> {
        self.leaf
            .file
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

impl RetainedInstallState {
    fn persist(
        staged: &StagedApplication,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        require_prepared(staged, false)?;
        let bytes = canonical_evidence(&staged.record, states)?;
        let leaf =
            create_private_data_leaf(&staged._retained.operation, INSTALL_STATE_RECORD, bytes)?;
        let retained = Self { leaf };
        require_prepared(staged, true)?;
        retained.revalidate(&staged._retained.operation, &staged.record, states)?;
        Ok(retained)
    }

    /// Does not reconcile phase records or write anything, including on failure.
    pub(crate) fn reopen(
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        let retained = Self {
            leaf: read_private_data_leaf(operation, INSTALL_STATE_RECORD, MAX_INSTALL_STATE_BYTES)?,
        };
        retained.revalidate(operation, record, states)?;
        Ok(retained)
    }

    pub(crate) fn revalidate(
        &self,
        operation: &InstallerDirectory,
        record: &InstallerOperationRecord,
        states: &mut InspectedStateRoots,
    ) -> Result<(), InstallerStageError> {
        let expected = canonical_evidence(record, states)?;
        self.leaf
            .require_contents(operation, INSTALL_STATE_RECORD, &expected)?;
        states.revalidate()
    }
}

fn canonical_evidence(
    operation: &InstallerOperationRecord,
    states: &mut InspectedStateRoots,
) -> Result<Vec<u8>, InstallerStageError> {
    serialize_evidence(operation, states.records()?)
}

fn serialize_evidence(
    operation: &InstallerOperationRecord,
    roots: Vec<StateRootRecord>,
) -> Result<Vec<u8>, InstallerStageError> {
    let operation_bytes = operation
        .to_json()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    serialize_evidence_digest(Sha256::digest(operation_bytes).into(), roots)
}

/// Canonical historical shape and record binding only; stored paths are never opened.
pub(crate) fn parse_historical_state_evidence(
    bytes: &[u8],
    record_sha256: [u8; 32],
) -> Result<Vec<StateRootRecord>, InstallerStageError> {
    if bytes.is_empty() || bytes.len() > MAX_INSTALL_STATE_BYTES {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let saved: InstallStateEvidence =
        serde_json::from_slice(bytes).map_err(|_| InstallerStageError::RecoveryRequired)?;
    let expected = serialize_evidence_digest(record_sha256, saved.state_roots.clone())?;
    if expected != bytes {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(saved.state_roots)
}

fn serialize_evidence_digest(
    record_sha256: [u8; 32],
    roots: Vec<StateRootRecord>,
) -> Result<Vec<u8>, InstallerStageError> {
    StateRootRecord::validate_history(&roots)?;
    let evidence = InstallStateEvidence {
        schema: 1,
        candidate_record_sha256: crate::record::encode_hex(&record_sha256),
        state_roots: roots,
    };
    let bytes = serde_json::to_vec(&evidence).map_err(|_| InstallerStageError::UnsafeState)?;
    if bytes.len() > MAX_INSTALL_STATE_BYTES {
        return Err(InstallerStageError::UnsafeState);
    }
    Ok(bytes)
}

/// Keeps application-state guards alive until all preparation handles are closed.
/// Unix execution consumes this owner; fresh recovery must independently reacquire authority.
pub(crate) struct Installation<R> {
    record: R,
    staged: StagedApplication,
    states: InspectedStateRoots,
}

pub(crate) type PreparedInstallation = Installation<RetainedInstallState>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparationBoundary {
    StatesLocked,
    Staged,
    StateRecorded,
}

impl PreparedInstallation {
    /// Read-only readiness at this instant; installation must reacquire all authority.
    pub(crate) fn preflight(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
    ) -> Result<(), InstallerStageError> {
        let mut states = inspect_first_install(destination, executable, roots)?;
        states.revalidate()?;
        require_absent_destination(destination, executable.subject().spec().executable_name())
    }

    pub(crate) fn prepare(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
    ) -> Result<Self, InstallerStageError> {
        Self::prepare_with_hook(destination, executable, roots, |_| Ok(()))
    }

    fn prepare_with_hook(
        destination: &Path,
        executable: &AuthenticatedApplicationExecutable,
        roots: &[PathBuf],
        mut boundary: impl FnMut(PreparationBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        let mut states = inspect_first_install(destination, executable, roots)?;
        boundary(PreparationBoundary::StatesLocked)?;
        let staged = crate::stage_authenticated_application(destination, executable)?;
        // Once staging exists, every incomplete preparation is retained for recovery.
        (|| -> Result<Self, InstallerStageError> {
            boundary(PreparationBoundary::Staged)?;
            let record = RetainedInstallState::persist(&staged, &mut states)?;
            boundary(PreparationBoundary::StateRecorded)?;
            let mut prepared = Self {
                record,
                staged,
                states,
            };
            prepared.revalidate()?;
            Ok(prepared)
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        require_prepared(&self.staged, true)?;
        self.record.revalidate(
            &self.staged._retained.operation,
            &self.staged.record,
            &mut self.states,
        )?;
        require_prepared(&self.staged, true)
    }
}

impl std::fmt::Debug for PreparedInstallation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedInstallation")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
#[path = "first_install_execution.rs"]
mod execution;

#[cfg(windows)]
#[path = "windows_first_install_execution.rs"]
mod execution;

#[path = "first_install_recovery.rs"]
pub(crate) mod recovery;

fn inspect_first_install(
    destination: &Path,
    executable: &AuthenticatedApplicationExecutable,
    roots: &[PathBuf],
) -> Result<InspectedStateRoots, InstallerStageError> {
    crate::require_compiled_target(executable)?;
    crate::require_current_user_installation()?;
    let states = InspectedStateRoots::capture(roots)?;
    require_absent_destination(destination, executable.subject().spec().executable_name())?;
    Ok(states)
}

fn require_absent_destination(destination: &Path, name: &str) -> Result<(), InstallerStageError> {
    #[cfg(unix)]
    {
        let directory = crate::unix_staging::open_destination(destination)?;
        require_absent_entry(directory.directory(), name)?;
        require_idle_installer_state(directory.directory())?;
        crate::unix_staging::revalidate_destination(&directory)
    }
    #[cfg(windows)]
    {
        let directory = kitrove_windows_security::validate_install_directory(destination)
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        require_absent_entry(
            directory
                .directory()
                .map_err(|_| InstallerStageError::UnsafeDestination)?,
            name,
        )?;
        require_idle_installer_state(
            directory
                .directory()
                .map_err(|_| InstallerStageError::UnsafeDestination)?,
        )?;
        directory
            .revalidate()
            .map_err(|_| InstallerStageError::UnsafeDestination)
    }
}

pub(crate) fn require_idle_installer_state(
    parent: &InstallerDirectory,
) -> Result<(), InstallerStageError> {
    use crate::staging_policy::{INSTALLER_LOCK, entry_exists};
    let name = OsStr::new(crate::INSTALLER_STATE_DIRECTORY);
    if !entry_exists(parent, crate::INSTALLER_STATE_DIRECTORY)? {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use crate::unix_staging as filesystem;
        let state = filesystem::open_private_child(parent, name)?;
        let identity = filesystem::directory_identity(&state)?;
        let _lock = filesystem::acquire_existing_installer_lock(&state)?;
        filesystem::require_exact_inventory(&state, &[OsStr::new(INSTALLER_LOCK)])?;
        filesystem::require_named_directory_identity(
            parent,
            crate::INSTALLER_STATE_DIRECTORY,
            &state,
            identity,
        )
    }
    #[cfg(windows)]
    {
        use crate::windows_staging as filesystem;
        let state = kitrove_windows_security::open_private_directory(parent, name)
            .map_err(|_| InstallerStageError::UnsafeState)?;
        let identity = filesystem::file_identity(&state)?;
        let _lock = filesystem::acquire_existing_installer_lock(&state)?;
        filesystem::require_exact_inventory(&state, &[OsStr::new(INSTALLER_LOCK)])?;
        filesystem::require_named_directory_identity(parent, name, identity)
    }
}

fn require_prepared(
    staged: &StagedApplication,
    with_record: bool,
) -> Result<(), InstallerStageError> {
    let extra = if with_record {
        vec![OsStr::new(INSTALL_STATE_RECORD)]
    } else {
        Vec::new()
    };
    #[cfg(unix)]
    {
        crate::unix_install::revalidate_prepared_stage_with_extra_entries(staged, &extra)?;
        require_absent_entry(
            staged._retained.destination.directory(),
            staged.record.executable_name(),
        )
    }
    #[cfg(windows)]
    {
        crate::windows_install::revalidate_stage_with_extra_entries(
            staged,
            crate::install_phase::InstallRecoveryPhase::Prepared,
            None,
            &extra,
        )?;
        require_absent_entry(
            staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::UnsafeDestination)?,
            staged.record.executable_name(),
        )
    }
}

#[cfg(all(unix, debug_assertions))]
#[cfg(test)]
#[path = "installation_state_tests.rs"]
mod tests;

#[cfg(all(windows, debug_assertions))]
#[cfg(test)]
#[path = "windows_installation_state_tests.rs"]
mod windows_tests;
