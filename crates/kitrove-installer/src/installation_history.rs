use std::ffi::OsStr;
use std::path::Path;

use kitrove_release_provenance::AuthenticatedApplicationExecutable;

use crate::install_phase::{FAILED_EXECUTABLE, InstallPhase, MAX_PHASE_RECORD_BYTES};
use crate::installation_state::{INSTALL_STATE_RECORD, MAX_INSTALL_STATE_BYTES};
use crate::record::MAX_OPERATION_RECORD_BYTES;
use crate::record::history::{
    HistoricalOperationRecord,
    journal::{HistoricalInstallJournal, HistoricalInstallOutcome},
};
#[cfg(unix)]
use crate::staging_policy::STAGED_EXECUTABLE;
use crate::staging_policy::{
    OPERATION_RECORD, OpenedLeaf, PrivateDataLeaf, entry_exists, read_pending_data_leaf,
    read_private_data_leaf,
};
use crate::{InstallerStageError, NativeFileIdentity, StagingInput};

#[path = "history_root.rs"]
pub(crate) mod filesystem;

#[path = "history_sync.rs"]
pub(crate) mod synchronization;

#[path = "replacement_history.rs"]
pub(crate) mod replacement;

struct JournalLeaf {
    phase: InstallPhase,
    pending: bool,
    name: &'static str,
    leaf: PrivateDataLeaf,
}

impl JournalLeaf {
    fn name(&self) -> &'static str {
        self.name
    }
}

struct ExecutableLeaf {
    name: &'static str,
    identity: NativeFileIdentity,
    leaf: OpenedLeaf,
}

/// Read-only retained archive evidence. No conversion to an installation or recovery owner.
/// Excludes current executable placement and does not assert archival synchronization.
pub(crate) struct ArchivedInstallation {
    record_leaf: PrivateDataLeaf,
    state_leaf: PrivateDataLeaf,
    phases: Vec<JournalLeaf>,
    executables: Vec<ExecutableLeaf>,
    record: HistoricalOperationRecord,
    journal: HistoricalInstallJournal,
    executable_size: u64,
    executable_sha256: [u8; 32],
    // Close all leaf handles before releasing namespace capabilities and the lock.
    root: filesystem::HistoryRoot,
}

impl ArchivedInstallation {
    pub(crate) fn open(
        destination: &Path,
        selected: &str,
        executable: &AuthenticatedApplicationExecutable,
    ) -> Result<Self, InstallerStageError> {
        crate::require_compiled_target(executable)?;
        crate::require_current_user_installation()?;
        let input = StagingInput::from(executable);
        let root = filesystem::HistoryRoot::open(destination, selected)?;
        let record_leaf = read_private_data_leaf(
            &root.operation,
            OPERATION_RECORD,
            MAX_OPERATION_RECORD_BYTES,
        )?;
        let record =
            HistoricalOperationRecord::parse_release_bound(&record_leaf.bytes, selected, &input)
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
        root.revalidate(record.recorded_operation_identity())?;
        let state_leaf = read_private_data_leaf(
            &root.operation,
            INSTALL_STATE_RECORD,
            MAX_INSTALL_STATE_BYTES,
        )?;
        record.validate_state_record(&state_leaf.bytes)?;
        let phases = read_journal(
            &root.operation,
            InstallPhase::file_name,
            InstallPhase::pending_file_name,
            MAX_PHASE_RECORD_BYTES,
        )?;
        let journal = parse_journal(&record, &phases)?;
        #[cfg(windows)]
        if journal.recorded_installed_identity() != record.recorded_staged_identity() {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let mut retained = Vec::new();
        #[cfg(unix)]
        retained.push((STAGED_EXECUTABLE, record.recorded_staged_identity()));
        if journal.outcome() == HistoricalInstallOutcome::RolledBack {
            retained.push((FAILED_EXECUTABLE, journal.recorded_installed_identity()));
        }
        let executables = retained
            .into_iter()
            .map(|(name, identity)| {
                let leaf = filesystem::open_executable(
                    &root.operation,
                    name,
                    input.executable_bytes.len() as u64,
                )?;
                Ok(ExecutableLeaf {
                    name,
                    identity,
                    leaf,
                })
            })
            .collect::<Result<Vec<_>, InstallerStageError>>()?;
        let history = Self {
            record_leaf,
            state_leaf,
            phases,
            executables,
            record,
            journal,
            executable_size: input.executable_bytes.len() as u64,
            executable_sha256: input.executable_sha256,
            root,
        };
        history.revalidate()?;
        Ok(history)
    }

    pub(crate) fn outcome(&self) -> Result<HistoricalInstallOutcome, InstallerStageError> {
        self.revalidate()?;
        Ok(self.journal.outcome())
    }

    pub(crate) fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.root
            .revalidate(self.record.recorded_operation_identity())?;
        let operation = &self.root.operation;
        let expected = [OPERATION_RECORD, INSTALL_STATE_RECORD]
            .into_iter()
            .chain(self.phases.iter().map(JournalLeaf::name))
            .chain(self.executables.iter().map(|leaf| leaf.name))
            .map(OsStr::new)
            .collect::<Vec<_>>();
        filesystem::require_exact_inventory(operation, &expected)?;
        self.revalidate_records()?;
        for executable in &self.executables {
            filesystem::require_executable(
                operation,
                executable.name,
                &executable.leaf,
                executable.identity,
                self.executable_size,
                self.executable_sha256,
            )?;
        }
        self.revalidate_records()?;
        filesystem::require_exact_inventory(operation, &expected)?;
        self.root
            .revalidate(self.record.recorded_operation_identity())
    }

    fn revalidate_records(&self) -> Result<(), InstallerStageError> {
        let operation = &self.root.operation;
        self.record_leaf
            .require_contents(operation, OPERATION_RECORD, &self.record_leaf.bytes)?;
        self.state_leaf.require_contents(
            operation,
            INSTALL_STATE_RECORD,
            &self.state_leaf.bytes,
        )?;
        for phase in &self.phases {
            phase
                .leaf
                .require_contents(operation, phase.name(), &phase.leaf.bytes)?;
        }
        Ok(())
    }
}

fn read_journal(
    operation: &crate::staging_policy::InstallerDirectory,
    complete_name: fn(InstallPhase) -> &'static str,
    pending_name: fn(InstallPhase) -> &'static str,
    maximum: usize,
) -> Result<Vec<JournalLeaf>, InstallerStageError> {
    let mut phases = Vec::new();
    for &phase in InstallPhase::all() {
        for pending in [false, true] {
            let name = if pending {
                pending_name(phase)
            } else {
                complete_name(phase)
            };
            if entry_exists(operation, name)? {
                let leaf = if pending {
                    read_pending_data_leaf(operation, name, maximum)?
                } else {
                    read_private_data_leaf(operation, name, maximum)?
                };
                phases.push(JournalLeaf {
                    phase,
                    pending,
                    name,
                    leaf,
                });
            }
        }
    }
    Ok(phases)
}

fn parse_journal(
    record: &HistoricalOperationRecord,
    phases: &[JournalLeaf],
) -> Result<HistoricalInstallJournal, InstallerStageError> {
    let select = |pending| {
        phases
            .iter()
            .filter(|leaf| leaf.pending == pending)
            .map(|leaf| (leaf.phase, leaf.leaf.bytes.as_slice()))
            .collect::<Vec<_>>()
    };
    HistoricalInstallJournal::parse(record, &select(false), &select(true))
}
