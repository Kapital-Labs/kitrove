use super::*;
use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::{ROLLBACK_DIRECTORY, RetainedRollbackKit};
use crate::upgrade_record::{
    MAX_UPGRADE_RECORD_BYTES, UPGRADE_RECORD, history::HistoricalUpgradeRecord,
};
use kitrove_release_provenance::{AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity};

#[path = "replacement_history_sync.rs"]
pub(crate) mod synchronization;

#[path = "replacement_history_journal.rs"]
mod journal;

#[cfg(windows)]
pub(crate) struct RetirementEvidence {
    pub(crate) operation_identity: NativeFileIdentity,
    pub(crate) operation_bytes: Vec<u8>,
    pub(crate) upgrade_identity: NativeFileIdentity,
    pub(crate) upgrade_digest: [u8; 32],
    pub(crate) journal: crate::upgrade_transaction::windows_journal::ReleasedJournal,
}

/// Historical replacement evidence, independent of the currently installed executable.
pub(crate) struct ArchivedReplacement {
    operation_leaf: PrivateDataLeaf,
    upgrade_leaf: PrivateDataLeaf,
    phases: journal::Journal,
    displaced: ExecutableLeaf,
    kit: RetainedRollbackKit,
    material: AuthenticatedRecoveryMaterial,
    operation: HistoricalOperationRecord,
    upgrade: HistoricalUpgradeRecord,
    outcome: HistoricalInstallOutcome,
    displaced_size: u64,
    displaced_sha256: [u8; 32],
    root: filesystem::HistoryRoot,
}

impl ArchivedReplacement {
    #[cfg(windows)]
    pub(crate) fn require_handoff(
        &self,
        evidence: &RetirementEvidence,
    ) -> Result<(), InstallerStageError> {
        self.revalidate()?;
        if self.operation_leaf.identity != evidence.operation_identity
            || self.operation_leaf.bytes != evidence.operation_bytes
            || self.upgrade_leaf.identity != evidence.upgrade_identity
            || self.upgrade.binding_digest()? != evidence.upgrade_digest
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        evidence.journal.require_same(&self.phases)
    }

    pub(crate) fn open(
        destination: &Path,
        selected: &str,
        candidate: &AuthenticatedApplicationExecutable,
        prior: &ExpectedReleaseIdentity,
        archive_sha256: [u8; 32],
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        Self::open_with(destination, selected, candidate, direction, |operation| {
            RetainedRollbackKit::reopen_at(operation, prior, archive_sha256)
        })
    }

    #[cfg(all(test, debug_assertions))]
    pub(crate) fn open_with_test_subject(
        destination: &Path,
        selected: &str,
        candidate: &AuthenticatedApplicationExecutable,
        prior: &ExpectedReleaseIdentity,
        archive_sha256: [u8; 32],
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        Self::open_with(destination, selected, candidate, direction, |operation| {
            RetainedRollbackKit::reopen_at_with_test_subject(operation, prior, archive_sha256)
        })
    }

    fn open_with(
        destination: &Path,
        selected: &str,
        candidate: &AuthenticatedApplicationExecutable,
        direction: ReplacementDirection,
        authenticate_kit: impl FnOnce(
            &crate::staging_policy::InstallerDirectory,
        ) -> Result<
            (RetainedRollbackKit, AuthenticatedRecoveryMaterial),
            InstallerStageError,
        >,
    ) -> Result<Self, InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let root = filesystem::HistoryRoot::open(destination, selected)?;
        Self::open_root(root, candidate, direction, authenticate_kit)
    }

    pub(crate) fn open_root(
        root: filesystem::HistoryRoot,
        candidate: &AuthenticatedApplicationExecutable,
        direction: ReplacementDirection,
        authenticate_kit: impl FnOnce(
            &crate::staging_policy::InstallerDirectory,
        ) -> Result<
            (RetainedRollbackKit, AuthenticatedRecoveryMaterial),
            InstallerStageError,
        >,
    ) -> Result<Self, InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let operation_leaf = read_private_data_leaf(
            &root.operation,
            OPERATION_RECORD,
            MAX_OPERATION_RECORD_BYTES,
        )?;
        let operation = HistoricalOperationRecord::parse_release_bound(
            &operation_leaf.bytes,
            root.selected(),
            &StagingInput::from(candidate),
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        root.revalidate(operation.recorded_operation_identity())?;
        let (kit, material) = authenticate_kit(&root.operation)?;
        let upgrade_leaf =
            read_private_data_leaf(&root.operation, UPGRADE_RECORD, MAX_UPGRADE_RECORD_BYTES)?;
        let upgrade = HistoricalUpgradeRecord::parse(
            &upgrade_leaf.bytes,
            &operation,
            candidate,
            &material,
            direction,
        )?;
        if kit.identities() != upgrade.kit_identities() {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let (phases, outcome) = journal::open(&root.operation, &operation, &upgrade)?;
        let (identity, displaced_executable) = match outcome {
            HistoricalInstallOutcome::Committed => {
                (upgrade.prior_identity(), material.executable())
            }
            HistoricalInstallOutcome::RolledBack => {
                (operation.recorded_staged_identity(), candidate)
            }
        };
        let displaced_size = displaced_executable.bytes().len() as u64;
        let displaced_sha256 = displaced_executable.executable_sha256();
        let name = journal::displaced_name(outcome);
        let displaced = ExecutableLeaf {
            name,
            identity,
            leaf: filesystem::open_executable(&root.operation, name, displaced_size)?,
        };
        let history = Self {
            operation_leaf,
            upgrade_leaf,
            phases,
            displaced,
            kit,
            material,
            operation,
            upgrade,
            outcome,
            displaced_size,
            displaced_sha256,
            root,
        };
        history.revalidate()?;
        Ok(history)
    }

    pub(crate) fn outcome(&self) -> Result<HistoricalInstallOutcome, InstallerStageError> {
        self.revalidate()?;
        Ok(self.outcome)
    }

    pub(crate) fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.root
            .revalidate(self.operation.recorded_operation_identity())?;
        let operation = &self.root.operation;
        let names = [
            OPERATION_RECORD,
            UPGRADE_RECORD,
            self.displaced.name,
            ROLLBACK_DIRECTORY,
        ]
        .into_iter()
        .map(OsStr::new)
        .chain(journal::names(&self.phases))
        .collect::<Vec<_>>();
        filesystem::require_exact_inventory(operation, &names)?;
        self.revalidate_records()?;
        self.kit.revalidate_at(operation, &self.material)?;
        filesystem::require_executable(
            operation,
            self.displaced.name,
            &self.displaced.leaf,
            self.displaced.identity,
            self.displaced_size,
            self.displaced_sha256,
        )?;
        self.revalidate_records()?;
        self.kit.revalidate_at(operation, &self.material)?;
        if self.kit.identities() != self.upgrade.kit_identities() {
            return Err(InstallerStageError::RecoveryRequired);
        }
        filesystem::require_exact_inventory(operation, &names)?;
        self.root
            .revalidate(self.operation.recorded_operation_identity())
    }

    fn revalidate_records(&self) -> Result<(), InstallerStageError> {
        let operation = &self.root.operation;
        self.operation_leaf.require_contents(
            operation,
            OPERATION_RECORD,
            &self.operation_leaf.bytes,
        )?;
        self.upgrade_leaf
            .require_contents(operation, UPGRADE_RECORD, &self.upgrade_leaf.bytes)?;
        journal::revalidate(&self.phases, operation)
    }
}
