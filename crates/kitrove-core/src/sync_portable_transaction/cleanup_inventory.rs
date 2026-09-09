use kitrove_model::{MAX_SUPPORTED_SYNC_COMPONENTS, ObjectDescriptor, SyncLimits};

use crate::guarded_control;
use crate::guarded_journal;
use crate::quarantine_cleanup::coordinator::MutationWork;

use super::{SyncPortableTransactionError, capture_limits, cleanup_coordinator_error};

const JOURNAL_TRANSITIONS: usize = 4;
const AUTHORITY_CONTROL_COUNT: usize = 2;
const TRANSACTION_CONTROL_CLEANUP: usize = 6;
const JOURNAL_RECOVERY: usize = guarded_journal::RECONCILE_TOMBSTONES;
const AUTHORITY_CONTROL_RECOVERY: usize =
    AUTHORITY_CONTROL_COUNT * guarded_control::RECONCILE_TOMBSTONES;

pub(super) struct SyncPortableMutationInventory {
    object_staging: usize,
    tree_staging: usize,
}

impl SyncPortableMutationInventory {
    pub(super) fn from_objects(
        objects: impl IntoIterator<Item = ObjectDescriptor>,
    ) -> Result<Self, SyncPortableTransactionError> {
        let mut object_staging = 0usize;
        let mut tree_staging = 0usize;
        for descriptor in objects {
            object_staging = object_staging.checked_add(1).ok_or_else(cleanup_limit)?;
            if descriptor.kind().is_tree_backed() {
                tree_staging = tree_staging.checked_add(1).ok_or_else(cleanup_limit)?;
            }
        }
        Ok(Self {
            object_staging,
            tree_staging,
        })
    }

    pub(super) fn commit_work(
        &self,
        limits: SyncLimits,
    ) -> Result<(MutationWork, MutationWork), SyncPortableTransactionError> {
        Ok((
            self.commit_forward_work(limits)?,
            self.recovery_forward_work(limits)?,
        ))
    }

    fn commit_forward_work(
        &self,
        limits: SyncLimits,
    ) -> Result<MutationWork, SyncPortableTransactionError> {
        self.validate_supported_size()?;
        let journal = JOURNAL_TRANSITIONS
            .checked_mul(guarded_journal::RECONCILE_TOMBSTONES)
            .ok_or_else(cleanup_limit)?;
        let authority = AUTHORITY_CONTROL_COUNT
            .checked_mul(guarded_control::RECONCILE_TOMBSTONES)
            .ok_or_else(cleanup_limit)?;
        let tombstones = checked_sum(&[
            self.object_staging,
            journal,
            authority,
            TRANSACTION_CONTROL_CLEANUP,
        ])?;
        work(tombstones, self.tree_staging, limits)
    }

    pub(super) fn recovery_work(
        &self,
        limits: SyncLimits,
    ) -> Result<(MutationWork, MutationWork), SyncPortableTransactionError> {
        Ok((self.recovery_forward_work(limits)?, MutationWork::none()))
    }

    fn recovery_forward_work(
        &self,
        limits: SyncLimits,
    ) -> Result<MutationWork, SyncPortableTransactionError> {
        self.validate_supported_size()?;
        let journal_transitions = JOURNAL_TRANSITIONS
            .checked_mul(guarded_journal::RECONCILE_TOMBSTONES)
            .ok_or_else(cleanup_limit)?;
        let tombstones = checked_sum(&[
            self.object_staging,
            JOURNAL_RECOVERY,
            AUTHORITY_CONTROL_RECOVERY,
            journal_transitions,
            AUTHORITY_CONTROL_COUNT,
            TRANSACTION_CONTROL_CLEANUP,
        ])?;
        work(tombstones, self.tree_staging, limits)
    }

    fn validate_supported_size(&self) -> Result<(), SyncPortableTransactionError> {
        if self.object_staging > MAX_SUPPORTED_SYNC_COMPONENTS
            || self.tree_staging > self.object_staging
        {
            Err(cleanup_limit())
        } else {
            Ok(())
        }
    }
}

fn checked_sum(parts: &[usize]) -> Result<usize, SyncPortableTransactionError> {
    parts.iter().try_fold(0usize, |total, part| {
        total.checked_add(*part).ok_or_else(cleanup_limit)
    })
}

fn work(
    tombstones: usize,
    trees: usize,
    limits: SyncLimits,
) -> Result<MutationWork, SyncPortableTransactionError> {
    MutationWork::try_from_counts(tombstones, trees, capture_limits(limits))
        .map_err(cleanup_coordinator_error)
}

fn cleanup_limit() -> SyncPortableTransactionError {
    super::error(
        "sync_portable.cleanup_limit",
        "local sync transaction exceeds the supported cleanup limit",
    )
}

#[cfg(test)]
mod tests {
    use kitrove_model::{ContentHash, PortablePath, SnapshotObjectKind};

    use crate::quarantine_cleanup::coordinator::{
        persistent_top_level_limit, require_persistent_top_level_capacity,
    };

    use super::*;

    fn descriptor(kind: SnapshotObjectKind, index: usize) -> ObjectDescriptor {
        ObjectDescriptor::new(
            kind,
            PortablePath::parse(format!("objects/{index}")).unwrap(),
            ContentHash::digest(format!("object-{index}").as_bytes()),
            1,
        )
        .unwrap()
    }

    #[test]
    fn inventory_counts_document_and_tree_staging_exactly() {
        let inventory = SyncPortableMutationInventory::from_objects([
            descriptor(SnapshotObjectKind::PortableSkillTree, 0),
            descriptor(SnapshotObjectKind::PortableInstruction, 1),
        ])
        .unwrap();
        assert_eq!(inventory.object_staging, 2);
        assert_eq!(inventory.tree_staging, 1);
        let (commit, commit_recovery) = inventory.commit_work(SyncLimits::default()).unwrap();
        let (recovery, _) = inventory.recovery_work(SyncLimits::default()).unwrap();
        assert_eq!(commit.top_level_entries(), 14);
        assert_eq!(recovery.top_level_entries(), 17);
        assert_eq!(commit_recovery, recovery);
    }

    #[test]
    fn commit_reserves_exact_persistent_capacity_for_crash_recovery() {
        let inventory = SyncPortableMutationInventory::from_objects([]).unwrap();
        let (forward, crash_recovery) = inventory.commit_work(SyncLimits::default()).unwrap();
        let retained = persistent_top_level_limit()
            - forward.top_level_entries()
            - crash_recovery.top_level_entries();

        require_persistent_top_level_capacity(retained, forward, crash_recovery).unwrap();
        assert_eq!(
            require_persistent_top_level_capacity(retained + 1, forward, crash_recovery),
            Err(crate::quarantine_cleanup::coordinator::MutationCleanupError::InvalidReservation)
        );
    }

    #[test]
    fn maximum_supported_sync_inventory_is_admitted_exactly() {
        let maximum = SyncPortableMutationInventory {
            object_staging: MAX_SUPPORTED_SYNC_COMPONENTS,
            tree_staging: MAX_SUPPORTED_SYNC_COMPONENTS,
        };
        maximum.recovery_work(SyncLimits::default()).unwrap();

        let unsupported = SyncPortableMutationInventory {
            object_staging: MAX_SUPPORTED_SYNC_COMPONENTS + 1,
            tree_staging: MAX_SUPPORTED_SYNC_COMPONENTS + 1,
        };
        assert!(unsupported.recovery_work(SyncLimits::default()).is_err());
    }
}
