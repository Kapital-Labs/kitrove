use kitrove_model::SyncLimits;

use crate::PortableSnapshotV1;
use crate::guarded_control;
use crate::guarded_journal;
use crate::quarantine_cleanup::coordinator::MutationWork;
use crate::sync_portable_transaction::{sync_portable_commit_work, sync_portable_recovery_work};

use super::{SyncTransactionError, cleanup_coordinator_error, portable_error};

const OUTER_JOURNAL_TRANSITIONS_WITH_PUBLICATION: usize = 7;
const OUTER_JOURNAL_TRANSITIONS_WITHOUT_PUBLICATION: usize = 6;
const OUTER_JOURNAL_RECOVERY: usize = guarded_journal::RECONCILE_TOMBSTONES;
const OUTER_GUARD_CLEANUP: usize = 1;
const OUTER_CONTROL_CLEANUP: usize = 8;
const BASE_POINTER_INSTALL: usize = guarded_control::RECONCILE_TOMBSTONES;

pub(super) struct SyncMutationInventory {
    objects: usize,
    trees: usize,
}

impl SyncMutationInventory {
    pub(super) fn from_snapshot(snapshot: &PortableSnapshotV1) -> Self {
        Self {
            objects: snapshot.objects().len(),
            trees: snapshot
                .objects()
                .iter()
                .filter(|descriptor| descriptor.kind().is_tree_backed())
                .count(),
        }
    }

    pub(super) fn commit_work(
        &self,
        snapshot: &PortableSnapshotV1,
        publication: bool,
        limits: SyncLimits,
    ) -> Result<(MutationWork, MutationWork), SyncTransactionError> {
        let transitions = if publication {
            OUTER_JOURNAL_TRANSITIONS_WITH_PUBLICATION
        } else {
            OUTER_JOURNAL_TRANSITIONS_WITHOUT_PUBLICATION
        };
        let outer = work(
            checked_sum(&[
                self.objects,
                transitions,
                OUTER_GUARD_CLEANUP,
                OUTER_CONTROL_CLEANUP,
                BASE_POINTER_INSTALL,
            ])?,
            self.trees,
            limits,
        )?;
        let (inner, inner_rollback) =
            sync_portable_commit_work(snapshot, limits).map_err(portable_error)?;
        let outer_recovery = self.outer_recovery_work(limits)?;
        Ok((
            outer
                .checked_add(inner)
                .map_err(cleanup_coordinator_error)?,
            outer_recovery
                .checked_add(inner_rollback)
                .map_err(cleanup_coordinator_error)?,
        ))
    }

    pub(super) fn recovery_work(
        &self,
        snapshot: &PortableSnapshotV1,
        limits: SyncLimits,
    ) -> Result<(MutationWork, MutationWork), SyncTransactionError> {
        let outer = self.outer_recovery_work(limits)?;
        let (inner, _) = sync_portable_recovery_work(snapshot, limits).map_err(portable_error)?;
        Ok((
            outer
                .checked_add(inner)
                .map_err(cleanup_coordinator_error)?,
            MutationWork::none(),
        ))
    }

    fn outer_recovery_work(
        &self,
        limits: SyncLimits,
    ) -> Result<MutationWork, SyncTransactionError> {
        work(
            checked_sum(&[
                self.objects,
                OUTER_JOURNAL_RECOVERY,
                OUTER_JOURNAL_TRANSITIONS_WITH_PUBLICATION,
                OUTER_GUARD_CLEANUP,
                OUTER_CONTROL_CLEANUP,
                BASE_POINTER_INSTALL,
            ])?,
            self.trees,
            limits,
        )
    }

    pub(super) fn orphan_guard_work(
        limits: SyncLimits,
    ) -> Result<(MutationWork, MutationWork), SyncTransactionError> {
        Ok((work(OUTER_GUARD_CLEANUP, 0, limits)?, MutationWork::none()))
    }
}

fn checked_sum(parts: &[usize]) -> Result<usize, SyncTransactionError> {
    parts.iter().try_fold(0usize, |total, part| {
        total.checked_add(*part).ok_or_else(super::cleanup_limit)
    })
}

fn work(
    tombstones: usize,
    trees: usize,
    limits: SyncLimits,
) -> Result<MutationWork, SyncTransactionError> {
    MutationWork::try_from_counts(tombstones, trees, super::capture_limits(limits))
        .map_err(cleanup_coordinator_error)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{EnvironmentManifest, MAX_SUPPORTED_SYNC_COMPONENTS, SchemaVersion};

    use crate::quarantine_cleanup::coordinator::{
        persistent_top_level_limit, require_persistent_top_level_capacity,
    };
    use crate::quarantine_cleanup::sync_policy::{
        MAX_SYNC_RECOVERY_TOMBSTONES, SYNC_RECOVERY_CONTROL_TOMBSTONES,
    };

    use super::*;

    fn empty_snapshot() -> PortableSnapshotV1 {
        PortableSnapshotV1::new(
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: BTreeSet::new(),
            },
            BTreeSet::new(),
            SyncLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn exact_empty_outer_and_inner_totals_are_bound() {
        let snapshot = empty_snapshot();
        let inventory = SyncMutationInventory::from_snapshot(&snapshot);
        let (receive, receive_recovery) = inventory
            .commit_work(&snapshot, false, SyncLimits::default())
            .unwrap();
        let (publish, publish_recovery) = inventory
            .commit_work(&snapshot, true, SyncLimits::default())
            .unwrap();
        let (recovery, _) = inventory
            .recovery_work(&snapshot, SyncLimits::default())
            .unwrap();
        assert_eq!(receive.top_level_entries(), 28);
        assert_eq!(publish.top_level_entries(), 29);
        assert_eq!(recovery.top_level_entries(), 33);
        assert_eq!(
            recovery.top_level_entries(),
            SYNC_RECOVERY_CONTROL_TOMBSTONES
        );
        assert_eq!(receive_recovery, recovery);
        assert_eq!(publish_recovery, recovery);
    }

    #[test]
    fn two_root_commit_reserves_exact_persistent_capacity_for_crash_recovery() {
        let snapshot = empty_snapshot();
        let inventory = SyncMutationInventory::from_snapshot(&snapshot);
        let (forward, crash_recovery) = inventory
            .commit_work(&snapshot, true, SyncLimits::default())
            .unwrap();
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
    fn maximum_supported_two_root_sync_inventory_is_admitted_exactly() {
        let maximum = SyncMutationInventory {
            objects: MAX_SUPPORTED_SYNC_COMPONENTS,
            trees: MAX_SUPPORTED_SYNC_COMPONENTS,
        };
        let limits = SyncLimits::default();
        let inner_recovery = MutationWork::try_from_counts(
            MAX_SUPPORTED_SYNC_COMPONENTS + 15,
            MAX_SUPPORTED_SYNC_COMPONENTS,
            super::super::capture_limits(limits),
        )
        .unwrap();
        maximum
            .outer_recovery_work(limits)
            .unwrap()
            .checked_add(inner_recovery)
            .map(|work| assert_eq!(work.top_level_entries(), MAX_SYNC_RECOVERY_TOMBSTONES))
            .unwrap();

        let unsupported = SyncMutationInventory {
            objects: MAX_SUPPORTED_SYNC_COMPONENTS + 1,
            trees: MAX_SUPPORTED_SYNC_COMPONENTS + 1,
        };
        let unsupported_inner = MutationWork::try_from_counts(
            MAX_SUPPORTED_SYNC_COMPONENTS + 16,
            MAX_SUPPORTED_SYNC_COMPONENTS + 1,
            super::super::capture_limits(limits),
        )
        .unwrap();
        assert!(
            unsupported
                .outer_recovery_work(limits)
                .unwrap()
                .checked_add(unsupported_inner)
                .is_err()
        );
    }
}
