use kitrove_agent_skills::{CaptureLimits, MAX_CAPTURE_DEPTH, MAX_CAPTURE_DIRECTORIES};
use kitrove_model::MAX_SUPPORTED_SYNC_COMPONENTS;

use crate::ObjectStore;
use crate::apply_batch::{
    ATOMIC_COMMIT_CONTROL_TOMBSTONES, ATOMIC_COMMIT_TOMBSTONES_PER_PARTICIPANT,
    ATOMIC_ROLLBACK_CONTROL_TOMBSTONES, ATOMIC_ROLLBACK_TOMBSTONES_PER_PARTICIPANT,
    ATOMIC_TREE_TOMBSTONES_PER_TREE_PARTICIPANT, MAX_BATCH_PARTICIPANTS,
};

#[cfg(any(unix, windows))]
use super::batch::{QuarantineCleanupError, cleanup_inspected_quarantines};
use super::budget::{
    CleanupPassWork, QuarantineBudgetError, QuarantineCleanupBudget, QuarantineCleanupLimits,
    QuarantineCleanupReservation, QuarantineWorkPortion, TombstoneWork,
};
use super::inspection::{QuarantineInspectionError, inspect_store_quarantine};
use super::sync_policy::{MAX_SYNC_RECOVERY_TOMBSTONES, MAX_SYNC_TREE_TOMBSTONES};

const MAX_MUTATION_ROOTS: usize = MAX_BATCH_PARTICIPANTS + 2;
const MAX_BATCH_TOMBSTONES: usize = MAX_BATCH_PARTICIPANTS
    * ATOMIC_COMMIT_TOMBSTONES_PER_PARTICIPANT
    + ATOMIC_COMMIT_CONTROL_TOMBSTONES;
const MAX_BATCH_TREE_TOMBSTONES: usize =
    MAX_BATCH_PARTICIPANTS * ATOMIC_TREE_TOMBSTONES_PER_TREE_PARTICIPANT;
const MAX_BATCH_ROLLBACK_TOMBSTONES: usize = MAX_BATCH_PARTICIPANTS
    * ATOMIC_ROLLBACK_TOMBSTONES_PER_PARTICIPANT
    + ATOMIC_ROLLBACK_CONTROL_TOMBSTONES;
const MAX_PHASE_TOMBSTONES: usize = if MAX_BATCH_TOMBSTONES > MAX_SYNC_RECOVERY_TOMBSTONES {
    MAX_BATCH_TOMBSTONES
} else {
    MAX_SYNC_RECOVERY_TOMBSTONES
};
const MAX_PHASE_TREE_TOMBSTONES: usize = if MAX_BATCH_TREE_TOMBSTONES > MAX_SYNC_TREE_TOMBSTONES {
    MAX_BATCH_TREE_TOMBSTONES
} else {
    MAX_SYNC_TREE_TOMBSTONES
};
const MAX_ROLLBACK_TOMBSTONES: usize =
    if MAX_BATCH_ROLLBACK_TOMBSTONES > MAX_SYNC_RECOVERY_TOMBSTONES {
        MAX_BATCH_ROLLBACK_TOMBSTONES
    } else {
        MAX_SYNC_RECOVERY_TOMBSTONES
    };
const MAX_RETAINED_TOMBSTONES: usize = MAX_PHASE_TOMBSTONES + MAX_ROLLBACK_TOMBSTONES;
const MAX_RETAINED_TREE_TOMBSTONES: usize = MAX_PHASE_TREE_TOMBSTONES * 2;
const MAX_MUTATION_TREE_FILES: usize = MAX_SUPPORTED_SYNC_COMPONENTS;
const MAX_TREE_DESCENDANTS: usize = MAX_MUTATION_TREE_FILES + MAX_CAPTURE_DIRECTORIES;
const MAX_PHASE_DESCENDANTS: usize = MAX_PHASE_TREE_TOMBSTONES * MAX_TREE_DESCENDANTS;
const MAX_RETAINED_DESCENDANTS: usize = MAX_RETAINED_TREE_TOMBSTONES * MAX_TREE_DESCENDANTS;
const MAX_BATCH_DESCENDANTS: usize = MAX_RETAINED_DESCENDANTS + MAX_RETAINED_TOMBSTONES;
const MAX_QUARANTINE_TREE_DEPTH: usize = MAX_CAPTURE_DEPTH + 2;

/// Stable structural failure from the cleanup boundary shared by mutation coordinators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationCleanupError {
    InvalidReservation,
    CleanupFailed,
}

impl From<QuarantineBudgetError> for MutationCleanupError {
    fn from(_: QuarantineBudgetError) -> Self {
        Self::InvalidReservation
    }
}

impl From<QuarantineInspectionError> for MutationCleanupError {
    fn from(error: QuarantineInspectionError) -> Self {
        match error {
            QuarantineInspectionError::Budget(_) => Self::InvalidReservation,
            QuarantineInspectionError::UnsafeState
            | QuarantineInspectionError::UnrecognizedState => Self::CleanupFailed,
        }
    }
}

#[cfg(any(unix, windows))]
impl From<QuarantineCleanupError> for MutationCleanupError {
    fn from(error: QuarantineCleanupError) -> Self {
        match error {
            QuarantineCleanupError::Budget(_) => Self::InvalidReservation,
            QuarantineCleanupError::UnsafeState | QuarantineCleanupError::MutationFailed => {
                Self::CleanupFailed
            }
        }
    }
}

/// Worst-case tombstone work derived from an exact coordinator inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MutationWork(TombstoneWork);

impl MutationWork {
    pub(crate) const fn none() -> Self {
        Self(TombstoneWork::new(0, 0, 0))
    }

    pub(crate) fn try_from_counts(
        tombstones: usize,
        tree_tombstones: usize,
        capture_limits: CaptureLimits,
    ) -> Result<Self, MutationCleanupError> {
        if capture_limits.max_files > MAX_MUTATION_TREE_FILES
            || tree_tombstones > tombstones
            || tombstones > MAX_PHASE_TOMBSTONES
            || tree_tombstones > MAX_PHASE_TREE_TOMBSTONES
        {
            return Err(MutationCleanupError::InvalidReservation);
        }
        let descendants_per_tree = capture_limits
            .max_files
            .checked_add(MAX_CAPTURE_DIRECTORIES)
            .ok_or(MutationCleanupError::InvalidReservation)?;
        let descendants = tree_tombstones
            .checked_mul(descendants_per_tree)
            .ok_or(MutationCleanupError::InvalidReservation)?;
        if descendants > MAX_PHASE_DESCENDANTS {
            return Err(MutationCleanupError::InvalidReservation);
        }
        Ok(Self(TombstoneWork::new(
            tombstones,
            descendants,
            if tree_tombstones == 0 {
                0
            } else {
                MAX_QUARANTINE_TREE_DEPTH
            },
        )))
    }

    pub(crate) fn checked_add(self, other: Self) -> Result<Self, MutationCleanupError> {
        let combined = self
            .0
            .checked_add(other.0)
            .ok_or(MutationCleanupError::InvalidReservation)?;
        if combined.top_level_entries() > MAX_PHASE_TOMBSTONES
            || combined.descendant_visits() > MAX_PHASE_DESCENDANTS
            || combined.max_depth() > MAX_QUARANTINE_TREE_DEPTH
        {
            return Err(MutationCleanupError::InvalidReservation);
        }
        Ok(Self(combined))
    }

    #[cfg(test)]
    pub(crate) const fn top_level_entries(self) -> usize {
        self.0.top_level_entries()
    }
}

/// One transaction-global budget after all locked roots have been inspected and reclaimed.
pub(crate) struct LockedMutationBudget {
    budget: QuarantineCleanupBudget,
    forward: MutationWork,
    rollback: MutationWork,
}

impl LockedMutationBudget {
    pub(crate) fn begin_forward(mut self) -> Result<ActiveMutationBudget, MutationCleanupError> {
        self.budget
            .try_consume(QuarantineWorkPortion::Forward, self.forward.0)?;
        Ok(ActiveMutationBudget {
            _budget: self.budget,
        })
    }

    pub(crate) fn begin_rollback(mut self) -> Result<ActiveMutationBudget, MutationCleanupError> {
        self.budget
            .try_consume(QuarantineWorkPortion::Rollback, self.rollback.0)?;
        Ok(ActiveMutationBudget {
            _budget: self.budget,
        })
    }
}

/// Keeps the charged transaction-global budget alive for the selected mutation phase.
pub(crate) struct ActiveMutationBudget {
    _budget: QuarantineCleanupBudget,
}

/// Reclaims retained state across an already locked, distinct root set and returns the same budget
/// for the transaction's separately reserved forward and rollback work.
pub(crate) fn cleanup_locked_stores(
    stores: &[&ObjectStore],
    forward: MutationWork,
    rollback: MutationWork,
) -> Result<LockedMutationBudget, MutationCleanupError> {
    let reservation = production_reservation(stores.len(), forward, rollback)?;
    let mut budget = QuarantineCleanupBudget::new(reservation);
    let inspections = stores
        .iter()
        .map(|store| inspect_store_quarantine(store, &mut budget))
        .collect::<Result<Vec<_>, _>>()?;
    let retained = inspections
        .iter()
        .try_fold(TombstoneWork::default(), |total, inspection| {
            total.checked_add(inspection.work())
        })
        .ok_or(MutationCleanupError::InvalidReservation)?;

    #[cfg(not(any(unix, windows)))]
    require_retained_capacity(retained, forward, rollback)?;
    #[cfg(any(unix, windows))]
    let _ = retained;

    #[cfg(any(unix, windows))]
    {
        let targets = stores.iter().copied().zip(&inspections).collect::<Vec<_>>();
        cleanup_inspected_quarantines(&targets, &mut budget)?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = inspections;

    Ok(LockedMutationBudget {
        budget,
        forward,
        rollback,
    })
}

#[cfg(any(not(any(unix, windows)), test))]
fn require_retained_capacity(
    retained: TombstoneWork,
    forward: MutationWork,
    rollback: MutationWork,
) -> Result<(), MutationCleanupError> {
    let projected = forward
        .0
        .checked_add(rollback.0)
        .and_then(|mutation| retained.checked_add(mutation))
        .ok_or(MutationCleanupError::InvalidReservation)?;
    if projected.fits_within(persistent_retained_limit()) {
        Ok(())
    } else {
        Err(MutationCleanupError::InvalidReservation)
    }
}

#[cfg(any(not(any(unix, windows)), test))]
const fn persistent_retained_limit() -> TombstoneWork {
    TombstoneWork::new(
        MAX_RETAINED_TOMBSTONES,
        MAX_BATCH_DESCENDANTS,
        MAX_QUARANTINE_TREE_DEPTH,
    )
}

#[cfg(test)]
pub(crate) fn require_persistent_top_level_capacity(
    retained_entries: usize,
    forward: MutationWork,
    rollback: MutationWork,
) -> Result<(), MutationCleanupError> {
    require_retained_capacity(
        TombstoneWork::new(retained_entries, 0, 0),
        forward,
        rollback,
    )
}

#[cfg(test)]
pub(crate) const fn persistent_top_level_limit() -> usize {
    persistent_retained_limit().top_level_entries()
}

fn production_reservation(
    roots: usize,
    forward: MutationWork,
    rollback: MutationWork,
) -> Result<QuarantineCleanupReservation, MutationCleanupError> {
    if roots == 0 || roots > MAX_MUTATION_ROOTS {
        return Err(MutationCleanupError::InvalidReservation);
    }
    if !rollback.0.fits_within(TombstoneWork::new(
        MAX_ROLLBACK_TOMBSTONES,
        MAX_PHASE_DESCENDANTS,
        MAX_QUARANTINE_TREE_DEPTH,
    )) {
        return Err(MutationCleanupError::InvalidReservation);
    }
    let retained = TombstoneWork::new(
        MAX_RETAINED_TOMBSTONES,
        MAX_BATCH_DESCENDANTS,
        MAX_QUARANTINE_TREE_DEPTH,
    );
    let validation = TombstoneWork::new(roots, MAX_BATCH_DESCENDANTS, MAX_QUARANTINE_TREE_DEPTH);
    let deletion = TombstoneWork::new(
        MAX_RETAINED_TOMBSTONES
            .checked_add(
                roots
                    .checked_mul(3)
                    .ok_or(MutationCleanupError::InvalidReservation)?,
            )
            .ok_or(MutationCleanupError::InvalidReservation)?,
        MAX_BATCH_DESCENDANTS
            .checked_mul(2)
            .ok_or(MutationCleanupError::InvalidReservation)?,
        MAX_QUARANTINE_TREE_DEPTH,
    );
    let cleanup = CleanupPassWork::new(retained, validation, deletion);
    let aggregate = [retained, validation, deletion, forward.0, rollback.0]
        .into_iter()
        .try_fold(TombstoneWork::default(), |total, work| {
            total.checked_add(work)
        })
        .ok_or(MutationCleanupError::InvalidReservation)?;
    let limits = QuarantineCleanupLimits::try_new(
        MAX_MUTATION_ROOTS,
        aggregate.top_level_entries(),
        aggregate.descendant_visits(),
        aggregate.max_depth(),
    )?;
    QuarantineCleanupReservation::try_new(limits, roots, cleanup, forward.0, rollback.0)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_batch_reservation_uses_shared_capture_shape() {
        let forward = MutationWork::try_from_counts(
            MAX_PHASE_TOMBSTONES,
            MAX_PHASE_TREE_TOMBSTONES,
            CaptureLimits::default(),
        )
        .unwrap();
        let rollback = MutationWork::try_from_counts(
            MAX_ROLLBACK_TOMBSTONES,
            MAX_PHASE_TREE_TOMBSTONES,
            CaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            forward.0.top_level_entries() + rollback.0.top_level_entries(),
            MAX_RETAINED_TOMBSTONES
        );
        let reservation = production_reservation(MAX_MUTATION_ROOTS, forward, rollback).unwrap();
        let mut budget = QuarantineCleanupBudget::new(reservation);
        for _ in 0..MAX_MUTATION_ROOTS {
            budget.try_root().unwrap();
        }
        budget
            .try_consume(QuarantineWorkPortion::Forward, forward.0)
            .unwrap();
        budget
            .try_consume(QuarantineWorkPortion::Rollback, rollback.0)
            .unwrap();
    }

    #[test]
    fn unsupported_capture_or_batch_shape_is_rejected() {
        assert_eq!(
            MutationWork::try_from_counts(
                1,
                1,
                CaptureLimits {
                    max_files: MAX_MUTATION_TREE_FILES + 1,
                    ..CaptureLimits::default()
                },
            ),
            Err(MutationCleanupError::InvalidReservation)
        );
        assert_eq!(
            MutationWork::try_from_counts(1, 2, CaptureLimits::default()),
            Err(MutationCleanupError::InvalidReservation)
        );
        assert!(
            production_reservation(
                MAX_MUTATION_ROOTS + 1,
                MutationWork::try_from_counts(0, 0, CaptureLimits::default()).unwrap(),
                MutationWork::try_from_counts(0, 0, CaptureLimits::default()).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn forward_and_rollback_capacity_are_isolated() {
        let work = MutationWork::try_from_counts(2, 1, CaptureLimits::default()).unwrap();
        let reservation = production_reservation(1, work, work).unwrap();
        let budget = LockedMutationBudget {
            budget: QuarantineCleanupBudget::new(reservation),
            forward: work,
            rollback: work,
        };
        budget.begin_forward().unwrap();

        let rollback_budget = LockedMutationBudget {
            budget: QuarantineCleanupBudget::new(reservation),
            forward: work,
            rollback: work,
        };
        rollback_budget.begin_rollback().unwrap();
    }

    #[test]
    fn retained_capacity_accepts_exact_bound_and_rejects_plus_one() {
        let next = MutationWork::try_from_counts(10, 1, CaptureLimits::default()).unwrap();
        let limit = persistent_retained_limit();
        let exact = TombstoneWork::new(
            limit.top_level_entries() - next.0.top_level_entries() * 2,
            limit.descendant_visits() - next.0.descendant_visits() * 2,
            limit.max_depth(),
        );
        require_retained_capacity(exact, next, next).unwrap();

        assert_eq!(
            require_retained_capacity(
                TombstoneWork::new(
                    exact.top_level_entries() + 1,
                    exact.descendant_visits(),
                    exact.max_depth(),
                ),
                next,
                next,
            ),
            Err(MutationCleanupError::InvalidReservation)
        );
    }

    #[test]
    fn selected_recovery_work_is_rechecked_against_current_retained_capacity() {
        let selected = MutationWork::try_from_counts(8, 0, CaptureLimits::default()).unwrap();
        let limit = persistent_retained_limit();
        let exact = TombstoneWork::new(
            limit.top_level_entries() - selected.0.top_level_entries(),
            limit.descendant_visits(),
            limit.max_depth(),
        );
        require_retained_capacity(exact, selected, MutationWork::none()).unwrap();

        assert_eq!(
            require_retained_capacity(
                TombstoneWork::new(
                    exact.top_level_entries() + 1,
                    exact.descendant_visits(),
                    exact.max_depth(),
                ),
                selected,
                MutationWork::none(),
            ),
            Err(MutationCleanupError::InvalidReservation)
        );
    }

    #[cfg(unix)]
    #[test]
    fn maximum_capture_depth_is_reclaimed_through_the_batch_wrapper() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        use crate::filesystem_identity::MetadataIdentity;
        use crate::quarantine_name::{RemovalTombstoneName, RemovedObjectKind};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _lock = store.try_lock_environment().unwrap();
        let source = root.join("maximum-tree");
        fs::create_dir(&source).unwrap();
        let mut parent = source.clone();
        for _ in 0..MAX_CAPTURE_DEPTH {
            parent = parent.join("d");
            fs::create_dir(&parent).unwrap();
        }
        fs::write(parent.join("leaf"), b"authority").unwrap();
        let identity = MetadataIdentity::from_metadata(&fs::metadata(&source).unwrap());
        let control = root.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity,
        }
        .encode("00112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(source, quarantine.join(name)).unwrap();
        let no_work = MutationWork::try_from_counts(0, 0, CaptureLimits::default()).unwrap();

        cleanup_locked_stores(&[&store], no_work, no_work)
            .unwrap()
            .begin_forward()
            .unwrap();

        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
    }
}
