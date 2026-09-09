use kitrove_agent_skills::CaptureLimits;

use crate::guarded_journal;
use crate::quarantine_cleanup::coordinator::MutationWork;

use super::{PortableTransactionError, cleanup_error, cleanup_limit, recovery_blocked};

const ADOPTION_OBJECT_STAGING_TOMBSTONES: usize = 2;
const CONTROL_STAGING_TOMBSTONES_PER_PATH: usize = 1;
const GUARDED_INSTALL_TOMBSTONES_PER_CONTROL: usize = 1;
const PORTABLE_AUTHORITY_CONTROL_COUNT: usize = 2;
const LOCK_CONTROL_COUNT: usize = 1;
const AUTHORITY_CONTROL_STAGING_TOMBSTONES: usize =
    CONTROL_STAGING_TOMBSTONES_PER_PATH * PORTABLE_AUTHORITY_CONTROL_COUNT;
const PORTABLE_CONTROL_INSTALLS: usize =
    GUARDED_INSTALL_TOMBSTONES_PER_CONTROL * PORTABLE_AUTHORITY_CONTROL_COUNT;
const ADOPTION_JOURNAL_TRANSITIONS: usize = 5;
const MANIFEST_JOURNAL_TRANSITIONS: usize = 4;
const LOCK_JOURNAL_TRANSITIONS: usize = 3;
const UPDATE_JOURNAL_TRANSITIONS_WITHOUT_STATE: usize = 5;
const UPDATE_JOURNAL_TRANSITIONS_WITH_STATE: usize = 6;
const OBJECT_TOMBSTONES_PER_ROLLBACK_OBJECT: usize = 2;
const MANIFEST_PREPARATION_DIRECTORY_CLEANUP: usize = 2;
const ADOPTION_SUCCESS_CLEANUP_ARTIFACTS: usize = 3;
const MANIFEST_SUCCESS_CLEANUP_ARTIFACTS: usize = 8;
const LOCK_SUCCESS_CLEANUP_ARTIFACTS: usize = 3;
const UPDATE_ENVIRONMENT_SUCCESS_CLEANUP_ARTIFACTS: usize = 8;
const UPDATE_STATE_SUCCESS_CLEANUP_ARTIFACTS: usize = 4;
const JOURNAL_CONTROL_RECOVERY_TOMBSTONES: usize = 1;
const AUTHORITY_CONTROL_RECOVERY_TOMBSTONES: usize = 2;
const RECOVERY_LOCK_INSTALL_TOMBSTONES: usize = 1;
const COMPLETED_PORTABLE_RECOVERY_CLEANUP: usize = 8;
const ABANDONED_PORTABLE_RECOVERY_CLEANUP: usize = 8;
const LOCK_RECOVERY_CONTROL_TOMBSTONES: usize = 1;
const LOCK_RECOVERY_CLEANUP: usize = 6;
const UPDATE_STATE_RECOVERY_TOMBSTONES: usize = 1;
const UPDATE_STATE_STAGING_TOMBSTONES: usize = 1;
pub(super) const ORPHAN_PENDING_CLEANUP_TOMBSTONES: usize = 1;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum PortableRecoveryDirection {
    Forward,
    Rollback,
}

#[derive(Clone, Copy)]
pub(super) enum PortableMutationKind {
    Adoption,
    Manifest { rollback_objects: usize },
    Lock,
    Update { local_state: bool },
}

#[derive(Clone, Copy, Default)]
struct PortableTombstoneInventory {
    journal: usize,
    authority_controls: usize,
    objects: usize,
    guarded_installs: usize,
    cleanup: usize,
}

impl PortableTombstoneInventory {
    fn total(self) -> Result<usize, PortableTransactionError> {
        checked_portable_tombstones(&[
            self.journal,
            self.authority_controls,
            self.objects,
            self.guarded_installs,
            self.cleanup,
        ])
    }
}

impl PortableMutationKind {
    pub(super) fn commit_work(
        self,
        limits: CaptureLimits,
    ) -> Result<(MutationWork, MutationWork), PortableTransactionError> {
        let (forward, forward_trees, rollback, rollback_trees) = self.commit_inventory()?;
        Ok((
            MutationWork::try_from_counts(forward.total()?, forward_trees, limits)
                .map_err(cleanup_error)?,
            MutationWork::try_from_counts(rollback.total()?, rollback_trees, limits)
                .map_err(cleanup_error)?,
        ))
    }

    pub(super) fn recovery_work(
        self,
        direction: PortableRecoveryDirection,
        limits: CaptureLimits,
    ) -> Result<(MutationWork, MutationWork), PortableTransactionError> {
        let (inventory, trees) = self.recovery_inventory(direction)?;
        let work = MutationWork::try_from_counts(inventory.total()?, trees, limits)
            .map_err(cleanup_error)?;
        Ok(match direction {
            PortableRecoveryDirection::Forward => (work, MutationWork::none()),
            PortableRecoveryDirection::Rollback => (MutationWork::none(), work),
        })
    }

    fn commit_inventory(
        self,
    ) -> Result<
        (
            PortableTombstoneInventory,
            usize,
            PortableTombstoneInventory,
            usize,
        ),
        PortableTransactionError,
    > {
        Ok(match self {
            Self::Adoption => {
                let forward = PortableTombstoneInventory {
                    journal: checked_journal_tombstones(ADOPTION_JOURNAL_TRANSITIONS)?,
                    authority_controls: AUTHORITY_CONTROL_STAGING_TOMBSTONES,
                    objects: ADOPTION_OBJECT_STAGING_TOMBSTONES,
                    guarded_installs: PORTABLE_CONTROL_INSTALLS,
                    cleanup: ADOPTION_SUCCESS_CLEANUP_ARTIFACTS,
                };
                let rollback = abandoned_adoption_inventory();
                (
                    forward,
                    ADOPTION_OBJECT_STAGING_TOMBSTONES,
                    rollback,
                    ADOPTION_OBJECT_STAGING_TOMBSTONES,
                )
            }
            Self::Manifest { rollback_objects } => {
                let object_tombstones = rollback_objects
                    .checked_mul(OBJECT_TOMBSTONES_PER_ROLLBACK_OBJECT)
                    .ok_or_else(cleanup_limit)?;
                let forward = PortableTombstoneInventory {
                    journal: checked_journal_tombstones(MANIFEST_JOURNAL_TRANSITIONS)?,
                    authority_controls: AUTHORITY_CONTROL_STAGING_TOMBSTONES,
                    objects: object_tombstones,
                    guarded_installs: PORTABLE_CONTROL_INSTALLS,
                    cleanup: MANIFEST_PREPARATION_DIRECTORY_CLEANUP
                        .checked_add(MANIFEST_SUCCESS_CLEANUP_ARTIFACTS)
                        .ok_or_else(cleanup_limit)?,
                };
                (
                    forward,
                    object_tombstones,
                    abandoned_manifest_inventory(),
                    0,
                )
            }
            Self::Lock => {
                let forward = PortableTombstoneInventory {
                    journal: checked_journal_tombstones(LOCK_JOURNAL_TRANSITIONS)?,
                    authority_controls: CONTROL_STAGING_TOMBSTONES_PER_PATH * LOCK_CONTROL_COUNT,
                    guarded_installs: GUARDED_INSTALL_TOMBSTONES_PER_CONTROL * LOCK_CONTROL_COUNT,
                    cleanup: LOCK_SUCCESS_CLEANUP_ARTIFACTS,
                    ..PortableTombstoneInventory::default()
                };
                (forward, 0, PortableTombstoneInventory::default(), 0)
            }
            Self::Update { local_state } => {
                let journal_transitions = if local_state {
                    UPDATE_JOURNAL_TRANSITIONS_WITH_STATE
                } else {
                    UPDATE_JOURNAL_TRANSITIONS_WITHOUT_STATE
                };
                let state_staging = usize::from(local_state) * UPDATE_STATE_STAGING_TOMBSTONES;
                let state_install =
                    usize::from(local_state) * GUARDED_INSTALL_TOMBSTONES_PER_CONTROL;
                let state_cleanup =
                    usize::from(local_state) * UPDATE_STATE_SUCCESS_CLEANUP_ARTIFACTS;
                let forward = PortableTombstoneInventory {
                    journal: checked_journal_tombstones(journal_transitions)?,
                    authority_controls: AUTHORITY_CONTROL_STAGING_TOMBSTONES + state_staging,
                    objects: ADOPTION_OBJECT_STAGING_TOMBSTONES,
                    guarded_installs: PORTABLE_CONTROL_INSTALLS + state_install,
                    cleanup: UPDATE_ENVIRONMENT_SUCCESS_CLEANUP_ARTIFACTS + state_cleanup,
                };
                let rollback = update_rollback_inventory(local_state);
                (
                    forward,
                    ADOPTION_OBJECT_STAGING_TOMBSTONES,
                    rollback,
                    ADOPTION_OBJECT_STAGING_TOMBSTONES,
                )
            }
        })
    }

    fn recovery_inventory(
        self,
        direction: PortableRecoveryDirection,
    ) -> Result<(PortableTombstoneInventory, usize), PortableTransactionError> {
        Ok(match (self, direction) {
            (Self::Update { local_state }, PortableRecoveryDirection::Forward) => {
                let state_reconciliation =
                    usize::from(local_state) * UPDATE_STATE_RECOVERY_TOMBSTONES;
                let state_install =
                    usize::from(local_state) * GUARDED_INSTALL_TOMBSTONES_PER_CONTROL;
                let state_cleanup =
                    usize::from(local_state) * UPDATE_STATE_SUCCESS_CLEANUP_ARTIFACTS;
                (
                    PortableTombstoneInventory {
                        journal: JOURNAL_CONTROL_RECOVERY_TOMBSTONES,
                        authority_controls: AUTHORITY_CONTROL_RECOVERY_TOMBSTONES
                            + state_reconciliation,
                        guarded_installs: RECOVERY_LOCK_INSTALL_TOMBSTONES + state_install,
                        cleanup: UPDATE_ENVIRONMENT_SUCCESS_CLEANUP_ARTIFACTS + state_cleanup,
                        ..PortableTombstoneInventory::default()
                    },
                    0,
                )
            }
            (Self::Update { local_state }, PortableRecoveryDirection::Rollback) => (
                update_rollback_inventory(local_state),
                ADOPTION_OBJECT_STAGING_TOMBSTONES,
            ),
            (Self::Lock, PortableRecoveryDirection::Forward) => (
                PortableTombstoneInventory {
                    journal: JOURNAL_CONTROL_RECOVERY_TOMBSTONES,
                    authority_controls: LOCK_RECOVERY_CONTROL_TOMBSTONES,
                    guarded_installs: RECOVERY_LOCK_INSTALL_TOMBSTONES,
                    cleanup: LOCK_RECOVERY_CLEANUP,
                    ..PortableTombstoneInventory::default()
                },
                0,
            ),
            (_, PortableRecoveryDirection::Forward) => (
                PortableTombstoneInventory {
                    journal: JOURNAL_CONTROL_RECOVERY_TOMBSTONES,
                    authority_controls: AUTHORITY_CONTROL_RECOVERY_TOMBSTONES,
                    guarded_installs: RECOVERY_LOCK_INSTALL_TOMBSTONES,
                    cleanup: COMPLETED_PORTABLE_RECOVERY_CLEANUP,
                    ..PortableTombstoneInventory::default()
                },
                0,
            ),
            (Self::Adoption, PortableRecoveryDirection::Rollback) => (
                abandoned_adoption_inventory(),
                ADOPTION_OBJECT_STAGING_TOMBSTONES,
            ),
            (Self::Manifest { .. }, PortableRecoveryDirection::Rollback) => {
                (abandoned_manifest_inventory(), 0)
            }
            (Self::Lock, PortableRecoveryDirection::Rollback) => return Err(recovery_blocked()),
        })
    }
}

fn abandoned_adoption_inventory() -> PortableTombstoneInventory {
    PortableTombstoneInventory {
        journal: JOURNAL_CONTROL_RECOVERY_TOMBSTONES,
        authority_controls: AUTHORITY_CONTROL_RECOVERY_TOMBSTONES,
        objects: ADOPTION_OBJECT_STAGING_TOMBSTONES,
        cleanup: ABANDONED_PORTABLE_RECOVERY_CLEANUP,
        ..PortableTombstoneInventory::default()
    }
}

fn abandoned_manifest_inventory() -> PortableTombstoneInventory {
    PortableTombstoneInventory {
        journal: JOURNAL_CONTROL_RECOVERY_TOMBSTONES,
        authority_controls: AUTHORITY_CONTROL_RECOVERY_TOMBSTONES,
        cleanup: ABANDONED_PORTABLE_RECOVERY_CLEANUP,
        ..PortableTombstoneInventory::default()
    }
}

fn update_rollback_inventory(local_state: bool) -> PortableTombstoneInventory {
    let state_cleanup = usize::from(local_state) * UPDATE_STATE_SUCCESS_CLEANUP_ARTIFACTS;
    PortableTombstoneInventory {
        journal: JOURNAL_CONTROL_RECOVERY_TOMBSTONES,
        authority_controls: AUTHORITY_CONTROL_RECOVERY_TOMBSTONES
            + usize::from(local_state) * UPDATE_STATE_RECOVERY_TOMBSTONES,
        objects: ADOPTION_OBJECT_STAGING_TOMBSTONES,
        cleanup: ABANDONED_PORTABLE_RECOVERY_CLEANUP + state_cleanup,
        ..PortableTombstoneInventory::default()
    }
}

fn checked_journal_tombstones(transitions: usize) -> Result<usize, PortableTransactionError> {
    transitions
        .checked_mul(guarded_journal::RECONCILE_TOMBSTONES)
        .ok_or_else(cleanup_limit)
}

fn checked_portable_tombstones(parts: &[usize]) -> Result<usize, PortableTransactionError> {
    parts.iter().try_fold(0usize, |total, part| {
        total.checked_add(*part).ok_or_else(cleanup_limit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totals(kind: PortableMutationKind) -> (usize, usize, usize, usize, usize, usize) {
        let (forward, forward_trees, rollback, rollback_trees) = kind.commit_inventory().unwrap();
        let (recovery_forward, _) = kind
            .recovery_inventory(PortableRecoveryDirection::Forward)
            .unwrap();
        let recovery_rollback = kind
            .recovery_inventory(PortableRecoveryDirection::Rollback)
            .ok()
            .map_or(0, |(inventory, _)| inventory.total().unwrap());
        (
            forward.total().unwrap(),
            forward_trees,
            rollback.total().unwrap(),
            rollback_trees,
            recovery_forward.total().unwrap(),
            recovery_rollback,
        )
    }

    #[test]
    fn operation_inventories_bind_exact_commit_and_recovery_totals() {
        assert_eq!(
            totals(PortableMutationKind::Adoption),
            (14, 2, 13, 2, 12, 13)
        );
        assert_eq!(
            totals(PortableMutationKind::Manifest {
                rollback_objects: 0,
            }),
            (18, 0, 11, 0, 12, 11)
        );
        assert_eq!(totals(PortableMutationKind::Lock), (8, 0, 0, 0, 9, 0));
        assert_eq!(
            totals(PortableMutationKind::Update { local_state: false }),
            (19, 2, 13, 2, 12, 13)
        );
        assert_eq!(
            totals(PortableMutationKind::Update { local_state: true }),
            (26, 2, 18, 2, 18, 18)
        );
        assert_eq!(ORPHAN_PENDING_CLEANUP_TOMBSTONES, 1);
    }

    #[test]
    fn maximum_manifest_object_inventory_is_checked_and_supported() {
        let kind = PortableMutationKind::Manifest {
            rollback_objects: 4096,
        };
        assert_eq!(totals(kind), (8210, 8192, 11, 0, 12, 11));
        assert!(kind.commit_work(CaptureLimits::default()).is_ok());
        assert_eq!(
            PortableMutationKind::Manifest {
                rollback_objects: usize::MAX,
            }
            .commit_work(CaptureLimits::default())
            .unwrap_err()
            .code(),
            "transaction.cleanup_limit"
        );
    }
}
