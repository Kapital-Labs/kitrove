use kitrove_agent_skills::CaptureLimits;

use crate::quarantine_cleanup::coordinator::MutationWork;
use crate::{guarded_control, guarded_journal};

use super::{ExecutableTrustTransactionError, cleanup_error};

const GUARDED_STATE_INSTALL_TOMBSTONES: usize = guarded_control::RECONCILE_TOMBSTONES;
const GUARDED_JOURNAL_TRANSITION_TOMBSTONES: usize = guarded_journal::RECONCILE_TOMBSTONES;
const TRANSACTION_FILE_CLEANUP_TOMBSTONES: usize = 3;
const RECOVERY_RECONCILIATION_TOMBSTONES: usize = guarded_control::RECONCILE_TOMBSTONES;
const RECOVERY_TOMBSTONES: usize =
    RECOVERY_RECONCILIATION_TOMBSTONES + TRANSACTION_FILE_CLEANUP_TOMBSTONES;
const COMMIT_TOMBSTONES: usize = GUARDED_STATE_INSTALL_TOMBSTONES
    + GUARDED_JOURNAL_TRANSITION_TOMBSTONES
    + TRANSACTION_FILE_CLEANUP_TOMBSTONES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TrustRecoveryDirection {
    Completed,
    Aborted,
}

pub(super) struct TrustMutationInventory;

impl TrustMutationInventory {
    pub(super) fn commit_work(
        limits: CaptureLimits,
    ) -> Result<(MutationWork, MutationWork), ExecutableTrustTransactionError> {
        Ok((
            work(COMMIT_TOMBSTONES, limits)?,
            work(RECOVERY_TOMBSTONES, limits)?,
        ))
    }

    pub(super) fn recovery_work(
        direction: TrustRecoveryDirection,
        limits: CaptureLimits,
    ) -> Result<(MutationWork, MutationWork), ExecutableTrustTransactionError> {
        let selected = work(RECOVERY_TOMBSTONES, limits)?;
        Ok(match direction {
            TrustRecoveryDirection::Completed => (selected, MutationWork::none()),
            TrustRecoveryDirection::Aborted => (MutationWork::none(), selected),
        })
    }
}

fn work(
    tombstones: usize,
    limits: CaptureLimits,
) -> Result<MutationWork, ExecutableTrustTransactionError> {
    MutationWork::try_from_counts(tombstones, 0, limits).map_err(cleanup_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_accepts_exact_commit_and_recovery_work() {
        assert_eq!(COMMIT_TOMBSTONES, 5);
        assert_eq!(TRANSACTION_FILE_CLEANUP_TOMBSTONES, 3);
        assert_eq!(RECOVERY_TOMBSTONES, 4);
        assert!(TrustMutationInventory::commit_work(CaptureLimits::default()).is_ok());
        for direction in [
            TrustRecoveryDirection::Completed,
            TrustRecoveryDirection::Aborted,
        ] {
            assert!(
                TrustMutationInventory::recovery_work(direction, CaptureLimits::default()).is_ok()
            );
        }
    }
}
