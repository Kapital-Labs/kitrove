use crate::guarded_control::{self, GuardedControlError};
use crate::object_mutation::guarded_backup_path;
use kitrove_model::{ContentHash, PortablePath};

use super::{
    JOURNAL_PATH, JOURNAL_PENDING_PATH, MAX_JOURNAL_BYTES, ObjectStore, PortableJournal,
    PortableJournalStatus, PortableTransactionError, journal_invalid, parse_valid_journal,
    portable_path, recovery_blocked, store_error, valid_journal_transition,
};

pub(super) fn effective_guarded_control_text(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    old_hash: Option<&ContentHash>,
    new_hash: &ContentHash,
    max_bytes: usize,
) -> Result<Option<String>, PortableTransactionError> {
    guarded_control::inspect(
        store,
        staging_path,
        destination_path,
        old_hash,
        new_hash,
        max_bytes,
        recovery_blocked,
    )
    .map_err(map_guarded_control_error)
}

pub(super) fn reconcile_guarded_control(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    old_hash: Option<&ContentHash>,
    new_hash: &ContentHash,
    max_bytes: usize,
) -> Result<(), PortableTransactionError> {
    guarded_control::reconcile(
        store,
        staging_path,
        destination_path,
        old_hash,
        new_hash,
        max_bytes,
        recovery_blocked,
    )
    .map_err(map_guarded_control_error)
}

fn map_guarded_control_error(
    error: GuardedControlError<PortableTransactionError>,
) -> PortableTransactionError {
    match error {
        GuardedControlError::Storage(error) => store_error(error),
        GuardedControlError::Authority(error) => error,
    }
}

pub(super) fn journal_status_with_store(
    store: &ObjectStore,
) -> Result<PortableJournalStatus, PortableTransactionError> {
    Ok(match portable_journal_control_state(store)? {
        PortableJournalControlState::Absent => PortableJournalStatus::Absent,
        PortableJournalControlState::Live {
            orphan_pending: false,
            ..
        }
        | PortableJournalControlState::RestoreOld(_)
        | PortableJournalControlState::KeepAdvanced(_) => PortableJournalStatus::Pending,
        PortableJournalControlState::OrphanPending
        | PortableJournalControlState::Live {
            orphan_pending: true,
            ..
        }
        | PortableJournalControlState::Invalid => PortableJournalStatus::Invalid,
    })
}

pub(super) enum PortableJournalControlState {
    Absent,
    OrphanPending,
    Live {
        journal: PortableJournal,
        orphan_pending: bool,
    },
    RestoreOld(PortableJournal),
    KeepAdvanced(PortableJournal),
    Invalid,
}

impl PortableJournalControlState {
    pub(super) fn selected_journal(&self) -> Option<&PortableJournal> {
        match self {
            Self::Live { journal, .. }
            | Self::RestoreOld(journal)
            | Self::KeepAdvanced(journal) => Some(journal),
            Self::Absent | Self::OrphanPending | Self::Invalid => None,
        }
    }

    pub(super) const fn requires_reconciliation(&self) -> bool {
        matches!(
            self,
            Self::OrphanPending
                | Self::Live {
                    orphan_pending: true,
                    ..
                }
                | Self::RestoreOld(_)
                | Self::KeepAdvanced(_)
        )
    }
}

pub(super) fn portable_journal_control_state(
    store: &ObjectStore,
) -> Result<PortableJournalControlState, PortableTransactionError> {
    let journal_path = portable_path(JOURNAL_PATH)?;
    let pending_path = portable_path(JOURNAL_PENDING_PATH)?;
    let backup_path = guarded_backup_path(&pending_path).map_err(store_error)?;
    let current = store
        .read_text(&journal_path, MAX_JOURNAL_BYTES)
        .map_err(store_error)?;
    let pending = store
        .read_text(&pending_path, MAX_JOURNAL_BYTES)
        .map_err(store_error)?;
    let backup = store
        .read_text(&backup_path, MAX_JOURNAL_BYTES)
        .map_err(store_error)?;
    Ok(classify_portable_journal_controls(
        current.as_deref(),
        pending.as_deref(),
        backup.as_deref(),
    ))
}

fn classify_portable_journal_controls(
    current: Option<&str>,
    pending: Option<&str>,
    backup: Option<&str>,
) -> PortableJournalControlState {
    let Some(backup) = backup else {
        return match current {
            None if pending.is_none() => PortableJournalControlState::Absent,
            None => PortableJournalControlState::OrphanPending,
            Some(current) => parse_valid_journal(current).map_or(
                PortableJournalControlState::Invalid,
                |journal| PortableJournalControlState::Live {
                    journal,
                    orphan_pending: pending.is_some(),
                },
            ),
        };
    };
    let Some(old) = parse_valid_journal(backup) else {
        return PortableJournalControlState::Invalid;
    };
    match (current, pending) {
        (None, None) => PortableJournalControlState::RestoreOld(old),
        (None, Some(next)) => match parse_valid_journal(next) {
            Some(next) if valid_journal_transition(&old, &next) => {
                PortableJournalControlState::RestoreOld(old)
            }
            Some(_) | None => PortableJournalControlState::Invalid,
        },
        (Some(next), None) => match parse_valid_journal(next) {
            Some(next) if valid_journal_transition(&old, &next) => {
                PortableJournalControlState::KeepAdvanced(next)
            }
            Some(_) | None => PortableJournalControlState::Invalid,
        },
        (Some(_), Some(_)) => PortableJournalControlState::Invalid,
    }
}

pub(super) fn restore_interrupted_journal_control(
    store: &ObjectStore,
) -> Result<(), PortableTransactionError> {
    let journal_path = portable_path(JOURNAL_PATH)?;
    let pending_path = portable_path(JOURNAL_PENDING_PATH)?;
    let backup_path = guarded_backup_path(&pending_path).map_err(store_error)?;
    match portable_journal_control_state(store)? {
        PortableJournalControlState::Absent
        | PortableJournalControlState::Live {
            orphan_pending: false,
            ..
        } => Ok(()),
        PortableJournalControlState::OrphanPending
        | PortableJournalControlState::Live {
            orphan_pending: true,
            ..
        } => store
            .remove_regular_file_if_present(&pending_path)
            .map_err(store_error),
        PortableJournalControlState::RestoreOld(_) => {
            store
                .restore_guarded_backup(&backup_path, &journal_path, MAX_JOURNAL_BYTES)
                .map_err(store_error)?;
            store
                .remove_regular_file_if_present(&pending_path)
                .map_err(store_error)
        }
        PortableJournalControlState::KeepAdvanced(_) => store
            .remove_regular_file_if_present(&backup_path)
            .map_err(store_error),
        PortableJournalControlState::Invalid => Err(journal_invalid()),
    }
}

#[cfg(test)]
mod tests {
    use kitrove_model::{ContentHash, Revision};

    use super::*;
    use crate::portable_transaction::{JournalOperation, JournalPhase, transaction_paths};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StateKind {
        Absent,
        OrphanPending,
        Live,
        LiveWithOrphanPending,
        RestoreOld,
        KeepAdvanced,
        Invalid,
    }

    fn kind(state: PortableJournalControlState) -> StateKind {
        match state {
            PortableJournalControlState::Absent => StateKind::Absent,
            PortableJournalControlState::OrphanPending => StateKind::OrphanPending,
            PortableJournalControlState::Live {
                orphan_pending: false,
                ..
            } => StateKind::Live,
            PortableJournalControlState::Live {
                orphan_pending: true,
                ..
            } => StateKind::LiveWithOrphanPending,
            PortableJournalControlState::RestoreOld(_) => StateKind::RestoreOld,
            PortableJournalControlState::KeepAdvanced(_) => StateKind::KeepAdvanced,
            PortableJournalControlState::Invalid => StateKind::Invalid,
        }
    }

    fn journal(phase: JournalPhase) -> PortableJournal {
        let digest = ContentHash::digest(b"recovery-control-test");
        PortableJournal {
            schema_version: 2,
            operation: JournalOperation::Lock,
            phase,
            plan_digest: digest.clone(),
            old_manifest_revision: Revision::parse(format!("manifest:blake3:{}", "a".repeat(64)))
                .unwrap(),
            new_manifest_revision: Revision::parse(format!("manifest:blake3:{}", "a".repeat(64)))
                .unwrap(),
            old_manifest_hash: ContentHash::digest(b"manifest"),
            new_manifest_hash: ContentHash::digest(b"manifest"),
            staging_manifest: None,
            staging_lock: transaction_paths(&digest).unwrap().lock,
            old_lock_hash: None,
            new_lock_hash: ContentHash::digest(b"lock"),
            portable_root: None,
            portable_hash: None,
            native_root: None,
            native_hash: None,
            portable_preexisting: None,
            native_preexisting: None,
            portable_format: None,
            native_format: None,
            staging_state: None,
            old_state_hash: None,
            new_state_hash: None,
            receipt_id: None,
            reviewed_target_hash: None,
            expected_prior: None,
        }
    }

    fn encode(journal: &PortableJournal) -> String {
        serde_json::to_string(journal).unwrap()
    }

    #[test]
    fn classifier_covers_every_supported_control_shape() {
        let old = encode(&journal(JournalPhase::Prepared));
        let next = encode(&journal(JournalPhase::LockCommitted));
        let invalid = "{}";
        let cases = [
            (None, None, None, StateKind::Absent),
            (None, Some(invalid), None, StateKind::OrphanPending),
            (Some(old.as_str()), None, None, StateKind::Live),
            (
                Some(old.as_str()),
                Some(invalid),
                None,
                StateKind::LiveWithOrphanPending,
            ),
            (Some(invalid), None, None, StateKind::Invalid),
            (None, None, Some(old.as_str()), StateKind::RestoreOld),
            (
                None,
                Some(next.as_str()),
                Some(old.as_str()),
                StateKind::RestoreOld,
            ),
            (
                Some(next.as_str()),
                None,
                Some(old.as_str()),
                StateKind::KeepAdvanced,
            ),
            (None, Some(invalid), Some(old.as_str()), StateKind::Invalid),
            (Some(invalid), None, Some(old.as_str()), StateKind::Invalid),
            (
                Some(old.as_str()),
                Some(next.as_str()),
                Some(old.as_str()),
                StateKind::Invalid,
            ),
            (None, None, Some(invalid), StateKind::Invalid),
        ];

        for (current, pending, backup, expected) in cases {
            assert_eq!(
                kind(classify_portable_journal_controls(current, pending, backup)),
                expected
            );
        }
    }
}
