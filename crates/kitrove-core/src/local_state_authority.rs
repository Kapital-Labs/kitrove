use kitrove_model::PortablePath;

use crate::object_mutation::{ObjectMutationError, ObjectStore};

// Every transaction that can replace state.json uses this lock in the state root.
pub(crate) const CONTROL_DIRECTORY: &str = ".kitrove";
pub(crate) const LOCK_FILE_NAME: &str = "environment.lock";
pub(crate) const TRUST_JOURNAL_PATH: &str = ".kitrove/trust-journal.json";
pub(crate) const TRUST_PENDING_PATH: &str = ".kitrove/trust-journal.pending";
pub(crate) const EXTENSION_APPLY_JOURNAL_PATH: &str = ".kitrove/extension-apply-journal.json";
pub(crate) const INSTRUCTION_APPLY_JOURNAL_PATH: &str = ".kitrove/instruction-apply-journal.json";
pub(crate) const INSTRUCTION_APPLY_PENDING_PATH: &str =
    ".kitrove/instruction-apply-journal.pending";
pub(crate) const SKILL_APPLY_JOURNAL_PATH: &str = ".kitrove/apply-journal.json";
pub(crate) const SKILL_APPLY_PENDING_PATH: &str = ".kitrove/apply-journal.pending";
pub(crate) const ATOMIC_APPLY_JOURNAL_PATH: &str = ".kitrove/atomic-apply-journal.json";
pub(crate) const ATOMIC_APPLY_PENDING_PATH: &str = ".kitrove/atomic-apply-journal.pending";
pub(crate) const ADOPTION_JOURNAL_PATH: &str = ".kitrove/adoption-journal.json";
pub(crate) const ADOPTION_PENDING_PATH: &str = ".kitrove/adoption-journal.pending";
pub(crate) const SYNC_PORTABLE_JOURNAL_PATH: &str = ".kitrove/sync-portable-journal.json";
pub(crate) const SYNC_PORTABLE_PENDING_PATH: &str = ".kitrove/sync-portable-journal.pending";
pub(crate) const OUTER_SYNC_GUARD_PATH: &str = ".kitrove/sync-transaction.guard";

pub(crate) const FOREIGN_TO_TRUST: &[&str] = &[
    EXTENSION_APPLY_JOURNAL_PATH,
    INSTRUCTION_APPLY_JOURNAL_PATH,
    INSTRUCTION_APPLY_PENDING_PATH,
    SKILL_APPLY_JOURNAL_PATH,
    SKILL_APPLY_PENDING_PATH,
    ATOMIC_APPLY_JOURNAL_PATH,
    ATOMIC_APPLY_PENDING_PATH,
];
pub(crate) const ALL_LOCAL_STATE_RECOVERY: &[&str] = &[
    TRUST_JOURNAL_PATH,
    TRUST_PENDING_PATH,
    EXTENSION_APPLY_JOURNAL_PATH,
    INSTRUCTION_APPLY_JOURNAL_PATH,
    INSTRUCTION_APPLY_PENDING_PATH,
    SKILL_APPLY_JOURNAL_PATH,
    SKILL_APPLY_PENDING_PATH,
    ATOMIC_APPLY_JOURNAL_PATH,
    ATOMIC_APPLY_PENDING_PATH,
];
pub(crate) const ALL_PORTABLE_RECOVERY: &[&str] = &[
    ADOPTION_JOURNAL_PATH,
    ADOPTION_PENDING_PATH,
    SYNC_PORTABLE_JOURNAL_PATH,
    SYNC_PORTABLE_PENDING_PATH,
    OUTER_SYNC_GUARD_PATH,
];
pub(crate) const FOREIGN_TO_ADOPTION: &[&str] = &[
    SYNC_PORTABLE_JOURNAL_PATH,
    SYNC_PORTABLE_PENDING_PATH,
    OUTER_SYNC_GUARD_PATH,
];
pub(crate) const FOREIGN_TO_SYNC_PORTABLE: &[&str] = &[
    ADOPTION_JOURNAL_PATH,
    ADOPTION_PENDING_PATH,
    OUTER_SYNC_GUARD_PATH,
];
pub(crate) const ADOPTION_RECOVERY: &[&str] = &[ADOPTION_JOURNAL_PATH, ADOPTION_PENDING_PATH];

pub(crate) const FOREIGN_TO_INSTRUCTION_APPLY: &[&str] = &[
    TRUST_JOURNAL_PATH,
    TRUST_PENDING_PATH,
    EXTENSION_APPLY_JOURNAL_PATH,
    SKILL_APPLY_JOURNAL_PATH,
    SKILL_APPLY_PENDING_PATH,
    ATOMIC_APPLY_JOURNAL_PATH,
    ATOMIC_APPLY_PENDING_PATH,
];

pub(crate) fn any_journal_present(
    store: &ObjectStore,
    paths: &[&str],
    max_bytes: usize,
) -> Result<bool, ObjectMutationError> {
    for path in paths {
        let path = PortablePath::parse(*path).expect("fixed local-state journal path");
        if store.read_text(&path, max_bytes)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}
