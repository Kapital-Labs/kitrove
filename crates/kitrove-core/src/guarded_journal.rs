use kitrove_model::PortablePath;

use crate::object_mutation::{ObjectMutationError, ObjectStore, guarded_backup_path};

/// Maximum removal tombstones emitted while reconciling one guarded journal transition.
pub(crate) const RECONCILE_TOMBSTONES: usize = 1;

pub(crate) enum GuardedJournalError<E> {
    Storage,
    Authority(E),
}

/// Exact journal branch observed before cleanup and required again before mutation.
pub(crate) enum JournalExpectation<T> {
    Absent,
    Present(T),
}

impl<T> JournalExpectation<T> {
    pub(crate) fn from_option(value: Option<T>) -> Self {
        value.map_or(Self::Absent, Self::Present)
    }

    pub(crate) const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

impl<T: PartialEq> JournalExpectation<T> {
    pub(crate) fn matches(&self, actual: Option<&T>) -> bool {
        match (self, actual) {
            (Self::Absent, None) => true,
            (Self::Present(expected), Some(actual)) => expected == actual,
            (Self::Absent, Some(_)) | (Self::Present(_), None) => false,
        }
    }
}

fn storage<E>(_: ObjectMutationError) -> GuardedJournalError<E> {
    GuardedJournalError::Storage
}

struct GuardedJournalTexts {
    current: Option<String>,
    pending: Option<String>,
    backup: Option<String>,
}

/// Resolves the journal that guarded reconciliation would retain without mutating control files.
pub(crate) fn inspect<T, E>(
    store: &ObjectStore,
    live_path: &PortablePath,
    pending_path: &PortablePath,
    max_bytes: usize,
    parse: impl Fn(&str) -> Result<T, E>,
    valid_transition: impl Fn(&T, &T) -> bool,
    invalid: impl Fn() -> E,
) -> Result<Option<T>, GuardedJournalError<E>> {
    let texts = read_texts(store, live_path, pending_path, max_bytes)?;
    if let Some(backup) = texts.backup.as_deref() {
        let old = parse(backup).map_err(GuardedJournalError::Authority)?;
        return match (texts.current.as_deref(), texts.pending.as_deref()) {
            (None, next) => {
                if let Some(next) = next {
                    let next = parse(next).map_err(GuardedJournalError::Authority)?;
                    require_transition(&old, &next, &valid_transition, &invalid)?;
                }
                Ok(Some(old))
            }
            (Some(next), None) => {
                let next = parse(next).map_err(GuardedJournalError::Authority)?;
                require_transition(&old, &next, &valid_transition, &invalid)?;
                Ok(Some(next))
            }
            (Some(_), Some(_)) => Err(GuardedJournalError::Authority(invalid())),
        };
    }

    match (texts.current.as_deref(), texts.pending.as_deref()) {
        (None, Some(next)) => parse(next)
            .map(Some)
            .map_err(GuardedJournalError::Authority),
        (Some(old), Some(next)) => {
            let old = parse(old).map_err(GuardedJournalError::Authority)?;
            let next = parse(next).map_err(GuardedJournalError::Authority)?;
            if valid_transition(&old, &next) {
                Ok(Some(next))
            } else if valid_transition(&next, &old) {
                Ok(Some(old))
            } else {
                Err(GuardedJournalError::Authority(invalid()))
            }
        }
        (Some(current), None) => parse(current)
            .map(Some)
            .map_err(GuardedJournalError::Authority),
        (None, None) => Ok(None),
    }
}

/// Reconciles one guarded live/pending journal pair after any durable replacement boundary.
pub(crate) fn reconcile<T, E>(
    store: &ObjectStore,
    live_path: &PortablePath,
    pending_path: &PortablePath,
    max_bytes: usize,
    parse: impl Fn(&str) -> Result<T, E>,
    valid_transition: impl Fn(&T, &T) -> bool,
    invalid: impl Fn() -> E,
) -> Result<(), GuardedJournalError<E>> {
    let texts = read_texts(store, live_path, pending_path, max_bytes)?;
    let backup_path = guarded_backup_path(pending_path).map_err(storage)?;

    if let Some(backup) = texts.backup {
        let old = parse(&backup).map_err(GuardedJournalError::Authority)?;
        return match (texts.current.as_deref(), texts.pending.as_deref()) {
            (None, next) => {
                if let Some(next) = next {
                    let next = parse(next).map_err(GuardedJournalError::Authority)?;
                    if !valid_transition(&old, &next) {
                        return Err(GuardedJournalError::Authority(invalid()));
                    }
                }
                store
                    .restore_guarded_backup(&backup_path, live_path, max_bytes)
                    .map_err(storage)?;
                store
                    .remove_regular_file_if_present(pending_path)
                    .map_err(storage)
            }
            (Some(next), None) => {
                let next = parse(next).map_err(GuardedJournalError::Authority)?;
                if !valid_transition(&old, &next) {
                    return Err(GuardedJournalError::Authority(invalid()));
                }
                store
                    .remove_regular_file_if_present(&backup_path)
                    .map_err(storage)
            }
            (Some(_), Some(_)) => Err(GuardedJournalError::Authority(invalid())),
        };
    }

    match (texts.current.as_deref(), texts.pending.as_deref()) {
        (None, Some(next)) => {
            parse(next).map_err(GuardedJournalError::Authority)?;
            store
                .install_staged_text_guarded(pending_path, live_path, None, next, max_bytes)
                .map_err(storage)
        }
        (Some(old), Some(next)) => {
            let old_journal = parse(old).map_err(GuardedJournalError::Authority)?;
            let next_journal = parse(next).map_err(GuardedJournalError::Authority)?;
            if valid_transition(&old_journal, &next_journal) {
                return store
                    .install_staged_text_guarded(
                        pending_path,
                        live_path,
                        Some(old),
                        next,
                        max_bytes,
                    )
                    .map_err(storage);
            }
            if valid_transition(&next_journal, &old_journal) {
                return store
                    .remove_regular_file_if_present(pending_path)
                    .map_err(storage);
            }
            Err(GuardedJournalError::Authority(invalid()))
        }
        (Some(current), None) => parse(current)
            .map(|_| ())
            .map_err(GuardedJournalError::Authority),
        (None, None) => Ok(()),
    }
}

fn read_texts<E>(
    store: &ObjectStore,
    live_path: &PortablePath,
    pending_path: &PortablePath,
    max_bytes: usize,
) -> Result<GuardedJournalTexts, GuardedJournalError<E>> {
    let backup_path = guarded_backup_path(pending_path).map_err(storage)?;
    Ok(GuardedJournalTexts {
        current: store.read_text(live_path, max_bytes).map_err(storage)?,
        pending: store.read_text(pending_path, max_bytes).map_err(storage)?,
        backup: store.read_text(&backup_path, max_bytes).map_err(storage)?,
    })
}

fn require_transition<T, E>(
    old: &T,
    next: &T,
    valid_transition: &impl Fn(&T, &T) -> bool,
    invalid: &impl Fn() -> E,
) -> Result<(), GuardedJournalError<E>> {
    if valid_transition(old, next) {
        Ok(())
    } else {
        Err(GuardedJournalError::Authority(invalid()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> PortablePath {
        PortablePath::parse(value).unwrap()
    }

    fn parse(value: &str) -> Result<u8, ()> {
        value.parse().map_err(|_| ())
    }

    fn advances_by_one(old: &u8, next: &u8) -> bool {
        old.checked_add(1).as_ref() == Some(next)
    }

    #[test]
    fn inspection_selects_a_valid_pending_transition_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().canonicalize().unwrap().join("state");
        let store = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let live = path(".kitrove/test-journal.json");
        let pending = path(".kitrove/test-journal.pending");
        store.stage_private_text(&live, "1", 16).unwrap();
        store.stage_private_text(&pending, "2", 16).unwrap();

        let Ok(Some(selected)) =
            inspect(&store, &live, &pending, 16, parse, advances_by_one, || ())
        else {
            panic!("valid guarded journal pair was not inspectable");
        };

        assert_eq!(selected, 2);
        assert_eq!(store.read_text(&live, 16).unwrap().as_deref(), Some("1"));
        assert_eq!(store.read_text(&pending, 16).unwrap().as_deref(), Some("2"));
    }

    #[test]
    fn inspection_uses_the_backup_as_authority_before_an_incomplete_replacement() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().canonicalize().unwrap().join("state");
        let store = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let live = path(".kitrove/test-journal.json");
        let pending = path(".kitrove/test-journal.pending");
        let backup = guarded_backup_path(&pending).unwrap();
        store.stage_private_text(&backup, "1", 16).unwrap();
        store.stage_private_text(&pending, "2", 16).unwrap();

        let Ok(Some(selected)) =
            inspect(&store, &live, &pending, 16, parse, advances_by_one, || ())
        else {
            panic!("interrupted guarded journal was not inspectable");
        };

        assert_eq!(selected, 1);
    }
}
