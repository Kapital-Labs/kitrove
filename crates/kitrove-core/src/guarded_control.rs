use kitrove_model::{ContentHash, PortablePath};

use crate::object_mutation::{ObjectMutationError, ObjectStore, guarded_backup_path};

/// Maximum removal tombstones emitted while reconciling one guarded control replacement.
pub(crate) const RECONCILE_TOMBSTONES: usize = 1;

pub(crate) enum GuardedControlError<E> {
    Storage(ObjectMutationError),
    Authority(E),
}

fn storage<E>(error: ObjectMutationError) -> GuardedControlError<E> {
    GuardedControlError::Storage(error)
}

#[derive(Debug)]
enum GuardedControlState {
    Stable(Option<String>),
    RestoreBackup(Option<String>),
    RemoveBackup(Option<String>),
    RemoveDuplicateStaging(String),
}

impl GuardedControlState {
    fn into_effective_text(self) -> Option<String> {
        match self {
            Self::Stable(text) | Self::RestoreBackup(text) | Self::RemoveBackup(text) => text,
            Self::RemoveDuplicateStaging(text) => Some(text),
        }
    }
}

#[derive(Clone, Copy)]
struct ExpectedControl<'a> {
    old_hash: Option<&'a ContentHash>,
    new_hash: &'a ContentHash,
    accept_duplicate_new: bool,
}

fn classify(
    backup: Option<String>,
    destination: Option<String>,
    staging: Option<String>,
    expected: ExpectedControl<'_>,
) -> Result<GuardedControlState, ()> {
    let hash = |text: &Option<String>| {
        text.as_deref()
            .map(|text| ContentHash::digest(text.as_bytes()))
    };
    let destination_hash = hash(&destination);
    let staging_hash = hash(&staging);
    if let Some(backup) = backup {
        if expected.old_hash != Some(&ContentHash::digest(backup.as_bytes())) {
            return Err(());
        }
        return match destination_hash.as_ref() {
            None if staging_hash.as_ref() == Some(expected.new_hash) => {
                Ok(GuardedControlState::RestoreBackup(Some(backup)))
            }
            Some(current) if Some(current) == expected.old_hash || current == expected.new_hash => {
                Ok(GuardedControlState::RemoveBackup(destination))
            }
            None | Some(_) => Err(()),
        };
    }
    match (destination_hash.as_ref(), staging_hash.as_ref()) {
        (Some(destination_hash), Some(staging_hash))
            if expected.accept_duplicate_new
                && destination_hash == expected.new_hash
                && staging_hash == expected.new_hash =>
        {
            Ok(GuardedControlState::RemoveDuplicateStaging(
                destination.expect("hashed destination is present"),
            ))
        }
        (Some(destination_hash), None) if destination_hash == expected.new_hash => {
            Ok(GuardedControlState::Stable(destination))
        }
        (Some(destination_hash), Some(staging_hash))
            if destination_hash == expected.new_hash && Some(staging_hash) == expected.old_hash =>
        {
            Ok(GuardedControlState::Stable(destination))
        }
        (Some(destination_hash), Some(staging_hash))
            if Some(destination_hash) == expected.old_hash && staging_hash == expected.new_hash =>
        {
            Ok(GuardedControlState::Stable(destination))
        }
        (None, Some(staging_hash))
            if expected.old_hash.is_none() && staging_hash == expected.new_hash =>
        {
            Ok(GuardedControlState::Stable(None))
        }
        _ => Err(()),
    }
}

fn inspect_state<E>(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    expected: ExpectedControl<'_>,
    max_bytes: usize,
    invalid: impl Fn() -> E,
) -> Result<(PortablePath, GuardedControlState), GuardedControlError<E>> {
    let backup_path = guarded_backup_path(staging_path).map_err(storage)?;
    let backup = store.read_text(&backup_path, max_bytes).map_err(storage)?;
    let destination = store
        .read_text(destination_path, max_bytes)
        .map_err(storage)?;
    let staging = store.read_text(staging_path, max_bytes).map_err(storage)?;
    let state = classify(backup, destination, staging, expected)
        .map_err(|()| GuardedControlError::Authority(invalid()))?;
    Ok((backup_path, state))
}

/// Resolves the control bytes a guarded replacement would retain without mutating files.
pub(crate) fn inspect<E>(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    old_hash: Option<&ContentHash>,
    new_hash: &ContentHash,
    max_bytes: usize,
    invalid: impl Fn() -> E,
) -> Result<Option<String>, GuardedControlError<E>> {
    inspect_state(
        store,
        staging_path,
        destination_path,
        ExpectedControl {
            old_hash,
            new_hash,
            accept_duplicate_new: false,
        },
        max_bytes,
        invalid,
    )
    .map(|(_, state)| state.into_effective_text())
}

pub(crate) fn inspect_accepting_duplicate_new<E>(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    old_hash: Option<&ContentHash>,
    new_hash: &ContentHash,
    max_bytes: usize,
    invalid: impl Fn() -> E,
) -> Result<Option<String>, GuardedControlError<E>> {
    inspect_state(
        store,
        staging_path,
        destination_path,
        ExpectedControl {
            old_hash,
            new_hash,
            accept_duplicate_new: true,
        },
        max_bytes,
        invalid,
    )
    .map(|(_, state)| state.into_effective_text())
}

/// Reconciles a previously inspected guarded replacement.
pub(crate) fn reconcile<E>(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    old_hash: Option<&ContentHash>,
    new_hash: &ContentHash,
    max_bytes: usize,
    invalid: impl Fn() -> E,
) -> Result<(), GuardedControlError<E>> {
    reconcile_with_policy(
        store,
        staging_path,
        destination_path,
        ExpectedControl {
            old_hash,
            new_hash,
            accept_duplicate_new: false,
        },
        max_bytes,
        invalid,
    )
}

pub(crate) fn reconcile_accepting_duplicate_new<E>(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    old_hash: Option<&ContentHash>,
    new_hash: &ContentHash,
    max_bytes: usize,
    invalid: impl Fn() -> E,
) -> Result<(), GuardedControlError<E>> {
    reconcile_with_policy(
        store,
        staging_path,
        destination_path,
        ExpectedControl {
            old_hash,
            new_hash,
            accept_duplicate_new: true,
        },
        max_bytes,
        invalid,
    )
}

fn reconcile_with_policy<E>(
    store: &ObjectStore,
    staging_path: &PortablePath,
    destination_path: &PortablePath,
    expected: ExpectedControl<'_>,
    max_bytes: usize,
    invalid: impl Fn() -> E,
) -> Result<(), GuardedControlError<E>> {
    let (backup_path, state) = inspect_state(
        store,
        staging_path,
        destination_path,
        expected,
        max_bytes,
        invalid,
    )?;
    match state {
        GuardedControlState::Stable(_) => Ok(()),
        GuardedControlState::RestoreBackup(_) => store
            .restore_guarded_backup(&backup_path, destination_path, max_bytes)
            .map_err(storage),
        GuardedControlState::RemoveBackup(_) => store
            .remove_regular_file_if_present(&backup_path)
            .map_err(storage),
        GuardedControlState::RemoveDuplicateStaging(_) => store
            .remove_regular_file_if_present(staging_path)
            .map_err(storage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StateKind {
        Stable,
        RestoreBackup,
        RemoveBackup,
        RemoveDuplicateStaging,
    }

    fn kind(state: &GuardedControlState) -> StateKind {
        match state {
            GuardedControlState::Stable(_) => StateKind::Stable,
            GuardedControlState::RestoreBackup(_) => StateKind::RestoreBackup,
            GuardedControlState::RemoveBackup(_) => StateKind::RemoveBackup,
            GuardedControlState::RemoveDuplicateStaging(_) => StateKind::RemoveDuplicateStaging,
        }
    }

    #[test]
    fn classifier_covers_exchange_and_backup_shapes() {
        let old = "old control";
        let new = "new control";
        let invalid = "other control";
        let old_hash = ContentHash::digest(old.as_bytes());
        let new_hash = ContentHash::digest(new.as_bytes());
        let cases = [
            (
                Some(old),
                None,
                Some(new),
                true,
                Some((StateKind::RestoreBackup, Some(old))),
            ),
            (
                Some(old),
                Some(old),
                None,
                true,
                Some((StateKind::RemoveBackup, Some(old))),
            ),
            (
                Some(old),
                Some(new),
                Some(invalid),
                true,
                Some((StateKind::RemoveBackup, Some(new))),
            ),
            (Some(invalid), None, Some(new), true, None),
            (Some(old), None, None, true, None),
            (Some(old), None, Some(old), true, None),
            (
                None,
                Some(new),
                None,
                true,
                Some((StateKind::Stable, Some(new))),
            ),
            (
                None,
                Some(new),
                Some(old),
                true,
                Some((StateKind::Stable, Some(new))),
            ),
            (
                None,
                Some(old),
                Some(new),
                true,
                Some((StateKind::Stable, Some(old))),
            ),
            (
                None,
                None,
                Some(new),
                false,
                Some((StateKind::Stable, None)),
            ),
            (None, None, Some(new), true, None),
            (None, Some(new), Some(new), true, None),
            (None, Some(old), None, true, None),
            (None, Some(invalid), Some(new), true, None),
        ];

        for (backup, destination, staging, has_old, expected) in cases {
            let result = classify(
                backup.map(str::to_owned),
                destination.map(str::to_owned),
                staging.map(str::to_owned),
                ExpectedControl {
                    old_hash: has_old.then_some(&old_hash),
                    new_hash: &new_hash,
                    accept_duplicate_new: false,
                },
            );
            match expected {
                Some((expected_kind, expected_text)) => {
                    let state = result.unwrap();
                    assert_eq!(kind(&state), expected_kind);
                    assert_eq!(state.into_effective_text().as_deref(), expected_text);
                }
                None => assert!(result.is_err()),
            }
        }
    }

    #[test]
    fn duplicate_new_is_an_explicit_policy() {
        let new = "new control";
        let new_hash = ContentHash::digest(new.as_bytes());
        assert!(
            classify(
                None,
                Some(new.to_owned()),
                Some(new.to_owned()),
                ExpectedControl {
                    old_hash: None,
                    new_hash: &new_hash,
                    accept_duplicate_new: false,
                }
            )
            .is_err()
        );
        let state = classify(
            None,
            Some(new.to_owned()),
            Some(new.to_owned()),
            ExpectedControl {
                old_hash: None,
                new_hash: &new_hash,
                accept_duplicate_new: true,
            },
        )
        .unwrap();
        assert_eq!(kind(&state), StateKind::RemoveDuplicateStaging);
        assert_eq!(state.into_effective_text().as_deref(), Some(new));
    }
}
