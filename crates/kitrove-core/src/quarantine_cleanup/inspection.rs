use std::collections::BTreeMap;
use std::ffi::OsString;

use cap_fs_ext::{
    DirEntryExt as _, DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use kitrove_agent_skills::{BoundedDirectoryEntries, collect_bounded_sorted_directory_entries};

#[cfg(unix)]
use crate::filesystem_identity::MetadataIdentity;
use crate::object_mutation::ObjectStore;
#[cfg(any(unix, windows))]
use crate::quarantine_name::RemovalTombstoneName;
use crate::quarantine_name::RemovedObjectKind;
#[cfg(not(unix))]
use crate::quarantine_name::RetainedTombstoneName;
#[cfg(any(unix, windows))]
use crate::quarantine_name::{CleanupBatchName, CleanupPendingName};
#[cfg(any(unix, windows))]
use crate::read_only_fs::has_single_file_link;
use crate::read_only_fs::{safe_metadata, same_file};

#[cfg(test)]
use super::budget::{CleanupPassWork, QuarantineCleanupLimits, QuarantineCleanupReservation};
use super::budget::{
    QuarantineBudgetError, QuarantineCleanupBudget, QuarantineWorkPortion, TombstoneWork,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QuarantineInspection {
    candidates: Vec<QuarantineCandidate>,
    work: TombstoneWork,
}

impl QuarantineInspection {
    #[cfg(any(unix, windows, test))]
    pub(crate) fn candidates(&self) -> &[QuarantineCandidate] {
        &self.candidates
    }

    pub(crate) const fn work(&self) -> TombstoneWork {
        self.work
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineCandidate {
    File {
        name: OsString,
        content: FileContentState,
        disposition: CleanupDisposition,
    },
    Directory {
        name: OsString,
        work: TombstoneWork,
        disposition: CleanupDisposition,
    },
    #[cfg(any(unix, windows))]
    EmptyPendingBatch { name: OsString },
    #[cfg(any(unix, windows))]
    InterruptedBatch { name: OsString, work: TombstoneWork },
}

impl QuarantineCandidate {
    const fn work(&self) -> TombstoneWork {
        match self {
            Self::File { .. } => TombstoneWork::new(1, 0, 0),
            Self::Directory { work, .. } => {
                TombstoneWork::new(1, work.descendant_visits(), work.max_depth())
            }
            #[cfg(any(unix, windows))]
            Self::EmptyPendingBatch { .. } => TombstoneWork::new(1, 0, 0),
            #[cfg(any(unix, windows))]
            Self::InterruptedBatch { work, .. } => {
                TombstoneWork::new(1, work.descendant_visits(), work.max_depth())
            }
        }
    }

    #[cfg(any(unix, windows))]
    pub(super) const fn is_cleanup_control(&self) -> bool {
        matches!(
            self,
            Self::EmptyPendingBatch { .. } | Self::InterruptedBatch { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileContentState {
    Empty,
    NonEmpty,
}

impl FileContentState {
    const fn from_length(length: u64) -> Self {
        if length == 0 {
            Self::Empty
        } else {
            Self::NonEmpty
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupDisposition {
    #[cfg(any(unix, windows))]
    Eligible,
    #[cfg(not(unix))]
    Retain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineInspectionError {
    Budget(QuarantineBudgetError),
    UnsafeState,
    UnrecognizedState,
}

impl From<QuarantineBudgetError> for QuarantineInspectionError {
    fn from(error: QuarantineBudgetError) -> Self {
        Self::Budget(error)
    }
}

struct PendingDirectory {
    directory: Dir,
    key: Vec<u8>,
    depth: usize,
}

pub(crate) fn inspect_store_quarantine(
    store: &ObjectStore,
    budget: &mut QuarantineCleanupBudget,
) -> Result<QuarantineInspection, QuarantineInspectionError> {
    budget.try_root()?;
    let Some(quarantine) = store
        .open_existing_removal_quarantine()
        .map_err(|_| QuarantineInspectionError::UnsafeState)?
    else {
        return Ok(QuarantineInspection {
            candidates: Vec::new(),
            work: TombstoneWork::default(),
        });
    };
    inspect_quarantine_directory_with_hook(quarantine, budget, &mut |_| {})
}

fn inspect_quarantine_directory_with_hook(
    quarantine: Dir,
    budget: &mut QuarantineCleanupBudget,
    before_open: &mut impl FnMut(&OsString),
) -> Result<QuarantineInspection, QuarantineInspectionError> {
    let portion = QuarantineWorkPortion::CleanupInspection;
    let entries = quarantine
        .entries()
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    let entries = collect_bounded_sorted_directory_entries(
        entries,
        budget.remaining_top_level_entries(portion),
    )
    .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    let BoundedDirectoryEntries::Complete(entries) = entries else {
        return Err(QuarantineInspectionError::Budget(
            QuarantineBudgetError::ReservationExceeded(portion),
        ));
    };
    let mut candidates = Vec::with_capacity(entries.len());
    let mut work = TombstoneWork::default();
    #[cfg(any(unix, windows))]
    let mut has_cleanup_control = false;
    for entry in entries {
        budget.try_top_level_entry(portion)?;
        let name = entry.file_name();
        let metadata = entry
            .full_metadata()
            .map_err(|_| QuarantineInspectionError::UnsafeState)?;
        before_open(&name);
        let candidate = inspect_tombstone(&quarantine, name, metadata, budget)?;
        #[cfg(any(unix, windows))]
        if candidate.is_cleanup_control() {
            if has_cleanup_control {
                return Err(QuarantineInspectionError::UnsafeState);
            }
            has_cleanup_control = true;
        }
        work = work
            .checked_add(candidate.work())
            .ok_or(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ArithmeticOverflow,
            ))?;
        candidates.push(candidate);
    }
    Ok(QuarantineInspection { candidates, work })
}

#[cfg(unix)]
fn inspect_tombstone(
    quarantine: &Dir,
    name: OsString,
    metadata: Metadata,
    budget: &mut QuarantineCleanupBudget,
) -> Result<QuarantineCandidate, QuarantineInspectionError> {
    if CleanupPendingName::parse(&name).is_some() {
        validate_kind(RemovedObjectKind::Directory, &metadata)?;
        let directory = open_verified_directory(quarantine, &name, &metadata)?;
        require_empty_directory(&directory, budget)?;
        return Ok(QuarantineCandidate::EmptyPendingBatch { name });
    }
    if let Some(authority) = CleanupBatchName::parse(&name) {
        validate_kind(RemovedObjectKind::Directory, &metadata)?;
        if MetadataIdentity::from_metadata(&metadata) != authority.identity {
            return Err(QuarantineInspectionError::UnsafeState);
        }
        let directory = open_verified_directory(quarantine, &name, &metadata)?;
        return Ok(QuarantineCandidate::InterruptedBatch {
            name,
            work: inspect_descendants(directory, budget, QuarantineWorkPortion::CleanupInspection)?,
        });
    }
    let authority =
        RemovalTombstoneName::parse(&name).ok_or(QuarantineInspectionError::UnrecognizedState)?;
    validate_kind(authority.kind, &metadata)?;
    if MetadataIdentity::from_metadata(&metadata) != authority.identity {
        return Err(QuarantineInspectionError::UnsafeState);
    }
    match authority.kind {
        RemovedObjectKind::File => {
            let opened = open_verified_file(quarantine, &name, &metadata)?;
            require_single_link(&opened)?;
            Ok(QuarantineCandidate::File {
                name,
                content: FileContentState::from_length(opened.len()),
                disposition: CleanupDisposition::Eligible,
            })
        }
        RemovedObjectKind::Directory => {
            let directory = open_verified_directory(quarantine, &name, &metadata)?;
            Ok(QuarantineCandidate::Directory {
                name,
                work: inspect_descendants(
                    directory,
                    budget,
                    QuarantineWorkPortion::CleanupInspection,
                )?,
                disposition: CleanupDisposition::Eligible,
            })
        }
    }
}

#[cfg(windows)]
fn inspect_tombstone(
    quarantine: &Dir,
    name: OsString,
    metadata: Metadata,
    budget: &mut QuarantineCleanupBudget,
) -> Result<QuarantineCandidate, QuarantineInspectionError> {
    if CleanupPendingName::parse(&name).is_some() {
        validate_kind(RemovedObjectKind::Directory, &metadata)?;
        let directory = open_verified_directory(quarantine, &name, &metadata)?;
        kitrove_windows_security::inspect_private_directory(&directory)
            .map_err(|_| QuarantineInspectionError::UnsafeState)?;
        require_empty_directory(&directory, budget)?;
        return Ok(QuarantineCandidate::EmptyPendingBatch { name });
    }
    if let Some(authority) = CleanupBatchName::parse(&name) {
        validate_kind(RemovedObjectKind::Directory, &metadata)?;
        let directory = open_verified_directory(quarantine, &name, &metadata)?;
        kitrove_windows_security::inspect_private_directory(&directory)
            .map_err(|_| QuarantineInspectionError::UnsafeState)?;
        if kitrove_windows_security::file_identity(&directory)
            .map_err(|_| QuarantineInspectionError::UnsafeState)?
            != authority.identity
        {
            return Err(QuarantineInspectionError::UnsafeState);
        }
        return Ok(QuarantineCandidate::InterruptedBatch {
            name,
            work: inspect_descendants(directory, budget, QuarantineWorkPortion::CleanupInspection)?,
        });
    }
    let Some(authority) = RemovalTombstoneName::parse(&name) else {
        return inspect_retained_tombstone(quarantine, name, metadata, budget);
    };
    validate_kind(authority.kind, &metadata)?;
    match authority.kind {
        RemovedObjectKind::File => {
            let (file, opened) = open_verified_file_capability(quarantine, &name, &metadata)?;
            kitrove_windows_security::inspect_owned_file(&file)
                .map_err(|_| QuarantineInspectionError::UnsafeState)?;
            if kitrove_windows_security::file_identity(&file)
                .map_err(|_| QuarantineInspectionError::UnsafeState)?
                != authority.identity
            {
                return Err(QuarantineInspectionError::UnsafeState);
            }
            require_single_link(&opened)?;
            Ok(QuarantineCandidate::File {
                name,
                content: FileContentState::from_length(opened.len()),
                disposition: CleanupDisposition::Eligible,
            })
        }
        RemovedObjectKind::Directory => {
            let directory = open_verified_directory(quarantine, &name, &metadata)?;
            kitrove_windows_security::inspect_owned_directory(&directory)
                .map_err(|_| QuarantineInspectionError::UnsafeState)?;
            if kitrove_windows_security::file_identity(&directory)
                .map_err(|_| QuarantineInspectionError::UnsafeState)?
                != authority.identity
            {
                return Err(QuarantineInspectionError::UnsafeState);
            }
            Ok(QuarantineCandidate::Directory {
                name,
                work: inspect_descendants(
                    directory,
                    budget,
                    QuarantineWorkPortion::CleanupInspection,
                )?,
                disposition: CleanupDisposition::Eligible,
            })
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn inspect_tombstone(
    quarantine: &Dir,
    name: OsString,
    metadata: Metadata,
    budget: &mut QuarantineCleanupBudget,
) -> Result<QuarantineCandidate, QuarantineInspectionError> {
    inspect_retained_tombstone(quarantine, name, metadata, budget)
}

#[cfg(not(unix))]
fn inspect_retained_tombstone(
    quarantine: &Dir,
    name: OsString,
    metadata: Metadata,
    budget: &mut QuarantineCleanupBudget,
) -> Result<QuarantineCandidate, QuarantineInspectionError> {
    let retained =
        RetainedTombstoneName::parse(&name).ok_or(QuarantineInspectionError::UnrecognizedState)?;
    validate_kind(retained.kind, &metadata)?;
    match retained.kind {
        RemovedObjectKind::File => {
            let opened = open_verified_file(quarantine, &name, &metadata)?;
            Ok(QuarantineCandidate::File {
                name,
                content: FileContentState::from_length(opened.len()),
                disposition: CleanupDisposition::Retain,
            })
        }
        RemovedObjectKind::Directory => {
            let directory = open_verified_directory(quarantine, &name, &metadata)?;
            Ok(QuarantineCandidate::Directory {
                name,
                work: inspect_descendants(
                    directory,
                    budget,
                    QuarantineWorkPortion::CleanupInspection,
                )?,
                disposition: CleanupDisposition::Retain,
            })
        }
    }
}

fn validate_kind(
    kind: RemovedObjectKind,
    metadata: &Metadata,
) -> Result<(), QuarantineInspectionError> {
    let expected_kind = match kind {
        RemovedObjectKind::File => metadata.is_file(),
        RemovedObjectKind::Directory => metadata.is_dir(),
    };
    if !safe_metadata(metadata) || !expected_kind {
        return Err(QuarantineInspectionError::UnsafeState);
    }
    Ok(())
}

pub(super) fn open_verified_file(
    parent: &Dir,
    name: &std::ffi::OsStr,
    selected: &Metadata,
) -> Result<Metadata, QuarantineInspectionError> {
    open_verified_file_capability(parent, name, selected).map(|(_, metadata)| metadata)
}

pub(super) fn open_verified_file_capability(
    parent: &Dir,
    name: &std::ffi::OsStr,
    selected: &Metadata,
) -> Result<(cap_std::fs::File, Metadata), QuarantineInspectionError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent
        .open_with(name, &options)
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    let opened = file
        .metadata()
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    if !safe_metadata(&opened) || !opened.is_file() || !same_file(selected, &opened) {
        return Err(QuarantineInspectionError::UnsafeState);
    }
    Ok((file, opened))
}

pub(super) fn open_verified_directory(
    parent: &Dir,
    name: &std::ffi::OsStr,
    selected: &Metadata,
) -> Result<Dir, QuarantineInspectionError> {
    let directory = parent
        .open_dir_nofollow(name)
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    let opened = directory
        .dir_metadata()
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    if !safe_metadata(&opened) || !opened.is_dir() || !same_file(selected, &opened) {
        return Err(QuarantineInspectionError::UnsafeState);
    }
    Ok(directory)
}

#[cfg(any(unix, windows))]
pub(super) fn is_empty_directory(directory: &Dir) -> Result<bool, QuarantineInspectionError> {
    let mut entries = directory
        .entries()
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
    Ok(entries.next().is_none())
}

#[cfg(any(unix, windows))]
fn require_empty_directory(
    directory: &Dir,
    budget: &mut QuarantineCleanupBudget,
) -> Result<(), QuarantineInspectionError> {
    if is_empty_directory(directory)? {
        return Ok(());
    }
    budget.try_descendant(QuarantineWorkPortion::CleanupInspection, 1)?;
    Err(QuarantineInspectionError::UnsafeState)
}

pub(super) fn inspect_descendants(
    root: Dir,
    budget: &mut QuarantineCleanupBudget,
    portion: QuarantineWorkPortion,
) -> Result<TombstoneWork, QuarantineInspectionError> {
    let mut pending = BTreeMap::from([(
        Vec::new(),
        PendingDirectory {
            directory: root,
            key: Vec::new(),
            depth: 0,
        },
    )]);
    let mut work = TombstoneWork::default();
    while let Some((_key, current)) = pending.pop_first() {
        let entries = current
            .directory
            .entries()
            .map_err(|_| QuarantineInspectionError::UnsafeState)?;
        let entries = collect_bounded_sorted_directory_entries(
            entries,
            budget.remaining_descendant_visits(portion),
        )
        .map_err(|_| QuarantineInspectionError::UnsafeState)?;
        let BoundedDirectoryEntries::Complete(entries) = entries else {
            return Err(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ReservationExceeded(portion),
            ));
        };
        for entry in entries {
            let depth = current
                .depth
                .checked_add(1)
                .ok_or(QuarantineInspectionError::Budget(
                    QuarantineBudgetError::ArithmeticOverflow,
                ))?;
            budget.try_descendant(portion, depth)?;
            work = work.checked_add(TombstoneWork::new(0, 1, depth)).ok_or(
                QuarantineInspectionError::Budget(QuarantineBudgetError::ArithmeticOverflow),
            )?;
            let name = entry.file_name();
            let selected = entry
                .full_metadata()
                .map_err(|_| QuarantineInspectionError::UnsafeState)?;
            if !safe_metadata(&selected) {
                return Err(QuarantineInspectionError::UnsafeState);
            }
            if selected.is_file() {
                open_verified_file(&current.directory, &name, &selected)?;
            } else if selected.is_dir() {
                let directory = open_verified_directory(&current.directory, &name, &selected)?;
                let mut key = current.key.clone();
                if !key.is_empty() {
                    key.push(b'/');
                }
                key.extend_from_slice(name.as_encoded_bytes());
                pending.insert(
                    key.clone(),
                    PendingDirectory {
                        directory,
                        key,
                        depth,
                    },
                );
            } else {
                return Err(QuarantineInspectionError::UnsafeState);
            }
        }
    }
    Ok(work)
}

#[cfg(any(unix, windows))]
fn require_single_link(metadata: &Metadata) -> Result<(), QuarantineInspectionError> {
    if has_single_file_link(metadata) {
        Ok(())
    } else {
        Err(QuarantineInspectionError::UnsafeState)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kitrove_model::PortablePath;

    use super::*;

    fn inspection_budget(
        top_level_entries: usize,
        descendant_visits: usize,
        max_depth: usize,
    ) -> QuarantineCleanupBudget {
        inspection_budget_for_roots(1, top_level_entries, descendant_visits, max_depth)
    }

    fn inspection_budget_for_roots(
        roots: usize,
        top_level_entries: usize,
        descendant_visits: usize,
        max_depth: usize,
    ) -> QuarantineCleanupBudget {
        let limits = QuarantineCleanupLimits::try_new(
            roots,
            top_level_entries.max(1),
            descendant_visits.max(1),
            max_depth.max(1),
        )
        .unwrap();
        let inspection = TombstoneWork::new(
            top_level_entries,
            descendant_visits,
            if descendant_visits == 0 { 0 } else { max_depth },
        );
        let reservation = QuarantineCleanupReservation::try_new(
            limits,
            roots,
            CleanupPassWork::new(
                inspection,
                TombstoneWork::default(),
                TombstoneWork::default(),
            ),
            TombstoneWork::default(),
            TombstoneWork::default(),
        )
        .unwrap();
        QuarantineCleanupBudget::new(reservation)
    }

    #[cfg(unix)]
    fn create_private_quarantine(root: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let control = root.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        quarantine
    }

    #[cfg(unix)]
    fn move_directory_tombstone(
        root: &std::path::Path,
        source: &std::path::Path,
        nonce: &str,
    ) -> OsString {
        let metadata = fs::metadata(source).unwrap();
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity::from_metadata(&metadata),
        }
        .encode(nonce)
        .unwrap();
        let quarantine = create_private_quarantine(root);
        fs::rename(source, quarantine.join(&name)).unwrap();
        name
    }

    #[test]
    fn inspection_of_absent_quarantine_is_nonmutating() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert!(inspection.candidates().is_empty());
        assert_eq!(inspection.work(), TombstoneWork::default());
        assert!(!root.join(".kitrove").exists());
    }

    #[cfg(unix)]
    #[test]
    fn absent_quarantine_accepts_owned_nonwritable_control_without_changing_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        drop(store.try_lock_environment().unwrap());
        let control = root.join(".kitrove");
        fs::set_permissions(&control, fs::Permissions::from_mode(0o755)).unwrap();
        let before = fs::metadata(&control).unwrap().permissions().mode() & 0o777;
        let mut budget = inspection_budget(1, 0, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert!(inspection.candidates().is_empty());
        assert_eq!(
            fs::metadata(&control).unwrap().permissions().mode() & 0o777,
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn absent_quarantine_rejects_writable_control_without_permission_repair() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        drop(store.try_lock_environment().unwrap());
        let control = root.join(".kitrove");
        fs::set_permissions(&control, fs::Permissions::from_mode(0o777)).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        assert_eq!(
            inspect_store_quarantine(&store, &mut budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
        assert_eq!(
            fs::metadata(&control).unwrap().permissions().mode() & 0o777,
            0o777
        );
    }

    #[cfg(unix)]
    #[test]
    fn absent_quarantine_still_revalidates_the_ambient_root() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let root = parent.join("root");
        let moved = parent.join("moved-root");
        fs::create_dir(&root).unwrap();
        let store = ObjectStore::open(&root).unwrap();

        let result = store.open_existing_removal_quarantine_with_hook(|| {
            fs::rename(&root, &moved).unwrap();
            fs::create_dir(&root).unwrap();
        });

        assert_eq!(result.unwrap_err().code(), "object.unsafe_environment_root");
        assert!(!moved.join(".kitrove").exists());
        assert!(!root.join(".kitrove").exists());
    }

    #[cfg(unix)]
    #[test]
    fn inspection_validates_a_real_file_tombstone() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("control"), "authority").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("control").unwrap())
            .unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert_eq!(inspection.candidates().len(), 1);
        assert!(matches!(
            &inspection.candidates()[0],
            QuarantineCandidate::File {
                content: FileContentState::Empty,
                disposition: CleanupDisposition::Eligible,
                ..
            }
        ));
        assert_eq!(inspection.work(), TombstoneWork::new(1, 0, 0));
    }

    #[cfg(unix)]
    #[test]
    fn inspection_walks_a_directory_tombstone_with_one_shared_budget() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/file"), "managed").unwrap();
        move_directory_tombstone(&root, &source, "00112233445566778899aabbccddeeff");
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 2, 2);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert_eq!(inspection.candidates().len(), 1);
        assert_eq!(inspection.work(), TombstoneWork::new(1, 2, 2));
        assert!(matches!(
            &inspection.candidates()[0],
            QuarantineCandidate::Directory {
                work,
                disposition: CleanupDisposition::Eligible,
                ..
            } if *work == TombstoneWork::new(0, 2, 2)
        ));
        assert_eq!(
            budget.remaining_descendant_visits(QuarantineWorkPortion::CleanupInspection),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn inspection_recognizes_identity_bound_batches() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let quarantine = create_private_quarantine(&root);
        let staging = quarantine.join("staging");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("entry"), "").unwrap();
        let identity = MetadataIdentity::from_metadata(&fs::metadata(&staging).unwrap());
        let batch = CleanupBatchName { identity }
            .encode("20112233445566778899aabbccddeeff")
            .unwrap();
        fs::rename(&staging, quarantine.join(&batch)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 1, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert_eq!(inspection.work(), TombstoneWork::new(1, 1, 1));
        assert!(inspection.candidates().iter().any(
            |candidate| matches!(candidate, QuarantineCandidate::InterruptedBatch { name, work } if name == &batch && *work == TombstoneWork::new(0, 1, 1))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn nonempty_pending_and_identity_mismatched_batches_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();

        let pending_root = parent.join("pending");
        fs::create_dir(&pending_root).unwrap();
        let pending_quarantine = create_private_quarantine(&pending_root);
        let pending = CleanupPendingName::encode("30112233445566778899aabbccddeeff").unwrap();
        fs::create_dir(pending_quarantine.join(&pending)).unwrap();
        fs::write(pending_quarantine.join(&pending).join("unexpected"), "").unwrap();
        let pending_store = ObjectStore::open(&pending_root).unwrap();
        let mut pending_budget = inspection_budget(1, 1, 1);
        assert_eq!(
            inspect_store_quarantine(&pending_store, &mut pending_budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
        assert_eq!(
            pending_budget.remaining_descendant_visits(QuarantineWorkPortion::CleanupInspection),
            0
        );
        let mut zero_descendant_budget = inspection_budget(1, 0, 1);
        assert_eq!(
            inspect_store_quarantine(&pending_store, &mut zero_descendant_budget),
            Err(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ReservationExceeded(
                    QuarantineWorkPortion::CleanupInspection
                )
            ))
        );

        let batch_root = parent.join("batch");
        fs::create_dir(&batch_root).unwrap();
        let batch_quarantine = create_private_quarantine(&batch_root);
        let batch = CleanupBatchName {
            identity: MetadataIdentity {
                device: u64::MAX,
                inode: u64::MAX,
            },
        }
        .encode("40112233445566778899aabbccddeeff")
        .unwrap();
        fs::create_dir(batch_quarantine.join(batch)).unwrap();
        let batch_store = ObjectStore::open(&batch_root).unwrap();
        let mut batch_budget = inspection_budget(1, 0, 1);
        assert_eq!(
            inspect_store_quarantine(&batch_store, &mut batch_budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
    }

    #[cfg(unix)]
    #[test]
    fn inspection_rejects_multiple_cleanup_control_entries() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();

        for (index, controls) in [
            ["pending", "pending"],
            ["batch", "batch"],
            ["pending", "batch"],
        ]
        .into_iter()
        .enumerate()
        {
            let root = parent.join(format!("root-{index}"));
            fs::create_dir(&root).unwrap();
            let quarantine = create_private_quarantine(&root);
            for (control_index, control) in controls.into_iter().enumerate() {
                let nonce = format!("{control_index:032x}");
                if control == "pending" {
                    let name = CleanupPendingName::encode(&nonce).unwrap();
                    fs::create_dir(quarantine.join(name)).unwrap();
                } else {
                    let staging = quarantine.join(format!("staging-{control_index}"));
                    fs::create_dir(&staging).unwrap();
                    let name = CleanupBatchName {
                        identity: MetadataIdentity::from_metadata(&fs::metadata(&staging).unwrap()),
                    }
                    .encode(&nonce)
                    .unwrap();
                    fs::rename(staging, quarantine.join(name)).unwrap();
                }
            }
            let store = ObjectStore::open(&root).unwrap();
            let mut budget = inspection_budget(2, 0, 1);
            assert_eq!(
                inspect_store_quarantine(&store, &mut budget),
                Err(QuarantineInspectionError::UnsafeState)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn top_level_overflow_and_unknown_names_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let quarantine = create_private_quarantine(&root);
        fs::write(quarantine.join("unknown"), "").unwrap();
        fs::write(quarantine.join("also-unknown"), "").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut overflow_budget = inspection_budget(1, 0, 1);

        assert_eq!(
            inspect_store_quarantine(&store, &mut overflow_budget),
            Err(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ReservationExceeded(
                    QuarantineWorkPortion::CleanupInspection
                )
            ))
        );

        fs::remove_file(quarantine.join("also-unknown")).unwrap();
        let mut unknown_budget = inspection_budget(1, 0, 1);
        assert_eq!(
            inspect_store_quarantine(&store, &mut unknown_budget),
            Err(QuarantineInspectionError::UnrecognizedState)
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_file_tombstone_is_not_cleanup_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("source");
        fs::write(&source, "managed").unwrap();
        fs::hard_link(&source, root.join("external-alias")).unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::File,
            identity: MetadataIdentity::from_metadata(&metadata),
        }
        .encode("00112233445566778899aabbccddeeff")
        .unwrap();
        let quarantine = create_private_quarantine(&root);
        fs::rename(&source, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        assert_eq!(
            inspect_store_quarantine(&store, &mut budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
        assert_eq!(
            fs::read_to_string(root.join("external-alias")).unwrap(),
            "managed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descendant_and_depth_plus_one_fail_before_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();

        let descendant_root = parent.join("descendant-root");
        fs::create_dir(&descendant_root).unwrap();
        let descendant_source = descendant_root.join("source");
        fs::create_dir(&descendant_source).unwrap();
        fs::write(descendant_source.join("one"), "1").unwrap();
        fs::write(descendant_source.join("two"), "2").unwrap();
        move_directory_tombstone(
            &descendant_root,
            &descendant_source,
            "10112233445566778899aabbccddeeff",
        );
        let descendant_store = ObjectStore::open(&descendant_root).unwrap();
        let mut descendant_budget = inspection_budget(1, 1, 1);
        assert!(matches!(
            inspect_store_quarantine(&descendant_store, &mut descendant_budget),
            Err(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ReservationExceeded(
                    QuarantineWorkPortion::CleanupInspection
                )
            ))
        ));

        let depth_root = parent.join("depth-root");
        fs::create_dir(&depth_root).unwrap();
        let depth_source = depth_root.join("source");
        fs::create_dir_all(depth_source.join("one/two")).unwrap();
        move_directory_tombstone(
            &depth_root,
            &depth_source,
            "20112233445566778899aabbccddeeff",
        );
        let depth_store = ObjectStore::open(&depth_root).unwrap();
        let mut depth_budget = inspection_budget(1, 2, 1);
        assert!(matches!(
            inspect_store_quarantine(&depth_store, &mut depth_budget),
            Err(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ReservationExceeded(
                    QuarantineWorkPortion::CleanupInspection
                )
            ))
        ));

        assert!(descendant_root.join(".kitrove/removal-quarantine").exists());
        assert!(depth_root.join(".kitrove/removal-quarantine").exists());
    }

    #[cfg(unix)]
    #[test]
    fn identity_mismatch_and_malformed_canonical_name_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();

        let mismatch_root = parent.join("mismatch-root");
        fs::create_dir(&mismatch_root).unwrap();
        let quarantine = create_private_quarantine(&mismatch_root);
        let source = mismatch_root.join("source");
        fs::write(&source, "managed").unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let mut identity = MetadataIdentity::from_metadata(&metadata);
        identity.inode = identity.inode.wrapping_add(1);
        let mismatch_name = RemovalTombstoneName {
            kind: RemovedObjectKind::File,
            identity,
        }
        .encode("30112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&source, quarantine.join(mismatch_name)).unwrap();
        let mismatch_store = ObjectStore::open(&mismatch_root).unwrap();
        let mut mismatch_budget = inspection_budget(1, 0, 1);
        assert_eq!(
            inspect_store_quarantine(&mismatch_store, &mut mismatch_budget),
            Err(QuarantineInspectionError::UnsafeState)
        );

        let malformed_root = parent.join("malformed-root");
        fs::create_dir(&malformed_root).unwrap();
        let quarantine = create_private_quarantine(&malformed_root);
        fs::write(
            quarantine.join(
                ".kitrove-removed-v1-unix-f-0000000000000001-0000000000000002-ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
            ),
            "",
        )
        .unwrap();
        let malformed_store = ObjectStore::open(&malformed_root).unwrap();
        let mut malformed_budget = inspection_budget(1, 0, 1);
        assert_eq!(
            inspect_store_quarantine(&malformed_store, &mut malformed_budget),
            Err(QuarantineInspectionError::UnrecognizedState)
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_between_metadata_and_open_survives() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("source");
        fs::write(&source, "original").unwrap();
        let metadata = fs::metadata(&source).unwrap();
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::File,
            identity: MetadataIdentity::from_metadata(&metadata),
        }
        .encode("60112233445566778899aabbccddeeff")
        .unwrap();
        let quarantine_path = create_private_quarantine(&root);
        fs::rename(&source, quarantine_path.join(&name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let quarantine = store.open_existing_removal_quarantine().unwrap().unwrap();
        let mut budget = inspection_budget(1, 0, 1);
        budget.try_root().unwrap();
        let original_path = quarantine_path.join("moved-original");

        let error =
            inspect_quarantine_directory_with_hook(quarantine, &mut budget, &mut |selected_name| {
                fs::rename(quarantine_path.join(selected_name), &original_path).unwrap();
                fs::write(quarantine_path.join(selected_name), "replacement").unwrap();
            })
            .unwrap_err();

        assert_eq!(error, QuarantineInspectionError::UnsafeState);
        assert_eq!(fs::read_to_string(original_path).unwrap(), "original");
        assert_eq!(
            fs::read_to_string(quarantine_path.join(name)).unwrap(),
            "replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn link_and_special_descendants_fail_closed() {
        use std::os::unix::net::UnixListener;

        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();

        let link_root = parent.join("link-root");
        fs::create_dir(&link_root).unwrap();
        let link_source = link_root.join("source");
        fs::create_dir(&link_source).unwrap();
        std::os::unix::fs::symlink("outside", link_source.join("link")).unwrap();
        move_directory_tombstone(&link_root, &link_source, "40112233445566778899aabbccddeeff");
        let link_store = ObjectStore::open(&link_root).unwrap();
        let mut link_budget = inspection_budget(1, 1, 1);
        assert_eq!(
            inspect_store_quarantine(&link_store, &mut link_budget),
            Err(QuarantineInspectionError::UnsafeState)
        );

        let special_root = parent.join("special-root");
        fs::create_dir(&special_root).unwrap();
        let special_source = special_root.join("source");
        fs::create_dir(&special_source).unwrap();
        let listener = UnixListener::bind(special_source.join("socket")).unwrap();
        move_directory_tombstone(
            &special_root,
            &special_source,
            "50112233445566778899aabbccddeeff",
        );
        drop(listener);
        let special_store = ObjectStore::open(&special_root).unwrap();
        let mut special_budget = inspection_budget(1, 1, 1);
        assert_eq!(
            inspect_store_quarantine(&special_store, &mut special_budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
    }

    #[cfg(unix)]
    #[test]
    fn roots_share_top_level_allowance_without_reset() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let first_root = parent.join("first");
        let second_root = parent.join("second");
        fs::create_dir(&first_root).unwrap();
        fs::create_dir(&second_root).unwrap();
        fs::write(first_root.join("control"), "first").unwrap();
        fs::write(second_root.join("control"), "second").unwrap();
        let first = ObjectStore::open(&first_root).unwrap();
        let second = ObjectStore::open(&second_root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&first, &second]).unwrap();
        let path = PortablePath::parse("control").unwrap();
        first.remove_regular_file_if_present(&path).unwrap();
        second.remove_regular_file_if_present(&path).unwrap();
        let mut budget = inspection_budget_for_roots(2, 1, 0, 1);

        inspect_store_quarantine(&first, &mut budget).unwrap();
        assert!(matches!(
            inspect_store_quarantine(&second, &mut budget),
            Err(QuarantineInspectionError::Budget(
                QuarantineBudgetError::ReservationExceeded(
                    QuarantineWorkPortion::CleanupInspection
                )
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn insecure_private_boundary_is_rejected_without_permission_repair() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let control = root.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o755)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        assert_eq!(
            inspect_store_quarantine(&store, &mut budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
        assert_eq!(fs::metadata(&control).unwrap().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(&quarantine).unwrap().mode() & 0o777, 0o755);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_boundary_acl_is_rejected_without_mutation() {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::PermissionsExt as _;

        for acl_on_quarantine in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let control = root.join(".kitrove");
            let quarantine = control.join("removal-quarantine");
            fs::create_dir_all(&quarantine).unwrap();
            fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
            let boundary = if acl_on_quarantine {
                &quarantine
            } else {
                &control
            };
            kitrove_testkit::install_macos_extended_acl(boundary);
            let before_mode = fs::metadata(boundary).unwrap().permissions().mode() & 0o777;
            let store = ObjectStore::open(&root).unwrap();
            let mut budget = inspection_budget(1, 0, 1);

            assert_eq!(
                inspect_store_quarantine(&store, &mut budget),
                Err(QuarantineInspectionError::UnsafeState)
            );
            assert_eq!(
                fs::metadata(boundary).unwrap().permissions().mode() & 0o777,
                before_mode
            );
            let opened = fs::File::open(boundary).unwrap();
            assert!(
                !calcifer_macos_acl::read_acl(opened.as_fd())
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn complete_windows_identity_names_are_cleanup_eligible() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&root).unwrap();
        let seed = PortablePath::parse("windows-authority").unwrap();
        mutation
            .stage_private_text(&seed, "identity-bound", 1024)
            .unwrap();
        mutation.remove_regular_file_if_present(&seed).unwrap();
        let root = root.canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert!(matches!(
            &inspection.candidates()[0],
            QuarantineCandidate::File {
                content: FileContentState::NonEmpty,
                disposition: CleanupDisposition::Eligible,
                ..
            }
        ));
        let quarantined = fs::read_dir(root.join(".kitrove/removal-quarantine"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(fs::read(quarantined.path()).unwrap(), b"identity-bound");
    }

    #[cfg(windows)]
    #[test]
    fn complete_windows_directory_identity_is_eligible_and_mismatch_is_unsafe() {
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&state).unwrap();
        let removed = PortablePath::parse("removed-directory").unwrap();
        mutation.create_empty_directory_for_test(&removed).unwrap();
        mutation
            .remove_empty_directory_if_present(&removed)
            .unwrap();
        let root = state.canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        assert!(matches!(
            &inspection.candidates()[0],
            QuarantineCandidate::Directory {
                disposition: CleanupDisposition::Eligible,
                ..
            }
        ));

        let quarantine = root.join(".kitrove/removal-quarantine");
        let entry = fs::read_dir(&quarantine).unwrap().next().unwrap().unwrap();
        let mut authority = RemovalTombstoneName::parse(&entry.file_name()).unwrap();
        authority.identity.file_id[0] ^= 1;
        let mismatch = authority
            .encode("00112233445566778899aabbccddeeff")
            .unwrap();
        fs::rename(entry.path(), quarantine.join(mismatch)).unwrap();
        let mut mismatch_budget = inspection_budget(1, 0, 1);
        assert_eq!(
            inspect_store_quarantine(&store, &mut mismatch_budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_mismatch_is_unsafe_not_retained_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&root).unwrap();
        let seed = PortablePath::parse("windows-authority").unwrap();
        mutation
            .stage_private_text(&seed, "identity-bound", 1024)
            .unwrap();
        mutation.remove_regular_file_if_present(&seed).unwrap();
        let root = root.canonicalize().unwrap();
        let quarantine = root.join(".kitrove/removal-quarantine");
        let entry = fs::read_dir(&quarantine).unwrap().next().unwrap().unwrap();
        let mut authority = RemovalTombstoneName::parse(&entry.file_name()).unwrap();
        authority.identity.file_id[0] ^= 1;
        let mismatch = authority
            .encode("00112233445566778899aabbccddeeff")
            .unwrap();
        fs::rename(entry.path(), quarantine.join(mismatch)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        assert_eq!(
            inspect_store_quarantine(&store, &mut budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
    }

    #[cfg(windows)]
    #[test]
    fn hardlinked_windows_tombstone_is_not_cleanup_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&state).unwrap();
        let seed = PortablePath::parse("seed").unwrap();
        mutation.stage_private_text(&seed, "seed", 1024).unwrap();
        mutation.remove_regular_file_if_present(&seed).unwrap();
        let root = state.canonicalize().unwrap();
        let quarantine = root.join(".kitrove/removal-quarantine");
        for entry in fs::read_dir(&quarantine).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let source = root.join("source");
        fs::write(&source, "managed").unwrap();
        let opened = fs::File::open(&source).unwrap();
        let identity = kitrove_windows_security::file_identity(&opened).unwrap();
        drop(opened);
        fs::hard_link(&source, root.join("external-alias")).unwrap();
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::File,
            identity,
        }
        .encode("00112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&source, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        assert_eq!(
            inspect_store_quarantine(&store, &mut budget),
            Err(QuarantineInspectionError::UnsafeState)
        );
        assert_eq!(
            fs::read_to_string(root.join("external-alias")).unwrap(),
            "managed"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn retained_names_are_inspectable_but_never_deletable() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&root).unwrap();
        let seed = PortablePath::parse("retained-seed").unwrap();
        mutation
            .stage_private_text(&seed, "retained", 1024)
            .unwrap();
        mutation.remove_regular_file_if_present(&seed).unwrap();
        let root = root.canonicalize().unwrap();
        let quarantine = root.join(".kitrove/removal-quarantine");
        let name = RetainedTombstoneName {
            kind: RemovedObjectKind::File,
        }
        .encode("00112233445566778899aabbccddeeff")
        .unwrap();
        let seeded = fs::read_dir(&quarantine)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::rename(seeded, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let mut budget = inspection_budget(1, 0, 1);

        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        let expected_content = if cfg!(windows) {
            FileContentState::NonEmpty
        } else {
            FileContentState::Empty
        };
        assert!(matches!(
            &inspection.candidates()[0],
            QuarantineCandidate::File {
                content,
                disposition: CleanupDisposition::Retain,
                ..
            } if *content == expected_content
        ));
    }
}
