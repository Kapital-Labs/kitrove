use super::state_file::SnapshotFile;
use super::*;
use sha2::{Digest as _, Sha256};

/// Maximum number of descendant files and directories retained during state preflight.
pub const MAX_STATE_TREE_ENTRIES: usize = 1024;
/// Maximum aggregate private file bytes captured from one state root.
pub const MAX_STATE_TREE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STATE_TREE_DEPTH: usize = 32;

/// Complete bounded filesystem evidence, not schema or recovery-journal approval.
///
/// Every directory and regular file remains identity-bound. Contents and paths are
/// machine-local and excluded from Debug. This never executes private payloads.
pub struct StateTreeSnapshot {
    root_path: PathBuf,
    ancestry: Vec<NativeIdentity>,
    directories: Vec<SnapshotDirectory>,
    files: Vec<TreeFile>,
    total_bytes: usize,
    fingerprint: [u8; 32],
}

struct SnapshotDirectory {
    path: PathBuf,
    parent: Option<usize>,
    directory: Dir,
    identity: NativeIdentity,
    inventory: Vec<OsString>,
}

struct TreeFile {
    path: PathBuf,
    parent: usize,
    captured: SnapshotFile,
}

impl fmt::Debug for StateTreeSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateTreeSnapshot")
            .field("directories", &self.directories.len())
            .field("files", &self.files.len())
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl StateTreeSnapshot {
    /// Returns a machine-local digest binding topology, native identities, modes and bytes.
    #[must_use]
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Returns exact captured bytes and relative paths for the caller's schema checks.
    pub fn files(&self) -> impl Iterator<Item = (&Path, &[u8])> {
        self.files
            .iter()
            .map(|file| (file.path.as_path(), file.captured.bytes.as_slice()))
    }

    /// Returns relative directory paths, including the empty path for the state root.
    pub fn directories(&self) -> impl Iterator<Item = &Path> {
        self.directories
            .iter()
            .map(|directory| directory.path.as_path())
    }

    fn require_directories(&self, access: &ExclusiveStateAccess<'_>) -> Result<(), LifecycleError> {
        access.revalidate()?;
        if self.root_path != access.authority.path
            || self.ancestry
                != access
                    .authority
                    .ancestry
                    .iter()
                    .map(|entry| entry.identity)
                    .collect::<Vec<_>>()
            || directory_identity(access.authority.root()?)? != self.directories[0].identity
        {
            return Err(LifecycleError::UnsafeState);
        }
        for directory in &self.directories {
            require_private_directory(&directory.directory)?;
            if directory_identity(&directory.directory)? != directory.identity {
                return Err(LifecycleError::UnsafeState);
            }
            if let Some(parent) = directory.parent {
                require_retained_directory_identity(
                    &self.directories[parent].directory,
                    directory
                        .path
                        .file_name()
                        .ok_or(LifecycleError::UnsafeState)?,
                    &directory.directory,
                    directory.identity,
                )?;
            }
            if inventory(&directory.directory, directory.inventory.len())? != directory.inventory {
                return Err(LifecycleError::UnsafeState);
            }
        }
        access.revalidate()
    }

    fn compute_fingerprint(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kitrove-state-tree-v1\0");
        hash_path(&mut hash, &self.root_path);
        hash.update((self.ancestry.len() as u64).to_be_bytes());
        for identity in &self.ancestry {
            hash_identity(&mut hash, *identity);
        }
        hash.update((self.directories.len() as u64).to_be_bytes());
        for directory in &self.directories {
            hash_path(&mut hash, &directory.path);
            hash_identity(&mut hash, directory.identity);
        }
        hash.update((self.files.len() as u64).to_be_bytes());
        for file in &self.files {
            hash_path(&mut hash, &file.path);
            hash_identity(&mut hash, file.captured.identity);
            hash.update(file.captured.mode.to_be_bytes());
            hash.update((file.captured.bytes.len() as u64).to_be_bytes());
            hash.update(Sha256::digest(&file.captured.bytes));
        }
        hash.finalize().into()
    }
}

impl ExclusiveStateAccess<'_> {
    /// Captures all private state descendants without mutation, following links or execution.
    ///
    /// Enforces 1024 descendants, depth 32, 32 MiB per file and 64 MiB aggregate bytes.
    /// Resource-limit refusal preserves the complete state tree unchanged.
    pub fn capture_state_tree(&self) -> Result<StateTreeSnapshot, LifecycleError> {
        self.capture_state_tree_with_limits(
            MAX_STATE_TREE_ENTRIES,
            MAX_STATE_TREE_BYTES,
            MAX_STATE_TREE_DEPTH,
        )
    }

    fn capture_state_tree_with_limits(
        &self,
        max_entries: usize,
        max_bytes: usize,
        max_depth: usize,
    ) -> Result<StateTreeSnapshot, LifecycleError> {
        self.revalidate()?;
        let root = self.authority.root()?;
        let mut snapshot = StateTreeSnapshot {
            root_path: self.authority.path.clone(),
            ancestry: self
                .authority
                .ancestry
                .iter()
                .map(|entry| entry.identity)
                .collect(),
            directories: vec![SnapshotDirectory {
                path: PathBuf::new(),
                parent: None,
                directory: root.try_clone().map_err(|_| LifecycleError::UnsafeState)?,
                identity: directory_identity(root)?,
                inventory: Vec::new(),
            }],
            files: Vec::new(),
            total_bytes: 0,
            fingerprint: [0; 32],
        };
        let mut index = 0;
        let mut entries = 0;
        // Iterative traversal bounds stack use independently of hostile directory nesting.
        while index < snapshot.directories.len() {
            let names = inventory(
                &snapshot.directories[index].directory,
                max_entries - entries,
            )?;
            entries += names.len();
            for name in &names {
                let parent = &snapshot.directories[index];
                let path = parent.path.join(name);
                if path.components().count() > max_depth {
                    return Err(LifecycleError::UnsafeState);
                }
                let metadata = parent
                    .directory
                    .symlink_metadata(name)
                    .map_err(|_| LifecycleError::UnsafeState)?;
                reject_link_like(&metadata)?;
                if metadata.is_dir() {
                    let directory = open_existing_private_directory(&parent.directory, name)?;
                    let identity = directory_identity(&directory)?;
                    if snapshot
                        .directories
                        .iter()
                        .any(|entry| entry.identity == identity)
                    {
                        return Err(LifecycleError::UnsafeState);
                    }
                    snapshot.directories.push(SnapshotDirectory {
                        path,
                        parent: Some(index),
                        directory,
                        identity,
                        inventory: Vec::new(),
                    });
                } else {
                    let allow_executable = path != Path::new(INITIAL_STATE_FILE)
                        && path != Path::new(CONTROL_DIRECTORY).join(LIFECYCLE_LOCK);
                    let captured = SnapshotFile::capture(
                        &parent.directory,
                        name,
                        (max_bytes - snapshot.total_bytes).min(MAX_INITIAL_STATE_BYTES),
                        allow_executable,
                    )?;
                    snapshot.total_bytes += captured.bytes.len();
                    snapshot.files.push(TreeFile {
                        path,
                        parent: index,
                        captured,
                    });
                }
            }
            snapshot.directories[index].inventory = names;
            index += 1;
        }
        self.revalidate_state_tree(&mut snapshot)?;
        snapshot.fingerprint = snapshot.compute_fingerprint();
        Ok(snapshot)
    }

    /// Rejects changed inventory, bytes, modes, identities or authority under the live guard.
    pub fn revalidate_state_tree(
        &self,
        snapshot: &mut StateTreeSnapshot,
    ) -> Result<(), LifecycleError> {
        snapshot.require_directories(self)?;
        for file in &mut snapshot.files {
            file.captured.revalidate(
                &snapshot.directories[file.parent].directory,
                file.path.file_name().ok_or(LifecycleError::UnsafeState)?,
            )?;
        }
        snapshot.require_directories(self)
    }
}

fn inventory(directory: &Dir, limit: usize) -> Result<Vec<OsString>, LifecycleError> {
    let mut names = directory
        .entries()
        .map_err(|_| LifecycleError::UnsafeState)?
        .take(limit + 1)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| LifecycleError::UnsafeState)?;
    if names.len() > limit {
        return Err(LifecycleError::UnsafeState);
    }
    names.sort_unstable();
    Ok(names)
}

fn hash_path(hash: &mut Sha256, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let bytes = path.as_os_str().as_bytes();
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        hash.update((units.len() as u64).to_be_bytes());
        for unit in units {
            hash.update(unit.to_be_bytes());
        }
    }
}

fn hash_identity(hash: &mut Sha256, identity: NativeIdentity) {
    #[cfg(unix)]
    {
        hash.update(b"unix\0");
        hash.update(identity.device.to_be_bytes());
        hash.update(identity.inode.to_be_bytes());
    }
    #[cfg(windows)]
    {
        hash.update(b"windows\0");
        hash.update(identity.volume_serial_number.to_be_bytes());
        hash.update(identity.file_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn initialized() -> (tempfile::TempDir, StateAuthority, ExclusiveLifecycleGuard) {
        let (parent, path) = crate::tests::initialized_state();
        let authority = StateAuthority::open_existing(&path).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        authority
            .exclusive_access(&guard)
            .unwrap()
            .create_initial_state(b"body")
            .unwrap();
        (parent, authority, guard)
    }

    fn nested(authority: &StateAuthority) {
        let directory =
            create_private_directory(authority.root().unwrap(), OsStr::new("nested")).unwrap();
        create_private_file_with_contents(
            &directory,
            OsStr::new("control.json"),
            b"PRIVATE-CANARY",
        )
        .unwrap();
        create_private_directory(&directory, OsStr::new("empty")).unwrap();
    }

    #[test]
    fn empty_locked_file_is_inspected_without_reading_locked_bytes() {
        let (_parent, authority, guard) = initialized();
        let control = &guard._guard._control;
        let mut captured =
            SnapshotFile::capture(control, OsStr::new(LIFECYCLE_LOCK), 0, false).unwrap();
        assert!(captured.bytes.is_empty());
        captured
            .revalidate(control, OsStr::new(LIFECYCLE_LOCK))
            .unwrap();
        assert!(matches!(
            authority.try_lock_shared(),
            Err(LifecycleError::LockUnavailable)
        ));
    }

    #[test]
    fn empty_file_evidence_rejects_growth() {
        let (_parent, authority, _guard) = initialized();
        let root = authority.root().unwrap();
        let name = OsStr::new("empty");
        create_private_file_with_contents(root, name, b"").unwrap();
        let mut captured = SnapshotFile::capture(root, name, 0, false).unwrap();
        fs::write(authority.path.join(name), b"changed").unwrap();
        assert_eq!(
            captured.revalidate(root, name),
            Err(LifecycleError::UnsafeState)
        );
        assert_eq!(
            require_exact_file_contents(&mut root.open(name).unwrap(), b""),
            Err(LifecycleError::UnsafeState)
        );
    }

    #[test]
    fn captures_complete_private_tree_and_stable_identity_bound_fingerprint() {
        let (_parent, authority, guard) = initialized();
        nested(&authority);
        let access = authority.exclusive_access(&guard).unwrap();
        let mut snapshot = access.capture_state_tree().unwrap();
        assert_eq!(snapshot.files().count(), 3);
        assert_eq!(snapshot.directories().count(), 4);
        assert!(
            snapshot
                .files()
                .any(|(path, bytes)| path == Path::new("nested/control.json")
                    && bytes == b"PRIVATE-CANARY")
        );
        assert!(
            snapshot
                .directories()
                .any(|path| path == Path::new("nested/empty"))
        );
        assert!(!format!("{snapshot:?}").contains("PRIVATE-CANARY"));
        assert!(!format!("{snapshot:?}").contains("nested"));
        assert_eq!(
            snapshot.fingerprint(),
            access.capture_state_tree().unwrap().fingerprint()
        );
        access.revalidate_state_tree(&mut snapshot).unwrap();
    }

    #[test]
    fn detects_uncooperative_nested_writer_and_fingerprint_changes() {
        let (_parent, authority, guard) = initialized();
        nested(&authority);
        let access = authority.exclusive_access(&guard).unwrap();
        let mut snapshot = access.capture_state_tree().unwrap();
        let path = authority.path.join("nested/control.json");
        fs::write(&path, b"CHANGED-CANARY").unwrap();
        assert_eq!(
            access.revalidate_state_tree(&mut snapshot),
            Err(LifecycleError::UnsafeState)
        );
        assert_ne!(
            snapshot.fingerprint(),
            access.capture_state_tree().unwrap().fingerprint()
        );
        assert_eq!(fs::read(&path).unwrap(), b"CHANGED-CANARY");
    }

    #[test]
    fn inventory_addition_and_empty_directory_changes_are_detected() {
        for directory in [false, true] {
            let (_parent, authority, guard) = initialized();
            let access = authority.exclusive_access(&guard).unwrap();
            let mut snapshot = access.capture_state_tree().unwrap();
            if directory {
                create_private_directory(authority.root().unwrap(), OsStr::new("extra")).unwrap();
            } else {
                create_private_file_with_contents(
                    authority.root().unwrap(),
                    OsStr::new("extra"),
                    b"retained",
                )
                .unwrap();
            }
            assert_eq!(
                access.revalidate_state_tree(&mut snapshot),
                Err(LifecycleError::UnsafeState)
            );
            assert_ne!(
                snapshot.fingerprint(),
                access.capture_state_tree().unwrap().fingerprint()
            );
            assert!(authority.path.join("extra").exists());
        }
    }

    #[test]
    fn exact_resource_bounds_are_enforced_without_mutation() {
        let (_parent, authority, guard) = initialized();
        let access = authority.exclusive_access(&guard).unwrap();
        access.capture_state_tree_with_limits(3, 4, 2).unwrap();
        for limits in [(2, 4, 2), (3, 3, 2), (3, 4, 1)] {
            assert_eq!(
                access
                    .capture_state_tree_with_limits(limits.0, limits.1, limits.2)
                    .err(),
                Some(LifecycleError::UnsafeState)
            );
        }
        assert_eq!(
            fs::read(authority.path.join(INITIAL_STATE_FILE)).unwrap(),
            b"body"
        );
        access.capture_state_tree_with_limits(3, 4, 2).unwrap();
    }

    #[test]
    fn another_root_cannot_revalidate_a_snapshot_or_reuse_its_fingerprint() {
        let (_first_parent, first, first_guard) = initialized();
        let (_second_parent, second, second_guard) = initialized();
        let first_access = first.exclusive_access(&first_guard).unwrap();
        let second_access = second.exclusive_access(&second_guard).unwrap();
        let mut snapshot = first_access.capture_state_tree().unwrap();
        assert_eq!(
            second_access.revalidate_state_tree(&mut snapshot),
            Err(LifecycleError::UnsafeState)
        );
        assert_ne!(
            snapshot.fingerprint(),
            second_access.capture_state_tree().unwrap().fingerprint()
        );
    }

    #[test]
    fn nested_hard_link_is_never_accepted_as_independent_state_authority() {
        let (_parent, authority, guard) = initialized();
        nested(&authority);
        let access = authority.exclusive_access(&guard).unwrap();
        let mut snapshot = access.capture_state_tree().unwrap();
        fs::hard_link(
            authority.path.join("nested/control.json"),
            authority.path.join("alias"),
        )
        .unwrap();
        assert_eq!(
            access.revalidate_state_tree(&mut snapshot),
            Err(LifecycleError::UnsafeState)
        );
        assert_eq!(
            access.capture_state_tree().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert_eq!(
            fs::read(authority.path.join("alias")).unwrap(),
            b"PRIVATE-CANARY"
        );
    }

    #[test]
    #[cfg(unix)]
    fn equal_byte_file_and_directory_replacement_cannot_revalidate() {
        for directory in [false, true] {
            let (parent, authority, guard) = initialized();
            nested(&authority);
            let access = authority.exclusive_access(&guard).unwrap();
            let mut snapshot = access.capture_state_tree().unwrap();
            if directory {
                fs::rename(
                    authority.path.join("nested"),
                    parent.path().join("retained"),
                )
                .unwrap();
                nested(&authority);
            } else {
                fs::rename(
                    authority.path.join("nested/control.json"),
                    parent.path().join("retained"),
                )
                .unwrap();
                let nested = open_existing_private_directory(
                    authority.root().unwrap(),
                    OsStr::new("nested"),
                )
                .unwrap();
                create_private_file_with_contents(
                    &nested,
                    OsStr::new("control.json"),
                    b"PRIVATE-CANARY",
                )
                .unwrap();
            }
            assert_eq!(
                access.revalidate_state_tree(&mut snapshot),
                Err(LifecycleError::UnsafeState)
            );
            assert_ne!(
                snapshot.fingerprint(),
                access.capture_state_tree().unwrap().fingerprint()
            );
            assert!(parent.path().join("retained").exists());
        }
    }

    #[test]
    #[cfg(unix)]
    fn private_executable_payloads_are_inspected_but_document_modes_stay_strict() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_parent, authority, guard) = initialized();
        nested(&authority);
        let payload = authority.path.join("nested/control.json");
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o700)).unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let mut snapshot = access.capture_state_tree().unwrap();
        access.revalidate_state_tree(&mut snapshot).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            access.revalidate_state_tree(&mut snapshot),
            Err(LifecycleError::UnsafeState)
        );
        assert_ne!(
            snapshot.fingerprint(),
            access.capture_state_tree().unwrap().fingerprint()
        );
        fs::set_permissions(
            authority.path.join(INITIAL_STATE_FILE),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(
            access.capture_state_tree().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert_eq!(
            access.capture_state_document().err(),
            Some(LifecycleError::UnsafeState)
        );
    }

    #[test]
    #[cfg(unix)]
    fn nested_symlink_is_preserved_and_never_followed() {
        let (_parent, authority, guard) = initialized();
        nested(&authority);
        let path = authority.path.join("nested/link");
        std::os::unix::fs::symlink("../state.json", &path).unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        assert_eq!(
            access.capture_state_tree().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        assert_eq!(
            fs::read(authority.path.join(INITIAL_STATE_FILE)).unwrap(),
            b"body"
        );
    }
}
