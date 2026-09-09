use super::*;

/// Retained exact state-document evidence, not schema or upgrade authorization.
///
/// Contents are machine-local. The retained file prevents identity reuse; a
/// matching exclusive state access is required to revalidate this snapshot.
pub struct StateDocumentSnapshot {
    root: Dir,
    root_identity: NativeIdentity,
    captured: state_file::SnapshotFile,
}

impl StateDocumentSnapshot {
    /// Returns the bounded captured bytes for the caller's strict schema validator.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.captured.bytes
    }

    fn require_root_identity(&self, root: &Dir) -> Result<(), LifecycleError> {
        if directory_identity(&self.root)? != self.root_identity
            || directory_identity(root)? != self.root_identity
        {
            return Err(LifecycleError::UnsafeState);
        }
        Ok(())
    }
}

impl fmt::Debug for StateDocumentSnapshot {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateDocumentSnapshot")
            .field("bytes_len", &self.captured.bytes.len())
            .finish_non_exhaustive()
    }
}

impl ExclusiveStateAccess<'_> {
    /// Captures the existing private state document without mutation or permission repair.
    ///
    /// This does not validate its schema or inspect other state-control files.
    pub fn capture_state_document(&self) -> Result<StateDocumentSnapshot, LifecycleError> {
        self.revalidate()?;
        let root = self.authority.root()?;
        let captured = state_file::SnapshotFile::capture(
            root,
            OsStr::new(INITIAL_STATE_FILE),
            MAX_INITIAL_STATE_BYTES,
            false,
        )?;
        let mut snapshot = StateDocumentSnapshot {
            root: root.try_clone().map_err(|_| LifecycleError::UnsafeState)?,
            root_identity: directory_identity(root)?,
            captured,
        };
        self.revalidate_state_document(&mut snapshot)?;
        Ok(snapshot)
    }

    /// Requires unchanged exact bytes, identity and private authority under the live guard.
    pub fn revalidate_state_document(
        &self,
        snapshot: &mut StateDocumentSnapshot,
    ) -> Result<(), LifecycleError> {
        self.revalidate()?;
        let root = self.authority.root()?;
        snapshot.require_root_identity(root)?;
        snapshot
            .captured
            .revalidate(root, OsStr::new(INITIAL_STATE_FILE))?;
        snapshot.require_root_identity(root)?;
        self.revalidate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::initialized_state;
    use std::fs;

    #[test]
    fn captures_exact_private_bytes_and_redacts_debug() {
        let (_parent, path) = initialized_state();
        let authority = StateAuthority::open_existing(&path).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let bytes = b"PRIVATE-STATE-CANARY";
        access.create_initial_state(bytes).unwrap();
        let mut snapshot = access.capture_state_document().unwrap();
        assert_eq!(snapshot.bytes(), bytes);
        assert!(!format!("{snapshot:?}").contains("PRIVATE-STATE-CANARY"));
        access.revalidate_state_document(&mut snapshot).unwrap();
        assert_eq!(fs::read(path.join(INITIAL_STATE_FILE)).unwrap(), bytes);
    }

    #[test]
    fn rejects_a_writer_that_ignores_the_lifecycle_lock() {
        for changed in [b"changed!".as_slice(), b"short", b"longer-than-original"] {
            let (_parent, path) = initialized_state();
            let authority = StateAuthority::open_existing(&path).unwrap();
            let guard = authority.try_lock_exclusive().unwrap();
            let access = authority.exclusive_access(&guard).unwrap();
            access.create_initial_state(b"original").unwrap();
            let mut snapshot = access.capture_state_document().unwrap();
            fs::write(path.join(INITIAL_STATE_FILE), changed).unwrap();
            assert_eq!(
                access.revalidate_state_document(&mut snapshot),
                Err(LifecycleError::UnsafeState)
            );
            assert_eq!(fs::read(path.join(INITIAL_STATE_FILE)).unwrap(), changed);
        }
    }

    #[test]
    fn rejects_snapshot_from_another_root() {
        let (_first_parent, first) = initialized_state();
        let (_second_parent, second) = initialized_state();
        let first = StateAuthority::open_existing(&first).unwrap();
        let second = StateAuthority::open_existing(&second).unwrap();
        let first_guard = first.try_lock_exclusive().unwrap();
        let second_guard = second.try_lock_exclusive().unwrap();
        let first_access = first.exclusive_access(&first_guard).unwrap();
        let second_access = second.exclusive_access(&second_guard).unwrap();
        first_access.create_initial_state(b"same").unwrap();
        second_access.create_initial_state(b"same").unwrap();
        let mut snapshot = first_access.capture_state_document().unwrap();
        assert_eq!(
            second_access.revalidate_state_document(&mut snapshot),
            Err(LifecycleError::UnsafeState)
        );
    }

    #[test]
    fn missing_and_oversized_documents_are_preserved_and_rejected() {
        let (_parent, path) = initialized_state();
        let authority = StateAuthority::open_existing(&path).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        assert_eq!(
            access.capture_state_document().err(),
            Some(LifecycleError::UnsafeState)
        );
        access.create_initial_state(b"small").unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path.join(INITIAL_STATE_FILE))
            .unwrap();
        file.set_len(MAX_INITIAL_STATE_BYTES as u64 + 1).unwrap();
        assert_eq!(
            access.capture_state_document().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert_eq!(
            file.metadata().unwrap().len(),
            MAX_INITIAL_STATE_BYTES as u64 + 1
        );
    }

    #[test]
    fn hard_link_added_after_capture_blocks_without_deleting_either_name() {
        let (_parent, path) = initialized_state();
        let authority = StateAuthority::open_existing(&path).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        access.create_initial_state(b"retained").unwrap();
        let mut snapshot = access.capture_state_document().unwrap();
        let alias = path.join("alias");
        fs::hard_link(path.join(INITIAL_STATE_FILE), &alias).unwrap();
        assert_eq!(
            access.revalidate_state_document(&mut snapshot),
            Err(LifecycleError::UnsafeState)
        );
        assert_eq!(
            access.capture_state_document().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert_eq!(fs::read(alias).unwrap(), b"retained");
        assert_eq!(
            fs::read(path.join(INITIAL_STATE_FILE)).unwrap(),
            b"retained"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_substitution_between_metadata_and_open_is_nonblocking() {
        let (_parent, path) = initialized_state();
        let authority = StateAuthority::open_existing(&path).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        access.create_initial_state(b"retained").unwrap();
        let result = open_named_private_file_with_hook(
            authority.root().unwrap(),
            OsStr::new(INITIAL_STATE_FILE),
            8,
            || {
                fs::rename(path.join(INITIAL_STATE_FILE), path.join("retained")).unwrap();
                assert!(
                    std::process::Command::new("mkfifo")
                        .arg(path.join(INITIAL_STATE_FILE))
                        .status()
                        .expect("mkfifo must be available on supported Unix test hosts")
                        .success()
                );
            },
        );
        assert_eq!(result.err(), Some(LifecycleError::UnsafeState));
        assert_eq!(fs::read(path.join("retained")).unwrap(), b"retained");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_without_reading_or_repairing_its_target() {
        use std::os::unix::fs::symlink;
        let (_parent, path) = initialized_state();
        let target = path.join("unmanaged");
        fs::write(&target, b"private-canary").unwrap();
        symlink(&target, path.join(INITIAL_STATE_FILE)).unwrap();
        let authority = StateAuthority::open_existing(&path).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        assert_eq!(
            access.capture_state_document().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert!(
            fs::symlink_metadata(path.join(INITIAL_STATE_FILE))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"private-canary");
    }

    #[cfg(unix)]
    #[test]
    fn equal_byte_replacement_and_permission_changes_cannot_revalidate() {
        use std::os::unix::fs::PermissionsExt as _;
        for replace in [true, false] {
            let (_parent, path) = initialized_state();
            let authority = StateAuthority::open_existing(&path).unwrap();
            let guard = authority.try_lock_exclusive().unwrap();
            let access = authority.exclusive_access(&guard).unwrap();
            access.create_initial_state(b"same").unwrap();
            let mut snapshot = access.capture_state_document().unwrap();
            let document = path.join(INITIAL_STATE_FILE);
            if replace {
                fs::rename(&document, path.join("retained-original")).unwrap();
                fs::write(&document, b"same").unwrap();
                fs::set_permissions(&document, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                fs::set_permissions(&document, fs::Permissions::from_mode(0o644)).unwrap();
            }
            assert_eq!(
                access.revalidate_state_document(&mut snapshot),
                Err(LifecycleError::UnsafeState)
            );
            assert_eq!(fs::read(&document).unwrap(), b"same");
            if !replace {
                assert_eq!(
                    fs::metadata(&document).unwrap().permissions().mode() & 0o777,
                    0o644
                );
                assert_eq!(
                    access.capture_state_document().err(),
                    Some(LifecycleError::UnsafeState)
                );
            }
        }
    }
}
