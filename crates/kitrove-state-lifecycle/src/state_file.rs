use super::*;

/// Shared retained read-only evidence for a data document or private cached payload.
pub(super) struct SnapshotFile {
    file: cap_std::fs::File,
    pub(super) identity: NativeIdentity,
    pub(super) bytes: Vec<u8>,
    pub(super) mode: u32,
    allow_executable: bool,
}

impl SnapshotFile {
    pub(super) fn capture(
        parent: &Dir,
        name: &OsStr,
        max_bytes: usize,
        allow_executable: bool,
    ) -> Result<Self, LifecycleError> {
        let metadata = parent
            .symlink_metadata(name)
            .map_err(|_| LifecycleError::UnsafeState)?;
        reject_link_like(&metadata)?;
        if !metadata.is_file() || metadata.len() > max_bytes as u64 {
            return Err(LifecycleError::UnsafeState);
        }
        let mut file = open_named_private_file_with_policy(
            parent,
            name,
            metadata.len(),
            allow_executable,
            || {},
        )?;
        let identity = file_identity(&file)?;
        let mode = file_mode(&file)?;
        let mut bytes = Vec::new();
        // Revalidation proves empty-file length without probing a Windows lock
        // through a second handle. Nonempty files retain the bounded EOF probe.
        if metadata.len() != 0 {
            (&mut file)
                .take(metadata.len() + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| LifecycleError::UnsafeState)?;
        }
        if bytes.len() as u64 != metadata.len() {
            return Err(LifecycleError::UnsafeState);
        }
        let mut captured = Self {
            file,
            identity,
            bytes,
            mode,
            allow_executable,
        };
        captured.revalidate(parent, name)?;
        Ok(captured)
    }

    pub(super) fn revalidate(&mut self, parent: &Dir, name: &OsStr) -> Result<(), LifecycleError> {
        self.require_named_identity(parent, name)?;
        require_exact_file_contents(&mut self.file, &self.bytes)?;
        self.require_named_identity(parent, name)
    }

    fn require_named_identity(&self, parent: &Dir, name: &OsStr) -> Result<(), LifecycleError> {
        let named = open_named_private_file_with_policy(
            parent,
            name,
            self.bytes.len() as u64,
            self.allow_executable,
            || {},
        )?;
        require_private_file_length_with_policy(
            &self.file,
            self.bytes.len() as u64,
            self.allow_executable,
        )?;
        if file_identity(&self.file)? != self.identity
            || file_identity(&named)? != self.identity
            || file_mode(&self.file)? != self.mode
            || file_mode(&named)? != self.mode
        {
            return Err(LifecycleError::UnsafeState);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn file_mode(file: &cap_std::fs::File) -> Result<u32, LifecycleError> {
    use cap_std::fs::PermissionsExt as _;
    Ok(file
        .metadata()
        .map_err(|_| LifecycleError::UnsafeState)?
        .permissions()
        .mode()
        & 0o7777)
}

#[cfg(windows)]
fn file_mode(_file: &cap_std::fs::File) -> Result<u32, LifecycleError> {
    // Windows authority is owner/DACL based, not a POSIX mode projection.
    Ok(0)
}
