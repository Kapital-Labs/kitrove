#![forbid(unsafe_code)]
//! Advisory process-wide coordination for cooperating Kitrove versions that use one local-state
//! authority.
//!
//! The lifecycle lock is deliberately distinct from Kitrove's shorter-lived
//! transaction lock. A running CLI command holds a shared lifecycle lock while
//! an application upgrade holds the exclusive form.

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use cap_fs_ext::DirExt as _;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};

mod state_document;
mod state_file;
mod state_tree;
pub use state_document::StateDocumentSnapshot;
pub use state_tree::{MAX_STATE_TREE_BYTES, MAX_STATE_TREE_ENTRIES, StateTreeSnapshot};

const CONTROL_DIRECTORY: &str = ".kitrove";
const LIFECYCLE_LOCK: &str = "lifecycle.lock";
const MAX_PATH_COMPONENTS: usize = 256;
const MAX_INITIALIZATION_ENTRIES: usize = 4;
/// Maximum serialized size accepted for the initial local-state document.
pub const MAX_INITIAL_STATE_BYTES: usize = 32 * 1024 * 1024;
const INITIAL_STATE_FILE: &str = "state.json";

/// A retained, filesystem-validated local-state authority.
///
/// This type does not validate `state.json` or its schema.
pub struct StateAuthority {
    path: PathBuf,
    ancestry: Vec<OpenedDirectory>,
}

struct OpenedDirectory {
    name: Option<OsString>,
    directory: Dir,
    identity: NativeIdentity,
}

/// Shared authority showing that no cooperating application lifecycle change is active.
#[must_use = "dropping the guard releases the lifecycle lock"]
pub struct SharedLifecycleGuard {
    _guard: LifecycleGuard,
}

/// Exclusive authority showing that no cooperating Kitrove command is using this state root.
#[must_use = "dropping the guard releases the lifecycle lock"]
pub struct ExclusiveLifecycleGuard {
    _guard: LifecycleGuard,
}

/// Guard-bound access to one exclusively locked local-state authority.
///
/// Values can only be borrowed from the authority and its matching live guard.
#[must_use = "dropping the access releases its borrows but not the underlying guard"]
pub struct ExclusiveStateAccess<'a> {
    authority: &'a StateAuthority,
    _guard: &'a ExclusiveLifecycleGuard,
}

struct LifecycleGuard {
    // Drop the operating-system lock before releasing retained ancestry capabilities.
    lock: std::fs::File,
    _lock_capability: cap_std::fs::File,
    _control: Dir,
    _ancestry: Vec<Dir>,
    root_identity: NativeIdentity,
    control_identity: NativeIdentity,
    lock_identity: NativeIdentity,
}

impl Drop for LifecycleGuard {
    fn drop(&mut self) {
        // Closing is the fallback. Explicit release avoids platform-specific delayed
        // unlock while the retained capability still owns a duplicate descriptor.
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}

/// Failure to establish or lock a trustworthy local-state authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    /// The path, ownership, permissions, link count, or retained identity was unsafe.
    UnsafeState,
    /// Another lifecycle operation holds an incompatible lock.
    LockUnavailable,
    /// An initialization-owned name already exists or was created concurrently.
    InitializationConflict,
    /// Creating lifecycle coordination or initial state authority failed.
    WriteFailed,
}

impl Display for LifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeState => "the local state authority is unsafe",
            Self::LockUnavailable => "the local state lifecycle lock is unavailable",
            Self::InitializationConflict => "a local state initialization name already exists",
            Self::WriteFailed => {
                "the local state lifecycle or initial authority could not be prepared"
            }
        })
    }
}

impl Error for LifecycleError {}

impl StateAuthority {
    /// Opens an existing exact-private state root without following link-like ancestry.
    ///
    /// This inspection never repairs permissions or creates filesystem entries.
    pub fn open_existing(path: &Path) -> Result<Self, LifecycleError> {
        let path = std::path::absolute(path).map_err(|_| LifecycleError::UnsafeState)?;
        let ancestry = open_root_nofollow(&path, DirectoryAccess::Private)?;
        require_private_directory(root_of(&ancestry)?)?;
        Ok(Self { path, ancestry })
    }

    /// Publishes a state authority only when its final directory is absent.
    ///
    /// Missing path suffixes are created with private platform security. A collision or a
    /// partially initialized final authority is refused rather than adopted because another
    /// process may already be using it. Once published, partial private state is preserved on
    /// failure rather than removed through a raceable pathname.
    pub fn initialize_absent(
        path: &Path,
    ) -> Result<(Self, ExclusiveLifecycleGuard), LifecycleError> {
        let path = std::path::absolute(path).map_err(|_| LifecycleError::UnsafeState)?;
        let ancestry = create_absent_root_nofollow(&path)?;
        let authority = Self { path, ancestry };
        let guard = authority.initialize_lifecycle_lock()?;
        Ok((authority, ExclusiveLifecycleGuard { _guard: guard }))
    }

    /// Tries to acquire shared lifecycle authority for a normal Kitrove command.
    pub fn try_lock_shared(&self) -> Result<SharedLifecycleGuard, LifecycleError> {
        self.try_lock(LockMode::Shared)
            .map(|guard| SharedLifecycleGuard { _guard: guard })
    }

    /// Tries to acquire exclusive lifecycle authority for installation or upgrade.
    pub fn try_lock_exclusive(&self) -> Result<ExclusiveLifecycleGuard, LifecycleError> {
        self.try_lock(LockMode::Exclusive)
            .map(|guard| ExclusiveLifecycleGuard { _guard: guard })
    }

    /// Binds this authority to its matching live exclusive guard.
    pub fn exclusive_access<'a>(
        &'a self,
        guard: &'a ExclusiveLifecycleGuard,
    ) -> Result<ExclusiveStateAccess<'a>, LifecycleError> {
        guard._guard.revalidate(self)?;
        Ok(ExclusiveStateAccess {
            authority: self,
            _guard: guard,
        })
    }

    fn try_lock(&self, mode: LockMode) -> Result<LifecycleGuard, LifecycleError> {
        self.require_named_root_identity()?;
        let root = self.root()?;
        let control = open_existing_private_directory(root, OsStr::new(CONTROL_DIRECTORY))?;
        let lock_capability = open_private_lock(&control)?;
        self.lock_prepared_file(mode, control, lock_capability)
    }

    fn initialize_lifecycle_lock(&self) -> Result<LifecycleGuard, LifecycleError> {
        self.initialize_lifecycle_lock_with_hook(|| {})
    }

    fn initialize_lifecycle_lock_with_hook(
        &self,
        after_publish: impl FnOnce(),
    ) -> Result<LifecycleGuard, LifecycleError> {
        self.require_named_root_identity()?;
        let root = self.root()?;
        let control = create_private_directory(root, OsStr::new(CONTROL_DIRECTORY))?;
        let lock_capability = create_private_lock(&control)?;
        after_publish();
        self.lock_prepared_file(LockMode::Exclusive, control, lock_capability)
    }

    fn lock_prepared_file(
        &self,
        mode: LockMode,
        control: Dir,
        lock_capability: cap_std::fs::File,
    ) -> Result<LifecycleGuard, LifecycleError> {
        let identity = file_identity(&lock_capability)?;
        let control_identity = directory_identity(&control)?;
        let lock = lock_capability
            .try_clone()
            .map_err(|_| LifecycleError::UnsafeState)?
            .into_std();
        let lock_result = match mode {
            LockMode::Shared => fs2::FileExt::try_lock_shared(&lock),
            LockMode::Exclusive => fs2::FileExt::try_lock_exclusive(&lock),
        };
        lock_result.map_err(|error| {
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
                LifecycleError::LockUnavailable
            } else {
                LifecycleError::UnsafeState
            }
        })?;
        require_named_file_identity(&control, &lock_capability, identity)?;
        self.require_named_root_identity()?;
        Ok(LifecycleGuard {
            lock,
            _lock_capability: lock_capability,
            _control: control,
            _ancestry: clone_ancestry(&self.ancestry)?,
            root_identity: directory_identity(self.root()?)?,
            control_identity,
            lock_identity: identity,
        })
    }

    fn require_named_root_identity(&self) -> Result<(), LifecycleError> {
        let reopened = open_root_nofollow(&self.path, DirectoryAccess::Private)?;
        if reopened.len() != self.ancestry.len() {
            return Err(LifecycleError::UnsafeState);
        }
        for (expected, observed) in self.ancestry.iter().zip(&reopened) {
            if expected.name != observed.name
                || directory_identity(&expected.directory)? != expected.identity
                || observed.identity != expected.identity
            {
                return Err(LifecycleError::UnsafeState);
            }
        }
        require_private_directory(root_of(&reopened)?)
    }

    fn root(&self) -> Result<&Dir, LifecycleError> {
        root_of(&self.ancestry)
    }
}

impl ExclusiveStateAccess<'_> {
    /// Revalidates the named root, control directory, and lock while their handles remain retained.
    pub fn revalidate(&self) -> Result<(), LifecycleError> {
        self._guard._guard.revalidate(self.authority)
    }

    /// Requires the exact lifecycle-only inventory accepted for interrupted initialization.
    pub fn validate_initialization_inventory(&self) -> Result<(), LifecycleError> {
        self.revalidate()?;
        require_exact_directory_inventory(
            self.authority.root()?,
            &[OsStr::new(CONTROL_DIRECTORY)],
        )?;
        require_exact_directory_inventory(
            &self._guard._guard._control,
            &[OsStr::new(LIFECYCLE_LOCK)],
        )?;
        self.revalidate()
    }

    /// Returns the ambient spelling for read-only topology comparison.
    #[must_use]
    pub fn state_root_path(&self) -> &Path {
        &self.authority.path
    }

    /// Creates the initial local-state document through the retained authority.
    pub fn create_initial_state(&self, contents: &[u8]) -> Result<(), LifecycleError> {
        self.create_initial_state_with_hooks(contents, || {}, || {})
    }

    fn create_initial_state_with_hooks(
        &self,
        contents: &[u8],
        after_write: impl FnOnce(),
        before_final_validation: impl FnOnce(),
    ) -> Result<(), LifecycleError> {
        if contents.len() > MAX_INITIAL_STATE_BYTES {
            return Err(LifecycleError::WriteFailed);
        }
        self.validate_initialization_inventory()?;
        let root = self.authority.root()?;
        let mut file =
            create_private_file_with_contents(root, OsStr::new(INITIAL_STATE_FILE), contents)?;
        after_write();
        let identity = file_identity(&file)?;
        require_named_private_file_identity(
            root,
            OsStr::new(INITIAL_STATE_FILE),
            &file,
            identity,
            contents.len() as u64,
        )?;
        require_exact_file_contents(&mut file, contents)?;
        before_final_validation();
        require_exact_file_contents(&mut file, contents)?;
        require_named_private_file_identity(
            root,
            OsStr::new(INITIAL_STATE_FILE),
            &file,
            identity,
            contents.len() as u64,
        )?;
        require_exact_directory_inventory(
            root,
            &[
                OsStr::new(CONTROL_DIRECTORY),
                OsStr::new(INITIAL_STATE_FILE),
            ],
        )?;
        require_exact_directory_inventory(
            &self._guard._guard._control,
            &[OsStr::new(LIFECYCLE_LOCK)],
        )?;
        self.revalidate()?;
        sync_directory(root)
    }
}

fn require_exact_file_contents(
    file: &mut cap_std::fs::File,
    contents: &[u8],
) -> Result<(), LifecycleError> {
    // Empty files have no bytes to read. Windows byte-range locks also cover
    // offsets beyond EOF, so probing a held empty lock through another handle
    // can fail. Verify EOF directly; callers retain identity/permission checks.
    if contents.is_empty() {
        return if file
            .metadata()
            .map_err(|_| LifecycleError::UnsafeState)?
            .len()
            == 0
        {
            Ok(())
        } else {
            Err(LifecycleError::UnsafeState)
        };
    }
    file.seek(io::SeekFrom::Start(0))
        .map_err(|_| LifecycleError::UnsafeState)?;
    let mut observed = Vec::with_capacity(contents.len());
    let read_limit = u64::try_from(contents.len())
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or(LifecycleError::UnsafeState)?;
    file.take(read_limit)
        .read_to_end(&mut observed)
        .map_err(|_| LifecycleError::UnsafeState)?;
    if observed == contents {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

impl LifecycleGuard {
    fn revalidate(&self, authority: &StateAuthority) -> Result<(), LifecycleError> {
        authority.require_named_root_identity()?;
        if directory_identity(authority.root()?)? != self.root_identity {
            return Err(LifecycleError::UnsafeState);
        }
        require_retained_directory_identity(
            authority.root()?,
            OsStr::new(CONTROL_DIRECTORY),
            &self._control,
            self.control_identity,
        )?;
        require_named_file_identity(&self._control, &self._lock_capability, self.lock_identity)
    }
}

fn require_exact_directory_inventory(
    directory: &Dir,
    allowed: &[&OsStr],
) -> Result<(), LifecycleError> {
    let mut observed = Vec::new();
    for entry in directory
        .read_dir(".")
        .map_err(|_| LifecycleError::UnsafeState)?
    {
        let entry = entry.map_err(|_| LifecycleError::UnsafeState)?;
        observed.push(entry.file_name());
        if observed.len() > MAX_INITIALIZATION_ENTRIES {
            return Err(LifecycleError::UnsafeState);
        }
    }
    observed.sort_unstable();
    let mut expected = allowed
        .iter()
        .map(|name| name.to_os_string())
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if observed == expected {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[derive(Clone, Copy)]
enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy)]
enum DirectoryAccess {
    Structural,
    Private,
}

fn open_root_nofollow(
    path: &Path,
    final_access: DirectoryAccess,
) -> Result<Vec<OpenedDirectory>, LifecycleError> {
    let (anchor, components) = split_absolute_root(path)?;
    let mut directory = open_anchor(&anchor)?;
    reject_link_like(
        &directory
            .dir_metadata()
            .map_err(|_| LifecycleError::UnsafeState)?,
    )?;
    require_trusted_ancestor(&directory)?;
    let mut ancestry = vec![OpenedDirectory {
        name: None,
        identity: directory_identity(&directory)?,
        directory,
    }];
    let component_count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        let access = if index + 1 == component_count {
            final_access
        } else {
            DirectoryAccess::Structural
        };
        directory = open_child_directory(
            &ancestry
                .last()
                .ok_or(LifecycleError::UnsafeState)?
                .directory,
            &component,
            access,
        )?;
        require_trusted_ancestor(&directory)?;
        ancestry.push(OpenedDirectory {
            name: Some(component),
            identity: directory_identity(&directory)?,
            directory,
        });
    }
    Ok(ancestry)
}

fn create_absent_root_nofollow(path: &Path) -> Result<Vec<OpenedDirectory>, LifecycleError> {
    let (anchor, components) = split_absolute_root(path)?;
    if components.is_empty() {
        return Err(LifecycleError::InitializationConflict);
    }
    let directory = open_anchor(&anchor)?;
    reject_link_like(
        &directory
            .dir_metadata()
            .map_err(|_| LifecycleError::UnsafeState)?,
    )?;
    require_trusted_ancestor(&directory)?;
    let mut ancestry = vec![OpenedDirectory {
        name: None,
        identity: directory_identity(&directory)?,
        directory,
    }];
    let component_count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        let parent = &ancestry
            .last()
            .ok_or(LifecycleError::UnsafeState)?
            .directory;
        let is_final = index + 1 == component_count;
        let next = match parent.symlink_metadata(&component) {
            Ok(_) if is_final => {
                return Err(LifecycleError::InitializationConflict);
            }
            Ok(_) => open_child_directory(parent, &component, DirectoryAccess::Structural),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_directory(parent, &component)
            }
            Err(_) => Err(LifecycleError::UnsafeState),
        };
        let directory = next?;
        let identity =
            require_trusted_ancestor(&directory).and_then(|()| directory_identity(&directory))?;
        ancestry.push(OpenedDirectory {
            name: Some(component),
            identity,
            directory,
        });
    }
    Ok(ancestry)
}

#[cfg(unix)]
fn open_anchor(anchor: &Path) -> Result<Dir, LifecycleError> {
    Dir::open_ambient_dir(anchor, ambient_authority()).map_err(|_| LifecycleError::UnsafeState)
}

#[cfg(windows)]
fn open_anchor(anchor: &Path) -> Result<Dir, LifecycleError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .access_mode(kitrove_windows_security::STRUCTURAL_DIRECTORY_ACCESS)
        .share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE)
        .custom_flags(kitrove_windows_security::PRIVATE_DIRECTORY_OPEN_FLAGS)
        .open(anchor)
        .map_err(|_| LifecycleError::UnsafeState)?;
    Ok(Dir::from_std_file(file))
}

fn root_of(ancestry: &[OpenedDirectory]) -> Result<&Dir, LifecycleError> {
    ancestry
        .last()
        .map(|entry| &entry.directory)
        .ok_or(LifecycleError::UnsafeState)
}

fn clone_ancestry(ancestry: &[OpenedDirectory]) -> Result<Vec<Dir>, LifecycleError> {
    ancestry
        .iter()
        .map(|entry| {
            entry
                .directory
                .try_clone()
                .map_err(|_| LifecycleError::UnsafeState)
        })
        .collect()
}

fn split_absolute_root(path: &Path) -> Result<(PathBuf, Vec<OsString>), LifecycleError> {
    if raw_parent_component(path) {
        return Err(LifecycleError::UnsafeState);
    }
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(component) if component == OsStr::new(".") => {}
            Component::Normal(component) if component == OsStr::new("..") => {
                return Err(LifecycleError::UnsafeState);
            }
            Component::Normal(component) => components.push(component.to_owned()),
            Component::ParentDir => return Err(LifecycleError::UnsafeState),
        }
        if components.len() > MAX_PATH_COMPONENTS {
            return Err(LifecycleError::UnsafeState);
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(LifecycleError::UnsafeState);
    }
    Ok((anchor, components))
}

#[cfg(windows)]
fn raw_parent_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| segment == "..")
}

#[cfg(not(windows))]
const fn raw_parent_component(_path: &Path) -> bool {
    false
}

fn open_child_directory(
    parent: &Dir,
    name: &OsStr,
    access: DirectoryAccess,
) -> Result<Dir, LifecycleError> {
    let before = parent
        .symlink_metadata(name)
        .map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&before)?;
    if !before.is_dir() {
        return Err(LifecycleError::UnsafeState);
    }
    let directory = open_child_handle(parent, name, access)?;
    let after = directory
        .dir_metadata()
        .map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&after)?;
    if !after.is_dir() {
        return Err(LifecycleError::UnsafeState);
    }
    require_named_directory_identity(parent, name, &directory, &before, &after, access)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_child_handle(
    parent: &Dir,
    name: &OsStr,
    _access: DirectoryAccess,
) -> Result<Dir, LifecycleError> {
    parent
        .open_dir_nofollow(name)
        .map_err(|_| LifecycleError::UnsafeState)
}

#[cfg(windows)]
fn open_child_handle(
    parent: &Dir,
    name: &OsStr,
    access: DirectoryAccess,
) -> Result<Dir, LifecycleError> {
    use cap_std::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .access_mode(match access {
            DirectoryAccess::Structural => kitrove_windows_security::STRUCTURAL_DIRECTORY_ACCESS,
            DirectoryAccess::Private => {
                kitrove_windows_security::PRIVATE_DIRECTORY_AUTHORITY_ACCESS
            }
        })
        .share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE)
        .custom_flags(kitrove_windows_security::PRIVATE_DIRECTORY_OPEN_FLAGS)
        .follow(FollowSymlinks::No);
    parent
        .open_with(name, &options)
        .map(|file| Dir::from_std_file(file.into_std()))
        .map_err(|_| LifecycleError::UnsafeState)
}

#[cfg(unix)]
fn require_named_directory_identity(
    _parent: &Dir,
    _name: &OsStr,
    _directory: &Dir,
    before: &Metadata,
    after: &Metadata,
    _access: DirectoryAccess,
) -> Result<(), LifecycleError> {
    if metadata_identity(before) == metadata_identity(after) {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[cfg(windows)]
fn require_named_directory_identity(
    parent: &Dir,
    name: &OsStr,
    directory: &Dir,
    _before: &Metadata,
    _after: &Metadata,
    access: DirectoryAccess,
) -> Result<(), LifecycleError> {
    let rebound = open_child_handle(parent, name, access)?;
    reject_link_like(
        &rebound
            .dir_metadata()
            .map_err(|_| LifecycleError::UnsafeState)?,
    )?;
    if directory_identity(directory)? == directory_identity(&rebound)? {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

fn require_retained_directory_identity(
    parent: &Dir,
    name: &OsStr,
    directory: &Dir,
    expected: NativeIdentity,
) -> Result<(), LifecycleError> {
    let reopened = open_existing_private_directory(parent, name)?;
    if directory_identity(directory)? == expected && directory_identity(&reopened)? == expected {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[cfg(unix)]
fn require_trusted_ancestor(directory: &Dir) -> Result<(), LifecycleError> {
    use cap_fs_ext::OsMetadataExt as _;
    use cap_std::fs::PermissionsExt as _;

    let metadata = directory
        .dir_metadata()
        .map_err(|_| LifecycleError::UnsafeState)?;
    let owner = metadata.uid();
    let current = rustix::process::geteuid().as_raw();
    if !metadata.is_dir()
        || (owner != 0 && owner != current)
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(LifecycleError::UnsafeState);
    }
    require_safe_ancestry_acl(directory)
}

#[cfg(windows)]
const fn require_trusted_ancestor(_directory: &Dir) -> Result<(), LifecycleError> {
    // Every retained Windows ancestry handle denies delete sharing, preventing a
    // parent rename even when an inherited ancestor DACL is intentionally broad.
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_safe_ancestry_acl(directory: &Dir) -> Result<(), LifecycleError> {
    use std::os::fd::AsFd as _;

    let acl =
        calcifer_macos_acl::read_acl(directory.as_fd()).map_err(|_| LifecycleError::UnsafeState)?;
    if acl.flags == 0
        && acl
            .entries
            .iter()
            .all(|entry| entry.tag == calcifer_macos_acl::TAG_DENY)
    {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
const fn require_safe_ancestry_acl(_directory: &Dir) -> Result<(), LifecycleError> {
    Ok(())
}

fn open_existing_private_directory(parent: &Dir, name: &OsStr) -> Result<Dir, LifecycleError> {
    let directory = open_child_directory(parent, name, DirectoryAccess::Private)?;
    require_private_directory(&directory)?;
    Ok(directory)
}

#[cfg(unix)]
fn create_private_directory(parent: &Dir, name: &OsStr) -> Result<Dir, LifecycleError> {
    use cap_std::fs::{DirBuilder, DirBuilderExt as _, Permissions, PermissionsExt as _};

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            LifecycleError::InitializationConflict
        } else {
            LifecycleError::WriteFailed
        }
    })?;
    (|| {
        let directory = open_child_directory(parent, name, DirectoryAccess::Private)
            .map_err(|_| LifecycleError::WriteFailed)?;
        directory
            .set_permissions(".", Permissions::from_mode(0o700))
            .map_err(|_| LifecycleError::WriteFailed)?;
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd as _;
            calcifer_macos_acl::clear_acl(directory.as_fd())
                .map_err(|_| LifecycleError::WriteFailed)?;
        }
        require_private_directory(&directory).map_err(|_| LifecycleError::WriteFailed)?;
        sync_directory(parent)?;
        Ok(directory)
    })()
}

#[cfg(windows)]
fn create_private_directory(parent: &Dir, name: &OsStr) -> Result<Dir, LifecycleError> {
    use kitrove_windows_security::ObjectCreationError;

    kitrove_windows_security::create_private_directory(parent, name)
        .map(Dir::from_std_file)
        .map_err(|error| match error {
            ObjectCreationError::AlreadyExists => LifecycleError::InitializationConflict,
            ObjectCreationError::Failed
            | ObjectCreationError::RollbackFailed
            | ObjectCreationError::HandoffFailed => LifecycleError::WriteFailed,
        })
}

#[cfg(unix)]
fn create_private_lock(control: &Dir) -> Result<cap_std::fs::File, LifecycleError> {
    use cap_std::fs::{OpenOptionsExt as _, Permissions, PermissionsExt as _};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let file = control
        .open_with(LIFECYCLE_LOCK, &options)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                LifecycleError::InitializationConflict
            } else {
                LifecycleError::WriteFailed
            }
        })?;
    (|| {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|_| LifecycleError::WriteFailed)?;
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsFd as _;
            calcifer_macos_acl::clear_acl(file.as_fd()).map_err(|_| LifecycleError::WriteFailed)?;
        }
        require_private_file(&file).map_err(|_| LifecycleError::WriteFailed)?;
        file.sync_all().map_err(|_| LifecycleError::WriteFailed)?;
        sync_directory(control)?;
        Ok(())
    })()?;
    Ok(file)
}

#[cfg(windows)]
fn create_private_lock(control: &Dir) -> Result<cap_std::fs::File, LifecycleError> {
    use kitrove_windows_security::ObjectCreationError;

    let created =
        kitrove_windows_security::create_private_file(control, OsStr::new(LIFECYCLE_LOCK))
            .map_err(|error| match error {
                ObjectCreationError::AlreadyExists => LifecycleError::InitializationConflict,
                ObjectCreationError::Failed
                | ObjectCreationError::RollbackFailed
                | ObjectCreationError::HandoffFailed => LifecycleError::WriteFailed,
            })?;
    created
        .sync_all()
        .map_err(|_| LifecycleError::WriteFailed)?;
    sync_directory(control)?;
    retain_created_private_file(control, OsStr::new(LIFECYCLE_LOCK), created)
}

#[cfg(windows)]
fn retain_created_private_file(
    parent: &Dir,
    name: &OsStr,
    created: std::fs::File,
) -> Result<cap_std::fs::File, LifecycleError> {
    let expected = kitrove_windows_security::file_identity(&created)
        .map_err(|_| LifecycleError::WriteFailed)?;
    // Creation retains DELETE authority for rollback. Close it before acquiring the
    // retained handle, whose share policy prevents replacement of the file name.
    drop(created);
    let reopened = kitrove_windows_security::open_private_lock_file(parent, name)
        .map_err(|_| LifecycleError::WriteFailed)?;
    if kitrove_windows_security::file_identity(&reopened)
        .map_err(|_| LifecycleError::WriteFailed)?
        != expected
    {
        return Err(LifecycleError::UnsafeState);
    }
    Ok(cap_std::fs::File::from_std(reopened))
}

#[cfg(unix)]
fn create_private_file_with_contents(
    parent: &Dir,
    name: &OsStr,
    contents: &[u8],
) -> Result<cap_std::fs::File, LifecycleError> {
    use cap_std::fs::{OpenOptionsExt as _, Permissions, PermissionsExt as _};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = parent.open_with(name, &options).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            LifecycleError::InitializationConflict
        } else {
            LifecycleError::WriteFailed
        }
    })?;
    file.write_all(contents)
        .map_err(|_| LifecycleError::WriteFailed)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| LifecycleError::WriteFailed)?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd as _;
        calcifer_macos_acl::clear_acl(file.as_fd()).map_err(|_| LifecycleError::WriteFailed)?;
    }
    require_private_file_length(&file, contents.len() as u64)
        .map_err(|_| LifecycleError::WriteFailed)?;
    file.sync_all().map_err(|_| LifecycleError::WriteFailed)?;
    sync_directory(parent)?;
    Ok(file)
}

#[cfg(windows)]
fn create_private_file_with_contents(
    parent: &Dir,
    name: &OsStr,
    contents: &[u8],
) -> Result<cap_std::fs::File, LifecycleError> {
    use kitrove_windows_security::ObjectCreationError;

    let mut file = kitrove_windows_security::create_private_file(parent, name)
        .map(cap_std::fs::File::from_std)
        .map_err(|error| match error {
            ObjectCreationError::AlreadyExists => LifecycleError::InitializationConflict,
            ObjectCreationError::Failed
            | ObjectCreationError::RollbackFailed
            | ObjectCreationError::HandoffFailed => LifecycleError::WriteFailed,
        })?;
    file.write_all(contents)
        .map_err(|_| LifecycleError::WriteFailed)?;
    require_private_file_length(&file, contents.len() as u64)
        .map_err(|_| LifecycleError::WriteFailed)?;
    file.sync_all().map_err(|_| LifecycleError::WriteFailed)?;
    sync_directory(parent)?;
    retain_created_private_file(parent, name, file.into_std())
}

fn open_private_lock(control: &Dir) -> Result<cap_std::fs::File, LifecycleError> {
    let before = control
        .symlink_metadata(LIFECYCLE_LOCK)
        .map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&before)?;
    if !before.is_file() {
        return Err(LifecycleError::UnsafeState);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options
            .access_mode(kitrove_windows_security::PRIVATE_FILE_INSPECT_ACCESS)
            .share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE);
    }
    let file = control
        .open_with(LIFECYCLE_LOCK, &options)
        .map_err(|_| LifecycleError::UnsafeState)?;
    require_private_file(&file)?;
    require_opened_file_identity(control, &file, &before)?;
    Ok(file)
}

#[cfg(unix)]
fn require_opened_file_identity(
    _control: &Dir,
    file: &cap_std::fs::File,
    before: &Metadata,
) -> Result<(), LifecycleError> {
    if metadata_identity(before) == file_identity(file)? {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[cfg(windows)]
fn require_opened_file_identity(
    control: &Dir,
    file: &cap_std::fs::File,
    _before: &Metadata,
) -> Result<(), LifecycleError> {
    let mut options = OpenOptions::new();
    use cap_std::fs::OpenOptionsExt as _;
    options
        .access_mode(kitrove_windows_security::PRIVATE_FILE_INSPECT_ACCESS)
        .share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE)
        .follow(FollowSymlinks::No);
    let rebound = control
        .open_with(LIFECYCLE_LOCK, &options)
        .map_err(|_| LifecycleError::UnsafeState)?;
    require_private_file(&rebound)?;
    if file_identity(file)? == file_identity(&rebound)? {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[cfg(unix)]
fn require_private_directory(directory: &Dir) -> Result<(), LifecycleError> {
    use cap_fs_ext::OsMetadataExt as _;
    use cap_std::fs::PermissionsExt as _;

    let metadata = directory
        .dir_metadata()
        .map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&metadata)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(LifecycleError::UnsafeState);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd as _;
        if !calcifer_macos_acl::read_acl(directory.as_fd())
            .map_err(|_| LifecycleError::UnsafeState)?
            .is_empty()
        {
            return Err(LifecycleError::UnsafeState);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn require_private_directory(directory: &Dir) -> Result<(), LifecycleError> {
    kitrove_windows_security::inspect_private_directory(directory)
        .map_err(|_| LifecycleError::UnsafeState)
}

fn require_private_file(file: &cap_std::fs::File) -> Result<(), LifecycleError> {
    require_private_file_length(file, 0)
}

fn require_private_file_length(
    file: &cap_std::fs::File,
    expected_length: u64,
) -> Result<(), LifecycleError> {
    require_private_file_length_with_policy(file, expected_length, false)
}

#[cfg(unix)]
fn require_private_file_length_with_policy(
    file: &cap_std::fs::File,
    expected_length: u64,
    allow_executable: bool,
) -> Result<(), LifecycleError> {
    use cap_fs_ext::OsMetadataExt as _;
    use cap_std::fs::PermissionsExt as _;

    let metadata = file.metadata().map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&metadata)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let permitted_mode = mode == 0o600 || (allow_executable && mode == 0o700);
    if !metadata.is_file()
        || metadata.len() != expected_length
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || !permitted_mode
        || cap_fs_ext::MetadataExt::nlink(&metadata) != 1
    {
        return Err(LifecycleError::UnsafeState);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd as _;
        if !calcifer_macos_acl::read_acl(file.as_fd())
            .map_err(|_| LifecycleError::UnsafeState)?
            .is_empty()
        {
            return Err(LifecycleError::UnsafeState);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn require_private_file_length_with_policy(
    file: &cap_std::fs::File,
    expected_length: u64,
    _allow_executable: bool,
) -> Result<(), LifecycleError> {
    let metadata = file.metadata().map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&metadata)?;
    if !metadata.is_file() || metadata.len() != expected_length {
        return Err(LifecycleError::UnsafeState);
    }
    kitrove_windows_security::inspect_private_single_link_file(file)
        .map_err(|_| LifecycleError::UnsafeState)
}

fn require_named_file_identity(
    control: &Dir,
    file: &cap_std::fs::File,
    expected: NativeIdentity,
) -> Result<(), LifecycleError> {
    let reopened = open_private_lock(control)?;
    if file_identity(file)? == expected && file_identity(&reopened)? == expected {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

fn require_named_private_file_identity(
    parent: &Dir,
    name: &OsStr,
    file: &cap_std::fs::File,
    expected: NativeIdentity,
    expected_length: u64,
) -> Result<(), LifecycleError> {
    let reopened = open_named_private_file(parent, name, expected_length)?;
    if file_identity(file)? == expected && file_identity(&reopened)? == expected {
        Ok(())
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

fn open_named_private_file(
    parent: &Dir,
    name: &OsStr,
    expected_length: u64,
) -> Result<cap_std::fs::File, LifecycleError> {
    open_named_private_file_with_hook(parent, name, expected_length, || {})
}

fn open_named_private_file_with_hook(
    parent: &Dir,
    name: &OsStr,
    expected_length: u64,
    before_open: impl FnOnce(),
) -> Result<cap_std::fs::File, LifecycleError> {
    open_named_private_file_with_policy(parent, name, expected_length, false, before_open)
}

fn open_named_private_file_with_policy(
    parent: &Dir,
    name: &OsStr,
    expected_length: u64,
    allow_executable: bool,
    before_open: impl FnOnce(),
) -> Result<cap_std::fs::File, LifecycleError> {
    let before = parent
        .symlink_metadata(name)
        .map_err(|_| LifecycleError::UnsafeState)?;
    reject_link_like(&before)?;
    if !before.is_file() || before.len() != expected_length {
        return Err(LifecycleError::UnsafeState);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        // A concurrent FIFO substitution must not block before metadata validation.
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options
            .access_mode(kitrove_windows_security::PRIVATE_FILE_INSPECT_ACCESS)
            .share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE);
    }
    before_open();
    let reopened = parent
        .open_with(name, &options)
        .map_err(|_| LifecycleError::UnsafeState)?;
    require_private_file_length_with_policy(&reopened, expected_length, allow_executable)?;
    if metadata_identity_matches_file(&before, &reopened)? {
        Ok(reopened)
    } else {
        Err(LifecycleError::UnsafeState)
    }
}

#[cfg(unix)]
fn metadata_identity_matches_file(
    metadata: &Metadata,
    file: &cap_std::fs::File,
) -> Result<bool, LifecycleError> {
    Ok(metadata_identity(metadata) == file_identity(file)?)
}

#[cfg(windows)]
fn metadata_identity_matches_file(
    _metadata: &Metadata,
    _file: &cap_std::fs::File,
) -> Result<bool, LifecycleError> {
    Ok(true)
}

#[cfg(unix)]
fn sync_directory(directory: &Dir) -> Result<(), LifecycleError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(".", &options)
        .and_then(|file| file.into_std().sync_all())
        .map_err(|_| LifecycleError::WriteFailed)
}

#[cfg(windows)]
const fn sync_directory(_directory: &Dir) -> Result<(), LifecycleError> {
    // Windows has no directory equivalent of FlushFileBuffers. The created file
    // itself is flushed before its containing directory is released.
    Ok(())
}

fn reject_link_like(metadata: &Metadata) -> Result<(), LifecycleError> {
    if metadata.is_symlink() || metadata_is_windows_reparse(metadata) {
        Err(LifecycleError::UnsafeState)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn metadata_is_windows_reparse(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct NativeIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn metadata_identity(metadata: &Metadata) -> NativeIdentity {
    use cap_fs_ext::OsMetadataExt as _;
    NativeIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn file_identity(file: &cap_std::fs::File) -> Result<NativeIdentity, LifecycleError> {
    file.metadata()
        .map_err(|_| LifecycleError::UnsafeState)
        .map(|metadata| metadata_identity(&metadata))
}

#[cfg(unix)]
fn directory_identity(directory: &Dir) -> Result<NativeIdentity, LifecycleError> {
    directory
        .dir_metadata()
        .map_err(|_| LifecycleError::UnsafeState)
        .map(|metadata| metadata_identity(&metadata))
}

#[cfg(windows)]
type NativeIdentity = kitrove_windows_security::WindowsFileIdentity;

#[cfg(windows)]
fn file_identity(file: &cap_std::fs::File) -> Result<NativeIdentity, LifecycleError> {
    kitrove_windows_security::file_identity(file).map_err(|_| LifecycleError::UnsafeState)
}

#[cfg(windows)]
fn directory_identity(directory: &Dir) -> Result<NativeIdentity, LifecycleError> {
    kitrove_windows_security::file_identity(directory).map_err(|_| LifecycleError::UnsafeState)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufRead as _, BufReader};
    #[cfg(target_os = "macos")]
    use std::os::fd::AsFd as _;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

    use super::*;

    fn private_parent() -> tempfile::TempDir {
        #[cfg(unix)]
        let state = {
            let home = std::env::var_os("HOME").expect("test user directory");
            tempfile::Builder::new()
                .prefix(".kitrove-lifecycle-test-")
                .tempdir_in(home)
                .unwrap()
        };
        #[cfg(windows)]
        let state = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
            #[cfg(target_os = "macos")]
            calcifer_macos_acl::clear_acl(fs::File::open(state.path()).unwrap().as_fd()).unwrap();
        }
        state
    }

    pub(super) fn initialized_state() -> (tempfile::TempDir, PathBuf) {
        let parent = private_parent();
        let path = fs::canonicalize(parent.path()).unwrap().join("state");
        let (_, guard) = StateAuthority::initialize_absent(&path).unwrap();
        drop(guard);
        (parent, path)
    }

    struct LockChild {
        process: Child,
        input: Option<ChildStdin>,
        _output: BufReader<ChildStdout>,
    }

    impl LockChild {
        fn start(path: &Path, mode: &str) -> Self {
            let mut process = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::subprocess_lock_actor", "--nocapture"])
                .env("KITROVE_LIFECYCLE_TEST_PATH", path)
                .env("KITROVE_LIFECYCLE_TEST_MODE", mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut output = BufReader::new(process.stdout.take().unwrap());
            let mut line = String::new();
            loop {
                assert_ne!(output.read_line(&mut line).unwrap(), 0);
                if line.contains("lifecycle-child-ready") {
                    break;
                }
                line.clear();
            }
            Self {
                input: process.stdin.take(),
                process,
                _output: output,
            }
        }

        fn spawn_inheritance_probe(path: &Path) {
            let mut process = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::subprocess_lock_actor", "--nocapture"])
                .env("KITROVE_LIFECYCLE_TEST_PATH", path)
                .env("KITROVE_LIFECYCLE_TEST_MODE", "exclusive-spawn")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut output = BufReader::new(process.stdout.take().unwrap());
            let mut line = String::new();
            loop {
                assert_ne!(output.read_line(&mut line).unwrap(), 0);
                if line.contains("lifecycle-child-ready") {
                    break;
                }
                line.clear();
            }
            assert!(process.wait().unwrap().success());
        }

        fn stop(mut self) {
            drop(self.input.take());
            assert!(self.process.wait().unwrap().success());
        }
    }

    #[test]
    fn subprocess_lock_actor() {
        let Some(path) = std::env::var_os("KITROVE_LIFECYCLE_TEST_PATH") else {
            return;
        };
        let mode = std::env::var("KITROVE_LIFECYCLE_TEST_MODE").unwrap();
        let authority = StateAuthority::open_existing(Path::new(&path)).unwrap();
        let _guard = match mode.as_str() {
            "shared" => authority
                .try_lock_shared()
                .map(|guard| Box::new(guard) as Box<dyn Send>),
            "exclusive" | "exclusive-spawn" => authority
                .try_lock_exclusive()
                .map(|guard| Box::new(guard) as Box<dyn Send>),
            _ => panic!("unknown subprocess lock mode"),
        }
        .unwrap();
        if mode == "exclusive-spawn" {
            let grandchild = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::subprocess_idle_actor", "--nocapture"])
                .env("KITROVE_LIFECYCLE_IDLE_TEST", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            std::mem::forget(grandchild);
        }
        println!("lifecycle-child-ready");
        std::io::stdout().flush().unwrap();
        if mode == "exclusive-spawn" {
            return;
        }
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input).unwrap();
    }

    #[test]
    fn subprocess_idle_actor() {
        if std::env::var_os("KITROVE_LIFECYCLE_IDLE_TEST").is_some() {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    #[test]
    fn initializer_is_absent_only_and_existing_locking_never_mints_authority() {
        let parent = private_parent();
        let parent_path = fs::canonicalize(parent.path()).unwrap();
        let state = parent_path.join("state");
        let (authority, guard) = StateAuthority::initialize_absent(&state).unwrap();
        assert!(state.join(CONTROL_DIRECTORY).join(LIFECYCLE_LOCK).is_file());
        assert_eq!(
            StateAuthority::initialize_absent(&state).err(),
            Some(LifecycleError::InitializationConflict)
        );
        drop(guard);
        drop(authority);

        let legacy = parent_path.join("legacy-state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::create_dir(&legacy).unwrap();
            fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).unwrap();
            #[cfg(target_os = "macos")]
            calcifer_macos_acl::clear_acl(fs::File::open(&legacy).unwrap().as_fd()).unwrap();
        }
        #[cfg(windows)]
        kitrove_windows_security::ensure_private_directory_for_tests(&legacy).unwrap();
        let legacy_authority = StateAuthority::open_existing(&legacy).unwrap();
        assert_eq!(
            legacy_authority.try_lock_shared().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert!(!legacy.join(CONTROL_DIRECTORY).exists());
    }

    #[test]
    fn initializer_creates_private_missing_suffixes() {
        let parent = private_parent();
        let parent_path = fs::canonicalize(parent.path()).unwrap();
        let state = parent_path.join("missing/parent/state");
        let (_authority, _guard) = StateAuthority::initialize_absent(&state).unwrap();

        for directory in [
            parent_path.join("missing"),
            parent_path.join("missing/parent"),
            state,
        ] {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            #[cfg(windows)]
            {
                let directory =
                    Dir::open_ambient_dir(directory, cap_std::ambient_authority()).unwrap();
                kitrove_windows_security::inspect_private_directory(&directory).unwrap();
            }
        }
    }

    #[test]
    fn initializer_contention_preserves_one_named_lock_namespace() {
        let parent = private_parent();
        let parent_path = fs::canonicalize(parent.path()).unwrap();
        let state = parent_path.join("state");
        let ancestry = create_absent_root_nofollow(&state).unwrap();
        let authority = StateAuthority {
            path: state.clone(),
            ancestry,
        };
        let mut peer_lock = None;
        assert_eq!(
            authority
                .initialize_lifecycle_lock_with_hook(|| {
                    let control = open_existing_private_directory(
                        authority.root().unwrap(),
                        OsStr::new(CONTROL_DIRECTORY),
                    )
                    .unwrap();
                    let lock = open_private_lock(&control).unwrap().into_std();
                    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
                    peer_lock = Some(lock);
                })
                .err(),
            Some(LifecycleError::LockUnavailable)
        );
        assert!(state.join(CONTROL_DIRECTORY).join(LIFECYCLE_LOCK).is_file());
        assert_eq!(
            StateAuthority::initialize_absent(&state).err(),
            Some(LifecycleError::InitializationConflict)
        );
        drop(peer_lock);
        let reopened = StateAuthority::open_existing(&state).unwrap();
        let _guard = reopened.try_lock_exclusive().unwrap();
    }

    #[test]
    fn concurrent_initializers_have_one_winner() {
        use std::sync::{Arc, Barrier};

        let parent = private_parent();
        let state = fs::canonicalize(parent.path()).unwrap().join("state");
        let barrier = Arc::new(Barrier::new(3));
        let attempts = (0..2)
            .map(|_| {
                let state = state.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    StateAuthority::initialize_absent(&state)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = attempts
            .into_iter()
            .map(|attempt| attempt.join().unwrap())
            .collect::<Vec<_>>();
        let errors = results
            .iter()
            .map(|result| result.as_ref().err().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "{errors:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| { matches!(result, Err(LifecycleError::InitializationConflict)) })
                .count(),
            1
        );
    }

    #[test]
    fn refuses_unbounded_path_components_before_opening() {
        let base = std::path::absolute(".").unwrap();
        let (anchor, existing) = split_absolute_root(&base).unwrap();
        let existing_count = existing.len();
        let mut exact = anchor;
        exact.extend(existing);
        for _ in existing_count..MAX_PATH_COMPONENTS {
            exact.push("component");
        }
        assert!(split_absolute_root(&exact).is_ok());
        exact.push("overflow");
        assert!(matches!(
            split_absolute_root(&exact),
            Err(LifecycleError::UnsafeState)
        ));
    }

    #[test]
    fn locks_exclude_other_processes_and_release_on_exit() {
        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();

        let shared = LockChild::start(&state, "shared");
        let local_shared = authority.try_lock_shared().unwrap();
        assert_eq!(
            authority.try_lock_exclusive().err(),
            Some(LifecycleError::LockUnavailable)
        );
        drop(local_shared);
        shared.stop();

        let exclusive = LockChild::start(&state, "exclusive");
        assert_eq!(
            authority.try_lock_shared().err(),
            Some(LifecycleError::LockUnavailable)
        );
        assert_eq!(
            authority.try_lock_exclusive().err(),
            Some(LifecycleError::LockUnavailable)
        );
        exclusive.stop();
        let _released = authority.try_lock_exclusive().unwrap();
    }

    #[test]
    fn lock_handle_is_not_inherited_by_spawned_process() {
        let (_parent, state) = initialized_state();
        LockChild::spawn_inheritance_probe(&state);
        let authority = StateAuthority::open_existing(&state).unwrap();
        let _exclusive = authority.try_lock_exclusive().unwrap();
    }

    #[test]
    fn exclusive_access_accepts_only_its_matching_live_guard() {
        let (_first_parent, first_path) = initialized_state();
        let (_second_parent, second_path) = initialized_state();
        let first = StateAuthority::open_existing(&first_path).unwrap();
        let second = StateAuthority::open_existing(&second_path).unwrap();
        let first_guard = first.try_lock_exclusive().unwrap();

        assert!(
            first
                .exclusive_access(&first_guard)
                .unwrap()
                .revalidate()
                .is_ok()
        );
        assert!(matches!(
            second.exclusive_access(&first_guard),
            Err(LifecycleError::UnsafeState)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_access_rejects_replaced_named_control_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let control = state.join(CONTROL_DIRECTORY);
        fs::rename(&control, state.join("displaced-control")).unwrap();
        fs::create_dir(&control).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(control.join(LIFECYCLE_LOCK), []).unwrap();
        fs::set_permissions(
            control.join(LIFECYCLE_LOCK),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        assert_eq!(access.revalidate(), Err(LifecycleError::UnsafeState));
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_access_rejects_replaced_named_lock_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let control = state.join(CONTROL_DIRECTORY);
        let lock = control.join(LIFECYCLE_LOCK);
        fs::rename(&lock, control.join("displaced-lock")).unwrap();
        fs::write(&lock, []).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(access.revalidate(), Err(LifecycleError::UnsafeState));
    }

    #[test]
    fn initialization_inventory_rejects_unknown_root_and_control_entries() {
        for in_control in [false, true] {
            let (_parent, state) = initialized_state();
            let authority = StateAuthority::open_existing(&state).unwrap();
            let guard = authority.try_lock_exclusive().unwrap();
            let access = authority.exclusive_access(&guard).unwrap();
            let parent = if in_control {
                state.join(CONTROL_DIRECTORY)
            } else {
                state.clone()
            };
            fs::write(parent.join("unexpected"), "foreign authority").unwrap();

            assert_eq!(
                access.validate_initialization_inventory(),
                Err(LifecycleError::UnsafeState)
            );
            assert_eq!(
                fs::read_to_string(parent.join("unexpected")).unwrap(),
                "foreign authority"
            );
        }
    }

    #[test]
    fn initial_state_creation_retains_verified_contents() {
        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();

        access.create_initial_state(b"expected").unwrap();

        assert_eq!(
            fs::read(state.join(INITIAL_STATE_FILE)).unwrap(),
            b"expected"
        );
        access.revalidate().unwrap();
    }

    #[test]
    fn initial_state_creation_rejects_changed_bytes_and_late_inventory() {
        for change_bytes in [true, false] {
            let (_parent, state) = initialized_state();
            let authority = StateAuthority::open_existing(&state).unwrap();
            let guard = authority.try_lock_exclusive().unwrap();
            let access = authority.exclusive_access(&guard).unwrap();
            let mut mutation_reached = false;
            let result = access.create_initial_state_with_hooks(
                b"expected",
                || {
                    mutation_reached = true;
                    if change_bytes {
                        fs::write(state.join(INITIAL_STATE_FILE), b"altered!").unwrap();
                    } else {
                        fs::write(state.join("unexpected"), b"foreign authority").unwrap();
                    }
                },
                || {},
            );

            assert!(
                mutation_reached,
                "creation failed before the mutation: {result:?}"
            );
            assert_eq!(result, Err(LifecycleError::UnsafeState));
        }
    }

    #[test]
    fn initial_state_creation_rejects_changes_at_final_validation_boundary() {
        for change_bytes in [true, false] {
            let (_parent, state) = initialized_state();
            let authority = StateAuthority::open_existing(&state).unwrap();
            let guard = authority.try_lock_exclusive().unwrap();
            let access = authority.exclusive_access(&guard).unwrap();
            let mut mutation_reached = false;
            let result = access.create_initial_state_with_hooks(
                b"expected",
                || {},
                || {
                    mutation_reached = true;
                    if change_bytes {
                        fs::write(state.join(INITIAL_STATE_FILE), b"altered!").unwrap();
                    } else {
                        fs::write(
                            state.join(CONTROL_DIRECTORY).join("unexpected"),
                            b"foreign authority",
                        )
                        .unwrap();
                    }
                },
            );

            assert!(
                mutation_reached,
                "creation failed before the mutation: {result:?}"
            );
            assert_eq!(result, Err(LifecycleError::UnsafeState));
        }
    }

    #[cfg(unix)]
    #[test]
    fn initial_state_creation_rejects_late_named_file_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let result = access.create_initial_state_with_hooks(
            b"expected",
            || {},
            || {
                let path = state.join(INITIAL_STATE_FILE);
                fs::rename(&path, state.join("displaced-state")).unwrap();
                fs::write(&path, b"expected").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            },
        );

        assert_eq!(result, Err(LifecycleError::UnsafeState));
    }

    #[cfg(windows)]
    #[test]
    fn initial_state_creation_rejects_late_external_hard_link() {
        let (parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let alias = parent.path().join("external-state-alias");
        let result = access.create_initial_state_with_hooks(
            b"expected",
            || {},
            || {
                fs::hard_link(state.join(INITIAL_STATE_FILE), &alias).unwrap();
            },
        );

        assert_eq!(result, Err(LifecycleError::UnsafeState));
        assert_eq!(fs::read(alias).unwrap(), b"expected");
    }

    #[cfg(windows)]
    #[test]
    fn initial_state_creation_prevents_late_named_file_replacement() {
        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_exclusive().unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        let result = access.create_initial_state_with_hooks(
            b"expected",
            || {},
            || {
                assert!(
                    fs::rename(
                        state.join(INITIAL_STATE_FILE),
                        state.join("displaced-state"),
                    )
                    .is_err()
                );
            },
        );

        assert_eq!(result, Ok(()));
        assert_eq!(
            fs::read(state.join(INITIAL_STATE_FILE)).unwrap(),
            b"expected"
        );
        assert!(!state.join("displaced-state").exists());
    }

    #[test]
    fn shared_locks_coexist_and_exclude_writer() {
        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let first = authority.try_lock_shared().unwrap();
        let second = authority.try_lock_shared().unwrap();
        assert_eq!(
            authority.try_lock_exclusive().err(),
            Some(LifecycleError::LockUnavailable)
        );
        drop((first, second));
        let _exclusive = authority.try_lock_exclusive().unwrap();
    }

    #[test]
    fn exclusive_lock_excludes_every_peer() {
        let (_parent, state) = initialized_state();
        let authority = StateAuthority::open_existing(&state).unwrap();
        let _exclusive = authority.try_lock_exclusive().unwrap();
        assert_eq!(
            authority.try_lock_shared().err(),
            Some(LifecycleError::LockUnavailable)
        );
        assert_eq!(
            authority.try_lock_exclusive().err(),
            Some(LifecycleError::LockUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn inspection_does_not_repair_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = private_parent();
        let state = fs::canonicalize(parent.path()).unwrap().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            StateAuthority::open_existing(&state),
            Err(LifecycleError::UnsafeState)
        ));
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_root_and_lock_file() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let (_parent, state) = initialized_state();
        let alias_parent = private_parent();
        let alias = fs::canonicalize(alias_parent.path()).unwrap().join("state");
        symlink(&state, &alias).unwrap();
        assert!(StateAuthority::open_existing(&alias).is_err());

        let authority = StateAuthority::open_existing(&state).unwrap();
        let guard = authority.try_lock_shared().unwrap();
        drop(guard);
        let lock = state.join(CONTROL_DIRECTORY).join(LIFECYCLE_LOCK);
        let linked = state.join("linked-lock");
        fs::hard_link(&lock, &linked).unwrap();
        assert!(authority.try_lock_shared().is_err());
        assert_eq!(
            fs::metadata(lock).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_replaced_root_after_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let (parent, path) = initialized_state();
        let parent_path = fs::canonicalize(parent.path()).unwrap();
        let authority = StateAuthority::open_existing(&path).unwrap();
        fs::rename(&path, parent_path.join("old-state")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            authority.try_lock_shared().err(),
            Some(LifecycleError::UnsafeState)
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_unsafe_existing_control_state_without_repair() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_parent, state_path) = initialized_state();
        let control = state_path.join(CONTROL_DIRECTORY);
        fs::set_permissions(&control, fs::Permissions::from_mode(0o755)).unwrap();
        let authority = StateAuthority::open_existing(&state_path).unwrap();
        assert_eq!(
            authority.try_lock_shared().err(),
            Some(LifecycleError::UnsafeState)
        );
        assert_eq!(
            fs::metadata(control).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_nonempty_existing_lock() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_parent, state_path) = initialized_state();
        let authority = StateAuthority::open_existing(&state_path).unwrap();
        let lock = state_path.join(CONTROL_DIRECTORY).join(LIFECYCLE_LOCK);
        fs::write(&lock, b"unexpected").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            authority.try_lock_shared().err(),
            Some(LifecycleError::UnsafeState)
        );
    }
}
