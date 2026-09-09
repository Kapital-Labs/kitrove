use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

#[cfg(not(windows))]
use cap_fs_ext::OpenOptionsSyncExt as _;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};
#[cfg(windows)]
use kitrove_agent_skills::{CaptureHandleValidator, capture_tree_from_dir_with_validator};
use kitrove_agent_skills::{
    CaptureLimits, CapturedTree, FileMode, NativeSkillObject, SkillSourceLayout, StoredSkillTree,
    capture_standalone_tree_from_dir, capture_tree_from_dir, hash_skill_source,
};
use kitrove_agents::{StoredAgent, StoredNativeAgent};
use kitrove_instructions::{NativeInstructionRegion, StoredInstruction};
use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{ContentHash, EnvironmentManifest, LocalState, PortablePath};
use kitrove_prompt_commands::{StoredNativePromptCommand, StoredPromptCommand};

use crate::NativeExtensionObject;
use crate::filesystem_identity::MetadataIdentity;
use crate::object_store::{
    ObjectState, bounded_envelope_limits, decode_native_extension_object,
    decode_native_instruction_object, decode_native_object, decode_portable_instruction_object,
    decode_portable_object, envelope_limits,
};
#[cfg(any(unix, windows))]
use crate::quarantine_name::RemovalTombstoneName;
use crate::quarantine_name::RemovedObjectKind;
#[cfg(not(unix))]
use crate::quarantine_name::RetainedTombstoneName;
use crate::read_only_fs::{RegularFileMode, has_single_file_link};

const INITIAL_AUTHORITY_LIMIT: usize = 32 * 1024 * 1024;
#[cfg(test)]
const REMOVED_DIRECTORY_PREFIX: &str = ".kitrove-removed-directory-";

/// Validates an empty-authority initialization request without creating or repairing anything.
pub fn preflight_empty_authority_initialization(
    environment_root: &Path,
    state_root: &Path,
    manifest: &EnvironmentManifest,
    state: &LocalState,
) -> Result<(), ObjectMutationError> {
    validate_empty_authority_inputs(manifest, state)?;
    require_non_overlapping_root_topology(environment_root, state_root)?;
    inspect_initial_authority_conflicts(environment_root, state_root)
}

/// Creates one empty environment and its machine-local state through the shared mutation boundary.
pub fn initialize_empty_authority(
    environment_root: &Path,
    state_access: &kitrove_state_lifecycle::ExclusiveStateAccess<'_>,
    manifest: &EnvironmentManifest,
    state: &LocalState,
) -> Result<(), ObjectMutationError> {
    initialize_empty_authority_inner(
        environment_root,
        state_access,
        manifest,
        state,
        || {},
        || {},
    )
}

#[cfg(all(test, unix))]
fn initialize_empty_authority_with_prevalidation_hook_for_tests(
    environment_root: &Path,
    state_access: &kitrove_state_lifecycle::ExclusiveStateAccess<'_>,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    after_prevalidation: impl FnOnce(),
) -> Result<(), ObjectMutationError> {
    state_access
        .validate_initialization_inventory()
        .map_err(|_| unsafe_root())?;
    after_prevalidation();
    let result = initialize_empty_authority_inner(
        environment_root,
        state_access,
        manifest,
        state,
        || {},
        || {},
    );
    state_access.revalidate().map_err(|_| unsafe_root())?;
    result
}

#[cfg(test)]
pub(crate) fn initialize_empty_authority_for_tests(
    environment_root: &Path,
    state_root: &Path,
    manifest: &EnvironmentManifest,
    state: &LocalState,
) -> Result<(), ObjectMutationError> {
    initialize_empty_authority_with_hooks_for_tests(
        environment_root,
        state_root,
        manifest,
        state,
        || {},
        || {},
    )
}

#[cfg(test)]
fn initialize_empty_authority_with_hooks_for_tests(
    environment_root: &Path,
    state_root: &Path,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    before_lock_write: impl FnOnce(),
    before_state_write: impl FnOnce(),
) -> Result<(), ObjectMutationError> {
    preflight_empty_authority_initialization(environment_root, state_root, manifest, state)
        .map_err(|error| mutation_error_at_test_stage(error, "initialization-preflight"))?;
    let (authority, guard) =
        match kitrove_state_lifecycle::StateAuthority::open_existing(state_root) {
            Ok(authority) => {
                let guard = authority.try_lock_exclusive().map_err(|_| {
                    mutation_error_at_test_stage(unsafe_root(), "existing-state-lock")
                })?;
                (authority, guard)
            }
            Err(_) => kitrove_state_lifecycle::StateAuthority::initialize_absent(state_root)
                .map_err(|_| {
                    mutation_error_at_test_stage(unsafe_root(), "absent-state-initialization")
                })?,
        };
    let access = authority
        .exclusive_access(&guard)
        .map_err(|_| mutation_error_at_test_stage(unsafe_root(), "state-access-binding"))?;
    let result = initialize_empty_authority_inner(
        environment_root,
        &access,
        manifest,
        state,
        before_lock_write,
        before_state_write,
    );
    access
        .revalidate()
        .map_err(|_| mutation_error_at_test_stage(unsafe_root(), "state-access-revalidation"))?;
    result
}

fn initialize_empty_authority_inner(
    environment_root: &Path,
    state_access: &kitrove_state_lifecycle::ExclusiveStateAccess<'_>,
    manifest: &EnvironmentManifest,
    state: &LocalState,
    before_lock_write: impl FnOnce(),
    before_state_write: impl FnOnce(),
) -> Result<(), ObjectMutationError> {
    validate_empty_authority_inputs(manifest, state)?;
    state_access
        .validate_initialization_inventory()
        .map_err(|_| unsafe_root())?;
    require_non_overlapping_root_topology(environment_root, state_access.state_root_path())?;
    let manifest_text = manifest.to_toml().map_err(|_| invalid_object())?;
    let lock_text = crate::derive_lockfile(manifest)
        .and_then(|lock| lock.to_json())
        .map_err(|_| invalid_object())?;
    let state_text = state.to_json().map_err(|_| invalid_object())?;
    let environment = ObjectStore::open_or_create(environment_root)?;
    let _root_locks = ObjectStore::try_lock_distinct_roots(&[&environment])?;
    require_initial_environment_files_absent(&environment)?;

    let manifest_path = PortablePath::parse("kitrove.toml").expect("fixed portable path");
    let lock_path = PortablePath::parse("kitrove.lock.json").expect("fixed portable path");
    let manifest_identity = environment.create_text(&manifest_path, &manifest_text)?;
    before_lock_write();
    let lock_identity = match environment.create_text(&lock_path, &lock_text) {
        Ok(identity) => identity,
        Err(error) => {
            environment.remove_regular_file_if_identity(&manifest_path, manifest_identity)?;
            return Err(error);
        }
    };
    before_state_write();
    if state_access
        .create_initial_state(state_text.as_bytes())
        .is_err()
    {
        environment.remove_regular_file_if_identity(&lock_path, lock_identity)?;
        environment.remove_regular_file_if_identity(&manifest_path, manifest_identity)?;
        return Err(mutation_io());
    }
    Ok(())
}

fn validate_empty_authority_inputs(
    manifest: &EnvironmentManifest,
    state: &LocalState,
) -> Result<(), ObjectMutationError> {
    if !manifest.assets.is_empty()
        || !manifest.packs.is_empty()
        || !manifest.profiles.is_empty()
        || !manifest.required_bindings.is_empty()
        || state.machine.active_profile.is_some()
        || !state.machine.enabled_targets.is_empty()
        || !state.machine.harness_roots.is_empty()
        || !state.bindings.is_empty()
        || !state.receipts.is_empty()
        || !state.pack_applications.is_empty()
        || !state.trust.is_empty()
        || !state.scans.is_empty()
    {
        Err(invalid_initial_authority())
    } else {
        Ok(())
    }
}

fn inspect_initial_authority_conflicts(
    environment_root: &Path,
    state_root: &Path,
) -> Result<(), ObjectMutationError> {
    let environment = open_optional_store(environment_root, ObjectStore::open)?;
    let state = open_optional_store(state_root, ObjectStore::open_private_state)?;
    match (environment.as_ref(), state.as_ref()) {
        (Some(environment), Some(state)) => {
            ObjectStore::require_distinct_roots(&[environment, state])?;
            require_initial_authority_files_absent(environment, state)
        }
        (Some(environment), None) => require_initial_environment_files_absent(environment),
        (None, Some(state)) => require_initial_state_file_absent(state),
        (None, None) => Ok(()),
    }
}

fn open_optional_store(
    root: &Path,
    open: impl FnOnce(&Path) -> Result<ObjectStore, ObjectMutationError>,
) -> Result<Option<ObjectStore>, ObjectMutationError> {
    match std::fs::symlink_metadata(root) {
        Ok(_) => open(root).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(unsafe_root()),
    }
}

fn require_initial_authority_files_absent(
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<(), ObjectMutationError> {
    require_initial_environment_files_absent(environment)?;
    require_initial_state_file_absent(state)
}

fn require_initial_environment_files_absent(
    environment: &ObjectStore,
) -> Result<(), ObjectMutationError> {
    for path in [
        PortablePath::parse("kitrove.toml").expect("fixed portable path"),
        PortablePath::parse("kitrove.lock.json").expect("fixed portable path"),
    ] {
        if environment
            .read_text(&path, INITIAL_AUTHORITY_LIMIT)?
            .is_some()
        {
            return Err(existing_conflict());
        }
    }
    Ok(())
}

fn require_initial_state_file_absent(state: &ObjectStore) -> Result<(), ObjectMutationError> {
    let path = PortablePath::parse("state.json").expect("fixed portable path");
    if state.read_text(&path, INITIAL_AUTHORITY_LIMIT)?.is_some() {
        Err(existing_conflict())
    } else {
        Ok(())
    }
}

/// Result of writing one immutable object into a staging location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectStageOutcome {
    /// A new, verified staging object was written.
    Written,
    /// The staging location already contained the exact object.
    AlreadyPresent,
}

/// Result of installing one verified staging object without replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectInstallOutcome {
    /// The staged directory was moved into its absent destination.
    Installed,
    /// The destination already contained the exact object.
    AlreadyPresent,
}

#[derive(Clone, Copy)]
enum StoredObjectKind {
    Portable,
    PortableInstruction,
    PortablePromptCommand,
    PortableAgent,
    PortableMcp,
    Native,
    NativeInstruction,
    NativePromptCommand,
    NativeAgent,
    NativeMcp,
    NativeExtension,
}

fn empty_object_tree() -> CapturedTree {
    let files = std::collections::BTreeMap::new();
    CapturedTree {
        hash: kitrove_agent_skills::hash_tree(&files),
        files,
    }
}

/// A path- and content-redacted immutable object mutation failure.
#[derive(Clone)]
pub struct ObjectMutationError {
    code: &'static str,
    message: &'static str,
    #[cfg(test)]
    test_stage: Option<&'static str>,
}

impl PartialEq for ObjectMutationError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message
    }
}

impl Eq for ObjectMutationError {}

impl ObjectMutationError {
    pub(crate) const fn invalid_object() -> Self {
        invalid_object()
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for ObjectMutationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ObjectMutationError");
        debug.field("code", &self.code);
        #[cfg(test)]
        if let Some(stage) = self.test_stage {
            debug.field("stage", &stage);
        }
        debug.finish()
    }
}

impl Display for ObjectMutationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for ObjectMutationError {}

/// A capability-scoped store rooted at one securely opened portable environment.
pub struct ObjectStore {
    root_path: PathBuf,
    root: Dir,
    root_identity: MetadataIdentity,
    security: StoreSecurity,
    private_access: Option<PrivateDirectoryAccess>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreSecurity {
    Portable,
    PrivateState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateDirectoryAccess {
    Inspect,
    Mutate,
}

/// An operating-system-backed exclusive lock held for one portable mutation.
pub(crate) struct EnvironmentLock {
    // Field order is intentional: release the file lock before parent rename protection.
    _file: std::fs::File,
    _parent: Dir,
}

impl ObjectStore {
    /// Opens an existing environment root without accepting link-like ancestors.
    pub fn open(environment_root: &Path) -> Result<Self, ObjectMutationError> {
        let root_path = std::path::absolute(environment_root).map_err(|_| unsafe_root())?;
        let root = open_root_nofollow(&root_path)?;
        let metadata = root.dir_metadata().map_err(|_| unsafe_root())?;
        Ok(Self {
            root_path,
            root,
            root_identity: MetadataIdentity::from_metadata(&metadata),
            security: StoreSecurity::Portable,
            private_access: None,
        })
    }

    /// Opens an existing machine-local state root without mutating its private boundary.
    pub(crate) fn open_private_state(state_root: &Path) -> Result<Self, ObjectMutationError> {
        Self::open_private_state_with_access(state_root, PrivateDirectoryAccess::Inspect)
    }

    /// Opens an existing machine-local state root for an authorized mutation.
    pub(crate) fn open_private_state_for_mutation(
        state_root: &Path,
    ) -> Result<Self, ObjectMutationError> {
        Self::open_private_state_with_access(state_root, PrivateDirectoryAccess::Mutate)
    }

    fn open_private_state_with_access(
        state_root: &Path,
        access: PrivateDirectoryAccess,
    ) -> Result<Self, ObjectMutationError> {
        let mut store = Self::open(state_root)?;
        prepare_private_directory(&store.root, access)?;
        store.security = StoreSecurity::PrivateState;
        store.private_access = Some(access);
        Ok(store)
    }

    /// Opens or creates a capability-scoped root without following link-like components.
    pub(crate) fn open_or_create(root: &Path) -> Result<Self, ObjectMutationError> {
        Self::open_or_create_with_security(root, StoreSecurity::Portable)
    }

    /// Opens or creates a machine-local state root with private directory permissions.
    pub(crate) fn open_or_create_private_state(root: &Path) -> Result<Self, ObjectMutationError> {
        Self::open_or_create_with_security(root, StoreSecurity::PrivateState)
    }

    fn open_or_create_with_security(
        root: &Path,
        security: StoreSecurity,
    ) -> Result<Self, ObjectMutationError> {
        let root_path = std::path::absolute(root).map_err(|_| unsafe_root())?;
        let (anchor, components) = split_absolute_root(&root_path)?;
        let mut directory =
            Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|_| unsafe_root())?;
        reject_link_like(&directory.dir_metadata().map_err(|_| unsafe_root())?)?;
        let component_count = components.len();
        for (index, component) in components.into_iter().enumerate() {
            let component_security = if index + 1 == component_count {
                security
            } else {
                StoreSecurity::Portable
            };
            directory =
                open_or_create_directory_with_security(&directory, &component, component_security)?;
        }
        let metadata = directory.dir_metadata().map_err(|_| unsafe_root())?;
        if security == StoreSecurity::PrivateState {
            prepare_private_directory(&directory, PrivateDirectoryAccess::Mutate)?;
        }
        Ok(Self {
            root_path,
            root: directory,
            root_identity: MetadataIdentity::from_metadata(&metadata),
            security,
            private_access: (security == StoreSecurity::PrivateState)
                .then_some(PrivateDirectoryAccess::Mutate),
        })
    }

    fn require_distinct_roots(stores: &[&Self]) -> Result<(), ObjectMutationError> {
        Self::resolve_distinct_root_order(stores).map(|_| ())
    }

    fn resolve_distinct_root_order(stores: &[&Self]) -> Result<Vec<usize>, ObjectMutationError> {
        let order = resolve_root_lock_order(stores.len(), |index| {
            let store = stores[index];
            let identity = store.verified_root_identity()?;
            let canonical_path =
                std::fs::canonicalize(&store.root_path).map_err(|_| unsafe_root())?;
            Ok((identity, canonical_path))
        })?;
        for store in stores {
            store.require_ambient_root_identity()?;
        }
        Ok(order)
    }

    /// Refuses roots that are identical or nested, including aliases resolved by the OS.
    pub(crate) fn require_non_overlapping_root(
        &self,
        other: &Self,
    ) -> Result<(), ObjectMutationError> {
        Self::require_distinct_roots(&[self, other])
    }

    /// Returns the revalidated operating-system identity of this held capability root.
    pub(crate) fn verified_root_identity(&self) -> Result<MetadataIdentity, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        Ok(self.root_identity)
    }

    /// Clones the held private-state capability without reopening its ambient path.
    pub(crate) fn try_clone_private_state_for_mutation(&self) -> Result<Self, ObjectMutationError> {
        if self.security != StoreSecurity::PrivateState {
            return Err(unsafe_root());
        }
        self.require_mutation_access()?;
        Ok(Self {
            root_path: self.root_path.clone(),
            root: self.root.try_clone().map_err(|_| mutation_io())?,
            root_identity: self.root_identity,
            security: self.security,
            private_access: self.private_access,
        })
    }

    /// Locks distinct capability roots in stable filesystem-identity order.
    pub(crate) fn try_lock_distinct_roots(
        stores: &[&Self],
    ) -> Result<Vec<EnvironmentLock>, ObjectMutationError> {
        Self::resolve_distinct_root_order(stores)?
            .into_iter()
            .map(|index| stores[index].try_lock_environment())
            .collect()
    }

    pub(crate) fn portable_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_portable(root, limits)
            .is_ok_and(|object| &object.tree().hash == expected_hash)
    }

    pub(crate) fn native_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_native(root, limits)
            .is_ok_and(|object| object.hash() == expected_hash)
    }

    pub(crate) fn portable_instruction_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_portable_instruction(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn native_instruction_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_native_instruction(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn portable_prompt_command_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_portable_prompt_command(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn native_prompt_command_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_native_prompt_command(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn portable_agent_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_portable_agent(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn native_agent_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_native_agent(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn portable_mcp_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> bool {
        self.load_portable_mcp(root, limits)
            .is_ok_and(|object| object.object_hash() == expected_hash)
    }

    pub(crate) fn native_mcp_is_verified(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        expected_harness: &kitrove_model::HarnessId,
        limits: CaptureLimits,
    ) -> bool {
        self.load_native_mcp(root, limits).is_ok_and(|object| {
            object.dialect().harness() == *expected_harness && object.object_hash() == expected_hash
        })
    }

    pub(crate) fn load_portable(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredSkillTree, ObjectMutationError> {
        self.load_portable_bounded(root, limits, envelope_limits(limits).max_total_bytes)
    }

    pub(crate) fn load_portable_bounded(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
        max_envelope_bytes: u64,
    ) -> Result<StoredSkillTree, ObjectMutationError> {
        crate::object_store::decode_portable_object(
            self.capture_directory(root, bounded_envelope_limits(limits, max_envelope_bytes))?,
            limits,
        )
        .map_err(|_| invalid_object())
    }

    pub(crate) fn load_native(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<NativeSkillObject, ObjectMutationError> {
        self.load_native_bounded(root, limits, envelope_limits(limits).max_total_bytes)
    }

    pub(crate) fn load_native_bounded(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
        max_envelope_bytes: u64,
    ) -> Result<NativeSkillObject, ObjectMutationError> {
        crate::object_store::decode_native_object(
            self.capture_directory(root, bounded_envelope_limits(limits, max_envelope_bytes))?,
            limits,
        )
        .map_err(|_| invalid_object())
    }

    pub fn load_portable_instruction(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredInstruction, ObjectMutationError> {
        decode_portable_instruction_object(
            self.capture_directory(root, envelope_limits(limits))?,
            limits,
        )
        .map_err(|_| invalid_object())
    }

    /// Captures one JSON-only object envelope within its exact declared byte allowance.
    pub(crate) fn capture_document_bounded(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
        max_envelope_bytes: u64,
    ) -> Result<CapturedTree, ObjectMutationError> {
        self.capture_directory(
            root,
            crate::object_store::bounded_envelope_limits(limits, max_envelope_bytes),
        )
    }

    pub fn load_native_instruction(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<NativeInstructionRegion, ObjectMutationError> {
        decode_native_instruction_object(self.capture_directory(root, envelope_limits(limits))?)
            .map_err(|_| invalid_object())
    }

    pub fn load_portable_prompt_command(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredPromptCommand, ObjectMutationError> {
        crate::object_store::decode_portable_prompt_command_object(
            self.capture_directory(root, envelope_limits(limits))?,
            limits,
        )
        .map_err(|_| invalid_object())
    }

    pub fn load_native_prompt_command(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredNativePromptCommand, ObjectMutationError> {
        crate::object_store::decode_native_prompt_command_object(
            self.capture_directory(root, envelope_limits(limits))?,
        )
        .map_err(|_| invalid_object())
    }

    pub fn load_portable_agent(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredAgent, ObjectMutationError> {
        crate::object_store::decode_portable_agent_object(
            self.capture_directory(root, envelope_limits(limits))?,
            limits,
        )
        .map_err(|_| invalid_object())
    }

    pub fn load_native_agent(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredNativeAgent, ObjectMutationError> {
        crate::object_store::decode_native_agent_object(
            self.capture_directory(root, envelope_limits(limits))?,
        )
        .map_err(|_| invalid_object())
    }

    pub fn load_portable_mcp(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredMcpServer, ObjectMutationError> {
        crate::object_store::decode_portable_mcp_object(
            self.capture_directory(root, envelope_limits(limits))?,
        )
        .map_err(|_| invalid_object())
    }

    pub fn load_native_mcp(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<StoredNativeMcpEntry, ObjectMutationError> {
        crate::object_store::decode_native_mcp_object(
            self.capture_directory(root, envelope_limits(limits))?,
        )
        .map_err(|_| invalid_object())
    }

    pub(crate) fn load_native_extension(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<NativeExtensionObject, ObjectMutationError> {
        self.load_native_extension_bounded(root, limits, envelope_limits(limits).max_total_bytes)
    }

    pub(crate) fn load_native_extension_bounded(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
        max_envelope_bytes: u64,
    ) -> Result<NativeExtensionObject, ObjectMutationError> {
        decode_native_extension_object(
            self.capture_directory(root, bounded_envelope_limits(limits, max_envelope_bytes))?,
            limits,
        )
        .map_err(|_| invalid_object())
    }

    pub(crate) fn capture_directory(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
    ) -> Result<CapturedTree, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let (parent, name) = self.open_existing_parent(root)?;
        let directory = open_child_directory(&parent, &name)?;
        let captured = self
            .capture_open_directory(directory, &self.root_path.join(root.as_str()), limits)
            .map_err(|_| invalid_object())?;
        self.require_ambient_root_identity()?;
        Ok(captured)
    }

    fn require_ambient_root_identity(&self) -> Result<(), ObjectMutationError> {
        let reopened = open_root_nofollow(&self.root_path)?;
        let metadata = reopened.dir_metadata().map_err(|_| unsafe_root())?;
        if MetadataIdentity::from_metadata(&metadata) != self.root_identity {
            return Err(unsafe_root());
        }
        Ok(())
    }

    fn inspect_stored_object(
        &self,
        root: &PortablePath,
        limits: CaptureLimits,
        expected_hash: &ContentHash,
        kind: StoredObjectKind,
    ) -> Result<(ObjectState, Option<ContentHash>), ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(root)? else {
            return Ok((ObjectState::Missing, None));
        };
        let metadata = match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok((ObjectState::Missing, None));
            }
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => metadata,
        };
        if reject_link_like(&metadata).is_err() || !metadata.is_dir() {
            return Ok((ObjectState::Unsafe, None));
        }
        let directory = match open_child_directory(&parent, &name) {
            Ok(directory) => directory,
            Err(_) => return Ok((ObjectState::Unsafe, None)),
        };
        let stored = match self.capture_open_directory(
            directory,
            &self.root_path.join(root.as_str()),
            envelope_limits(limits),
        ) {
            Ok(stored) => stored,
            Err(_) => return Ok((ObjectState::Unsafe, None)),
        };
        self.require_ambient_root_identity()?;
        Ok(match kind {
            StoredObjectKind::Portable => match decode_portable_object(stored, limits) {
                Ok(object) if &object.tree().hash == expected_hash => {
                    (ObjectState::Verified, Some(object.tree().hash.clone()))
                }
                Ok(object) => (ObjectState::HashMismatch, Some(object.tree().hash.clone())),
                Err(()) => (ObjectState::Invalid, None),
            },
            StoredObjectKind::PortableInstruction => {
                match decode_portable_instruction_object(stored, limits) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::PortablePromptCommand => {
                match crate::object_store::decode_portable_prompt_command_object(stored, limits) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::PortableAgent => {
                match crate::object_store::decode_portable_agent_object(stored, limits) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::PortableMcp => {
                match crate::object_store::decode_portable_mcp_object(stored) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::Native => match decode_native_object(stored, limits) {
                Ok(object) if object.hash() == expected_hash => {
                    (ObjectState::Verified, Some(object.hash().clone()))
                }
                Ok(object) => (ObjectState::HashMismatch, Some(object.hash().clone())),
                Err(()) => (ObjectState::Invalid, None),
            },
            StoredObjectKind::NativeInstruction => match decode_native_instruction_object(stored) {
                Ok(object) if object.object_hash() == expected_hash => {
                    (ObjectState::Verified, Some(object.object_hash().clone()))
                }
                Ok(object) => (
                    ObjectState::HashMismatch,
                    Some(object.object_hash().clone()),
                ),
                Err(()) => (ObjectState::Invalid, None),
            },
            StoredObjectKind::NativePromptCommand => {
                match crate::object_store::decode_native_prompt_command_object(stored) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::NativeAgent => {
                match crate::object_store::decode_native_agent_object(stored) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::NativeMcp => {
                match crate::object_store::decode_native_mcp_object(stored) {
                    Ok(object) if object.object_hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.object_hash().clone()))
                    }
                    Ok(object) => (
                        ObjectState::HashMismatch,
                        Some(object.object_hash().clone()),
                    ),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
            StoredObjectKind::NativeExtension => {
                match decode_native_extension_object(stored, limits) {
                    Ok(object) if object.hash() == expected_hash => {
                        (ObjectState::Verified, Some(object.hash().clone()))
                    }
                    Ok(object) => (ObjectState::HashMismatch, Some(object.hash().clone())),
                    Err(()) => (ObjectState::Invalid, None),
                }
            }
        })
    }

    fn capture_open_directory(
        &self,
        directory: Dir,
        display_path: &Path,
        limits: CaptureLimits,
    ) -> Result<CapturedTree, kitrove_agent_skills::SkillError> {
        #[cfg(windows)]
        if self.security == StoreSecurity::PrivateState {
            return capture_tree_from_dir_with_validator(
                directory,
                display_path,
                limits,
                &mut PrivateCaptureHandleValidator,
            );
        }
        capture_tree_from_dir(directory, display_path, limits)
    }

    /// Acquires the environment's exclusive portable-mutation lock.
    pub(crate) fn try_lock_environment(&self) -> Result<EnvironmentLock, ObjectMutationError> {
        let control = self.open_or_create_private_control_directory()?;
        self.try_lock_file_in_parent(
            control,
            OsStr::new(crate::local_state_authority::LOCK_FILE_NAME),
            StoreSecurity::PrivateState,
        )
    }

    /// Acquires one exclusive lock file beneath this verified capability root.
    pub(crate) fn try_lock_file(
        &self,
        path: &PortablePath,
    ) -> Result<EnvironmentLock, ObjectMutationError> {
        let (control, name) = self.open_or_create_parent(path)?;
        self.try_lock_file_in_parent(control, &name, self.security)
    }

    fn try_lock_file_in_parent(
        &self,
        control: Dir,
        name: &OsStr,
        security: StoreSecurity,
    ) -> Result<EnvironmentLock, ObjectMutationError> {
        if let Ok(metadata) = control.symlink_metadata(name) {
            reject_link_like(&metadata)?;
            if !metadata.is_file() {
                return Err(unsafe_path());
            }
        }
        let file = open_or_create_lock_file(&control, name, security)?;
        let metadata = file.metadata().map_err(|_| mutation_io())?;
        reject_link_like(&metadata)?;
        if !metadata.is_file() {
            return Err(unsafe_path());
        }
        #[cfg(unix)]
        if security == StoreSecurity::PrivateState {
            use cap_std::fs::PermissionsExt as _;
            file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))
                .map_err(|_| mutation_io())?;
        }
        #[cfg(windows)]
        if security == StoreSecurity::PrivateState {
            require_private_single_link_file(&file)?;
        }
        let file = file.into_std();
        fs2::FileExt::try_lock_exclusive(&file).map_err(lock_error)?;
        Ok(EnvironmentLock {
            _parent: control,
            _file: file,
        })
    }

    /// Acquires a shared lock only when an already-initialized lock file exists.
    pub(crate) fn try_lock_existing_file_shared(
        &self,
        path: &PortablePath,
    ) -> Result<Option<EnvironmentLock>, ObjectMutationError> {
        let Some((parent, name)) = self.open_existing_parent_optional(path)? else {
            return Ok(None);
        };
        match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => {
                reject_link_like(&metadata)?;
                if !metadata.is_file() {
                    return Err(unsafe_path());
                }
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;

            options.share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE);
            if self.security == StoreSecurity::PrivateState {
                options.access_mode(kitrove_windows_security::PRIVATE_FILE_INSPECT_ACCESS);
            }
        }
        let file = parent
            .open_with(&name, &options)
            .map_err(|_| mutation_io())?;
        let metadata = file.metadata().map_err(|_| mutation_io())?;
        reject_link_like(&metadata)?;
        if !metadata.is_file() {
            return Err(unsafe_path());
        }
        #[cfg(windows)]
        if self.security == StoreSecurity::PrivateState {
            require_private_single_link_file(&file)?;
        }
        let file = file.into_std();
        fs2::FileExt::try_lock_shared(&file).map_err(lock_error)?;
        Ok(Some(EnvironmentLock {
            _parent: parent,
            _file: file,
        }))
    }

    /// Reads a bounded UTF-8 control file without following link-like entries.
    pub(crate) fn read_text(
        &self,
        path: &PortablePath,
        max_bytes: usize,
    ) -> Result<Option<String>, ObjectMutationError> {
        let Some(bytes) = self.read_control_bytes(path, max_bytes)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| control_file_invalid())
    }

    pub(crate) fn read_text_with_mode(
        &self,
        path: &PortablePath,
        max_bytes: usize,
    ) -> Result<Option<(String, RegularFileMode)>, ObjectMutationError> {
        let Some((bytes, mode)) = self.read_control_file(path, max_bytes)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(|text| Some((text, mode)))
            .map_err(|_| control_file_invalid())
    }

    fn read_control_bytes(
        &self,
        path: &PortablePath,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, ObjectMutationError> {
        self.read_control_file(path, max_bytes)
            .map(|file| file.map(|(bytes, _mode)| bytes))
    }

    fn read_control_file(
        &self,
        path: &PortablePath,
        max_bytes: usize,
    ) -> Result<Option<(Vec<u8>, RegularFileMode)>, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(path)? else {
            return Ok(None);
        };
        match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => {
                reject_link_like(&metadata)?;
                if !metadata.is_file() {
                    return Err(unsafe_path());
                }
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        #[cfg(windows)]
        if self.private_access.is_some() {
            use cap_std::fs::OpenOptionsExt as _;
            options.access_mode(kitrove_windows_security::PRIVATE_FILE_INSPECT_ACCESS);
        }
        let mut file = parent
            .open_with(&name, &options)
            .map_err(|_| mutation_io())?;
        #[cfg(windows)]
        if self.private_access.is_some() {
            require_private_single_link_file(&file)?;
        }
        let opened = file.metadata().map_err(|_| mutation_io())?;
        reject_link_like(&opened)?;
        if !opened.is_file() {
            return Err(unsafe_path());
        }
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| mutation_io())?;
        if bytes.len() > max_bytes {
            return Err(control_file_invalid());
        }
        let after = file.metadata().map_err(|_| mutation_io())?;
        let selected = parent.symlink_metadata(&name).map_err(|_| mutation_io())?;
        reject_link_like(&after)?;
        reject_link_like(&selected)?;
        if MetadataIdentity::from_metadata(&opened) != MetadataIdentity::from_metadata(&after)
            || MetadataIdentity::from_metadata(&opened)
                != MetadataIdentity::from_metadata(&selected)
            || after.len() != bytes.len() as u64
        {
            return Err(precondition_failed());
        }
        let mode = RegularFileMode::from_metadata(&after).map_err(|_| unsafe_path())?;
        self.require_ambient_root_identity()?;
        Ok(Some((bytes, mode)))
    }

    /// Writes an absent staging file, accepting an already-identical file idempotently.
    pub(crate) fn stage_text(
        &self,
        path: &PortablePath,
        contents: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        match self.read_text(path, max_bytes)? {
            Some(existing) if existing == contents => return Ok(()),
            Some(_) => return Err(existing_conflict()),
            None => {}
        }
        let (parent, name) = self.open_or_create_parent(path)?;
        write_new_file_with_mode(
            &parent,
            &name,
            contents.as_bytes(),
            self.default_file_mode(),
        )?;
        self.sync_and_revalidate(&parent)
    }

    /// Writes an absent staging file with exact observed regular-file permissions.
    pub(crate) fn stage_text_with_mode(
        &self,
        path: &PortablePath,
        contents: &str,
        mode: RegularFileMode,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        if !mode.is_valid_for_platform() {
            return Err(control_file_invalid());
        }
        match self.read_text_with_mode(path, max_bytes)? {
            Some((existing, existing_mode)) if existing == contents && existing_mode == mode => {
                return Ok(());
            }
            Some(_) => return Err(existing_conflict()),
            None => {}
        }
        let (parent, name) = self.open_or_create_parent(path)?;
        write_new_file_with_mode(
            &parent,
            &name,
            contents.as_bytes(),
            NewFileMode::Exact(mode),
        )?;
        self.sync_and_revalidate(&parent)
    }

    pub(crate) fn install_staged_exact_text(
        &self,
        staging_path: &PortablePath,
        destination_path: &PortablePath,
        expected_text: &str,
        expected_mode: RegularFileMode,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        if !self.exact_text_matches(staging_path, expected_text, expected_mode, max_bytes)?
            || self.read_text(destination_path, max_bytes)?.is_some()
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(staging_path, destination_path)
            .map_err(|_| precondition_failed())?;
        if !self.exact_text_matches(destination_path, expected_text, expected_mode, max_bytes)? {
            return Err(verification_failed());
        }
        Ok(())
    }

    pub(crate) fn quarantine_exact_text(
        &self,
        destination_path: &PortablePath,
        backup_path: &PortablePath,
        expected_text: &str,
        expected_mode: RegularFileMode,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        if self.read_text(backup_path, max_bytes)?.is_some()
            || !self.exact_text_matches(
                destination_path,
                expected_text,
                expected_mode,
                max_bytes,
            )?
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(destination_path, backup_path)
            .map_err(|_| precondition_failed())?;
        if !self.exact_text_matches(backup_path, expected_text, expected_mode, max_bytes)? {
            if self.read_text(destination_path, max_bytes)?.is_none() {
                self.move_noreplace(backup_path, destination_path)
                    .map_err(|_| precondition_failed())?;
            }
            return Err(precondition_failed());
        }
        Ok(())
    }

    pub(crate) fn restore_quarantined_exact_text(
        &self,
        backup_path: &PortablePath,
        destination_path: &PortablePath,
        expected_text: &str,
        expected_mode: RegularFileMode,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        if self.read_text(destination_path, max_bytes)?.is_some()
            || !self.exact_text_matches(backup_path, expected_text, expected_mode, max_bytes)?
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(backup_path, destination_path)
            .map_err(|_| precondition_failed())?;
        if !self.exact_text_matches(destination_path, expected_text, expected_mode, max_bytes)? {
            return Err(verification_failed());
        }
        Ok(())
    }

    pub(crate) fn exact_text_matches(
        &self,
        path: &PortablePath,
        expected_text: &str,
        expected_mode: RegularFileMode,
        max_bytes: usize,
    ) -> Result<bool, ObjectMutationError> {
        self.read_text_with_mode(path, max_bytes).map(|observed| {
            observed.is_some_and(|(text, mode)| text == expected_text && mode == expected_mode)
        })
    }

    fn create_text(
        &self,
        path: &PortablePath,
        contents: &str,
    ) -> Result<MetadataIdentity, ObjectMutationError> {
        self.create_text_with_hook(path, contents, NewFileMode::Inherited, || Ok(()))
    }

    fn create_text_with_hook(
        &self,
        path: &PortablePath,
        contents: &str,
        mode: NewFileMode,
        after_parent_sync: impl FnOnce() -> Result<(), ObjectMutationError>,
    ) -> Result<MetadataIdentity, ObjectMutationError> {
        let (parent, name) = self.open_or_create_parent(path)?;
        write_new_file_with_hooks(
            &parent,
            &name,
            contents.as_bytes(),
            mode,
            || Ok(()),
            || {
                sync_directory(&parent)?;
                after_parent_sync()?;
                self.require_ambient_root_identity()
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn create_empty_directory_for_test(
        &self,
        path: &PortablePath,
    ) -> Result<(), ObjectMutationError> {
        self.require_mutation_access()?;
        let (parent, name) = self.open_or_create_parent(path)?;
        drop(
            create_new_directory_with_security(&parent, &name, self.security)
                .map_err(|_| mutation_io())?,
        );
        self.sync_and_revalidate(&parent)
    }

    /// Writes an absent machine-local control file with restrictive permissions where supported.
    pub(crate) fn stage_private_text(
        &self,
        path: &PortablePath,
        contents: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        self.require_mutation_access()?;
        match self.read_text(path, max_bytes)? {
            Some(existing) if existing == contents => return Ok(()),
            Some(_) => return Err(existing_conflict()),
            None => {}
        }
        let (parent, name) = self.open_or_create_parent(path)?;
        write_new_private_file(&parent, &name, contents.as_bytes())?;
        self.sync_and_revalidate(&parent)
    }

    /// Atomically replaces a control file without overwriting a changed destination.
    pub(crate) fn replace_text_atomically_guarded(
        &self,
        staging_path: &PortablePath,
        destination_path: &PortablePath,
        expected_current: Option<&str>,
        contents: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        self.stage_text(staging_path, contents, max_bytes)?;
        self.install_staged_text_guarded(
            staging_path,
            destination_path,
            expected_current,
            contents,
            max_bytes,
        )
    }

    /// Installs staged authority only while the destination retains its planned prior bytes.
    pub(crate) fn install_staged_text_guarded(
        &self,
        staging_path: &PortablePath,
        destination_path: &PortablePath,
        expected_current: Option<&str>,
        expected_new: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        self.install_staged_text_guarded_with_hook(
            staging_path,
            destination_path,
            expected_current,
            expected_new,
            max_bytes,
            true,
            || {},
            || {},
        )
    }

    /// Installs staged bytes only from the exact planned prior state.
    ///
    /// Equal destination bytes do not prove this transaction wrote them and therefore cannot
    /// acquire ownership.
    pub(crate) fn install_staged_text_guarded_from_old(
        &self,
        staging_path: &PortablePath,
        destination_path: &PortablePath,
        expected_current: Option<&str>,
        expected_new: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        self.install_staged_text_guarded_with_hook(
            staging_path,
            destination_path,
            expected_current,
            expected_new,
            max_bytes,
            false,
            || {},
            || {},
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn install_staged_text_guarded_with_hook(
        &self,
        staging_path: &PortablePath,
        destination_path: &PortablePath,
        expected_current: Option<&str>,
        expected_new: &str,
        max_bytes: usize,
        accept_already_new: bool,
        after_precondition: impl FnOnce(),
        after_exchange: impl FnOnce(),
    ) -> Result<(), ObjectMutationError> {
        if self.read_text(staging_path, max_bytes)?.as_deref() != Some(expected_new) {
            return Err(invalid_stage());
        }
        let backup_path = guarded_backup_path(staging_path)?;
        if self.read_text(&backup_path, max_bytes)?.is_some() {
            return self.resume_guarded_text_install(
                staging_path,
                &backup_path,
                destination_path,
                expected_current,
                expected_new,
                max_bytes,
            );
        }
        let current = self.read_text(destination_path, max_bytes)?;
        if current.as_deref() == Some(expected_new) {
            if !accept_already_new {
                return Err(precondition_failed());
            }
            self.remove_regular_file_if_present(staging_path)?;
            return Ok(());
        }
        if current.as_deref() != expected_current {
            return Err(precondition_failed());
        }
        after_precondition();

        if expected_current.is_some() {
            if atomic_exchange_supported() {
                self.exchange(staging_path, destination_path)
                    .map_err(|_| precondition_failed())?;
                after_exchange();
                let displaced = self.read_text(staging_path, max_bytes)?;
                if displaced.as_deref() != expected_current {
                    if self.read_text(destination_path, max_bytes)?.as_deref() == Some(expected_new)
                    {
                        self.exchange(staging_path, destination_path)
                            .map_err(|_| precondition_failed())?;
                    }
                    return Err(precondition_failed());
                }
                if self.read_text(destination_path, max_bytes)?.as_deref() != Some(expected_new) {
                    return Err(verification_failed());
                }
                self.remove_regular_file_if_present(staging_path)?;
                return Ok(());
            }
            self.move_noreplace(destination_path, &backup_path)
                .map_err(|_| precondition_failed())?;
            if self.read_text(&backup_path, max_bytes)?.as_deref() != expected_current {
                self.restore_guarded_backup(&backup_path, destination_path, max_bytes)?;
                return Err(precondition_failed());
            }
        }
        if self.move_noreplace(staging_path, destination_path).is_err() {
            if expected_current.is_some() && self.read_text(destination_path, max_bytes)?.is_none()
            {
                self.restore_guarded_backup(&backup_path, destination_path, max_bytes)?;
            }
            return Err(precondition_failed());
        }
        if self.read_text(destination_path, max_bytes)?.as_deref() != Some(expected_new) {
            return Err(verification_failed());
        }
        self.remove_regular_file_if_present(&backup_path)?;
        Ok(())
    }

    fn resume_guarded_text_install(
        &self,
        staging_path: &PortablePath,
        backup_path: &PortablePath,
        destination_path: &PortablePath,
        expected_current: Option<&str>,
        expected_new: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        if expected_current.is_none()
            || self.read_text(backup_path, max_bytes)?.as_deref() != expected_current
        {
            return Err(precondition_failed());
        }
        match self.read_text(destination_path, max_bytes)? {
            Some(current) if current == expected_new => {
                self.remove_regular_file_if_present(staging_path)?;
                self.remove_regular_file_if_present(backup_path)?;
                Ok(())
            }
            Some(_) => Err(precondition_failed()),
            None => {
                if self.move_noreplace(staging_path, destination_path).is_err() {
                    return Err(precondition_failed());
                }
                if self.read_text(destination_path, max_bytes)?.as_deref() != Some(expected_new) {
                    return Err(verification_failed());
                }
                self.remove_regular_file_if_present(backup_path)?;
                Ok(())
            }
        }
    }

    pub(crate) fn restore_guarded_backup(
        &self,
        backup_path: &PortablePath,
        destination_path: &PortablePath,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        if self.read_text(destination_path, max_bytes)?.is_some() {
            return Err(precondition_failed());
        }
        self.move_noreplace(backup_path, destination_path)
            .map_err(|_| precondition_failed())
    }

    fn move_noreplace(
        &self,
        source_path: &PortablePath,
        destination_path: &PortablePath,
    ) -> Result<(), ()> {
        self.require_ambient_root_identity().map_err(|_| ())?;
        let (source_parent, source_name) =
            self.open_existing_parent(source_path).map_err(|_| ())?;
        let (destination_parent, destination_name) = self
            .open_or_create_parent(destination_path)
            .map_err(|_| ())?;
        rename_noreplace(
            &source_parent,
            &source_name,
            &destination_parent,
            &destination_name,
        )?;
        sync_directory(&destination_parent).map_err(|_| ())?;
        sync_directory(&source_parent).map_err(|_| ())?;
        self.require_ambient_root_identity().map_err(|_| ())
    }

    /// Installs one already-verified staging directory at an absent destination.
    pub(crate) fn install_directory_noreplace(
        &self,
        staging: &PortablePath,
        destination: &PortablePath,
    ) -> Result<(), ObjectMutationError> {
        if staging == destination {
            return Err(invalid_install());
        }
        if let Some((parent, name)) = self.open_existing_parent_optional(destination)? {
            match parent.symlink_metadata(&name) {
                Ok(metadata) => {
                    reject_link_like(&metadata)?;
                    return Err(existing_conflict());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(mutation_io()),
            }
        }
        let (source_parent, source_name) = self.open_existing_parent(staging)?;
        let metadata = source_parent
            .symlink_metadata(&source_name)
            .map_err(|_| invalid_stage())?;
        reject_link_like(&metadata)?;
        if !metadata.is_dir() {
            return Err(invalid_stage());
        }
        let (destination_parent, destination_name) = self.open_or_create_parent(destination)?;
        rename_noreplace(
            &source_parent,
            &source_name,
            &destination_parent,
            &destination_name,
        )
        .map_err(|_| install_failed())?;
        sync_directory(&source_parent)?;
        sync_directory(&destination_parent)
    }

    #[cfg(all(test, any(target_vendor = "apple", target_os = "linux")))]
    pub(crate) fn exchange_control_files(
        &self,
        first_path: &PortablePath,
        second_path: &PortablePath,
    ) -> Result<(), ObjectMutationError> {
        self.exchange(first_path, second_path)
            .map_err(|_| precondition_failed())
    }

    fn exchange(&self, first_path: &PortablePath, second_path: &PortablePath) -> Result<(), ()> {
        self.require_mutation_access().map_err(|_| ())?;
        let (first_parent, first_name) = self.open_existing_parent(first_path).map_err(|_| ())?;
        let (second_parent, second_name) =
            self.open_existing_parent(second_path).map_err(|_| ())?;
        rename_exchange(&first_parent, &first_name, &second_parent, &second_name)?;
        sync_directory(&first_parent).map_err(|_| ())?;
        sync_directory(&second_parent).map_err(|_| ())
    }

    /// Removes one known regular control or staging file without following it.
    pub(crate) fn remove_regular_file_if_present(
        &self,
        path: &PortablePath,
    ) -> Result<(), ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(path)? else {
            return Ok(());
        };
        let metadata = match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => metadata,
        };
        reject_link_like(&metadata)?;
        if !metadata.is_file() {
            return Err(unsafe_path());
        }
        let file = open_regular_file_nofollow(&parent, &name)?;
        #[cfg(windows)]
        if self.security == StoreSecurity::PrivateState {
            require_private_single_link_file(&file)?;
        }
        self.quarantine_regular_file(&parent, &name, file)?;
        self.require_ambient_root_identity()
    }

    /// Removes only the exact opened regular file whose bounded bytes match expected authority.
    pub(crate) fn remove_regular_file_if_matches(
        &self,
        path: &PortablePath,
        max_bytes: usize,
        expected: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), ObjectMutationError> {
        self.remove_regular_file_if_matches_inner(path, max_bytes, None, expected)
    }

    pub(crate) fn remove_regular_file_if_matches_with_mode(
        &self,
        path: &PortablePath,
        max_bytes: usize,
        expected_mode: RegularFileMode,
        expected: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), ObjectMutationError> {
        self.remove_regular_file_if_matches_inner(path, max_bytes, Some(expected_mode), expected)
    }

    fn remove_regular_file_if_matches_inner(
        &self,
        path: &PortablePath,
        max_bytes: usize,
        expected_mode: Option<RegularFileMode>,
        expected: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(path)? else {
            return Ok(());
        };
        let mut file = match open_regular_file_nofollow(&parent, &name) {
            Ok(file) => file,
            Err(_)
                if parent
                    .symlink_metadata(&name)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        #[cfg(windows)]
        if self.security == StoreSecurity::PrivateState {
            require_private_single_link_file(&file)?;
        }
        let opened = file.metadata().map_err(|_| mutation_io())?;
        if expected_mode
            .is_some_and(|expected| RegularFileMode::from_metadata(&opened).ok() != Some(expected))
        {
            return Err(existing_conflict());
        }
        let identity = MetadataIdentity::from_metadata(&opened);
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| mutation_io())?;
        if bytes.len() > max_bytes || !expected(&bytes) {
            return Err(existing_conflict());
        }
        let after = file.metadata().map_err(|_| mutation_io())?;
        let selected = parent.symlink_metadata(&name).map_err(|_| mutation_io())?;
        reject_link_like(&after)?;
        reject_link_like(&selected)?;
        if !after.is_file() || !selected.is_file() {
            return Err(unsafe_path());
        }
        if identity != MetadataIdentity::from_metadata(&after)
            || identity != MetadataIdentity::from_metadata(&selected)
            || after.len() != bytes.len() as u64
        {
            return Err(precondition_failed());
        }
        self.quarantine_regular_file(&parent, &name, file)?;
        self.require_ambient_root_identity()
    }

    fn remove_regular_file_if_identity(
        &self,
        path: &PortablePath,
        expected: MetadataIdentity,
    ) -> Result<(), ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(path)? else {
            return Ok(());
        };
        let file = match open_regular_file_nofollow(&parent, &name) {
            Ok(file) => file,
            Err(_error)
                if parent
                    .symlink_metadata(&name)
                    .is_err_and(|current| current.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        #[cfg(windows)]
        if self.security == StoreSecurity::PrivateState {
            require_private_single_link_file(&file)?;
        }
        let current = MetadataIdentity::from_metadata(&file.metadata().map_err(|_| mutation_io())?);
        if current != expected {
            return Ok(());
        }
        self.quarantine_regular_file(&parent, &name, file)?;
        self.require_ambient_root_identity()
    }

    /// Removes one known empty staging directory without traversing it.
    pub(crate) fn remove_empty_directory_if_present(
        &self,
        path: &PortablePath,
    ) -> Result<(), ObjectMutationError> {
        let metadata = match self.root.symlink_metadata(path.as_str()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => metadata,
        };
        reject_link_like(&metadata)?;
        if !metadata.is_dir() {
            return Err(unsafe_path());
        }
        let (parent, name) = self.open_existing_parent(path)?;
        let directory = open_child_directory(&parent, &name)?;
        if directory
            .entries()
            .map_err(|_| mutation_io())?
            .next()
            .is_some()
        {
            return Ok(());
        }
        self.quarantine_directory(&parent, &name, directory)?;
        self.require_ambient_root_identity()
    }

    /// Writes and verifies a portable object only at an absent staging root.
    pub fn stage_portable(
        &self,
        staging_root: &PortablePath,
        object: &StoredSkillTree,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.metadata_json(),
            object.tree(),
            limits,
            object.tree().hash.clone(),
            StoredObjectKind::Portable,
        )
    }

    /// Writes and verifies an origin-native object only at an absent staging root.
    pub fn stage_native(
        &self,
        staging_root: &PortablePath,
        object: &NativeSkillObject,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.metadata_json(),
            object.tree(),
            limits,
            object.hash().clone(),
            StoredObjectKind::Native,
        )
    }

    /// Writes and verifies a portable instruction object at an absent staging root.
    pub fn stage_portable_instruction(
        &self,
        staging_root: &PortablePath,
        object: &StoredInstruction,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::PortableInstruction,
        )
    }

    /// Writes and verifies an exact native instruction region at an absent staging root.
    pub fn stage_native_instruction(
        &self,
        staging_root: &PortablePath,
        object: &NativeInstructionRegion,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::NativeInstruction,
        )
    }

    pub fn stage_portable_prompt_command(
        &self,
        staging_root: &PortablePath,
        object: &StoredPromptCommand,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::PortablePromptCommand,
        )
    }

    pub fn stage_native_prompt_command(
        &self,
        staging_root: &PortablePath,
        object: &StoredNativePromptCommand,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::NativePromptCommand,
        )
    }

    pub fn stage_portable_agent(
        &self,
        staging_root: &PortablePath,
        object: &StoredAgent,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::PortableAgent,
        )
    }

    pub fn stage_native_agent(
        &self,
        staging_root: &PortablePath,
        object: &StoredNativeAgent,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::NativeAgent,
        )
    }

    pub fn stage_portable_mcp(
        &self,
        staging_root: &PortablePath,
        object: &StoredMcpServer,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::PortableMcp,
        )
    }

    pub fn stage_native_mcp(
        &self,
        staging_root: &PortablePath,
        object: &StoredNativeMcpEntry,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.to_json().map_err(|_| invalid_object())?,
            &empty_object_tree(),
            limits,
            object.object_hash().clone(),
            StoredObjectKind::NativeMcp,
        )
    }

    /// Writes and verifies a native extension object at an absent staging root.
    pub fn stage_native_extension(
        &self,
        staging_root: &PortablePath,
        object: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.stage(
            staging_root,
            object.metadata_json(),
            object.tree(),
            limits,
            object.hash().clone(),
            StoredObjectKind::NativeExtension,
        )
    }

    /// Removes only an incomplete object at a transaction-owned staging root.
    pub(crate) fn reset_incomplete_portable_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::Portable,
        )
    }

    /// Removes only an incomplete native object at a transaction-owned staging root.
    pub(crate) fn reset_incomplete_native_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::Native,
        )
    }

    /// Removes only an incomplete native-extension object at a transaction-owned staging root.
    pub(crate) fn reset_incomplete_native_extension_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeExtension,
        )
    }

    pub(crate) fn reset_incomplete_portable_instruction_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableInstruction,
        )
    }

    pub(crate) fn reset_incomplete_native_instruction_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeInstruction,
        )
    }

    pub(crate) fn reset_incomplete_portable_prompt_command_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortablePromptCommand,
        )
    }

    pub(crate) fn reset_incomplete_native_prompt_command_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativePromptCommand,
        )
    }

    pub(crate) fn reset_incomplete_portable_agent_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableAgent,
        )
    }

    pub(crate) fn reset_incomplete_native_agent_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeAgent,
        )
    }

    pub(crate) fn reset_incomplete_portable_mcp_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableMcp,
        )
    }

    pub(crate) fn reset_incomplete_native_mcp_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.reset_incomplete_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeMcp,
        )
    }

    /// Removes a partial transaction-owned control stage while preserving an exact complete one.
    pub(crate) fn reset_incomplete_staged_text(
        &self,
        staging_path: &PortablePath,
        expected: &str,
        max_bytes: usize,
    ) -> Result<(), ObjectMutationError> {
        match self.read_control_bytes(staging_path, max_bytes)? {
            None => Ok(()),
            Some(current) if current == expected.as_bytes() => Ok(()),
            Some(_) => self.remove_regular_file_if_present(staging_path),
        }
    }

    pub(crate) fn clear_portable_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::Portable,
        )
    }

    pub(crate) fn clear_native_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::Native,
        )
    }

    pub(crate) fn clear_portable_instruction_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableInstruction,
        )
    }

    pub(crate) fn clear_native_instruction_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeInstruction,
        )
    }

    pub(crate) fn clear_portable_prompt_command_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortablePromptCommand,
        )
    }

    pub(crate) fn clear_native_prompt_command_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativePromptCommand,
        )
    }

    pub(crate) fn clear_portable_agent_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableAgent,
        )
    }

    pub(crate) fn clear_native_agent_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeAgent,
        )
    }

    pub(crate) fn clear_portable_mcp_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableMcp,
        )
    }

    pub(crate) fn clear_native_mcp_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeMcp,
        )
    }

    pub(crate) fn clear_native_extension_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_staging(
            staging_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeExtension,
        )
    }

    pub(crate) fn clear_rendered_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        match self.inspect_rendered_directory(staging_root, expected_hash, limits)? {
            RenderedState::Missing => Ok(()),
            RenderedState::Unsafe => Err(unsafe_path()),
            RenderedState::Exact => {
                self.remove_exact_rendered_directory(staging_root, expected_hash, limits)
            }
            RenderedState::Different => Err(existing_conflict()),
        }
    }

    pub(crate) fn clear_extension_target_staging(
        &self,
        staging_root: &PortablePath,
        object: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        match self.inspect_extension_target(staging_root, object, limits)? {
            RenderedState::Missing => Ok(()),
            RenderedState::Unsafe => Err(unsafe_path()),
            RenderedState::Exact => {
                self.remove_exact_extension_target(staging_root, object, limits)
            }
            RenderedState::Different => Err(existing_conflict()),
        }
    }

    pub(crate) fn stage_extension_target(
        &self,
        staging_root: &PortablePath,
        object: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_extension_target_staging(staging_root, object, limits)?;
        match object.layout() {
            crate::NativeExtensionLayout::Standalone => {
                let file = object
                    .tree()
                    .files
                    .get(&PortablePath::parse(object.entrypoint()).map_err(|_| invalid_stage())?)
                    .ok_or_else(invalid_stage)?;
                let (parent, name) = self.open_or_create_parent(staging_root)?;
                write_new_captured_file(&parent, &name, file)?;
                sync_directory(&parent)?;
            }
            crate::NativeExtensionLayout::Directory => {
                let (parent, name) = self.open_or_create_parent(staging_root)?;
                let staging =
                    create_new_directory_with_security(&parent, &name, StoreSecurity::Portable)
                        .map_err(|_| mutation_io())?;
                write_extension_tree(&staging, object.tree())?;
                sync_directory(&staging)?;
                sync_directory(&parent)?;
            }
        }
        if self.inspect_extension_target(staging_root, object, limits)? != RenderedState::Exact {
            return Err(verification_failed());
        }
        Ok(())
    }

    pub(crate) fn install_extension_target(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        object: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_extension_target(destination_root, object, limits)?
            != RenderedState::Missing
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(staging_root, destination_root)
            .map_err(|_| precondition_failed())?;
        if self.inspect_extension_target(destination_root, object, limits)? != RenderedState::Exact
        {
            return Err(verification_failed());
        }
        Ok(())
    }

    pub(crate) fn quarantine_extension_target(
        &self,
        destination_root: &PortablePath,
        backup_root: &PortablePath,
        expected: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_extension_target(backup_root, expected, limits)? != RenderedState::Missing {
            return Err(precondition_failed());
        }
        if self.inspect_extension_target(destination_root, expected, limits)?
            != RenderedState::Exact
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(destination_root, backup_root)
            .map_err(|_| precondition_failed())?;
        if self.inspect_extension_target(backup_root, expected, limits)? != RenderedState::Exact {
            if self.inspect_extension_target(destination_root, expected, limits)?
                == RenderedState::Missing
            {
                self.move_noreplace(backup_root, destination_root)
                    .map_err(|_| precondition_failed())?;
            }
            return Err(precondition_failed());
        }
        Ok(())
    }

    pub(crate) fn restore_quarantined_extension_target(
        &self,
        backup_root: &PortablePath,
        destination_root: &PortablePath,
        expected: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_extension_target(destination_root, expected, limits)?
            != RenderedState::Missing
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(backup_root, destination_root)
            .map_err(|_| precondition_failed())?;
        if self.inspect_extension_target(destination_root, expected, limits)?
            != RenderedState::Exact
        {
            return Err(verification_failed());
        }
        Ok(())
    }

    pub(crate) fn remove_exact_extension_target(
        &self,
        root: &PortablePath,
        expected: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        match self.inspect_extension_target(root, expected, limits)? {
            RenderedState::Missing => return Ok(()),
            RenderedState::Exact => {}
            RenderedState::Different => return Err(existing_conflict()),
            RenderedState::Unsafe => return Err(unsafe_path()),
        }
        let (parent, name) = self.open_existing_parent(root)?;
        let before = parent.symlink_metadata(&name).map_err(|_| mutation_io())?;
        reject_link_like(&before)?;
        match expected.layout() {
            crate::NativeExtensionLayout::Standalone if before.is_file() => {
                if self.inspect_extension_target(root, expected, limits)? != RenderedState::Exact {
                    return Err(precondition_failed());
                }
                let after = parent.symlink_metadata(&name).map_err(|_| mutation_io())?;
                if MetadataIdentity::from_metadata(&before)
                    != MetadataIdentity::from_metadata(&after)
                {
                    return Err(precondition_failed());
                }
                let file = open_regular_file_nofollow(&parent, &name)?;
                let opened = file.metadata().map_err(|_| mutation_io())?;
                if MetadataIdentity::from_metadata(&opened)
                    != MetadataIdentity::from_metadata(&after)
                {
                    return Err(precondition_failed());
                }
                self.quarantine_regular_file(&parent, &name, file)
            }
            crate::NativeExtensionLayout::Directory if before.is_dir() => {
                if self.inspect_extension_target(root, expected, limits)? != RenderedState::Exact {
                    return Err(precondition_failed());
                }
                let after = parent.symlink_metadata(&name).map_err(|_| mutation_io())?;
                if MetadataIdentity::from_metadata(&before)
                    != MetadataIdentity::from_metadata(&after)
                {
                    return Err(precondition_failed());
                }
                self.remove_verified_directory_with_identity(
                    root,
                    MetadataIdentity::from_metadata(&after),
                )
            }
            _ => Err(unsafe_path()),
        }
    }

    fn inspect_extension_target(
        &self,
        root: &PortablePath,
        expected: &NativeExtensionObject,
        limits: CaptureLimits,
    ) -> Result<RenderedState, ObjectMutationError> {
        match self.capture_extension_target_object(
            root,
            expected.layout(),
            expected.entrypoint(),
            expected.native_id(),
            limits,
        ) {
            Ok(None) => Ok(RenderedState::Missing),
            Ok(Some(object)) if object.hash() == expected.hash() => Ok(RenderedState::Exact),
            Ok(Some(_)) => Ok(RenderedState::Different),
            Err(error) if error.code() == "object.unsafe_environment_root" => Err(error),
            Err(_) => Ok(RenderedState::Unsafe),
        }
    }

    pub(crate) fn capture_extension_target_object(
        &self,
        root: &PortablePath,
        layout: crate::NativeExtensionLayout,
        entrypoint: &str,
        native_id: &str,
        limits: CaptureLimits,
    ) -> Result<Option<NativeExtensionObject>, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(root)? else {
            return Ok(None);
        };
        let metadata = match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => metadata,
        };
        reject_link_like(&metadata)?;
        let display_path = self.root_path.join(root.as_str());
        let tree = match layout {
            crate::NativeExtensionLayout::Standalone if metadata.is_file() => {
                capture_standalone_tree_from_dir(&parent, &name, &display_path, limits)
                    .map(|(_, tree)| tree)
                    .map_err(|_| unsafe_path())?
            }
            crate::NativeExtensionLayout::Directory if metadata.is_dir() => {
                let directory = open_child_directory(&parent, &name)?;
                self.capture_open_directory(directory, &display_path, limits)
                    .map_err(|_| unsafe_path())?
            }
            _ => return Err(unsafe_path()),
        };
        let object = NativeExtensionObject::new(
            kitrove_model::HarnessId::Pi,
            layout,
            entrypoint,
            native_id,
            tree,
        )
        .map_err(|_| invalid_object())?;
        self.require_ambient_root_identity()?;
        Ok(Some(object))
    }

    pub(crate) fn stage_rendered_directory(
        &self,
        staging_root: &PortablePath,
        tree: &CapturedTree,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.clear_rendered_staging(staging_root, expected_hash, limits)?;
        if tree
            .files
            .values()
            .any(|file| file.mode == FileMode::Executable)
        {
            return Err(invalid_stage());
        }
        let (parent, name) = self.open_or_create_parent(staging_root)?;
        let staging = create_new_directory_with_security(&parent, &name, StoreSecurity::Portable)
            .map_err(|_| mutation_io())?;
        write_tree(&staging, tree)?;
        sync_directory(&staging)?;
        sync_directory(&parent)?;
        if self.inspect_rendered_directory(staging_root, expected_hash, limits)?
            != RenderedState::Exact
        {
            return Err(verification_failed());
        }
        Ok(())
    }

    pub(crate) fn install_rendered_directory(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.install_rendered_directory_with_hook(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            || {},
            || {},
        )
    }

    fn install_rendered_directory_with_hook(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        before_move: impl FnOnce(),
        after_move: impl FnOnce(),
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_rendered_directory(destination_root, expected_hash, limits)?
            != RenderedState::Missing
        {
            return Err(precondition_failed());
        }
        before_move();
        self.move_noreplace(staging_root, destination_root)
            .map_err(|_| precondition_failed())?;
        after_move();
        if self.inspect_rendered_directory(destination_root, expected_hash, limits)?
            != RenderedState::Exact
        {
            let quarantine = random_rendered_tombstone(destination_root)?;
            self.move_noreplace(destination_root, &quarantine)
                .map_err(|_| precondition_failed())?;
            if self.inspect_rendered_directory(destination_root, expected_hash, limits)?
                != RenderedState::Missing
            {
                return Err(precondition_failed());
            }
            return Err(precondition_failed());
        }
        Ok(())
    }

    pub(crate) fn quarantine_rendered_directory(
        &self,
        destination_root: &PortablePath,
        backup_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.quarantine_rendered_directory_with_hook(
            destination_root,
            backup_root,
            expected_hash,
            limits,
            || {},
        )
    }

    fn quarantine_rendered_directory_with_hook(
        &self,
        destination_root: &PortablePath,
        backup_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        before_move: impl FnOnce(),
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_rendered_directory(backup_root, expected_hash, limits)?
            != RenderedState::Missing
        {
            return Err(precondition_failed());
        }
        before_move();
        self.move_noreplace(destination_root, backup_root)
            .map_err(|_| precondition_failed())?;
        if self.inspect_rendered_directory(backup_root, expected_hash, limits)?
            != RenderedState::Exact
        {
            if self.inspect_rendered_directory(destination_root, expected_hash, limits)?
                == RenderedState::Missing
            {
                self.move_noreplace(backup_root, destination_root)
                    .map_err(|_| precondition_failed())?;
            }
            return Err(precondition_failed());
        }
        Ok(())
    }

    pub(crate) fn restore_quarantined_rendered_directory(
        &self,
        backup_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_rendered_directory(destination_root, expected_hash, limits)?
            != RenderedState::Missing
        {
            return Err(precondition_failed());
        }
        self.move_noreplace(backup_root, destination_root)
            .map_err(|_| precondition_failed())?;
        if self.inspect_rendered_directory(destination_root, expected_hash, limits)?
            != RenderedState::Exact
        {
            let quarantine = random_rendered_tombstone(destination_root)?;
            self.move_noreplace(destination_root, &quarantine)
                .map_err(|_| precondition_failed())?;
            return Err(precondition_failed());
        }
        Ok(())
    }

    pub(crate) fn remove_exact_rendered_directory(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_exact_rendered_directory_with_hooks(root, expected_hash, limits, || {}, || {})
    }

    fn remove_exact_rendered_directory_with_hooks(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        before_move: impl FnOnce(),
        before_remove: impl FnOnce(),
    ) -> Result<(), ObjectMutationError> {
        if self.inspect_rendered_directory(root, expected_hash, limits)? == RenderedState::Missing {
            return Ok(());
        }
        let tombstone = random_rendered_tombstone(root)?;
        before_move();
        self.move_noreplace(root, &tombstone)
            .map_err(|_| precondition_failed())?;
        match self.inspect_rendered_directory(&tombstone, expected_hash, limits)? {
            RenderedState::Exact => {
                let identity = self
                    .verified_rendered_identity(&tombstone, expected_hash, limits)
                    .ok_or_else(precondition_failed)?;
                before_remove();
                self.remove_verified_directory_with_identity(&tombstone, identity)
            }
            RenderedState::Different | RenderedState::Unsafe | RenderedState::Missing => {
                if self.inspect_rendered_directory(root, expected_hash, limits)?
                    == RenderedState::Missing
                {
                    self.move_noreplace(&tombstone, root)
                        .map_err(|_| precondition_failed())?;
                }
                Err(precondition_failed())
            }
        }
    }

    fn inspect_rendered_directory(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<RenderedState, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let Some((parent, name)) = self.open_existing_parent_optional(root)? else {
            return Ok(RenderedState::Missing);
        };
        let metadata = match parent.symlink_metadata(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(RenderedState::Missing);
            }
            Err(_) => return Err(mutation_io()),
            Ok(metadata) => metadata,
        };
        if reject_link_like(&metadata).is_err() || !metadata.is_dir() {
            return Ok(RenderedState::Unsafe);
        }
        let directory = match open_child_directory(&parent, &name) {
            Ok(directory) => directory,
            Err(_) => return Ok(RenderedState::Unsafe),
        };
        let tree = match self.capture_open_directory(
            directory,
            &self.root_path.join(root.as_str()),
            limits,
        ) {
            Ok(tree) => tree,
            Err(_) => return Ok(RenderedState::Unsafe),
        };
        self.require_ambient_root_identity()?;
        let actual = hash_skill_source(SkillSourceLayout::Directory, "SKILL.md", &tree);
        Ok(if &actual == expected_hash {
            RenderedState::Exact
        } else {
            RenderedState::Different
        })
    }

    fn verified_rendered_identity(
        &self,
        root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Option<MetadataIdentity> {
        let (parent, name) = self.open_existing_parent(root).ok()?;
        let before = parent.symlink_metadata(&name).ok()?;
        reject_link_like(&before).ok()?;
        if !before.is_dir()
            || self
                .inspect_rendered_directory(root, expected_hash, limits)
                .ok()?
                != RenderedState::Exact
        {
            return None;
        }
        let after = parent.symlink_metadata(&name).ok()?;
        if MetadataIdentity::from_metadata(&before) != MetadataIdentity::from_metadata(&after) {
            return None;
        }
        Some(MetadataIdentity::from_metadata(&after))
    }

    /// Installs a verified portable staging object at an absent destination.
    pub fn install_portable(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::Portable,
        )
    }

    /// Installs a verified native staging object at an absent destination.
    pub fn install_native(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::Native,
        )
    }

    /// Installs a verified portable instruction staging object at an absent destination.
    pub fn install_portable_instruction(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableInstruction,
        )
    }

    /// Installs a verified native instruction staging object at an absent destination.
    pub fn install_native_instruction(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeInstruction,
        )
    }

    pub fn install_portable_prompt_command(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortablePromptCommand,
        )
    }

    pub fn install_native_prompt_command(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativePromptCommand,
        )
    }

    pub fn install_portable_agent(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableAgent,
        )
    }

    pub fn install_native_agent(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeAgent,
        )
    }

    pub fn install_portable_mcp(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableMcp,
        )
    }

    pub fn install_native_mcp(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeMcp,
        )
    }

    /// Installs a verified native extension staging object at an absent destination.
    pub fn install_native_extension(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.install(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeExtension,
        )
    }

    pub(crate) fn remove_unreferenced_portable(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::Portable,
        )
    }

    pub(crate) fn remove_unreferenced_native(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::Native,
        )
    }

    pub(crate) fn remove_unreferenced_portable_instruction(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableInstruction,
        )
    }

    pub(crate) fn remove_unreferenced_native_instruction(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeInstruction,
        )
    }

    pub(crate) fn remove_unreferenced_portable_prompt_command(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortablePromptCommand,
        )
    }

    pub(crate) fn remove_unreferenced_native_prompt_command(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativePromptCommand,
        )
    }

    pub(crate) fn remove_unreferenced_portable_agent(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableAgent,
        )
    }

    pub(crate) fn remove_unreferenced_native_agent(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeAgent,
        )
    }

    pub(crate) fn remove_unreferenced_portable_mcp(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::PortableMcp,
        )
    }

    pub(crate) fn remove_unreferenced_native_mcp(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
    ) -> Result<(), ObjectMutationError> {
        self.remove_unreferenced_object(
            staging_root,
            destination_root,
            expected_hash,
            limits,
            StoredObjectKind::NativeMcp,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn stage(
        &self,
        staging_root: &PortablePath,
        metadata: String,
        tree: &CapturedTree,
        limits: CaptureLimits,
        expected_hash: ContentHash,
        kind: StoredObjectKind,
    ) -> Result<ObjectStageOutcome, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let (state, _) = self.inspect_stored_object(staging_root, limits, &expected_hash, kind)?;
        match state {
            ObjectState::Verified => return Ok(ObjectStageOutcome::AlreadyPresent),
            ObjectState::Missing => {}
            ObjectState::Unsafe => return Err(unsafe_path()),
            _ => return Err(existing_conflict()),
        }

        let (parent, name) = self.open_or_create_parent(staging_root)?;
        let object_root = match create_new_directory_with_security(&parent, &name, self.security) {
            Ok(directory) => directory,
            Err(error) => {
                if error == CreateDirectoryError::AlreadyExists
                    && self
                        .inspect_stored_object(staging_root, limits, &expected_hash, kind)?
                        .0
                        == ObjectState::Verified
                {
                    return Ok(ObjectStageOutcome::AlreadyPresent);
                }
                return Err(if error == CreateDirectoryError::AlreadyExists {
                    existing_conflict()
                } else {
                    mutation_io()
                });
            }
        };
        write_envelope(&object_root, &metadata, tree, self.security)?;
        sync_directory(&object_root)?;
        sync_directory(&parent)?;

        if self
            .inspect_stored_object(staging_root, limits, &expected_hash, kind)?
            .0
            != ObjectState::Verified
        {
            return Err(verification_failed());
        }
        self.require_ambient_root_identity()?;
        Ok(ObjectStageOutcome::Written)
    }

    fn reset_incomplete_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        kind: StoredObjectKind,
    ) -> Result<(), ObjectMutationError> {
        match self
            .inspect_stored_object(staging_root, limits, expected_hash, kind)?
            .0
        {
            ObjectState::Missing | ObjectState::Verified => Ok(()),
            ObjectState::Unsafe => Err(unsafe_path()),
            _ => self.remove_verified_directory(staging_root),
        }
    }

    fn clear_staging(
        &self,
        staging_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        kind: StoredObjectKind,
    ) -> Result<(), ObjectMutationError> {
        match self
            .inspect_stored_object(staging_root, limits, expected_hash, kind)?
            .0
        {
            ObjectState::Missing => Ok(()),
            ObjectState::Unsafe => Err(unsafe_path()),
            _ => self.remove_verified_directory(staging_root),
        }
    }

    fn install(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        kind: StoredObjectKind,
    ) -> Result<ObjectInstallOutcome, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        if staging_root == destination_root {
            return Err(invalid_install());
        }
        match self
            .inspect_stored_object(destination_root, limits, expected_hash, kind)?
            .0
        {
            ObjectState::Verified => return Ok(ObjectInstallOutcome::AlreadyPresent),
            ObjectState::Missing => {}
            ObjectState::Unsafe => return Err(unsafe_path()),
            _ => return Err(existing_conflict()),
        }

        if self
            .inspect_stored_object(staging_root, limits, expected_hash, kind)?
            .0
            != ObjectState::Verified
        {
            return Err(invalid_stage());
        }

        let (source_parent, source_name) = self.open_existing_parent(staging_root)?;
        let (destination_parent, destination_name) =
            self.open_or_create_parent(destination_root)?;
        if rename_noreplace(
            &source_parent,
            &source_name,
            &destination_parent,
            &destination_name,
        )
        .is_err()
        {
            if self
                .inspect_stored_object(destination_root, limits, expected_hash, kind)?
                .0
                == ObjectState::Verified
            {
                return Ok(ObjectInstallOutcome::AlreadyPresent);
            }
            return Err(install_failed());
        }
        sync_directory(&destination_parent)?;
        sync_directory(&source_parent)?;

        if self
            .inspect_stored_object(destination_root, limits, expected_hash, kind)?
            .0
            != ObjectState::Verified
        {
            return Err(verification_failed());
        }
        self.require_ambient_root_identity()?;
        Ok(ObjectInstallOutcome::Installed)
    }

    fn remove_unreferenced_object(
        &self,
        staging_root: &PortablePath,
        destination_root: &PortablePath,
        expected_hash: &ContentHash,
        limits: CaptureLimits,
        kind: StoredObjectKind,
    ) -> Result<(), ObjectMutationError> {
        self.require_ambient_root_identity()?;
        match self
            .inspect_stored_object(staging_root, limits, expected_hash, kind)?
            .0
        {
            ObjectState::Verified => self.remove_verified_directory(staging_root)?,
            ObjectState::Missing => {}
            ObjectState::Unsafe => return Err(unsafe_path()),
            _ => return Err(existing_conflict()),
        }
        match self
            .inspect_stored_object(destination_root, limits, expected_hash, kind)?
            .0
        {
            ObjectState::Missing => return Ok(()),
            ObjectState::Verified => {}
            ObjectState::Unsafe => return Err(unsafe_path()),
            _ => return Err(existing_conflict()),
        }
        self.move_noreplace(destination_root, staging_root)
            .map_err(|_| precondition_failed())?;
        if self
            .inspect_stored_object(staging_root, limits, expected_hash, kind)?
            .0
            != ObjectState::Verified
        {
            if self
                .inspect_stored_object(destination_root, limits, expected_hash, kind)?
                .0
                == ObjectState::Missing
            {
                self.move_noreplace(staging_root, destination_root)
                    .map_err(|_| precondition_failed())?;
            }
            return Err(precondition_failed());
        }
        self.remove_verified_directory(staging_root)?;
        self.require_ambient_root_identity()
    }

    fn remove_verified_directory(&self, path: &PortablePath) -> Result<(), ObjectMutationError> {
        let (parent, name) = self.open_existing_parent(path)?;
        let directory = open_child_directory(&parent, &name)?;
        self.quarantine_directory(&parent, &name, directory)
    }

    fn remove_verified_directory_with_identity(
        &self,
        path: &PortablePath,
        identity: MetadataIdentity,
    ) -> Result<(), ObjectMutationError> {
        let (parent, name) = self.open_existing_parent(path)?;
        let directory = open_child_directory(&parent, &name)?;
        let metadata = directory.dir_metadata().map_err(|_| mutation_io())?;
        if MetadataIdentity::from_metadata(&metadata) != identity {
            return Err(precondition_failed());
        }
        self.quarantine_directory(&parent, &name, directory)
    }

    fn open_or_create_parent(
        &self,
        path: &PortablePath,
    ) -> Result<(Dir, OsString), ObjectMutationError> {
        self.require_mutation_access()?;
        self.require_ambient_root_identity()?;
        let (parents, name) = split_portable(path);
        let mut directory = self.root.try_clone().map_err(|_| mutation_io())?;
        for component in parents {
            directory =
                open_or_create_directory_with_security(&directory, component, self.security)?;
        }
        Ok((directory, name.to_owned()))
    }

    const fn default_file_mode(&self) -> NewFileMode {
        file_mode_for_security(self.security)
    }

    fn require_mutation_access(&self) -> Result<(), ObjectMutationError> {
        if self.security == StoreSecurity::PrivateState
            && self.private_access != Some(PrivateDirectoryAccess::Mutate)
        {
            Err(unsafe_root())
        } else {
            Ok(())
        }
    }

    fn quarantine_regular_file(
        &self,
        source_parent: &Dir,
        name: &OsStr,
        file: cap_std::fs::File,
    ) -> Result<(), ObjectMutationError> {
        self.require_mutation_access()?;
        let quarantine = self.open_removal_quarantine()?;
        quarantine_open_file_to(
            source_parent,
            name,
            file,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::File),
            |_| {},
        )
    }

    fn quarantine_directory(
        &self,
        source_parent: &Dir,
        name: &OsStr,
        directory: Dir,
    ) -> Result<(), ObjectMutationError> {
        self.require_mutation_access()?;
        if self.security == StoreSecurity::PrivateState {
            prepare_private_directory(&directory, PrivateDirectoryAccess::Mutate)?;
        }
        let quarantine = self.open_removal_quarantine()?;
        quarantine_open_directory_to(
            source_parent,
            name,
            directory,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::Directory),
            |_| {},
        )
    }

    fn open_removal_quarantine(&self) -> Result<Dir, ObjectMutationError> {
        self.require_mutation_access()?;
        let control = self.open_or_create_private_control_directory()?;
        open_or_create_directory_with_security(
            &control,
            OsStr::new("removal-quarantine"),
            StoreSecurity::PrivateState,
        )
    }

    fn open_or_create_private_control_directory(&self) -> Result<Dir, ObjectMutationError> {
        self.require_mutation_access()?;
        open_or_create_directory_with_security(
            &self.root,
            OsStr::new(crate::local_state_authority::CONTROL_DIRECTORY),
            StoreSecurity::PrivateState,
        )
    }

    pub(crate) fn open_existing_removal_quarantine(
        &self,
    ) -> Result<Option<Dir>, ObjectMutationError> {
        self.open_existing_removal_quarantine_with_hook(|| {})
    }

    pub(crate) fn open_existing_removal_quarantine_with_hook(
        &self,
        after_inspection: impl FnOnce(),
    ) -> Result<Option<Dir>, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let quarantine = match open_optional_child_directory(
            &self.root,
            OsStr::new(crate::local_state_authority::CONTROL_DIRECTORY),
        )? {
            None => None,
            Some(control) => {
                let quarantine =
                    open_optional_child_directory(&control, OsStr::new("removal-quarantine"))?;
                if let Some(quarantine) = &quarantine {
                    prepare_private_directory(&control, PrivateDirectoryAccess::Inspect)?;
                    prepare_private_directory(quarantine, PrivateDirectoryAccess::Inspect)?;
                } else {
                    require_owned_nonwritable_directory(&control)?;
                }
                quarantine
            }
        };
        after_inspection();
        self.require_ambient_root_identity()?;
        Ok(quarantine)
    }

    fn open_existing_parent(
        &self,
        path: &PortablePath,
    ) -> Result<(Dir, OsString), ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let (parents, name) = split_portable(path);
        let mut directory = self.root.try_clone().map_err(|_| mutation_io())?;
        for component in parents {
            directory = open_child_directory(&directory, component)?;
            if let Some(access) = self.private_access {
                prepare_private_directory(&directory, access)?;
            }
        }
        Ok((directory, name.to_owned()))
    }

    fn sync_and_revalidate(&self, directory: &Dir) -> Result<(), ObjectMutationError> {
        sync_directory(directory)?;
        self.require_ambient_root_identity()
    }

    fn open_existing_parent_optional(
        &self,
        path: &PortablePath,
    ) -> Result<Option<(Dir, OsString)>, ObjectMutationError> {
        self.require_ambient_root_identity()?;
        let (parents, name) = split_portable(path);
        let mut directory = self.root.try_clone().map_err(|_| mutation_io())?;
        for component in parents {
            let metadata = match directory.symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(mutation_io()),
            };
            reject_link_like(&metadata)?;
            if !metadata.is_dir() {
                return Err(unsafe_path());
            }
            directory = open_child_directory(&directory, component)?;
            if let Some(access) = self.private_access {
                prepare_private_directory(&directory, access)?;
            }
        }
        Ok(Some((directory, name.to_owned())))
    }
}

fn resolve_root_lock_order(
    root_count: usize,
    mut resolve: impl FnMut(usize) -> Result<(MetadataIdentity, PathBuf), ObjectMutationError>,
) -> Result<Vec<usize>, ObjectMutationError> {
    let mut identities = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut resolved = Vec::with_capacity(root_count);
    for index in 0..root_count {
        let (identity, path) = resolve(index)?;
        if !identities.insert(identity) || !paths.insert(path.clone()) {
            return Err(unsafe_root());
        }
        resolved.push((identity, path, index));
    }
    if paths.iter().any(|path| {
        path.ancestors()
            .skip(1)
            .any(|ancestor| paths.contains(ancestor))
    }) {
        return Err(unsafe_root());
    }
    resolved.sort_unstable_by_key(|(identity, _, _)| *identity);
    Ok(resolved.into_iter().map(|(_, _, index)| index).collect())
}

impl Debug for ObjectStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStore")
            .field("root", &"capability-scoped")
            .finish()
    }
}

#[cfg(windows)]
struct PrivateCaptureHandleValidator;

#[cfg(windows)]
impl CaptureHandleValidator for PrivateCaptureHandleValidator {
    fn validate_directory(&mut self, directory: &Dir) -> bool {
        prepare_private_directory(directory, PrivateDirectoryAccess::Inspect).is_ok()
    }

    fn validate_file(&mut self, file: &cap_std::fs::File) -> bool {
        require_private_single_link_file(file).is_ok()
    }
}

fn write_envelope(
    object_root: &Dir,
    metadata: &str,
    tree: &CapturedTree,
    security: StoreSecurity,
) -> Result<(), ObjectMutationError> {
    write_new_file_with_mode(
        object_root,
        OsStr::new("metadata.json"),
        metadata.as_bytes(),
        file_mode_for_security(security),
    )?;
    let payload =
        open_or_create_directory_with_security(object_root, OsStr::new("payload"), security)?;
    for (path, file) in &tree.files {
        let (parents, name) = split_portable(path);
        let mut directory = payload.try_clone().map_err(|_| mutation_io())?;
        for component in parents {
            directory = open_or_create_directory_with_security(&directory, component, security)?;
        }
        write_new_file_with_mode(
            &directory,
            name,
            &file.bytes,
            file_mode_for_security(security),
        )?;
        sync_directory(&directory)?;
    }
    sync_directory(&payload)
}

const fn file_mode_for_security(security: StoreSecurity) -> NewFileMode {
    match security {
        StoreSecurity::Portable => NewFileMode::Inherited,
        StoreSecurity::PrivateState => NewFileMode::Private,
    }
}

fn write_tree(root: &Dir, tree: &CapturedTree) -> Result<(), ObjectMutationError> {
    for (path, file) in &tree.files {
        let (parents, name) = split_portable(path);
        let mut directory = root.try_clone().map_err(|_| mutation_io())?;
        for component in parents {
            directory = open_or_create_directory(&directory, component)?;
        }
        write_new_file(&directory, name, &file.bytes)?;
        sync_directory(&directory)?;
    }
    Ok(())
}

fn write_extension_tree(root: &Dir, tree: &CapturedTree) -> Result<(), ObjectMutationError> {
    for (path, file) in &tree.files {
        let (parents, name) = split_portable(path);
        let mut directory = root.try_clone().map_err(|_| mutation_io())?;
        for component in parents {
            directory = open_or_create_directory(&directory, component)?;
        }
        write_new_captured_file(&directory, name, file)?;
        sync_directory(&directory)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenderedState {
    Missing,
    Exact,
    Different,
    Unsafe,
}

fn write_new_file(parent: &Dir, name: &OsStr, bytes: &[u8]) -> Result<(), ObjectMutationError> {
    write_new_file_with_mode(parent, name, bytes, NewFileMode::Inherited)
}

fn write_new_file_with_mode(
    parent: &Dir,
    name: &OsStr,
    bytes: &[u8],
    mode: NewFileMode,
) -> Result<(), ObjectMutationError> {
    write_new_file_with_hook(parent, name, bytes, mode, || Ok(()))
}

#[derive(Clone, Copy)]
enum NewFileMode {
    Inherited,
    Private,
    Captured(FileMode),
    Exact(RegularFileMode),
}

fn write_new_file_with_hook(
    parent: &Dir,
    name: &OsStr,
    bytes: &[u8],
    mode: NewFileMode,
    after_open: impl FnOnce() -> Result<(), ObjectMutationError>,
) -> Result<(), ObjectMutationError> {
    write_new_file_with_hooks(parent, name, bytes, mode, after_open, || Ok(())).map(|_| ())
}

fn write_new_file_with_hooks(
    parent: &Dir,
    name: &OsStr,
    bytes: &[u8],
    mode: NewFileMode,
    after_open: impl FnOnce() -> Result<(), ObjectMutationError>,
    after_file_sync: impl FnOnce() -> Result<(), ObjectMutationError>,
) -> Result<MetadataIdentity, ObjectMutationError> {
    let mut file = create_new_file(parent, name, mode)?;
    let identity = match file.metadata() {
        Ok(metadata) => MetadataIdentity::from_metadata(&metadata),
        Err(_) => {
            remove_created_file(parent, name, file)?;
            return Err(mutation_io());
        }
    };
    let write_result = (|| {
        after_open()?;
        apply_new_file_mode(&mut file, mode)?;
        file.write_all(bytes).map_err(|_| mutation_io())?;
        file.sync_all().map_err(|_| mutation_io())?;
        after_file_sync()
    })();
    if let Err(error) = write_result {
        remove_created_file(parent, name, file)?;
        return Err(error);
    }
    Ok(identity)
}

fn create_new_file(
    parent: &Dir,
    name: &OsStr,
    _mode: NewFileMode,
) -> Result<cap_std::fs::File, ObjectMutationError> {
    #[cfg(windows)]
    {
        let file = if matches!(_mode, NewFileMode::Private) {
            kitrove_windows_security::create_private_file(parent, name)
        } else {
            kitrove_windows_security::create_owned_file(parent, name)
        }
        .map_err(|_| mutation_io())?;
        Ok(cap_std::fs::File::from_std(file))
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .sync(true);
        parent.open_with(name, &options).map_err(|_| mutation_io())
    }
}

fn open_or_create_lock_file(
    parent: &Dir,
    name: &OsStr,
    _security: StoreSecurity,
) -> Result<cap_std::fs::File, ObjectMutationError> {
    #[cfg(windows)]
    if _security == StoreSecurity::PrivateState {
        use kitrove_windows_security::ObjectCreationError;

        return match kitrove_windows_security::create_private_file(parent, name) {
            Ok(created) => {
                let identity =
                    kitrove_windows_security::file_identity(&created).map_err(|_| mutation_io())?;
                drop(created);
                let committed = open_private_lock_file(parent, name)?;
                if kitrove_windows_security::file_identity(&committed).map_err(|_| mutation_io())?
                    != identity
                    || kitrove_windows_security::inspect_private_file(&committed).is_err()
                {
                    return Err(mutation_io());
                }
                Ok(committed)
            }
            Err(ObjectCreationError::AlreadyExists) => open_private_lock_file(parent, name),
            Err(_) => Err(mutation_io()),
        };
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;

        options.share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE);
    }
    parent.open_with(name, &options).map_err(|_| mutation_io())
}

#[cfg(windows)]
fn open_private_lock_file(
    parent: &Dir,
    name: &OsStr,
) -> Result<cap_std::fs::File, ObjectMutationError> {
    use cap_std::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .access_mode(kitrove_windows_security::PRIVATE_FILE_WRITE_ACCESS)
        .share_mode(kitrove_windows_security::PRIVATE_FILE_LOCK_SHARE_MODE)
        .follow(FollowSymlinks::No);
    parent.open_with(name, &options).map_err(|_| mutation_io())
}

#[cfg(unix)]
fn apply_new_file_mode(
    file: &mut cap_std::fs::File,
    mode: NewFileMode,
) -> Result<(), ObjectMutationError> {
    use cap_std::fs::PermissionsExt as _;

    let permissions = match mode {
        NewFileMode::Inherited => return Ok(()),
        NewFileMode::Private | NewFileMode::Captured(FileMode::Regular) => 0o600,
        NewFileMode::Captured(FileMode::Executable) => 0o700,
        NewFileMode::Exact(mode) => mode.unix_mode().ok_or_else(mutation_io)?,
    };
    file.set_permissions(cap_std::fs::Permissions::from_mode(permissions))
        .map_err(|_| mutation_io())
}

#[cfg(windows)]
fn apply_new_file_mode(
    file: &mut cap_std::fs::File,
    mode: NewFileMode,
) -> Result<(), ObjectMutationError> {
    match mode {
        NewFileMode::Private => Ok(()),
        NewFileMode::Inherited
        | NewFileMode::Captured(FileMode::Regular | FileMode::Executable) => Ok(()),
        NewFileMode::Exact(mode) => {
            if mode.unix_mode().is_some() {
                return Err(mutation_io());
            }
            let mut permissions = file.metadata().map_err(|_| mutation_io())?.permissions();
            permissions.set_readonly(mode.readonly());
            file.set_permissions(permissions).map_err(|_| mutation_io())
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn apply_new_file_mode(
    file: &mut cap_std::fs::File,
    mode: NewFileMode,
) -> Result<(), ObjectMutationError> {
    match mode {
        NewFileMode::Inherited
        | NewFileMode::Private
        | NewFileMode::Captured(FileMode::Regular | FileMode::Executable) => Ok(()),
        NewFileMode::Exact(mode) => {
            if mode.unix_mode().is_some() {
                return Err(mutation_io());
            }
            let mut permissions = file.metadata().map_err(|_| mutation_io())?.permissions();
            permissions.set_readonly(mode.readonly());
            file.set_permissions(permissions).map_err(|_| mutation_io())
        }
    }
}

fn remove_created_file(
    parent: &Dir,
    name: &OsStr,
    file: cap_std::fs::File,
) -> Result<(), ObjectMutationError> {
    quarantine_open_file_with_prefix(parent, name, file, ".kitrove-incomplete-file-")
}

fn open_regular_file_nofollow(
    parent: &Dir,
    name: &OsStr,
) -> Result<cap_std::fs::File, ObjectMutationError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    parent.open_with(name, &options).map_err(|_| mutation_io())
}

fn quarantine_open_file_with_prefix(
    parent: &Dir,
    name: &OsStr,
    file: cap_std::fs::File,
    prefix: &str,
) -> Result<(), ObjectMutationError> {
    quarantine_open_file_with_hook(parent, name, file, prefix, |_| {})
}

fn quarantine_open_file_with_hook(
    parent: &Dir,
    name: &OsStr,
    file: cap_std::fs::File,
    prefix: &str,
    after_move: impl FnOnce(&OsStr),
) -> Result<(), ObjectMutationError> {
    quarantine_open_file_to(
        parent,
        name,
        file,
        parent,
        QuarantineName::RandomPrefix(prefix),
        after_move,
    )
}

#[derive(Clone, Copy)]
enum QuarantineName<'a> {
    RandomPrefix(&'a str),
    Removal(RemovedObjectKind),
}

fn quarantine_open_file_to(
    source_parent: &Dir,
    name: &OsStr,
    file: cap_std::fs::File,
    quarantine_parent: &Dir,
    name_spec: QuarantineName<'_>,
    after_move: impl FnOnce(&OsStr),
) -> Result<(), ObjectMutationError> {
    #[cfg(windows)]
    let mut file = Some(file);
    #[cfg(not(windows))]
    let file = Some(file);
    let opened = file
        .as_ref()
        .expect("quarantine owns the open file")
        .metadata()
        .map_err(|_| mutation_io())?;
    require_single_file_link(&opened)?;
    #[cfg(windows)]
    let native_identity = capture_windows_removal_file(
        name_spec,
        file.as_ref().expect("quarantine owns the open file"),
    )?;
    let tombstone = quarantine_name(name_spec, &opened)?;
    #[cfg(windows)]
    {
        let expected = kitrove_windows_security::file_identity(
            file.as_ref().expect("quarantine owns the open file"),
        )
        .map_err(|_| mutation_io())?;
        // Creation handles can carry DELETE access. Hand off that authority before
        // the native move retains its no-delete-sharing handle, binding the same identity.
        drop(file.take());
        let rollback = random_quarantine_name(".kitrove-move-retained-")?;
        kitrove_windows_security::move_owned_file(
            source_parent,
            name,
            quarantine_parent,
            &tombstone,
            &rollback,
            expected,
        )
        .map_err(map_windows_promotion_error)?;
        if native_identity.is_none() {
            let reopened = open_regular_file_nofollow(quarantine_parent, &tombstone)?;
            if kitrove_windows_security::file_identity(&reopened).map_err(|_| mutation_io())?
                != expected
            {
                return Err(precondition_failed());
            }
            file = Some(reopened);
        }
    }
    #[cfg(not(windows))]
    rename_noreplace(source_parent, name, quarantine_parent, &tombstone)
        .map_err(|_| quarantine_precondition_failed_at("initial-rename"))?;
    after_move(&tombstone);
    let current = quarantine_parent
        .symlink_metadata(&tombstone)
        .map_err(|_| quarantine_precondition_failed_at("staged-metadata"))?;
    reject_link_like(&current).map_err(|_| quarantine_precondition_failed_at("staged-kind"))?;
    let opened_identity = MetadataIdentity::from_metadata(&opened);
    if MetadataIdentity::from_metadata(&current) != opened_identity {
        return Err(quarantine_precondition_failed_at("staged-identity"));
    }
    #[cfg(windows)]
    let _committed_name = if let Some(expected) = native_identity {
        drop(file.take());
        let authoritative = windows_removal_quarantine_name(name_spec, expected)?;
        let rollback = windows_retained_quarantine_name(name_spec)?;
        kitrove_windows_security::promote_owned_file(
            quarantine_parent,
            &tombstone,
            &authoritative,
            &rollback,
            expected,
        )
        .map_err(map_windows_promotion_error)?;
        authoritative
    } else {
        tombstone
    };
    require_single_file_link(&current)?;

    let preserve_contents_for_exact_deletion =
        cfg!(windows) && matches!(name_spec, QuarantineName::Removal(_));
    if !preserve_contents_for_exact_deletion {
        // Truncate through the identity-bound handle. Unlinking by name after verification would
        // reintroduce a swap race on platforms without exact-handle deletion.
        let file = file.as_ref().ok_or_else(mutation_io)?;
        let before_truncate = file.metadata().map_err(|_| mutation_io())?;
        if MetadataIdentity::from_metadata(&before_truncate) != opened_identity {
            return Err(precondition_failed());
        }
        require_single_file_link(&before_truncate)?;
        file.set_len(0).map_err(|_| mutation_io())?;
        file.sync_all().map_err(|_| mutation_io())?;
    }
    drop(file);
    sync_directory(source_parent)?;
    sync_directory(quarantine_parent)
}

#[cfg(test)]
fn quarantine_open_directory_with_hook(
    parent: &Dir,
    name: &OsStr,
    directory: Dir,
    after_move: impl FnOnce(&OsStr),
) -> Result<(), ObjectMutationError> {
    quarantine_open_directory_to(
        parent,
        name,
        directory,
        parent,
        QuarantineName::RandomPrefix(REMOVED_DIRECTORY_PREFIX),
        after_move,
    )
}

fn quarantine_open_directory_to(
    source_parent: &Dir,
    name: &OsStr,
    directory: Dir,
    quarantine_parent: &Dir,
    name_spec: QuarantineName<'_>,
    after_move: impl FnOnce(&OsStr),
) -> Result<(), ObjectMutationError> {
    let opened = directory.dir_metadata().map_err(|_| mutation_io())?;
    #[cfg(windows)]
    let native_identity = capture_windows_removal_directory(name_spec, &directory)?;
    let tombstone = quarantine_name(name_spec, &opened)?;
    #[cfg(windows)]
    drop(directory);
    rename_noreplace(source_parent, name, quarantine_parent, &tombstone)
        .map_err(|_| quarantine_precondition_failed_at("initial-rename"))?;
    after_move(&tombstone);
    let current = quarantine_parent
        .symlink_metadata(&tombstone)
        .map_err(|_| quarantine_precondition_failed_at("staged-metadata"))?;
    reject_link_like(&current).map_err(|_| quarantine_precondition_failed_at("staged-kind"))?;
    if MetadataIdentity::from_metadata(&current) != MetadataIdentity::from_metadata(&opened) {
        return Err(quarantine_precondition_failed_at("staged-identity"));
    }
    #[cfg(windows)]
    {
        let _committed_name = if let Some(expected) = native_identity {
            let authoritative = windows_removal_quarantine_name(name_spec, expected)?;
            let rollback = windows_retained_quarantine_name(name_spec)?;
            kitrove_windows_security::promote_owned_directory(
                quarantine_parent,
                &tombstone,
                &authoritative,
                &rollback,
                expected,
            )
            .map_err(map_windows_promotion_error)?;
            authoritative
        } else {
            tombstone
        };
        // cap-std directory handles lack delete sharing, so stage under a retained-only name,
        // verify the reopened object, and only then promote it to identity-bearing authority.
        sync_directory(source_parent)?;
        sync_directory(quarantine_parent)
    }
    #[cfg(not(windows))]
    {
        directory.remove_open_dir_all().map_err(|_| mutation_io())?;
        sync_directory(source_parent)?;
        sync_directory(quarantine_parent)
    }
}

fn quarantine_precondition_failed_at(_stage: &'static str) -> ObjectMutationError {
    mutation_error_at_test_stage(precondition_failed(), _stage)
}

fn random_quarantine_name(prefix: &str) -> Result<OsString, ObjectMutationError> {
    Ok(OsString::from(format!("{prefix}{}", random_nonce()?)))
}

#[cfg(windows)]
fn capture_windows_removal_file(
    name: QuarantineName<'_>,
    file: &cap_std::fs::File,
) -> Result<Option<kitrove_windows_security::WindowsFileIdentity>, ObjectMutationError> {
    if !matches!(name, QuarantineName::Removal(_)) {
        return Ok(None);
    }
    kitrove_windows_security::inspect_owned_file(file).map_err(|_| precondition_failed())?;
    kitrove_windows_security::file_identity(file)
        .map(Some)
        .map_err(|_| mutation_io())
}

#[cfg(windows)]
fn capture_windows_removal_directory(
    name: QuarantineName<'_>,
    directory: &Dir,
) -> Result<Option<kitrove_windows_security::WindowsFileIdentity>, ObjectMutationError> {
    if !matches!(name, QuarantineName::Removal(_)) {
        return Ok(None);
    }
    kitrove_windows_security::inspect_owned_directory(directory)
        .map_err(|_| precondition_failed())?;
    kitrove_windows_security::file_identity(directory)
        .map(Some)
        .map_err(|_| mutation_io())
}

fn require_single_file_link(metadata: &Metadata) -> Result<(), ObjectMutationError> {
    if has_single_file_link(metadata) {
        Ok(())
    } else {
        Err(precondition_failed())
    }
}

fn quarantine_name(
    name: QuarantineName<'_>,
    metadata: &Metadata,
) -> Result<OsString, ObjectMutationError> {
    match name {
        QuarantineName::RandomPrefix(prefix) => random_quarantine_name(prefix),
        QuarantineName::Removal(kind) => {
            #[cfg(windows)]
            {
                let _ = metadata;
                RetainedTombstoneName { kind }
                    .encode(&random_nonce()?)
                    .ok_or_else(mutation_io)
            }
            #[cfg(not(windows))]
            {
                removal_quarantine_name(kind, metadata)
            }
        }
    }
}

#[cfg(unix)]
fn removal_quarantine_name(
    kind: RemovedObjectKind,
    metadata: &Metadata,
) -> Result<OsString, ObjectMutationError> {
    let record = RemovalTombstoneName {
        kind,
        identity: MetadataIdentity::from_metadata(metadata),
    };
    let encoded = record.encode(&random_nonce()?).ok_or_else(mutation_io)?;
    debug_assert_eq!(RemovalTombstoneName::parse(&encoded), Some(record));
    Ok(encoded)
}

#[cfg(windows)]
fn windows_removal_quarantine_name(
    name: QuarantineName<'_>,
    identity: kitrove_windows_security::WindowsFileIdentity,
) -> Result<OsString, ObjectMutationError> {
    let QuarantineName::Removal(kind) = name else {
        return Err(mutation_io());
    };
    let record = RemovalTombstoneName { kind, identity };
    let encoded = record.encode(&random_nonce()?).ok_or_else(mutation_io)?;
    debug_assert_eq!(RemovalTombstoneName::parse(&encoded), Some(record));
    Ok(encoded)
}

#[cfg(windows)]
fn windows_retained_quarantine_name(
    name: QuarantineName<'_>,
) -> Result<OsString, ObjectMutationError> {
    let QuarantineName::Removal(kind) = name else {
        return Err(mutation_io());
    };
    RetainedTombstoneName { kind }
        .encode(&random_nonce()?)
        .ok_or_else(mutation_io)
}

#[cfg(windows)]
fn map_windows_promotion_error(
    error: kitrove_windows_security::OwnedObjectPromotionError,
) -> ObjectMutationError {
    match error {
        kitrove_windows_security::OwnedObjectPromotionError::Failed => {
            quarantine_precondition_failed_at("promotion")
        }
        kitrove_windows_security::OwnedObjectPromotionError::RollbackFailed => {
            mutation_error_at_test_stage(mutation_io(), "promotion-rollback")
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn removal_quarantine_name(
    kind: RemovedObjectKind,
    _metadata: &Metadata,
) -> Result<OsString, ObjectMutationError> {
    RetainedTombstoneName { kind }
        .encode(&random_nonce()?)
        .ok_or_else(mutation_io)
}

fn write_new_captured_file(
    parent: &Dir,
    name: &OsStr,
    captured: &kitrove_agent_skills::CapturedFile,
) -> Result<(), ObjectMutationError> {
    write_new_file_with_hook(
        parent,
        name,
        &captured.bytes,
        NewFileMode::Captured(captured.mode),
        || Ok(()),
    )
}

fn write_new_private_file(
    parent: &Dir,
    name: &OsStr,
    bytes: &[u8],
) -> Result<(), ObjectMutationError> {
    write_new_file_with_hook(parent, name, bytes, NewFileMode::Private, || Ok(()))
}

fn open_or_create_directory(parent: &Dir, name: &OsStr) -> Result<Dir, ObjectMutationError> {
    open_or_create_directory_with_security(parent, name, StoreSecurity::Portable)
}

fn open_or_create_directory_with_security(
    parent: &Dir,
    name: &OsStr,
    security: StoreSecurity,
) -> Result<Dir, ObjectMutationError> {
    match parent.symlink_metadata(name) {
        Ok(_) => {
            let directory = open_child_directory(parent, name)?;
            if security == StoreSecurity::PrivateState {
                prepare_private_directory(&directory, PrivateDirectoryAccess::Mutate)?;
            }
            Ok(directory)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match create_new_directory_with_security(parent, name, security) {
                Ok(directory) => Ok(directory),
                Err(CreateDirectoryError::AlreadyExists) => {
                    let directory = open_child_directory(parent, name)?;
                    if security == StoreSecurity::PrivateState {
                        prepare_private_directory(&directory, PrivateDirectoryAccess::Mutate)?;
                    }
                    Ok(directory)
                }
                Err(CreateDirectoryError::Failed) => Err(mutation_io()),
            }
        }
        Err(_) => Err(mutation_io()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateDirectoryError {
    AlreadyExists,
    Failed,
}

fn create_new_directory_with_security(
    parent: &Dir,
    name: &OsStr,
    security: StoreSecurity,
) -> Result<Dir, CreateDirectoryError> {
    #[cfg(windows)]
    {
        use kitrove_windows_security::ObjectCreationError;

        let created = if security == StoreSecurity::PrivateState {
            kitrove_windows_security::create_private_directory(parent, name)
        } else {
            kitrove_windows_security::create_owned_directory(parent, name)
        };
        created
            .map(Dir::from_std_file)
            .map_err(|error| match error {
                ObjectCreationError::AlreadyExists => CreateDirectoryError::AlreadyExists,
                ObjectCreationError::Failed
                | ObjectCreationError::RollbackFailed
                | ObjectCreationError::HandoffFailed => CreateDirectoryError::Failed,
            })
    }
    #[cfg(not(windows))]
    {
        parent.create_dir(name).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CreateDirectoryError::AlreadyExists
            } else {
                CreateDirectoryError::Failed
            }
        })?;
        let directory =
            open_child_directory(parent, name).map_err(|_| CreateDirectoryError::Failed)?;
        if security == StoreSecurity::PrivateState {
            prepare_private_directory(&directory, PrivateDirectoryAccess::Mutate)
                .map_err(|_| CreateDirectoryError::Failed)?;
        }
        Ok(directory)
    }
}

#[cfg(not(windows))]
fn prepare_private_directory(
    directory: &Dir,
    access: PrivateDirectoryAccess,
) -> Result<(), ObjectMutationError> {
    require_private_directory_owner(directory)?;
    require_private_directory_acl(directory)?;
    if access == PrivateDirectoryAccess::Mutate {
        set_private_directory_permissions(directory)?;
    }
    require_private_directory_mode(directory)?;
    require_private_directory_acl(directory)
}

#[cfg(windows)]
fn prepare_private_directory(
    directory: &Dir,
    access: PrivateDirectoryAccess,
) -> Result<(), ObjectMutationError> {
    use kitrove_windows_security::{
        PRIVATE_INSPECT_ACCESS, PRIVATE_MUTATE_ACCESS, inspect_private_directory,
        repair_private_directory,
    };

    let handle = open_private_directory_security_handle(
        directory,
        match access {
            PrivateDirectoryAccess::Inspect => PRIVATE_INSPECT_ACCESS,
            PrivateDirectoryAccess::Mutate => PRIVATE_MUTATE_ACCESS,
        },
    )?;
    match access {
        PrivateDirectoryAccess::Inspect => {
            inspect_private_directory(&handle).map_err(|_| unsafe_root())
        }
        PrivateDirectoryAccess::Mutate => {
            if inspect_private_directory(&handle).is_err() {
                repair_private_directory(&handle).map_err(|_| mutation_io())?;
            }
            inspect_private_directory(&handle).map_err(|_| unsafe_root())
        }
    }
}

#[cfg(windows)]
fn open_private_directory_security_handle(
    directory: &Dir,
    access: u32,
) -> Result<std::fs::File, ObjectMutationError> {
    use cap_std::fs::OpenOptionsExt as _;
    use kitrove_windows_security::PRIVATE_DIRECTORY_OPEN_FLAGS;

    let mut options = OpenOptions::new();
    options
        .access_mode(access)
        .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
        .follow(FollowSymlinks::No);
    let handle = directory
        .open_with(".", &options)
        .map_err(|_| unsafe_root())?;
    let metadata = handle.metadata().map_err(|_| unsafe_root())?;
    if !metadata.is_dir() || metadata_is_windows_reparse(&metadata) {
        return Err(unsafe_root());
    }
    Ok(handle.into_std())
}

#[cfg(windows)]
fn require_private_single_link_file(file: &cap_std::fs::File) -> Result<(), ObjectMutationError> {
    kitrove_windows_security::inspect_private_single_link_file(file).map_err(|_| unsafe_path())
}

fn require_owned_nonwritable_directory(directory: &Dir) -> Result<(), ObjectMutationError> {
    require_private_directory_owner(directory)?;
    require_private_directory_acl(directory)?;
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        let metadata = directory.dir_metadata().map_err(|_| unsafe_root())?;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(unsafe_root());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "redox", windows))]
pub(crate) fn secure_private_directory_for_mutation(
    directory: &Dir,
) -> Result<(), ObjectMutationError> {
    prepare_private_directory(directory, PrivateDirectoryAccess::Mutate)
}

#[cfg(target_os = "macos")]
fn require_private_directory_acl(directory: &Dir) -> Result<(), ObjectMutationError> {
    use std::os::fd::AsFd as _;

    let acl = calcifer_macos_acl::read_acl(directory.as_fd()).map_err(|_| unsafe_root())?;
    if !acl.is_empty() {
        return Err(unsafe_root());
    }
    Ok(())
}

#[cfg(windows)]
fn require_private_directory_acl(directory: &Dir) -> Result<(), ObjectMutationError> {
    let handle = open_private_directory_security_handle(
        directory,
        kitrove_windows_security::PRIVATE_INSPECT_ACCESS,
    )?;
    kitrove_windows_security::inspect_private_directory(&handle).map_err(|_| unsafe_root())
}

#[cfg(not(any(target_os = "macos", windows)))]
const fn require_private_directory_acl(_directory: &Dir) -> Result<(), ObjectMutationError> {
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "redox"))
))]
pub(crate) const fn secure_private_directory_for_mutation(
    _directory: &Dir,
) -> Result<(), ObjectMutationError> {
    Err(unsafe_root())
}

#[cfg(unix)]
fn set_private_directory_permissions(directory: &Dir) -> Result<(), ObjectMutationError> {
    use cap_std::fs::PermissionsExt as _;
    directory
        .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
        .map_err(|_| mutation_io())
}

#[cfg(not(any(unix, windows)))]
const fn set_private_directory_permissions(_directory: &Dir) -> Result<(), ObjectMutationError> {
    Ok(())
}

#[cfg(unix)]
fn require_private_directory_mode(directory: &Dir) -> Result<(), ObjectMutationError> {
    use cap_std::fs::PermissionsExt as _;
    let metadata = directory.dir_metadata().map_err(|_| unsafe_root())?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(unsafe_root());
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
const fn require_private_directory_mode(_directory: &Dir) -> Result<(), ObjectMutationError> {
    Ok(())
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
fn require_private_directory_owner(directory: &Dir) -> Result<(), ObjectMutationError> {
    let metadata = directory.dir_metadata().map_err(|_| unsafe_root())?;
    use cap_fs_ext::OsMetadataExt as _;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(unsafe_root());
    }
    Ok(())
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "redox")))]
const fn require_private_directory_owner(_directory: &Dir) -> Result<(), ObjectMutationError> {
    Ok(())
}

fn open_child_directory(parent: &Dir, name: &OsStr) -> Result<Dir, ObjectMutationError> {
    let before = parent.symlink_metadata(name).map_err(|_| mutation_io())?;
    open_child_directory_from_metadata(parent, name, &before)
}

fn open_child_directory_from_metadata(
    parent: &Dir,
    name: &OsStr,
    before: &Metadata,
) -> Result<Dir, ObjectMutationError> {
    reject_link_like(before)?;
    if !before.is_dir() {
        return Err(unsafe_path());
    }
    let child = parent.open_dir_nofollow(name).map_err(|_| unsafe_path())?;
    let after = child.dir_metadata().map_err(|_| mutation_io())?;
    reject_link_like(&after)?;
    if !after.is_dir()
        || MetadataIdentity::from_metadata(before) != MetadataIdentity::from_metadata(&after)
    {
        return Err(unsafe_path());
    }
    Ok(child)
}

fn open_optional_child_directory(
    parent: &Dir,
    name: &OsStr,
) -> Result<Option<Dir>, ObjectMutationError> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(mutation_io()),
        Ok(metadata) => open_child_directory_from_metadata(parent, name, &metadata).map(Some),
    }
}

fn open_root_nofollow(root: &Path) -> Result<Dir, ObjectMutationError> {
    let (anchor, components) = split_absolute_root(root)?;
    let mut directory =
        Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|_| unsafe_root())?;
    reject_link_like(&directory.dir_metadata().map_err(|_| unsafe_root())?)?;
    for component in components {
        directory = open_child_directory(&directory, &component).map_err(|_| unsafe_root())?;
    }
    Ok(directory)
}

fn require_non_overlapping_root_topology(
    first: &Path,
    second: &Path,
) -> Result<(), ObjectMutationError> {
    let first = resolved_lexical_root(first)?;
    let second = resolved_lexical_root(second)?;
    if roots_overlap(&first, &second)? {
        Err(unsafe_root())
    } else {
        Ok(())
    }
}

fn resolved_lexical_root(root: &Path) -> Result<PathBuf, ObjectMutationError> {
    let normalized = normalized_absolute_root(root)?;
    let mut existing = normalized.as_path();
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => {
                open_root_nofollow(existing)?;
                let mut resolved = std::fs::canonicalize(existing).map_err(|_| unsafe_root())?;
                resolved.extend(missing.iter().rev());
                return normalized_absolute_root(&resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or_else(unsafe_root)?;
                missing.push(name.to_owned());
                existing = existing.parent().ok_or_else(unsafe_root)?;
            }
            Err(_) => return Err(unsafe_root()),
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn roots_overlap(first: &Path, second: &Path) -> Result<bool, ObjectMutationError> {
    Ok(first == second || first.starts_with(second) || second.starts_with(first))
}

#[cfg(windows)]
fn roots_overlap(first: &Path, second: &Path) -> Result<bool, ObjectMutationError> {
    kitrove_windows_security::paths_overlap_case_insensitive(first, second)
        .map_err(|_| unsafe_root())
}

#[cfg(target_os = "macos")]
fn roots_overlap(first: &Path, second: &Path) -> Result<bool, ObjectMutationError> {
    use unicode_normalization::UnicodeNormalization as _;

    fn collision_key(path: &Path) -> Result<PathBuf, ObjectMutationError> {
        let path = path.to_str().ok_or_else(unsafe_root)?;
        let normalized: String = path.nfc().collect();
        Ok(PathBuf::from(
            unicase::UniCase::unicode(normalized)
                .to_folded_case()
                .nfc()
                .collect::<String>(),
        ))
    }

    let first = collision_key(first)?;
    let second = collision_key(second)?;
    Ok(first == second || first.starts_with(&second) || second.starts_with(&first))
}

fn normalized_absolute_root(root: &Path) -> Result<PathBuf, ObjectMutationError> {
    let absolute = std::path::absolute(root).map_err(|_| unsafe_root())?;
    let (mut normalized, components) = split_absolute_root(&absolute)?;
    normalized.extend(components);
    Ok(normalized)
}

fn split_absolute_root(root: &Path) -> Result<(PathBuf, Vec<OsString>), ObjectMutationError> {
    if raw_parent_component(root) {
        return Err(unsafe_root());
    }
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in root.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(component) if component == OsStr::new(".") => {}
            Component::Normal(component) if component == OsStr::new("..") => {
                return Err(unsafe_root());
            }
            Component::Normal(component) => components.push(component.to_owned()),
            Component::ParentDir => return Err(unsafe_root()),
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(unsafe_root());
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

fn split_portable(path: &PortablePath) -> (Vec<&OsStr>, &OsStr) {
    let components = path.as_str().split('/').map(OsStr::new).collect::<Vec<_>>();
    let (name, parents) = components
        .split_last()
        .expect("PortablePath always has at least one segment");
    (parents.to_vec(), name)
}

pub(crate) fn guarded_backup_path(
    staging_path: &PortablePath,
) -> Result<PortablePath, ObjectMutationError> {
    PortablePath::parse(format!("{}.previous", staging_path.as_str()))
        .map_err(|_| invalid_install())
}

fn random_rendered_tombstone(root: &PortablePath) -> Result<PortablePath, ObjectMutationError> {
    let nonce = random_nonce()?;
    let (parent, name) = root.as_str().rsplit_once('/').ok_or_else(invalid_install)?;
    PortablePath::parse(format!("{parent}/.{name}.kitrove-remove-{nonce}"))
        .map_err(|_| invalid_install())
}

pub(crate) fn random_nonce() -> Result<String, ObjectMutationError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| mutation_io())?;
    Ok(random.iter().fold(
        String::with_capacity(random.len() * 2),
        |mut nonce, byte| {
            std::fmt::Write::write_fmt(&mut nonce, format_args!("{byte:02x}"))
                .expect("writing to a String cannot fail");
            nonce
        },
    ))
}

#[cfg(unix)]
pub(crate) fn sync_directory(directory: &Dir) -> Result<(), ObjectMutationError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(".", &options)
        .map_err(|_| mutation_io())?
        .into_std()
        .sync_all()
        .map_err(|_| mutation_io())
}

#[cfg(windows)]
pub(crate) fn sync_directory(_directory: &Dir) -> Result<(), ObjectMutationError> {
    // Windows does not expose a directory equivalent of fsync/FlushFileBuffers.
    // File payloads are synced before metadata operations at every call site.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_directory(directory: &Dir) -> Result<(), ObjectMutationError> {
    directory
        .try_clone()
        .map_err(|_| mutation_io())?
        .into_std_file()
        .sync_all()
        .map_err(|_| mutation_io())
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
pub(crate) fn rename_noreplace(
    source_parent: &Dir,
    source_name: &OsStr,
    destination_parent: &Dir,
    destination_name: &OsStr,
) -> Result<(), ()> {
    rustix::fs::renameat_with(
        source_parent,
        source_name,
        destination_parent,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|_| ())
}

#[cfg(any(target_vendor = "apple", target_os = "linux"))]
fn rename_exchange(
    first_parent: &Dir,
    first_name: &OsStr,
    second_parent: &Dir,
    second_name: &OsStr,
) -> Result<(), ()> {
    rustix::fs::renameat_with(
        first_parent,
        first_name,
        second_parent,
        second_name,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|_| ())
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
fn rename_exchange(
    _first_parent: &Dir,
    _first_name: &OsStr,
    _second_parent: &Dir,
    _second_name: &OsStr,
) -> Result<(), ()> {
    Err(())
}

const fn atomic_exchange_supported() -> bool {
    cfg!(any(target_vendor = "apple", target_os = "linux"))
}

#[cfg(windows)]
pub(crate) fn rename_noreplace(
    source_parent: &Dir,
    source_name: &OsStr,
    destination_parent: &Dir,
    destination_name: &OsStr,
) -> Result<(), ()> {
    let metadata = source_parent
        .symlink_metadata(source_name)
        .map_err(|_| ())?;
    reject_link_like(&metadata).map_err(|_| ())?;
    let rollback = random_quarantine_name(".kitrove-move-retained-").map_err(|_| ())?;
    if metadata.is_dir() {
        let source = open_child_directory_from_metadata(source_parent, source_name, &metadata)
            .map_err(|_| ())?;
        let identity = kitrove_windows_security::file_identity(&source).map_err(|_| ())?;
        drop(source);
        kitrove_windows_security::move_owned_directory(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
            &rollback,
            identity,
        )
        .map_err(|_| ())
    } else if metadata.is_file() {
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let source = source_parent
            .open_with(source_name, &options)
            .map_err(|_| ())?;
        let opened = source.metadata().map_err(|_| ())?;
        if MetadataIdentity::from_metadata(&metadata) != MetadataIdentity::from_metadata(&opened) {
            return Err(());
        }
        let identity = kitrove_windows_security::file_identity(&source).map_err(|_| ())?;
        drop(source);
        kitrove_windows_security::move_owned_file(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
            &rollback,
            identity,
        )
        .map_err(|_| ())
    } else {
        Err(())
    }
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "redox",
    windows
)))]
pub(crate) fn rename_noreplace(
    _source_parent: &Dir,
    _source_name: &OsStr,
    _destination_parent: &Dir,
    _destination_name: &OsStr,
) -> Result<(), ()> {
    Err(())
}

fn reject_link_like(metadata: &Metadata) -> Result<(), ObjectMutationError> {
    if metadata.is_symlink() || metadata_is_windows_reparse(metadata) {
        Err(unsafe_path())
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

const fn mutation_error(code: &'static str, message: &'static str) -> ObjectMutationError {
    ObjectMutationError {
        code,
        message,
        #[cfg(test)]
        test_stage: None,
    }
}

#[cfg(test)]
fn mutation_error_at_test_stage(
    mut error: ObjectMutationError,
    stage: &'static str,
) -> ObjectMutationError {
    error.test_stage = Some(stage);
    error
}

#[cfg(not(test))]
const fn mutation_error_at_test_stage(
    error: ObjectMutationError,
    _stage: &'static str,
) -> ObjectMutationError {
    error
}

const fn unsafe_root() -> ObjectMutationError {
    mutation_error(
        "object.unsafe_environment_root",
        "environment root is not a safe directory",
    )
}

const fn unsafe_path() -> ObjectMutationError {
    mutation_error(
        "object.unsafe_path",
        "object path contains an unsafe filesystem entry",
    )
}

const fn mutation_io() -> ObjectMutationError {
    mutation_error("object.io", "immutable object storage operation failed")
}

fn lock_error(error: io::Error) -> ObjectMutationError {
    let contended = fs2::lock_contended_error();
    let is_contended = match (error.raw_os_error(), contended.raw_os_error()) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => error.kind() == contended.kind(),
    };
    if is_contended {
        lock_busy()
    } else {
        mutation_io()
    }
}

const fn lock_busy() -> ObjectMutationError {
    mutation_error(
        "object.environment_locked",
        "another portable environment mutation is already active",
    )
}

const fn control_file_invalid() -> ObjectMutationError {
    mutation_error(
        "object.control_file_invalid",
        "a portable environment control file is invalid or exceeds its limit",
    )
}

const fn invalid_object() -> ObjectMutationError {
    mutation_error(
        "object_mutation.invalid_object",
        "immutable object is not a valid verified envelope",
    )
}

const fn invalid_initial_authority() -> ObjectMutationError {
    mutation_error(
        "object_mutation.initial_authority_not_empty",
        "initial portable and machine-local authority must be empty",
    )
}

const fn precondition_failed() -> ObjectMutationError {
    mutation_error(
        "object.precondition_failed",
        "portable authority changed after its transaction precondition was read",
    )
}

const fn existing_conflict() -> ObjectMutationError {
    mutation_error(
        "object.existing_conflict",
        "existing object path has different content",
    )
}

const fn invalid_stage() -> ObjectMutationError {
    mutation_error(
        "object.invalid_stage",
        "staging object is missing, unsafe, or does not match",
    )
}

const fn invalid_install() -> ObjectMutationError {
    mutation_error(
        "object.invalid_install",
        "staging and destination roots must differ",
    )
}

const fn install_failed() -> ObjectMutationError {
    mutation_error(
        "object.install_failed",
        "staged object could not be installed without replacement",
    )
}

const fn verification_failed() -> ObjectMutationError {
    mutation_error(
        "object.verification_failed",
        "written object did not pass independent verification",
    )
}

#[cfg(test)]
mod internal_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::sync::{Arc, Barrier};

    use kitrove_agent_skills::{CapturedFile, hash_tree};
    use kitrove_instructions::{InstructionBody, render_managed_region};
    use kitrove_model::{BindingName, MachineConfig, MachineId, ProfileId, SchemaVersion};

    use super::*;

    fn trusted_tempdir() -> tempfile::TempDir {
        crate::test_authority::trusted_tempdir(".kitrove-object-mutation-")
    }

    #[cfg(windows)]
    #[test]
    fn windows_creation_failure_hands_off_its_handle_before_quarantine() {
        let root = trusted_tempdir();
        let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
        let mut reached = false;
        assert!(
            write_new_file_with_hook(
                &parent,
                OsStr::new("fresh"),
                b"bytes",
                NewFileMode::Inherited,
                || {
                    reached = true;
                    Err(mutation_io())
                }
            )
            .is_err()
        );
        assert!(reached);
        assert!(!root.path().join("fresh").exists());
        let entries = fs::read_dir(root.path())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .file_name()
                .to_str()
                .unwrap()
                .starts_with(".kitrove-incomplete-file-")
        );
        assert_eq!(fs::read(entries[0].path()).unwrap(), b"");
    }

    #[cfg(windows)]
    #[test]
    fn windows_noreplace_preserves_collisions_and_moves_to_absent_names() {
        for directory in [false, true] {
            let root = trusted_tempdir();
            let parent = Dir::open_ambient_dir(root.path(), cap_std::ambient_authority()).unwrap();
            if directory {
                drop(
                    kitrove_windows_security::create_owned_directory(&parent, OsStr::new("source"))
                        .unwrap(),
                );
                drop(
                    kitrove_windows_security::create_owned_directory(
                        &parent,
                        OsStr::new("occupied"),
                    )
                    .unwrap(),
                );
                fs::write(root.path().join("source/bytes"), b"source").unwrap();
                fs::write(root.path().join("occupied/bytes"), b"occupied").unwrap();
            } else {
                for (name, bytes) in [
                    ("source", b"source".as_slice()),
                    ("occupied", b"occupied".as_slice()),
                ] {
                    let mut file =
                        kitrove_windows_security::create_owned_file(&parent, OsStr::new(name))
                            .unwrap();
                    file.write_all(bytes).unwrap();
                    file.sync_all().unwrap();
                }
            }
            let source_bytes = if directory { "source/bytes" } else { "source" };
            let occupied_bytes = if directory {
                "occupied/bytes"
            } else {
                "occupied"
            };
            assert!(
                rename_noreplace(
                    &parent,
                    OsStr::new("source"),
                    &parent,
                    OsStr::new("occupied")
                )
                .is_err()
            );
            assert_eq!(fs::read(root.path().join(source_bytes)).unwrap(), b"source");
            assert_eq!(
                fs::read(root.path().join(occupied_bytes)).unwrap(),
                b"occupied"
            );
            rename_noreplace(&parent, OsStr::new("source"), &parent, OsStr::new("absent")).unwrap();
            assert!(!root.path().join("source").exists());
            assert_eq!(
                fs::read(
                    root.path()
                        .join(if directory { "absent/bytes" } else { "absent" })
                )
                .unwrap(),
                b"source"
            );
        }
    }

    #[cfg(windows)]
    fn open_windows_directory_for_acl_mutation(path: &Path) -> fs::File {
        use std::os::windows::fs::OpenOptionsExt as _;

        let mut options = fs::OpenOptions::new();
        options
            .access_mode(kitrove_windows_security::PRIVATE_MUTATE_ACCESS)
            .custom_flags(kitrove_windows_security::PRIVATE_DIRECTORY_OPEN_FLAGS);
        options.open(path).unwrap()
    }

    #[cfg(windows)]
    fn make_windows_directory_unprotected(path: &Path) {
        let directory = open_windows_directory_for_acl_mutation(path);
        kitrove_windows_security::make_private_directory_unprotected_for_testing(&directory)
            .unwrap();
        assert!(kitrove_windows_security::inspect_private_directory(&directory).is_err());
    }

    fn empty_authority() -> (EnvironmentManifest, LocalState) {
        (
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: BTreeSet::new(),
            },
            LocalState {
                schema_version: SchemaVersion::V1,
                machine: MachineConfig {
                    id: MachineId::parse("initialization-test").unwrap(),
                    active_profile: None,
                    enabled_targets: BTreeSet::new(),
                    harness_roots: BTreeMap::new(),
                },
                bindings: BTreeMap::new(),
                receipts: BTreeMap::new(),
                pack_applications: BTreeMap::new(),
                trust: BTreeMap::new(),
                scans: Vec::new(),
            },
        )
    }

    fn initialize_empty_authority(
        environment_root: &Path,
        state_root: &Path,
        manifest: &EnvironmentManifest,
        state: &LocalState,
    ) -> Result<(), ObjectMutationError> {
        initialize_empty_authority_for_tests(environment_root, state_root, manifest, state)
    }

    #[test]
    fn instruction_objects_stage_install_and_verify_through_shared_store_guards() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let asset_id = kitrove_model::AssetId::parse("review").unwrap();
        let body = InstructionBody::parse("Review carefully.", 1024).unwrap();
        let portable = StoredInstruction::new(body.clone());
        let (exact_region, _) = render_managed_region(&asset_id, &body).unwrap();
        let native = NativeInstructionRegion::new(asset_id, exact_region.into_bytes()).unwrap();
        let portable_stage = PortablePath::parse("staging/portable").unwrap();
        let native_stage = PortablePath::parse("staging/native").unwrap();
        let portable_root = PortablePath::parse("objects/portable").unwrap();
        let native_root = PortablePath::parse("objects/native").unwrap();
        let limits = CaptureLimits::default();

        assert_eq!(
            store
                .stage_portable_instruction(&portable_stage, &portable, limits)
                .unwrap(),
            ObjectStageOutcome::Written
        );
        assert_eq!(
            store
                .stage_native_instruction(&native_stage, &native, limits)
                .unwrap(),
            ObjectStageOutcome::Written
        );
        assert_eq!(
            store
                .install_portable_instruction(
                    &portable_stage,
                    &portable_root,
                    portable.object_hash(),
                    limits,
                )
                .unwrap(),
            ObjectInstallOutcome::Installed
        );
        assert_eq!(
            store
                .install_native_instruction(
                    &native_stage,
                    &native_root,
                    native.object_hash(),
                    limits,
                )
                .unwrap(),
            ObjectInstallOutcome::Installed
        );
        assert_eq!(
            store
                .load_portable_instruction(&portable_root, limits)
                .unwrap(),
            portable
        );
        assert_eq!(
            store.load_native_instruction(&native_root, limits).unwrap(),
            native
        );

        fs::write(
            root.join("objects/portable/metadata.json"),
            "{\"schema_version\":1}",
        )
        .unwrap();
        assert_eq!(
            store
                .load_portable_instruction(&portable_root, limits)
                .unwrap_err()
                .code(),
            "object_mutation.invalid_object"
        );
    }

    #[test]
    fn verified_root_identity_matches_independent_handles_to_the_same_root() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let first = ObjectStore::open(&root).unwrap();
        let second = ObjectStore::open(&root).unwrap();

        assert_eq!(
            first.verified_root_identity().unwrap(),
            second.verified_root_identity().unwrap()
        );
    }

    #[test]
    fn concurrent_initializers_never_remove_successful_authority() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state_root = root.join("state");
        let (manifest, state) = empty_authority();
        let barrier = Arc::new(Barrier::new(2));
        let threads = (0..2)
            .map(|_| {
                let environment = environment.clone();
                let state_root = state_root.clone();
                let manifest = manifest.clone();
                let state = state.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    initialize_empty_authority(&environment, &state_root, &manifest, &state)
                })
            })
            .collect::<Vec<_>>();
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
            1,
            "{outcomes:?}"
        );
        assert!(environment.join("kitrove.toml").is_file());
        assert!(environment.join("kitrove.lock.json").is_file());
        assert!(state_root.join("state.json").is_file());
        let authority =
            kitrove_state_lifecycle::StateAuthority::open_existing(&state_root).unwrap();
        let _guard = authority.try_lock_exclusive().unwrap();
    }

    #[test]
    fn initialization_rollback_removes_only_files_owned_by_the_attempt() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state_root = root.join("state");
        let (manifest, state) = empty_authority();
        let state_path = state_root.join("state.json");

        let error = initialize_empty_authority_with_hooks_for_tests(
            &environment,
            &state_root,
            &manifest,
            &state,
            || {},
            || fs::write(&state_path, "EXTERNAL-STATE-CANARY").unwrap(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.io", "{error:?}");
        assert!(!environment.join("kitrove.toml").exists());
        assert!(!environment.join("kitrove.lock.json").exists());
        assert_eq!(
            fs::read_to_string(state_path).unwrap(),
            "EXTERNAL-STATE-CANARY"
        );
    }

    #[cfg(unix)]
    #[test]
    fn initialization_never_mutates_a_replacement_state_root() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::Builder::new()
            .prefix(".kitrove-core-init-bind-")
            .tempdir_in(std::env::var_os("HOME").expect("test user directory"))
            .unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state_root = root.join("state");
        let displaced = root.join("displaced-state");
        let replacement = root.join("replacement-state");
        let (manifest, state) = empty_authority();
        let (authority, guard) =
            kitrove_state_lifecycle::StateAuthority::initialize_absent(&state_root).unwrap();
        let access = authority.exclusive_access(&guard).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(replacement.join("canary"), "replacement-bytes").unwrap();

        let error = initialize_empty_authority_with_prevalidation_hook_for_tests(
            &environment,
            &access,
            &manifest,
            &state,
            || {
                fs::rename(&state_root, &displaced).unwrap();
                fs::rename(&replacement, &state_root).unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert_eq!(
            fs::read_to_string(state_root.join("canary")).unwrap(),
            "replacement-bytes"
        );
        assert_eq!(
            fs::metadata(&state_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!state_root.join(".kitrove").exists());
        assert!(!state_root.join("state.json").exists());
        assert!(!displaced.join("state.json").exists());
        assert!(!environment.exists());
    }

    #[test]
    fn initialization_lock_failure_preserves_a_replaced_manifest() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state_root = root.join("state");
        let (manifest, state) = empty_authority();

        let error = initialize_empty_authority_with_hooks_for_tests(
            &environment,
            &state_root,
            &manifest,
            &state,
            || {
                fs::rename(
                    environment.join("kitrove.toml"),
                    environment.join("created-manifest"),
                )
                .unwrap();
                fs::write(environment.join("kitrove.toml"), "EXTERNAL-MANIFEST-CANARY").unwrap();
                fs::write(environment.join("kitrove.lock.json"), "LOCK-CONFLICT").unwrap();
            },
            || {},
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.io");
        assert_eq!(
            fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
            "EXTERNAL-MANIFEST-CANARY"
        );
    }

    #[test]
    fn initialization_state_failure_preserves_replaced_portable_authority() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state_root = root.join("state");
        let (manifest, state) = empty_authority();

        let error = initialize_empty_authority_with_hooks_for_tests(
            &environment,
            &state_root,
            &manifest,
            &state,
            || {},
            || {
                for (name, canary) in [
                    ("kitrove.toml", "EXTERNAL-MANIFEST-CANARY"),
                    ("kitrove.lock.json", "EXTERNAL-LOCK-CANARY"),
                ] {
                    fs::rename(
                        environment.join(name),
                        environment.join(format!("created-{name}")),
                    )
                    .unwrap();
                    fs::write(environment.join(name), canary).unwrap();
                }
                fs::write(state_root.join("state.json"), "STATE-CONFLICT").unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.io");
        assert_eq!(
            fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
            "EXTERNAL-MANIFEST-CANARY"
        );
        assert_eq!(
            fs::read_to_string(environment.join("kitrove.lock.json")).unwrap(),
            "EXTERNAL-LOCK-CANARY"
        );
    }

    #[test]
    fn initialization_refuses_nested_portable_and_state_roots() {
        for state_is_nested in [true, false] {
            let temporary = trusted_tempdir();
            let root = temporary.path().canonicalize().unwrap();
            let (environment, state_root) = if state_is_nested {
                (root.join("authority"), root.join("authority/state"))
            } else {
                (root.join("state/authority"), root.join("state"))
            };
            let (manifest, state) = empty_authority();

            let error = initialize_empty_authority(&environment, &state_root, &manifest, &state)
                .unwrap_err();

            assert_eq!(error.code(), "object.unsafe_environment_root");
            assert!(!environment.exists());
            assert!(!state_root.exists());
            assert!(!environment.join("kitrove.toml").exists());
            assert!(!environment.join("kitrove.lock.json").exists());
            assert!(!state_root.join("state.json").exists());
        }
    }

    #[test]
    fn initialization_rejects_nonempty_authority_before_creating_roots() {
        let cases = ["portable", "local", "pack-application"];
        for case in cases {
            let temporary = trusted_tempdir();
            let root = temporary.path().canonicalize().unwrap();
            let environment = root.join("environment");
            let state_root = root.join("state");
            let (mut manifest, mut state) = empty_authority();
            if case == "portable" {
                manifest
                    .required_bindings
                    .insert(BindingName::parse("existing-binding").unwrap());
            } else if case == "local" {
                state.machine.active_profile = Some(ProfileId::parse("existing-profile").unwrap());
            } else {
                let claim = kitrove_model::PackApplicationClaim {
                    pack_id: kitrove_model::AssetId::parse("existing-pack").unwrap(),
                    pack_revision: ContentHash::digest(b"existing-pack-revision"),
                    scope: kitrove_model::HarnessScope::User,
                    target_anchor: crate::materialization::normalized_destination_from_path(&root)
                        .unwrap(),
                    targets: BTreeSet::from([kitrove_model::HarnessId::Claude]),
                    receipts: BTreeSet::new(),
                };
                state
                    .pack_applications
                    .insert(claim.application_id().unwrap(), claim);
            }

            let error = initialize_empty_authority(&environment, &state_root, &manifest, &state)
                .unwrap_err();

            assert_eq!(error.code(), "object_mutation.initial_authority_not_empty");
            assert!(!environment.exists());
            assert!(!state_root.exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn initialization_rejects_case_variant_overlaps_before_mutation() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let authority = root.join("MixedCaseAuthority");
        ObjectStore::open_or_create_private_state(&authority).unwrap();
        let case_variant = PathBuf::from(authority.display().to_string().to_uppercase());
        let nested_variant = case_variant.join("NestedEnvironment");
        let (manifest, state) = empty_authority();

        for environment in [&case_variant, &nested_variant] {
            let error =
                initialize_empty_authority(environment, &authority, &manifest, &state).unwrap_err();
            assert_eq!(error.code(), "object.unsafe_environment_root");
            assert!(!environment.join("kitrove.toml").exists());
            assert!(!authority.join("state.json").exists());
            assert!(!authority.join(".kitrove").exists());
        }

        let missing_environment = root.join("AbsentAuthority");
        let missing_state = root.join("absentauthority").join("State");
        let error =
            initialize_empty_authority(&missing_environment, &missing_state, &manifest, &state)
                .unwrap_err();
        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(!missing_environment.exists());
        assert!(!missing_state.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn initialization_conservatively_rejects_case_variant_missing_roots() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("AbsentAuthority");
        let state_root = root.join("absentauthority").join("State");
        let (manifest, state) = empty_authority();

        let error =
            initialize_empty_authority(&environment, &state_root, &manifest, &state).unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(!environment.exists());
        assert!(!state_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_state_root_directories_files_and_locks_are_restrictive() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state_root = root.join("state");
        let (manifest, state) = empty_authority();
        initialize_empty_authority(&environment, &state_root, &manifest, &state).unwrap();
        let store = ObjectStore::open_private_state_for_mutation(&state_root).unwrap();
        let staged = PortablePath::parse("nested/journal.json").unwrap();
        store.stage_text(&staged, "{}\n", 1024).unwrap();
        let lock = PortablePath::parse("nested/writer.lock").unwrap();
        let _held = store.try_lock_file(&lock).unwrap();

        for directory in [&state_root, &state_root.join("nested")] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for file in [
            state_root.join("state.json"),
            state_root.join(staged.as_str()),
            state_root.join(lock.as_str()),
        ] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn private_state_lock_creation_and_reopen_preserve_exact_authority() {
        let temporary = trusted_tempdir();
        let state_root = temporary.path().join("state");
        let store = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let lock = PortablePath::parse("nested/writer.lock").unwrap();

        for _ in 0..2 {
            let held = store.try_lock_file(&lock).unwrap();
            kitrove_windows_security::inspect_private_file(&held._file).unwrap();
            drop(held);
        }
    }

    #[cfg(windows)]
    #[test]
    fn portable_environment_lock_creates_inspectable_private_control_state() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();

        let held = store.try_lock_environment().unwrap();
        let control = open_child_directory(&store.root, OsStr::new(".kitrove")).unwrap();
        prepare_private_directory(&control, PrivateDirectoryAccess::Inspect).unwrap();
        drop(control);
        kitrove_windows_security::inspect_private_file(&held._file).unwrap();
        assert!(
            fs::rename(root.join(".kitrove"), root.join("moved-control")).is_err(),
            "the held control capability must refuse replacement"
        );
        assert!(
            fs::rename(
                root.join(".kitrove/environment.lock"),
                root.join("moved-lock"),
            )
            .is_err(),
            "the held lock handle must refuse replacement"
        );
        assert!(store.open_existing_removal_quarantine().unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_private_state_open_refuses_insecure_permissions_without_repairing_them() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = trusted_tempdir();
        let state_root = temporary.path().canonicalize().unwrap().join("state");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o755)).unwrap();

        let error = ObjectStore::open_private_state(&state_root).unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert_eq!(
            fs::metadata(&state_root).unwrap().permissions().mode() & 0o777,
            0o755
        );
        ObjectStore::open_private_state_for_mutation(&state_root).unwrap();
        assert_eq!(
            fs::metadata(&state_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn private_state_mutation_repairs_owned_unprotected_acl_for_read_only_reopen() {
        let temporary = trusted_tempdir();
        let state_root = temporary.path().canonicalize().unwrap().join("state");

        ObjectStore::open_or_create_private_state(&state_root).unwrap();
        make_windows_directory_unprotected(&state_root);
        assert_eq!(
            ObjectStore::open_private_state(&state_root)
                .unwrap_err()
                .code(),
            "object.unsafe_environment_root"
        );
        assert!(
            kitrove_windows_security::inspect_private_directory(
                &open_windows_directory_for_acl_mutation(&state_root)
            )
            .is_err()
        );
        ObjectStore::open_private_state_for_mutation(&state_root).unwrap();
        ObjectStore::open_private_state(&state_root).unwrap();
    }

    #[test]
    fn read_only_private_state_store_refuses_file_or_directory_creation() {
        let temporary = trusted_tempdir();
        let state_root = temporary.path().canonicalize().unwrap().join("state");
        ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let read_only = ObjectStore::open_private_state(&state_root).unwrap();
        let forbidden = PortablePath::parse("nested/new-state.json").unwrap();

        let error = read_only.stage_text(&forbidden, "{}\n", 1024).unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(!state_root.join("nested").exists());
    }

    #[test]
    fn read_only_private_state_store_refuses_existing_file_and_directory_removal() {
        let temporary = trusted_tempdir();
        let state_root = temporary.path().canonicalize().unwrap().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let file = PortablePath::parse("existing.json").unwrap();
        mutation.stage_text(&file, "{}\n", 1024).unwrap();
        let empty = PortablePath::parse("empty").unwrap();
        let empty_child = PortablePath::parse("empty/unused").unwrap();
        mutation.open_or_create_parent(&empty_child).unwrap();
        drop(mutation);
        let read_only = ObjectStore::open_private_state(&state_root).unwrap();

        let file_error = read_only.remove_regular_file_if_present(&file).unwrap_err();
        let directory_error = read_only
            .remove_empty_directory_if_present(&empty)
            .unwrap_err();

        assert_eq!(file_error.code(), "object.unsafe_environment_root");
        assert_eq!(directory_error.code(), "object.unsafe_environment_root");
        assert!(state_root.join("existing.json").is_file());
        assert!(state_root.join("empty").is_dir());
        assert!(!state_root.join(".kitrove").exists());
    }

    #[cfg(windows)]
    #[test]
    fn private_state_files_and_nested_directories_are_verified_on_read_only_reopen() {
        let temporary = trusted_tempdir();
        let state_root = temporary.path().canonicalize().unwrap().join("state");
        let store = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let control = PortablePath::parse("nested/state.json").unwrap();
        store.stage_private_text(&control, "{}\n", 1024).unwrap();
        drop(store);

        let read_only = ObjectStore::open_private_state(&state_root).unwrap();
        assert_eq!(
            read_only.read_text(&control, 1024).unwrap().as_deref(),
            Some("{}\n")
        );
    }

    #[cfg(windows)]
    #[test]
    fn authorized_empty_directory_cleanup_secures_the_final_handle_before_quarantine() {
        let temporary = trusted_tempdir();
        let state_root = temporary.path().canonicalize().unwrap().join("state");
        let mutation = ObjectStore::open_or_create_private_state(&state_root).unwrap();
        let staging = PortablePath::parse("inherited-staging").unwrap();
        let staging_child = PortablePath::parse("inherited-staging/unused").unwrap();
        mutation.open_or_create_parent(&staging_child).unwrap();
        drop(mutation);
        #[cfg(windows)]
        make_windows_directory_unprotected(&state_root.join(staging.as_str()));
        let read_only = ObjectStore::open_private_state(&state_root).unwrap();

        let error = read_only
            .remove_empty_directory_if_present(&staging)
            .unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(state_root.join(staging.as_str()).is_dir());
        #[cfg(windows)]
        assert!(
            kitrove_windows_security::inspect_private_directory(
                &open_windows_directory_for_acl_mutation(&state_root.join(staging.as_str()))
            )
            .is_err()
        );
        drop(read_only);
        let mutation = ObjectStore::open_private_state_for_mutation(&state_root).unwrap();
        mutation
            .remove_empty_directory_if_present(&staging)
            .unwrap();
        assert!(!state_root.join(staging.as_str()).exists());
        let quarantine = mutation
            .open_existing_removal_quarantine()
            .unwrap()
            .unwrap();
        let mut entries = quarantine.entries().unwrap();
        let tombstone_name = entries.next().unwrap().unwrap().file_name();
        assert!(entries.next().is_none());
        let tombstone = open_child_directory(&quarantine, &tombstone_name).unwrap();
        prepare_private_directory(&tombstone, PrivateDirectoryAccess::Inspect).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn private_state_open_refuses_a_reparse_root() {
        let temporary = trusted_tempdir();
        let real = temporary.path().join("real");
        let alias = temporary.path().join("alias");
        fs::create_dir(&real).unwrap();
        std::os::windows::fs::symlink_dir(&real, &alias)
            .expect("Windows CI must support creating a test reparse point");

        let error = ObjectStore::open_private_state_for_mutation(&alias).unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
    }

    #[test]
    fn every_create_new_mode_removes_its_owned_file_after_post_open_failure() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        for (name, mode) in [
            ("inherited", NewFileMode::Inherited),
            ("private", NewFileMode::Private),
            ("captured", NewFileMode::Captured(FileMode::Executable)),
        ] {
            let error = write_new_file_with_hook(
                &store.root,
                OsStr::new(name),
                b"PARTIAL-AUTHORITY-CANARY",
                mode,
                || Err(mutation_io()),
            )
            .unwrap_err();

            assert_eq!(error.code(), "object.io");
            assert!(!root.join(name).exists());
        }
    }

    #[test]
    fn create_new_failure_after_parent_sync_quarantines_only_the_owned_inode() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let authority = PortablePath::parse("authority").unwrap();

        let error = store
            .create_text_with_hook(
                &authority,
                "PARTIAL-AUTHORITY-CANARY",
                NewFileMode::Inherited,
                || Err(unsafe_root()),
            )
            .unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(!root.join("authority").exists());
        let quarantined = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".kitrove-incomplete-file-")
            })
            .expect("the failed inode remains safely quarantined");
        assert_eq!(quarantined.metadata().unwrap().len(), 0);
    }

    #[test]
    fn file_quarantine_never_deletes_a_replacement_after_a_name_swap() {
        use std::cell::RefCell;

        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        write_new_file(&store.root, OsStr::new("authority"), b"owned").unwrap();
        let file = open_regular_file_nofollow(&store.root, OsStr::new("authority")).unwrap();
        let tombstone = RefCell::new(None);

        let error = quarantine_open_file_with_hook(
            &store.root,
            OsStr::new("authority"),
            file,
            ".test-file-",
            |name| {
                tombstone.replace(Some(name.to_owned()));
                store
                    .root
                    .rename(name, &store.root, "owned-elsewhere")
                    .unwrap();
                write_new_file(&store.root, name, b"replacement").unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        let tombstone = tombstone.into_inner().unwrap();
        assert_eq!(fs::read(root.join(tombstone)).unwrap(), b"replacement");
        assert_eq!(fs::read(root.join("owned-elsewhere")).unwrap(), b"owned");
        assert!(!root.join("authority").exists());
    }

    #[cfg(unix)]
    #[test]
    fn removed_file_tombstone_persists_its_exact_identity() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("authority"), b"owned").unwrap();
        let identity = fs::metadata(root.join("authority")).unwrap();
        let store = ObjectStore::open(&root).unwrap();

        store
            .remove_regular_file_if_present(&PortablePath::parse("authority").unwrap())
            .unwrap();

        let quarantine = root.join(".kitrove/removal-quarantine");
        let entries = fs::read_dir(quarantine)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.metadata().unwrap().len(), 0);
        assert_eq!(
            RemovalTombstoneName::parse(&entry.file_name()),
            Some(RemovalTombstoneName {
                kind: RemovedObjectKind::File,
                identity: MetadataIdentity::from_metadata(&identity),
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_and_directory_promotion_preserve_rollback_failure_severity() {
        use kitrove_windows_security::OwnedObjectPromotionError;

        assert_eq!(
            map_windows_promotion_error(OwnedObjectPromotionError::Failed).code(),
            "object.precondition_failed"
        );
        assert_eq!(
            map_windows_promotion_error(OwnedObjectPromotionError::RollbackFailed).code(),
            "object.io"
        );
    }

    #[cfg(windows)]
    #[test]
    fn removed_file_tombstone_persists_its_complete_windows_identity() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        write_new_file(&store.root, OsStr::new("authority"), b"owned").unwrap();
        let original = fs::File::open(root.join("authority")).unwrap();
        let identity = kitrove_windows_security::file_identity(&original).unwrap();
        drop(original);
        store
            .remove_regular_file_if_present(&PortablePath::parse("authority").unwrap())
            .unwrap();

        let entries = fs::read_dir(root.join(".kitrove/removal-quarantine"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(fs::read(entries[0].path()).unwrap(), b"owned");
        assert_eq!(
            RemovalTombstoneName::parse(&entries[0].file_name()),
            Some(RemovalTombstoneName {
                kind: RemovedObjectKind::File,
                identity,
            })
        );
    }

    #[test]
    fn file_removal_refuses_an_existing_external_hard_link() {
        let temporary = trusted_tempdir();
        let root = temporary.path().join("managed-root");
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let external_alias = temporary.path().join("authority-alias");
        fs::write(root.join("authority"), b"owned").unwrap();
        fs::hard_link(root.join("authority"), &external_alias).unwrap();
        let store = ObjectStore::open(&root).unwrap();

        let error = store
            .remove_regular_file_if_present(&PortablePath::parse("authority").unwrap())
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(fs::read(root.join("authority")).unwrap(), b"owned");
        assert_eq!(fs::read(external_alias).unwrap(), b"owned");
    }

    #[cfg(unix)]
    #[test]
    fn file_quarantine_rechecks_links_immediately_before_truncation() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        write_new_file(&store.root, OsStr::new("authority"), b"owned").unwrap();
        let file = open_regular_file_nofollow(&store.root, OsStr::new("authority")).unwrap();

        let error = quarantine_open_file_with_hook(
            &store.root,
            OsStr::new("authority"),
            file,
            ".test-file-",
            |tombstone| {
                fs::hard_link(root.join(tombstone), root.join("external-alias")).unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(fs::read(root.join("external-alias")).unwrap(), b"owned");
        let tombstone = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".test-file-")
            })
            .unwrap();
        assert_eq!(fs::read(tombstone.path()).unwrap(), b"owned");
    }

    #[cfg(unix)]
    #[test]
    fn removed_directory_tombstone_persists_its_exact_identity() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        drop(
            create_new_directory_with_security(
                &store.root,
                OsStr::new("authority"),
                StoreSecurity::Portable,
            )
            .unwrap(),
        );
        let directory = open_child_directory(&store.root, OsStr::new("authority")).unwrap();
        let identity = MetadataIdentity::from_metadata(&directory.dir_metadata().unwrap());
        let quarantine = store.open_removal_quarantine().unwrap();

        quarantine_open_directory_to(
            &store.root,
            OsStr::new("authority"),
            directory,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::Directory),
            |tombstone| {
                assert_eq!(
                    RemovalTombstoneName::parse(tombstone),
                    Some(RemovalTombstoneName {
                        kind: RemovedObjectKind::Directory,
                        identity,
                    })
                );
            },
        )
        .unwrap();

        assert!(!root.join("authority").exists());
        assert_eq!(
            fs::read_dir(root.join(".kitrove/removal-quarantine"))
                .unwrap()
                .count(),
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn removed_directory_tombstone_persists_its_complete_windows_identity() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        drop(
            create_new_directory_with_security(
                &store.root,
                OsStr::new("authority"),
                StoreSecurity::Portable,
            )
            .unwrap(),
        );
        let directory = open_child_directory(&store.root, OsStr::new("authority")).unwrap();
        let identity = kitrove_windows_security::file_identity(&directory).unwrap();
        let quarantine = store.open_removal_quarantine().unwrap();

        quarantine_open_directory_to(
            &store.root,
            OsStr::new("authority"),
            directory,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::Directory),
            |tombstone| {
                assert_eq!(
                    RetainedTombstoneName::parse(tombstone),
                    Some(RetainedTombstoneName {
                        kind: RemovedObjectKind::Directory,
                    })
                );
            },
        )
        .unwrap();

        assert!(!root.join("authority").exists());
        let entries = fs::read_dir(root.join(".kitrove/removal-quarantine"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            RemovalTombstoneName::parse(&entries[0].file_name()),
            Some(RemovalTombstoneName {
                kind: RemovedObjectKind::Directory,
                identity,
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_replacement_never_receives_identity_bearing_authority() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        write_new_file(&store.root, OsStr::new("authority"), b"owned").unwrap();
        let file = open_regular_file_nofollow(&store.root, OsStr::new("authority")).unwrap();
        let quarantine = store.open_removal_quarantine().unwrap();

        let error = quarantine_open_file_to(
            &store.root,
            OsStr::new("authority"),
            file,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::File),
            |staged| {
                assert!(RetainedTombstoneName::parse(staged).is_some());
                quarantine
                    .rename(staged, &quarantine, "owned-elsewhere")
                    .unwrap();
                write_new_file(&quarantine, staged, b"replacement").unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        let names = quarantine
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(
            names
                .iter()
                .all(|name| RemovalTombstoneName::parse(name).is_none())
        );
        assert_eq!(
            fs::read(root.join(".kitrove/removal-quarantine/owned-elsewhere")).unwrap(),
            b"owned"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_hardlink_race_never_receives_identity_bearing_authority() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        write_new_file(&store.root, OsStr::new("authority"), b"owned").unwrap();
        let file = open_regular_file_nofollow(&store.root, OsStr::new("authority")).unwrap();
        let quarantine = store.open_removal_quarantine().unwrap();
        let external_alias = root.join("external-alias");

        let error = quarantine_open_file_to(
            &store.root,
            OsStr::new("authority"),
            file,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::File),
            |staged| {
                fs::hard_link(
                    root.join(".kitrove/removal-quarantine").join(staged),
                    &external_alias,
                )
                .unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(fs::read(external_alias).unwrap(), b"owned");
        assert!(
            quarantine
                .entries()
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .all(|name| RemovalTombstoneName::parse(&name).is_none())
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_replacement_never_receives_identity_bearing_authority() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        drop(
            create_new_directory_with_security(
                &store.root,
                OsStr::new("authority"),
                StoreSecurity::Portable,
            )
            .unwrap(),
        );
        let directory = open_child_directory(&store.root, OsStr::new("authority")).unwrap();
        let quarantine = store.open_removal_quarantine().unwrap();

        let error = quarantine_open_directory_to(
            &store.root,
            OsStr::new("authority"),
            directory,
            &quarantine,
            QuarantineName::Removal(RemovedObjectKind::Directory),
            |staged| {
                assert!(RetainedTombstoneName::parse(staged).is_some());
                quarantine
                    .rename(staged, &quarantine, "owned-elsewhere")
                    .unwrap();
                quarantine.create_dir(staged).unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        let names = quarantine
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(
            names
                .iter()
                .all(|name| RemovalTombstoneName::parse(name).is_none())
        );
        assert!(
            root.join(".kitrove/removal-quarantine/owned-elsewhere")
                .is_dir()
        );
    }

    #[test]
    fn directory_quarantine_never_deletes_a_replacement_after_a_name_swap() {
        use std::cell::RefCell;

        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        crate::test_authority::create_owned_fixture_directory(&root, "authority");
        let directory = open_child_directory(&store.root, OsStr::new("authority")).unwrap();
        let tombstone = RefCell::new(None);

        let error = quarantine_open_directory_with_hook(
            &store.root,
            OsStr::new("authority"),
            directory,
            |name| {
                tombstone.replace(Some(name.to_owned()));
                store
                    .root
                    .rename(name, &store.root, "owned-elsewhere")
                    .unwrap();
                store.root.create_dir(name).unwrap();
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        let tombstone = tombstone.into_inner().unwrap();
        assert!(root.join(tombstone).is_dir());
        assert!(root.join("owned-elsewhere").is_dir());
        assert!(!root.join("authority").exists());
    }

    #[test]
    fn environment_lock_refuses_a_second_writer() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _held = store.try_lock_environment().unwrap();
        let Err(error) = store.try_lock_environment() else {
            panic!("a second writer acquired the environment lock");
        };
        assert_eq!(error.code(), "object.environment_locked");
    }

    #[test]
    fn only_platform_contention_is_reported_as_an_occupied_lock() {
        assert_eq!(
            lock_error(fs2::lock_contended_error()).code(),
            "object.environment_locked"
        );
        assert_eq!(
            lock_error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic non-contention failure",
            ))
            .code(),
            "object.io"
        );
    }

    #[test]
    fn distinct_root_locks_accept_every_input_permutation() {
        let temporary = trusted_tempdir();
        let first_path = temporary.path().join("first");
        let second_path = temporary.path().join("second");
        fs::create_dir(&first_path).unwrap();
        fs::create_dir(&second_path).unwrap();
        let first_path = first_path.canonicalize().unwrap();
        let second_path = second_path.canonicalize().unwrap();
        let first = ObjectStore::open(&first_path).unwrap();
        let second = ObjectStore::open(&second_path).unwrap();

        let locks = ObjectStore::try_lock_distinct_roots(&[&first, &second]).unwrap();
        let Err(first_error) = first.try_lock_environment() else {
            panic!("first root lock was not held");
        };
        let Err(second_error) = second.try_lock_environment() else {
            panic!("second root lock was not held");
        };
        assert_eq!(first_error.code(), "object.environment_locked");
        assert_eq!(second_error.code(), "object.environment_locked");
        drop(locks);

        let reversed = ObjectStore::try_lock_distinct_roots(&[&second, &first]).unwrap();
        assert_eq!(reversed.len(), 2);
    }

    #[test]
    fn distinct_root_locks_reject_aliases_before_creating_lock_state() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let first = ObjectStore::open(&root).unwrap();
        let alias = ObjectStore::open(&root).unwrap();

        let Err(error) = ObjectStore::try_lock_distinct_roots(&[&first, &alias]) else {
            panic!("aliased roots acquired duplicate locks");
        };

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(!root.join(".kitrove").exists());
    }

    #[test]
    fn distinct_root_locks_reject_nested_roots_before_creating_lock_state() {
        let temporary = trusted_tempdir();
        let parent_path = temporary.path().join("parent");
        let child_path = parent_path.join("child");
        fs::create_dir_all(&child_path).unwrap();
        let parent_path = parent_path.canonicalize().unwrap();
        let child_path = child_path.canonicalize().unwrap();
        let parent = ObjectStore::open(&parent_path).unwrap();
        let child = ObjectStore::open(&child_path).unwrap();

        let Err(error) = ObjectStore::try_lock_distinct_roots(&[&parent, &child]) else {
            panic!("nested roots acquired independent locks");
        };

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(!parent_path.join(".kitrove").exists());
        assert!(!child_path.join(".kitrove").exists());
    }

    #[test]
    fn maximum_batch_root_order_resolves_each_root_once() {
        use std::cell::Cell;

        const MAX_TRANSACTION_ROOTS: usize =
            crate::apply_batch::MAX_BATCH_PARTICIPANTS.saturating_add(2);
        let resolutions = Cell::new(0);

        let order = resolve_root_lock_order(MAX_TRANSACTION_ROOTS, |index| {
            resolutions.set(resolutions.get() + 1);
            Ok((
                MetadataIdentity {
                    device: 1,
                    inode: index as u64 + 1,
                },
                PathBuf::from(format!("/synthetic-roots/root-{index:04x}")),
            ))
        })
        .unwrap();

        assert_eq!(resolutions.get(), MAX_TRANSACTION_ROOTS);
        assert_eq!(order.len(), MAX_TRANSACTION_ROOTS);
        assert_eq!(order[0], 0);
        assert_eq!(order[MAX_TRANSACTION_ROOTS - 1], MAX_TRANSACTION_ROOTS - 1);
    }

    #[test]
    fn distinct_root_lock_failure_releases_earlier_locks() {
        let temporary = trusted_tempdir();
        let first_path = temporary.path().join("first");
        let second_path = temporary.path().join("second");
        fs::create_dir(&first_path).unwrap();
        fs::create_dir(&second_path).unwrap();
        let first_path = first_path.canonicalize().unwrap();
        let second_path = second_path.canonicalize().unwrap();
        let first = ObjectStore::open(&first_path).unwrap();
        let second = ObjectStore::open(&second_path).unwrap();
        let (lower, higher) = if first.root_identity < second.root_identity {
            (&first, &second)
        } else {
            (&second, &first)
        };
        let held_higher = higher.try_lock_environment().unwrap();

        let Err(error) = ObjectStore::try_lock_distinct_roots(&[higher, lower]) else {
            panic!("held later lock did not block the ordered lock set");
        };

        assert_eq!(error.code(), "object.environment_locked");
        let released_lower = lower.try_lock_environment().unwrap();
        drop(released_lower);
        drop(held_higher);
    }

    #[test]
    fn guarded_install_preserves_a_concurrent_edit_after_its_precondition_read() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("authority"), "old\n").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let staging = PortablePath::parse(".kitrove/staging/authority").unwrap();
        let destination = PortablePath::parse("authority").unwrap();
        store.stage_text(&staging, "new\n", 1024).unwrap();

        let error = store
            .install_staged_text_guarded_with_hook(
                &staging,
                &destination,
                Some("old\n"),
                "new\n",
                1024,
                true,
                || fs::write(root.join("authority"), "concurrent\n").unwrap(),
                || assert_eq!(fs::read_to_string(root.join("authority")).unwrap(), "new\n"),
            )
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(
            fs::read_to_string(root.join("authority")).unwrap(),
            "concurrent\n"
        );
        assert_eq!(
            store.read_text(&staging, 1024).unwrap().as_deref(),
            Some("new\n")
        );
        assert!(
            store
                .read_text(&guarded_backup_path(&staging).unwrap(), 1024)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ownership_guarded_install_refuses_equal_bytes_not_written_from_its_stage() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("authority"), "new\n").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let staging = PortablePath::parse(".kitrove/staging/authority").unwrap();
        let destination = PortablePath::parse("authority").unwrap();
        store.stage_text(&staging, "new\n", 1024).unwrap();

        let error = store
            .install_staged_text_guarded_from_old(&staging, &destination, None, "new\n", 1024)
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(fs::read_to_string(root.join("authority")).unwrap(), "new\n");
        assert_eq!(
            store.read_text(&staging, 1024).unwrap().as_deref(),
            Some("new\n")
        );
    }

    #[test]
    fn exact_text_lifecycle_preserves_bytes_and_mode() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let staging = PortablePath::parse(".kitrove/staging/AGENTS.md").unwrap();
        let destination = PortablePath::parse("AGENTS.md").unwrap();
        let backup = PortablePath::parse(".kitrove/backup/AGENTS.md").unwrap();
        let mode = RegularFileMode::conservative();
        let _environment_lock = store.try_lock_environment().unwrap();

        store
            .stage_text_with_mode(&staging, "managed\n", mode, 1024)
            .unwrap();
        store
            .install_staged_exact_text(&staging, &destination, "managed\n", mode, 1024)
            .unwrap();
        assert!(
            store
                .exact_text_matches(&destination, "managed\n", mode, 1024)
                .unwrap()
        );
        store
            .quarantine_exact_text(&destination, &backup, "managed\n", mode, 1024)
            .unwrap();
        store
            .restore_quarantined_exact_text(&backup, &destination, "managed\n", mode, 1024)
            .unwrap();
        store
            .remove_regular_file_if_matches_with_mode(&destination, 1024, mode, |bytes| {
                bytes == b"managed\n"
            })
            .unwrap();
        assert!(!root.join("AGENTS.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn exact_text_removal_refuses_equal_bytes_with_changed_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let destination = PortablePath::parse("AGENTS.md").unwrap();
        fs::write(root.join("AGENTS.md"), "managed\n").unwrap();
        fs::set_permissions(root.join("AGENTS.md"), fs::Permissions::from_mode(0o600)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let (_, expected_mode) = store
            .read_text_with_mode(&destination, 1024)
            .unwrap()
            .unwrap();
        fs::set_permissions(root.join("AGENTS.md"), fs::Permissions::from_mode(0o644)).unwrap();

        let error = store
            .remove_regular_file_if_matches_with_mode(&destination, 1024, expected_mode, |bytes| {
                bytes == b"managed\n"
            })
            .unwrap_err();

        assert_eq!(error.code(), "object.existing_conflict");
        assert_eq!(fs::read(root.join("AGENTS.md")).unwrap(), b"managed\n");
    }

    #[test]
    fn guarded_recovery_refuses_a_third_state_and_preserves_the_backup() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let staging = PortablePath::parse(".kitrove/staging/authority").unwrap();
        let backup = guarded_backup_path(&staging).unwrap();
        let destination = PortablePath::parse("authority").unwrap();
        store.stage_text(&staging, "new\n", 1024).unwrap();
        store.stage_text(&backup, "old\n", 1024).unwrap();
        fs::write(root.join("authority"), "concurrent\n").unwrap();

        let error = store
            .install_staged_text_guarded(&staging, &destination, Some("old\n"), "new\n", 1024)
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(
            fs::read_to_string(root.join("authority")).unwrap(),
            "concurrent\n"
        );
        assert_eq!(
            store.read_text(&backup, 1024).unwrap().as_deref(),
            Some("old\n")
        );
    }

    fn rendered_tree(contents: &[u8]) -> (CapturedTree, ContentHash) {
        let mut files = BTreeMap::new();
        files.insert(
            PortablePath::parse("SKILL.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: contents.to_vec(),
            },
        );
        let tree = CapturedTree {
            hash: hash_tree(&files),
            files,
        };
        let hash = hash_skill_source(SkillSourceLayout::Directory, "SKILL.md", &tree);
        (tree, hash)
    }

    #[test]
    fn quarantine_restores_a_directory_swapped_after_precondition_read() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let destination = PortablePath::parse("targets/review").unwrap();
        let alternate = PortablePath::parse("targets/alternate").unwrap();
        let backup = PortablePath::parse("targets/backup").unwrap();
        let (expected_tree, expected_hash) = rendered_tree(b"expected\n");
        let (third_tree, third_hash) = rendered_tree(b"third-state\n");
        store
            .stage_rendered_directory(
                &destination,
                &expected_tree,
                &expected_hash,
                CaptureLimits::default(),
            )
            .unwrap();
        store
            .stage_rendered_directory(
                &alternate,
                &third_tree,
                &third_hash,
                CaptureLimits::default(),
            )
            .unwrap();

        let error = store
            .quarantine_rendered_directory_with_hook(
                &destination,
                &backup,
                &expected_hash,
                CaptureLimits::default(),
                || {
                    fs::rename(root.join("targets/review"), root.join("targets/swap")).unwrap();
                    fs::rename(root.join("targets/alternate"), root.join("targets/review"))
                        .unwrap();
                    fs::rename(root.join("targets/swap"), root.join("targets/alternate")).unwrap();
                },
            )
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(
            store
                .inspect_rendered_directory(&destination, &third_hash, CaptureLimits::default())
                .unwrap(),
            RenderedState::Exact
        );
        assert!(!root.join("targets/backup").exists());
    }

    #[test]
    fn removal_restores_a_directory_swapped_after_precondition_read() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let destination = PortablePath::parse("targets/review").unwrap();
        let alternate = PortablePath::parse("targets/alternate").unwrap();
        let (expected_tree, expected_hash) = rendered_tree(b"expected\n");
        let (third_tree, third_hash) = rendered_tree(b"third-state\n");
        store
            .stage_rendered_directory(
                &destination,
                &expected_tree,
                &expected_hash,
                CaptureLimits::default(),
            )
            .unwrap();
        store
            .stage_rendered_directory(
                &alternate,
                &third_tree,
                &third_hash,
                CaptureLimits::default(),
            )
            .unwrap();

        let error = store
            .remove_exact_rendered_directory_with_hooks(
                &destination,
                &expected_hash,
                CaptureLimits::default(),
                || {
                    fs::rename(root.join("targets/review"), root.join("targets/swap")).unwrap();
                    fs::rename(root.join("targets/alternate"), root.join("targets/review"))
                        .unwrap();
                    fs::rename(root.join("targets/swap"), root.join("targets/alternate")).unwrap();
                },
                || {},
            )
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert_eq!(
            store
                .inspect_rendered_directory(&destination, &third_hash, CaptureLimits::default())
                .unwrap(),
            RenderedState::Exact
        );
    }

    #[test]
    fn install_restores_a_staging_directory_swapped_before_move() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let staging = PortablePath::parse("targets/staging").unwrap();
        let alternate = PortablePath::parse("targets/alternate").unwrap();
        let destination = PortablePath::parse("targets/review").unwrap();
        let (expected_tree, expected_hash) = rendered_tree(b"expected\n");
        let (third_tree, third_hash) = rendered_tree(b"third-state\n");
        store
            .stage_rendered_directory(
                &staging,
                &expected_tree,
                &expected_hash,
                CaptureLimits::default(),
            )
            .unwrap();
        store
            .stage_rendered_directory(
                &alternate,
                &third_tree,
                &third_hash,
                CaptureLimits::default(),
            )
            .unwrap();

        let error = store
            .install_rendered_directory_with_hook(
                &staging,
                &destination,
                &expected_hash,
                CaptureLimits::default(),
                || {
                    fs::rename(root.join("targets/staging"), root.join("targets/swap")).unwrap();
                    fs::rename(root.join("targets/alternate"), root.join("targets/staging"))
                        .unwrap();
                    fs::rename(root.join("targets/swap"), root.join("targets/alternate")).unwrap();
                },
                || fs::create_dir(root.join("targets/staging")).unwrap(),
            )
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert!(!root.join("targets/review").exists());
        assert!(root.join("targets/staging").is_dir());
        assert!(fs::read_dir(root.join("targets")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("kitrove-remove")
        }));
    }

    #[test]
    fn identity_bound_removal_refuses_a_post_verification_swap() {
        let temporary = trusted_tempdir();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let destination = PortablePath::parse("targets/review").unwrap();
        let alternate = PortablePath::parse("targets/alternate").unwrap();
        let (expected_tree, expected_hash) = rendered_tree(b"expected\n");
        let (third_tree, third_hash) = rendered_tree(b"third-state\n");
        store
            .stage_rendered_directory(
                &destination,
                &expected_tree,
                &expected_hash,
                CaptureLimits::default(),
            )
            .unwrap();
        store
            .stage_rendered_directory(
                &alternate,
                &third_tree,
                &third_hash,
                CaptureLimits::default(),
            )
            .unwrap();

        let error = store
            .remove_exact_rendered_directory_with_hooks(
                &destination,
                &expected_hash,
                CaptureLimits::default(),
                || {},
                || {
                    let tombstone = fs::read_dir(root.join("targets"))
                        .unwrap()
                        .map(Result::unwrap)
                        .find(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .contains("kitrove-remove")
                        })
                        .unwrap()
                        .path();
                    fs::rename(&tombstone, root.join("targets/verified-original")).unwrap();
                    fs::rename(root.join("targets/alternate"), &tombstone).unwrap();
                },
            )
            .unwrap_err();

        assert_eq!(error.code(), "object.precondition_failed");
        assert!(root.join("targets/verified-original").exists());
        assert_eq!(
            store
                .inspect_rendered_directory(&alternate, &third_hash, CaptureLimits::default())
                .unwrap(),
            RenderedState::Missing
        );
        assert!(fs::read_dir(root.join("targets")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("kitrove-remove")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn rendered_operations_refuse_a_replaced_store_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("target");
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let rendered = PortablePath::parse("targets/review").unwrap();
        let (tree, hash) = rendered_tree(b"expected\n");
        store
            .stage_rendered_directory(&rendered, &tree, &hash, CaptureLimits::default())
            .unwrap();

        let displaced = parent.path().join("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();

        let error = store
            .inspect_rendered_directory(&rendered, &hash, CaptureLimits::default())
            .unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(displaced.join("targets/review/SKILL.md").exists());
        assert!(!root.join("targets").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extension_operations_refuse_a_replaced_store_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("target");
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let destination = PortablePath::parse("targets/review.ts").unwrap();
        let files = BTreeMap::from([(
            PortablePath::parse("review.ts").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"export const review = true;\n".to_vec(),
            },
        )]);
        let object = NativeExtensionObject::new(
            kitrove_model::HarnessId::Pi,
            crate::NativeExtensionLayout::Standalone,
            "review.ts",
            "review",
            CapturedTree {
                hash: hash_tree(&files),
                files,
            },
        )
        .unwrap();
        store
            .stage_extension_target(&destination, &object, CaptureLimits::default())
            .unwrap();

        let displaced = parent.path().join("displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();

        let error = store
            .clear_extension_target_staging(&destination, &object, CaptureLimits::default())
            .unwrap_err();

        assert_eq!(error.code(), "object.unsafe_environment_root");
        assert!(displaced.join("targets/review.ts").exists());
        assert!(!root.join("targets").exists());
    }
}
