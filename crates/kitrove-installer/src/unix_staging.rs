use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt as _, Metadata, OpenOptions, Permissions, PermissionsExt as _,
};
use sha2::{Digest as _, Sha256};

use crate::record::{
    MAX_DESTINATION_PATH_BYTES, MAX_OPERATION_RECORD_BYTES, PreparedFilesystemEvidence,
};
use crate::staging_policy::{inventory_matches, random_operation_id};
use crate::{
    INSTALLER_STATE_DIRECTORY, InstallerOperationRecord, InstallerStageError, NativeFileIdentity,
    StagedApplication, StagingInput,
};

pub(crate) use crate::staging_policy::{INSTALLER_LOCK, OPERATION_RECORD, STAGED_EXECUTABLE};
const MAX_DESTINATION_COMPONENTS: usize = 127;

struct OpenedDirectory {
    name: Option<OsString>,
    directory: Dir,
    identity: NativeFileIdentity,
}

pub(crate) struct OpenedDestination {
    path_bytes: Vec<u8>,
    chain: Vec<OpenedDirectory>,
}

impl OpenedDestination {
    pub(crate) fn directory(&self) -> &Dir {
        &self
            .chain
            .last()
            .expect("destination chain is nonempty")
            .directory
    }

    pub(crate) fn identities(&self) -> Vec<NativeFileIdentity> {
        self.chain.iter().map(|entry| entry.identity).collect()
    }

    pub(crate) fn path_bytes(&self) -> &[u8] {
        &self.path_bytes
    }
}

pub(crate) struct RetainedStage {
    pub(crate) destination: OpenedDestination,
    pub(crate) state: Dir,
    pub(crate) operation: Dir,
    pub(crate) executable: cap_std::fs::File,
    pub(crate) installed: Option<cap_std::fs::File>,
    pub(crate) record: cap_std::fs::File,
    pub(crate) phase_markers: Vec<cap_std::fs::File>,
    pub(crate) lock: InstallerLock,
}

pub(crate) struct InstallerLock {
    capability: cap_std::fs::File,
    native_lock: std::fs::File,
    identity: NativeFileIdentity,
}

impl Drop for InstallerLock {
    fn drop(&mut self) {
        // Closing remains the fallback; explicit unlock avoids platform-specific delayed release
        // while the retained capability's duplicate descriptor is still alive.
        let _ = fs2::FileExt::unlock(&self.native_lock);
    }
}

impl RetainedStage {
    pub(crate) fn new(
        destination: OpenedDestination,
        state: Dir,
        operation: Dir,
        executable: cap_std::fs::File,
        record: cap_std::fs::File,
        lock: InstallerLock,
    ) -> Self {
        Self {
            destination,
            state,
            operation,
            executable,
            installed: None,
            record,
            phase_markers: Vec::new(),
            lock,
        }
    }

    pub(crate) fn with_installed(mut self, installed: cap_std::fs::File) -> Self {
        self.installed = Some(installed);
        self
    }

    pub(crate) fn with_phase_marker(mut self, marker: cap_std::fs::File) -> Self {
        self.phase_markers.push(marker);
        self
    }
}

impl InstallerLock {
    pub(crate) const fn identity(&self) -> NativeFileIdentity {
        self.identity
    }
}

struct CreatedLeaf {
    name: &'static str,
    file: cap_std::fs::File,
    identity: NativeFileIdentity,
    mode: u32,
}

#[derive(Default)]
struct CreatedLeaves {
    executable: Option<CreatedLeaf>,
    record: Option<CreatedLeaf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageFault {
    None,
    AfterOperationCreated,
    AfterExecutableSynced,
    AfterRecordSynced,
    OperationDirectoryParentSync,
    #[cfg(test)]
    ReplaceLockAfterAcquisition,
    #[cfg(test)]
    MutateExecutableAfterRecord,
    #[cfg(test)]
    MutateRecordAfterRecord,
    #[cfg(test)]
    ReplaceExecutableOnFailure,
    #[cfg(test)]
    ReplaceStateAfterRecord,
    #[cfg(test)]
    ReplaceOperationAfterRecord,
    #[cfg(test)]
    AddStateEntryAfterRecord,
    #[cfg(test)]
    AddOperationEntryAfterRecord,
}

pub(crate) fn stage(
    destination_parent: &Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    stage_impl(destination_parent, input, StageFault::None, || {})
}

fn stage_impl<F>(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    fault: StageFault,
    after_destination_open: F,
) -> Result<StagedApplication, InstallerStageError>
where
    F: FnOnce(),
{
    require_unprivileged_process()?;
    let destination = open_destination(destination_parent)?;
    after_destination_open();
    revalidate_destination(&destination)?;

    sync_existing_history(&destination)?;

    let state = open_or_create_private_directory(
        destination.directory(),
        OsStr::new(INSTALLER_STATE_DIRECTORY),
    )?;
    let state_identity = directory_identity(&state)?;
    let lock = acquire_installer_lock(&state)?;
    apply_lock_fault(&state, fault)?;
    revalidate_control_boundary(&destination, &state, state_identity, &lock)?;
    require_exact_inventory(&state, &[OsStr::new(INSTALLER_LOCK)])?;

    let operation_id = random_operation_id()?;
    let operation = create_and_open_private_directory(
        &state,
        OsStr::new(&operation_id),
        fault == StageFault::OperationDirectoryParentSync,
    )?;
    let operation_identity = match directory_identity(&operation) {
        Ok(identity) => identity,
        Err(_) => {
            preserve_failed_operation(&state, &operation);
            return Err(InstallerStageError::RecoveryRequired);
        }
    };

    let mut leaves = CreatedLeaves::default();
    let prepared = prepare_operation(
        &destination,
        &state,
        &operation,
        &lock,
        &operation_id,
        state_identity,
        operation_identity,
        input,
        fault,
        &mut leaves,
    );
    let record = match prepared {
        Ok(prepared) => prepared,
        Err(_) => {
            let _ = apply_failure_fault(&operation, fault);
            preserve_failed_operation(&state, &operation);
            return Err(InstallerStageError::RecoveryRequired);
        }
    };
    let staged = leaves
        .executable
        .take()
        .expect("successful preparation retains its executable")
        .file;
    let record_file = leaves
        .record
        .take()
        .expect("successful preparation retains its record")
        .file;

    Ok(StagedApplication {
        record,
        manifest: input.manifest.clone(),
        executable_content_hash: kitrove_model::ContentHash::digest(input.executable_bytes),
        _retained: RetainedStage::new(destination, state, operation, staged, record_file, lock),
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_operation(
    destination: &OpenedDestination,
    state: &Dir,
    operation: &Dir,
    lock: &InstallerLock,
    operation_id: &str,
    state_identity: NativeFileIdentity,
    operation_identity: NativeFileIdentity,
    input: &StagingInput<'_>,
    fault: StageFault,
    leaves: &mut CreatedLeaves,
) -> Result<InstallerOperationRecord, InstallerStageError> {
    inject_fault(fault, StageFault::AfterOperationCreated)?;
    leaves.executable = Some(create_leaf(operation, STAGED_EXECUTABLE, 0o700)?);
    let staged = &leaves
        .executable
        .as_ref()
        .expect("executable was just created")
        .file;
    write_and_verify_executable(staged, input)?;
    let staged_metadata = staged
        .metadata()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    require_private_file(&staged_metadata, 0o700, input.executable_bytes.len() as u64)?;
    let staged_identity = leaves
        .executable
        .as_ref()
        .expect("executable is retained")
        .identity;
    inject_fault(fault, StageFault::AfterExecutableSynced)?;
    #[cfg(test)]
    if fault == StageFault::ReplaceExecutableOnFailure {
        return Err(InstallerStageError::WriteFailed);
    }

    let ancestry_identities = destination.identities();
    let record = InstallerOperationRecord::prepared(
        operation_id.to_owned(),
        input,
        PreparedFilesystemEvidence {
            destination_path: &destination.path_bytes,
            ancestry_identities: &ancestry_identities,
            state_identity,
            lock_identity: lock.identity,
            operation_identity,
            staged_identity,
        },
    );
    let record_bytes = record
        .to_json()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    if record_bytes.len() > MAX_OPERATION_RECORD_BYTES {
        return Err(InstallerStageError::WriteFailed);
    }
    leaves.record = Some(create_leaf(operation, OPERATION_RECORD, 0o600)?);
    let record_file = &mut leaves
        .record
        .as_mut()
        .expect("record was just created")
        .file;
    record_file
        .write_all(&record_bytes)
        .and_then(|()| record_file.sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)?;
    require_private_file(
        &record_file
            .metadata()
            .map_err(|_| InstallerStageError::WriteFailed)?,
        0o600,
        record_bytes.len() as u64,
    )?;
    inject_fault(fault, StageFault::AfterRecordSynced)?;
    apply_post_record_fault(destination, state, operation, operation_id, leaves, fault)?;

    sync_directory(operation)?;
    sync_directory(state)?;
    sync_directory(destination.directory())?;
    revalidate_executable(
        operation,
        leaves.executable.as_ref().expect("executable is retained"),
        input,
    )?;
    revalidate_record(
        operation,
        leaves.record.as_ref().expect("record is retained"),
        &record_bytes,
    )?;
    revalidate_control_boundary(destination, state, state_identity, lock)?;
    require_named_directory_identity(state, operation_id, operation, operation_identity)?;
    require_exact_inventory(
        state,
        &[OsStr::new(INSTALLER_LOCK), OsStr::new(operation_id)],
    )?;
    require_exact_inventory(
        operation,
        &[OsStr::new(STAGED_EXECUTABLE), OsStr::new(OPERATION_RECORD)],
    )?;
    let executable = leaves.executable.as_ref().expect("executable is retained");
    require_named_file_identity(
        operation,
        executable.name,
        &executable.file,
        executable.identity,
        executable.mode,
        input.executable_bytes.len() as u64,
    )?;
    let record_leaf = leaves.record.as_ref().expect("record is retained");
    require_named_file_identity(
        operation,
        record_leaf.name,
        &record_leaf.file,
        record_leaf.identity,
        record_leaf.mode,
        record_bytes.len() as u64,
    )?;
    // Retain identity without write access: Linux cannot execute an inode while
    // any writable descriptor remains open, including after an atomic exchange.
    use cap_fs_ext::Reopen as _;

    let executable = leaves.executable.as_mut().expect("executable is retained");
    let reader = executable
        .file
        .reopen(OpenOptions::new().read(true))
        .map_err(|_| InstallerStageError::WriteFailed)?;
    executable.file = reader;
    revalidate_executable(operation, executable, input)?;
    Ok(record)
}

fn inject_fault(observed: StageFault, point: StageFault) -> Result<(), InstallerStageError> {
    if observed == point {
        Err(InstallerStageError::WriteFailed)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn apply_lock_fault(state: &Dir, fault: StageFault) -> Result<(), InstallerStageError> {
    if fault != StageFault::ReplaceLockAfterAcquisition {
        return Ok(());
    }
    state
        .rename(INSTALLER_LOCK, state, "moved-lock")
        .map_err(|_| InstallerStageError::WriteFailed)?;
    create_private_file(state, OsStr::new(INSTALLER_LOCK), 0o600)?;
    sync_directory(state)
}

#[cfg(not(test))]
const fn apply_lock_fault(_state: &Dir, _fault: StageFault) -> Result<(), InstallerStageError> {
    Ok(())
}

#[cfg(test)]
fn apply_post_record_fault(
    destination: &OpenedDestination,
    state: &Dir,
    operation: &Dir,
    operation_id: &str,
    leaves: &CreatedLeaves,
    fault: StageFault,
) -> Result<(), InstallerStageError> {
    match fault {
        StageFault::MutateExecutableAfterRecord => overwrite_prefix(
            &leaves
                .executable
                .as_ref()
                .expect("fault requires executable")
                .file,
            b"X",
        ),
        StageFault::MutateRecordAfterRecord => overwrite_prefix(
            &leaves.record.as_ref().expect("fault requires record").file,
            b"[",
        ),
        StageFault::ReplaceStateAfterRecord => {
            destination
                .directory()
                .rename(
                    INSTALLER_STATE_DIRECTORY,
                    destination.directory(),
                    "moved-state",
                )
                .map_err(|_| InstallerStageError::WriteFailed)?;
            create_and_open_private_directory(
                destination.directory(),
                OsStr::new(INSTALLER_STATE_DIRECTORY),
                false,
            )?;
            Ok(())
        }
        StageFault::ReplaceOperationAfterRecord => {
            state
                .rename(operation_id, state, "moved-operation")
                .map_err(|_| InstallerStageError::WriteFailed)?;
            create_and_open_private_directory(state, OsStr::new(operation_id), false)?;
            Ok(())
        }
        StageFault::AddStateEntryAfterRecord => {
            create_and_open_private_directory(state, OsStr::new("unexpected-operation"), false)?;
            Ok(())
        }
        StageFault::AddOperationEntryAfterRecord => {
            create_private_file(operation, OsStr::new("unexpected-child"), 0o600)?;
            Ok(())
        }
        _ => {
            let _ = operation;
            Ok(())
        }
    }
}

#[cfg(not(test))]
const fn apply_post_record_fault(
    _destination: &OpenedDestination,
    _state: &Dir,
    _operation: &Dir,
    _operation_id: &str,
    _leaves: &CreatedLeaves,
    _fault: StageFault,
) -> Result<(), InstallerStageError> {
    Ok(())
}

#[cfg(test)]
fn overwrite_prefix(file: &cap_std::fs::File, bytes: &[u8]) -> Result<(), InstallerStageError> {
    let mut writer = file
        .try_clone()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    writer
        .seek(SeekFrom::Start(0))
        .and_then(|_| writer.write_all(bytes))
        .and_then(|()| writer.sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)
}

#[cfg(test)]
fn apply_failure_fault(operation: &Dir, fault: StageFault) -> Result<(), InstallerStageError> {
    if fault != StageFault::ReplaceExecutableOnFailure {
        return Ok(());
    }
    operation
        .rename(STAGED_EXECUTABLE, operation, "moved-application")
        .map_err(|_| InstallerStageError::WriteFailed)?;
    create_private_file(operation, OsStr::new(STAGED_EXECUTABLE), 0o700)?;
    Ok(())
}

#[cfg(not(test))]
const fn apply_failure_fault(
    _operation: &Dir,
    _fault: StageFault,
) -> Result<(), InstallerStageError> {
    Ok(())
}

pub(crate) fn require_unprivileged_process() -> Result<(), InstallerStageError> {
    let real_uid = rustix::process::getuid().as_raw();
    let effective_uid = rustix::process::geteuid().as_raw();
    let real_gid = rustix::process::getgid().as_raw();
    let effective_gid = rustix::process::getegid().as_raw();
    require_unprivileged_identity(
        real_uid,
        effective_uid,
        real_gid,
        effective_gid,
        has_capability_authority()?,
    )
}

fn require_unprivileged_identity(
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    has_effective_capabilities: bool,
) -> Result<(), InstallerStageError> {
    if effective_uid == 0
        || real_uid != effective_uid
        || real_gid != effective_gid
        || has_effective_capabilities
    {
        Err(InstallerStageError::UnsafeDestination)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn has_capability_authority() -> Result<bool, InstallerStageError> {
    rustix::thread::capabilities(None)
        .map(|sets| {
            capability_sets_carry_authority(
                !sets.effective.is_empty(),
                !sets.permitted.is_empty(),
                !sets.inheritable.is_empty(),
            )
        })
        .map_err(|_| InstallerStageError::UnsafeDestination)
}

#[cfg(target_os = "linux")]
const fn capability_sets_carry_authority(
    effective: bool,
    permitted: bool,
    inheritable: bool,
) -> bool {
    effective || permitted || inheritable
}

#[cfg(not(target_os = "linux"))]
const fn has_capability_authority() -> Result<bool, InstallerStageError> {
    Ok(false)
}

pub(crate) fn open_destination(path: &Path) -> Result<OpenedDestination, InstallerStageError> {
    let absolute = std::path::absolute(path).map_err(|_| InstallerStageError::UnsafeDestination)?;
    let (anchor, components) = split_absolute_path(&absolute)?;
    if components.is_empty() || components.len() > MAX_DESTINATION_COMPONENTS {
        return Err(InstallerStageError::UnsafeDestination);
    }
    let mut normalized = anchor.clone();
    normalized.extend(&components);
    let path_bytes = bounded_destination_path_bytes(&normalized)?;

    let directory = Dir::open_ambient_dir(anchor, ambient_authority())
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    let metadata = directory
        .dir_metadata()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    require_trusted_directory(&directory, &metadata, false)?;
    let mut chain = vec![OpenedDirectory {
        name: None,
        identity: metadata_identity(&metadata),
        directory,
    }];

    for (index, component) in components.iter().enumerate() {
        let parent = &chain.last().expect("root is retained").directory;
        let before = parent
            .symlink_metadata(component)
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        require_trusted_metadata(&before, index + 1 == components.len())?;
        let child = parent
            .open_dir_nofollow(component)
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        let after = child
            .dir_metadata()
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        require_trusted_directory(&child, &after, index + 1 == components.len())?;
        if metadata_identity(&before) != metadata_identity(&after) {
            return Err(InstallerStageError::UnsafeDestination);
        }
        chain.push(OpenedDirectory {
            name: Some(component.clone()),
            identity: metadata_identity(&after),
            directory: child,
        });
    }
    Ok(OpenedDestination { path_bytes, chain })
}

pub(crate) fn bounded_destination_path_bytes(path: &Path) -> Result<Vec<u8>, InstallerStageError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_DESTINATION_PATH_BYTES {
        Err(InstallerStageError::UnsafeDestination)
    } else {
        Ok(bytes.to_vec())
    }
}

pub(crate) fn revalidate_destination(
    destination: &OpenedDestination,
) -> Result<(), InstallerStageError> {
    let root = destination
        .chain
        .first()
        .ok_or(InstallerStageError::UnsafeDestination)?;
    let root_metadata = root
        .directory
        .dir_metadata()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    require_trusted_directory(&root.directory, &root_metadata, false)?;
    if metadata_identity(&root_metadata) != root.identity {
        return Err(InstallerStageError::UnsafeDestination);
    }
    let mut rebound = root
        .directory
        .try_clone()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    for (index, expected) in destination.chain.iter().enumerate().skip(1) {
        let name = expected
            .name
            .as_deref()
            .ok_or(InstallerStageError::UnsafeDestination)?;
        let child = rebound
            .open_dir_nofollow(name)
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        let metadata = child
            .dir_metadata()
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        require_trusted_directory(&child, &metadata, index + 1 == destination.chain.len())?;
        if metadata_identity(&metadata) != expected.identity {
            return Err(InstallerStageError::UnsafeDestination);
        }
        rebound = child;
    }
    Ok(())
}

pub(crate) fn revalidate_control_boundary(
    destination: &OpenedDestination,
    state: &Dir,
    state_identity: NativeFileIdentity,
    lock: &InstallerLock,
) -> Result<(), InstallerStageError> {
    revalidate_destination(destination)?;
    require_named_directory_identity(
        destination.directory(),
        INSTALLER_STATE_DIRECTORY,
        state,
        state_identity,
    )?;
    require_named_file_identity(
        state,
        INSTALLER_LOCK,
        &lock.capability,
        lock.identity,
        0o600,
        0,
    )
}

fn split_absolute_path(path: &Path) -> Result<(PathBuf, Vec<OsString>), InstallerStageError> {
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::Normal(component) => components.push(component.to_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(InstallerStageError::UnsafeDestination);
            }
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(InstallerStageError::UnsafeDestination);
    }
    Ok((anchor, components))
}

fn require_trusted_directory(
    directory: &Dir,
    metadata: &Metadata,
    require_current_user: bool,
) -> Result<(), InstallerStageError> {
    require_trusted_metadata(metadata, require_current_user)?;
    require_safe_ancestry_acl(directory)
}

fn require_trusted_metadata(
    metadata: &Metadata,
    require_current_user: bool,
) -> Result<(), InstallerStageError> {
    use cap_fs_ext::OsMetadataExt as _;

    let current = u64::from(rustix::process::geteuid().as_raw());
    let owner = u64::from(metadata.uid());
    if metadata.is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || if require_current_user {
            owner != current
        } else {
            owner != 0 && owner != current
        }
    {
        return Err(InstallerStageError::UnsafeDestination);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_safe_ancestry_acl(directory: &Dir) -> Result<(), InstallerStageError> {
    use std::os::fd::AsFd as _;

    let acl = calcifer_macos_acl::read_acl(directory.as_fd())
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    if acl.flags == 0
        && acl
            .entries
            .iter()
            .all(|entry| entry.tag == calcifer_macos_acl::TAG_DENY)
    {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeDestination)
    }
}

#[cfg(not(target_os = "macos"))]
const fn require_safe_ancestry_acl(_directory: &Dir) -> Result<(), InstallerStageError> {
    Ok(())
}

pub(crate) fn open_or_create_private_directory(
    parent: &Dir,
    name: &OsStr,
) -> Result<Dir, InstallerStageError> {
    match parent.symlink_metadata(name) {
        Ok(_) => open_private_child(parent, name),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_and_open_private_directory(parent, name, false)
        }
        Err(_) => Err(InstallerStageError::UnsafeState),
    }
}

/// Completes the directory durability side of an earlier interrupted retirement.
fn sync_existing_history(destination: &OpenedDestination) -> Result<(), InstallerStageError> {
    let name = OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY);
    match destination.directory().symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallerStageError::RecoveryRequired),
        Ok(_) => {
            let history = open_private_child(destination.directory(), name)?;
            let identity = directory_identity(&history)?;
            require_named_directory_identity(
                destination.directory(),
                crate::INSTALLER_HISTORY_DIRECTORY,
                &history,
                identity,
            )?;
            sync_directory(&history)?;
            require_named_directory_identity(
                destination.directory(),
                crate::INSTALLER_HISTORY_DIRECTORY,
                &history,
                identity,
            )?;
            revalidate_destination(destination)
        }
    }
}

pub(crate) fn create_private_child(parent: &Dir, name: &OsStr) -> Result<Dir, InstallerStageError> {
    create_and_open_private_directory(parent, name, false)
}

fn create_and_open_private_directory(
    parent: &Dir,
    name: &OsStr,
    inject_parent_sync_failure: bool,
) -> Result<Dir, InstallerStageError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    parent
        .create_dir_with(name, &builder)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => InstallerStageError::Conflict,
            _ => InstallerStageError::WriteFailed,
        })?;
    let directory = match open_created_private_child(parent, name) {
        Ok(directory) => directory,
        Err(_) => return Err(InstallerStageError::RecoveryRequired),
    };
    let sync_result = if inject_parent_sync_failure {
        Err(InstallerStageError::WriteFailed)
    } else {
        sync_directory(parent)
    };
    if sync_result.is_err() {
        let _ = sync_directory(parent);
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(directory)
}

fn open_created_private_child(parent: &Dir, name: &OsStr) -> Result<Dir, InstallerStageError> {
    use cap_fs_ext::OsMetadataExt as _;

    let before = parent
        .symlink_metadata(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let child = parent
        .open_dir_nofollow(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let after = child
        .dir_metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if metadata_identity(&before) != metadata_identity(&after)
        || after.is_symlink()
        || !after.is_dir()
        || after.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(InstallerStageError::UnsafeState);
    }
    child
        .set_permissions(".", Permissions::from_mode(0o700))
        .map_err(|_| InstallerStageError::WriteFailed)?;
    #[cfg(target_os = "macos")]
    clear_created_acl(&child)?;
    require_private_directory(&child)?;
    Ok(child)
}

pub(crate) fn open_private_child(parent: &Dir, name: &OsStr) -> Result<Dir, InstallerStageError> {
    let before = parent
        .symlink_metadata(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let child = parent
        .open_dir_nofollow(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let after = child
        .dir_metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if metadata_identity(&before) != metadata_identity(&after) {
        return Err(InstallerStageError::UnsafeState);
    }
    require_private_directory(&child)?;
    Ok(child)
}

fn require_private_directory(directory: &Dir) -> Result<(), InstallerStageError> {
    use cap_fs_ext::OsMetadataExt as _;

    let metadata = directory
        .dir_metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if metadata.is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(InstallerStageError::UnsafeState);
    }
    #[cfg(target_os = "macos")]
    require_empty_acl(directory)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_created_acl(directory: &Dir) -> Result<(), InstallerStageError> {
    use std::os::fd::AsFd as _;

    calcifer_macos_acl::clear_acl(directory.as_fd()).map_err(|_| InstallerStageError::WriteFailed)
}

#[cfg(target_os = "macos")]
pub(crate) fn require_empty_acl(
    object: &impl std::os::fd::AsFd,
) -> Result<(), InstallerStageError> {
    if calcifer_macos_acl::read_acl(object.as_fd())
        .map_err(|_| InstallerStageError::UnsafeState)?
        .is_empty()
    {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

fn acquire_installer_lock(state: &Dir) -> Result<InstallerLock, InstallerStageError> {
    let lock = match state.symlink_metadata(INSTALLER_LOCK) {
        Ok(_) => open_existing_lock(state)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match create_private_file(state, OsStr::new(INSTALLER_LOCK), 0o600) {
                Ok(lock) => lock,
                Err(InstallerStageError::Conflict) => open_existing_lock(state)?,
                Err(error) => return Err(error),
            }
        }
        Err(_) => return Err(InstallerStageError::UnsafeState),
    };
    lock_installer_file(state, lock)
}

pub(crate) fn acquire_existing_installer_lock(
    state: &Dir,
) -> Result<InstallerLock, InstallerStageError> {
    let lock = open_existing_lock(state)?;
    lock_installer_file(state, lock)
}

fn lock_installer_file(
    state: &Dir,
    lock: cap_std::fs::File,
) -> Result<InstallerLock, InstallerStageError> {
    let metadata = lock
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_private_file(&metadata, 0o600, 0)?;
    let identity = metadata_identity(&metadata);
    let native_lock = lock
        .try_clone()
        .map_err(|_| InstallerStageError::UnsafeState)?
        .into_std();
    fs2::FileExt::try_lock_exclusive(&native_lock).map_err(crate::staging_policy::lock_error)?;
    require_named_file_identity(state, INSTALLER_LOCK, &lock, identity, 0o600, 0)?;
    Ok(InstallerLock {
        capability: lock,
        native_lock,
        identity,
    })
}

fn open_existing_lock(state: &Dir) -> Result<cap_std::fs::File, InstallerStageError> {
    let before = state
        .symlink_metadata(INSTALLER_LOCK)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    let lock = state
        .open_with(INSTALLER_LOCK, &options)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let after = lock
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if metadata_identity(&before) != metadata_identity(&after) {
        return Err(InstallerStageError::UnsafeState);
    }
    Ok(lock)
}

pub(crate) fn require_exact_inventory(
    directory: &Dir,
    expected: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let mut observed = Vec::with_capacity(expected.len());
    let mut entries = directory
        .entries()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    for _ in 0..=expected.len() {
        let Some(entry) = entries.next() else {
            return if inventory_matches(observed, expected) {
                Ok(())
            } else {
                Err(InstallerStageError::RecoveryRequired)
            };
        };
        let entry = entry.map_err(|_| InstallerStageError::RecoveryRequired)?;
        observed.push(entry.file_name());
    }
    Err(InstallerStageError::RecoveryRequired)
}

pub(crate) fn create_private_file(
    directory: &Dir,
    name: &OsStr,
    mode: u32,
) -> Result<cap_std::fs::File, InstallerStageError> {
    use cap_std::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => InstallerStageError::Conflict,
            _ => InstallerStageError::WriteFailed,
        })?;
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|_| InstallerStageError::WriteFailed)?;
    Ok(file)
}

pub(crate) fn create_synced_private_file(
    directory: &Dir,
    name: &OsStr,
    bytes: &[u8],
) -> Result<cap_std::fs::File, InstallerStageError> {
    let mut file = create_private_file(directory, name, 0o600)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)?;
    Ok(file)
}

/// Completes a bounded caller-validated canonical record without replacing its prefix.
/// Any uncertain identity or content remains intact and requires recovery.
pub(crate) fn complete_private_file_prefix(
    parent: &Dir,
    name: &str,
    retained: &cap_std::fs::File,
    identity: NativeFileIdentity,
    prefix: &[u8],
    canonical: &[u8],
) -> Result<(), InstallerStageError> {
    use cap_std::fs::OpenOptionsExt as _;
    if !canonical.starts_with(prefix) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let require_prefix = || {
        require_named_file_identity(parent, name, retained, identity, 0o600, prefix.len() as u64)?;
        if read_bounded_file(retained, canonical.len())? != prefix {
            return Err(InstallerStageError::RecoveryRequired);
        }
        require_named_file_identity(parent, name, retained, identity, 0o600, prefix.len() as u64)
    };
    require_prefix()?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .append(true)
        .follow(FollowSymlinks::No)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    let mut writer = parent
        .open_with(name, &options)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_named_file_identity(parent, name, &writer, identity, 0o600, prefix.len() as u64)?;
    require_prefix()?;
    writer
        .write_all(&canonical[prefix.len()..])
        .and_then(|()| writer.sync_all())
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_named_file_identity(
        parent,
        name,
        retained,
        identity,
        0o600,
        canonical.len() as u64,
    )?;
    if read_bounded_file(retained, canonical.len())? != canonical {
        return Err(InstallerStageError::RecoveryRequired);
    }
    require_named_file_identity(
        parent,
        name,
        retained,
        identity,
        0o600,
        canonical.len() as u64,
    )
}

fn create_leaf(
    directory: &Dir,
    name: &'static str,
    mode: u32,
) -> Result<CreatedLeaf, InstallerStageError> {
    let file = create_private_file(directory, OsStr::new(name), mode)?;
    let metadata = file
        .metadata()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    require_private_file(&metadata, mode, 0)?;
    Ok(CreatedLeaf {
        name,
        identity: metadata_identity(&metadata),
        file,
        mode,
    })
}

fn write_and_verify_executable(
    file: &cap_std::fs::File,
    input: &StagingInput<'_>,
) -> Result<(), InstallerStageError> {
    let mut writer = file
        .try_clone()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    writer
        .write_all(input.executable_bytes)
        .and_then(|()| writer.sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)?;
    verify_executable_contents(&writer, input)
}

pub(crate) fn verify_executable_contents(
    file: &cap_std::fs::File,
    input: &StagingInput<'_>,
) -> Result<(), InstallerStageError> {
    verify_sha256_contents(
        file,
        input.executable_bytes.len() as u64,
        input.executable_sha256,
    )
}

pub(crate) fn verify_sha256_contents(
    file: &cap_std::fs::File,
    expected_size: u64,
    expected_sha256: [u8; 32],
) -> Result<(), InstallerStageError> {
    let mut reader = file
        .try_clone()
        .map_err(|_| InstallerStageError::WriteFailed)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallerStageError::WriteFailed)?;
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| InstallerStageError::WriteFailed)?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(read as u64)
            .filter(|size| *size <= expected_size)
            .ok_or(InstallerStageError::WriteFailed)?;
        digest.update(&buffer[..read]);
    }
    if observed != expected_size || <[u8; 32]>::from(digest.finalize()) != expected_sha256 {
        return Err(InstallerStageError::WriteFailed);
    }
    Ok(())
}

fn revalidate_executable(
    operation: &Dir,
    leaf: &CreatedLeaf,
    input: &StagingInput<'_>,
) -> Result<(), InstallerStageError> {
    require_named_file_identity(
        operation,
        leaf.name,
        &leaf.file,
        leaf.identity,
        leaf.mode,
        input.executable_bytes.len() as u64,
    )?;
    verify_executable_contents(&leaf.file, input)
}

fn revalidate_record(
    operation: &Dir,
    leaf: &CreatedLeaf,
    expected: &[u8],
) -> Result<(), InstallerStageError> {
    require_named_file_identity(
        operation,
        leaf.name,
        &leaf.file,
        leaf.identity,
        leaf.mode,
        expected.len() as u64,
    )?;
    let observed = read_bounded_file(&leaf.file, MAX_OPERATION_RECORD_BYTES)?;
    if observed == expected {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

pub(crate) fn read_bounded_file(
    file: &cap_std::fs::File,
    maximum: usize,
) -> Result<Vec<u8>, InstallerStageError> {
    let mut reader = file
        .try_clone()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let limit = u64::try_from(maximum)
        .map_err(|_| InstallerStageError::UnsafeState)?
        .checked_add(1)
        .ok_or(InstallerStageError::UnsafeState)?;
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if bytes.len() > maximum {
        Err(InstallerStageError::UnsafeState)
    } else {
        Ok(bytes)
    }
}

pub(crate) fn require_private_file(
    metadata: &Metadata,
    mode: u32,
    size: u64,
) -> Result<(), InstallerStageError> {
    require_private_file_with_link_count(metadata, mode, size, 1)
}

pub(crate) fn require_private_file_with_link_count(
    metadata: &Metadata,
    mode: u32,
    size: u64,
    link_count: u64,
) -> Result<(), InstallerStageError> {
    use cap_fs_ext::OsMetadataExt as _;

    if metadata.is_symlink()
        || !metadata.is_file()
        || metadata.len() != size
        || metadata.permissions().mode() & 0o7777 != mode
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || cap_fs_ext::MetadataExt::nlink(metadata) != link_count
    {
        return Err(InstallerStageError::UnsafeState);
    }
    Ok(())
}

pub(crate) fn require_named_directory_identity(
    parent: &Dir,
    name: &str,
    directory: &Dir,
    expected: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    require_private_directory(directory)?;
    let named = parent
        .symlink_metadata(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if metadata_identity(&named) == expected && directory_identity(directory)? == expected {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

pub(crate) fn require_named_file_identity(
    parent: &Dir,
    name: &str,
    file: &cap_std::fs::File,
    expected: NativeFileIdentity,
    mode: u32,
    size: u64,
) -> Result<(), InstallerStageError> {
    require_named_file_identity_with_link_count(parent, name, file, expected, mode, size, 1)
}

pub(crate) fn require_named_file_identity_with_link_count(
    parent: &Dir,
    name: &str,
    file: &cap_std::fs::File,
    expected: NativeFileIdentity,
    mode: u32,
    size: u64,
    link_count: u64,
) -> Result<(), InstallerStageError> {
    #[cfg(target_os = "macos")]
    require_empty_acl(file)?;
    let named = parent
        .symlink_metadata(name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let opened = file
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_private_file_with_link_count(&named, mode, size, link_count)?;
    require_private_file_with_link_count(&opened, mode, size, link_count)?;
    if metadata_identity(&named) == expected && metadata_identity(&opened) == expected {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

pub(crate) fn directory_identity(
    directory: &Dir,
) -> Result<NativeFileIdentity, InstallerStageError> {
    directory
        .dir_metadata()
        .map(|metadata| metadata_identity(&metadata))
        .map_err(|_| InstallerStageError::UnsafeState)
}

pub(crate) fn metadata_identity(metadata: &Metadata) -> NativeFileIdentity {
    NativeFileIdentity::new(metadata.dev(), metadata.ino())
}

fn preserve_failed_operation(state: &Dir, operation: &Dir) {
    let _ = sync_directory(operation);
    let _ = sync_directory(state);
}

pub(crate) fn sync_directory(directory: &Dir) -> Result<(), InstallerStageError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(".", &options)
        .and_then(|file| file.into_std().sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)
}

pub(crate) fn sync_file(file: &cap_std::fs::File) -> Result<(), InstallerStageError> {
    file.sync_all()
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;
    use crate::test_support::{private_tempdir, staging_input as input};

    #[test]
    fn prepared_executable_retains_only_read_access() {
        use cap_fs_ext::IsFileReadWrite as _;

        let root = private_tempdir();
        let prepared = stage(root.path(), &input(b"authenticated executable")).unwrap();
        assert_eq!(
            prepared._retained.executable.is_file_read_write().unwrap(),
            (true, false)
        );
    }

    #[test]
    fn stages_exact_bytes_and_a_strict_durable_prepared_record() {
        let root = private_tempdir();
        let prepared = stage(root.path(), &input(b"authenticated executable")).unwrap();
        let operation = root
            .path()
            .join(INSTALLER_STATE_DIRECTORY)
            .join(prepared.record.operation_id());
        let executable = operation.join(STAGED_EXECUTABLE);
        assert_eq!(fs::read(&executable).unwrap(), b"authenticated executable");
        let executable_metadata = fs::metadata(&executable).unwrap();
        assert_eq!(executable_metadata.permissions().mode() & 0o7777, 0o700);
        assert_eq!(executable_metadata.len(), 24);
        assert_eq!(
            prepared.record.staged_identity(),
            &NativeFileIdentity::new(
                std::os::unix::fs::MetadataExt::dev(&executable_metadata),
                std::os::unix::fs::MetadataExt::ino(&executable_metadata),
            )
        );

        let record_bytes = fs::read(operation.join(OPERATION_RECORD)).unwrap();
        assert!(record_bytes.len() <= MAX_OPERATION_RECORD_BYTES);
        let decoded = InstallerOperationRecord::parse_untrusted(&record_bytes).unwrap();
        assert_eq!(decoded.operation_id(), prepared.record.operation_id());
        assert_eq!(
            prepared.record.phase(),
            crate::InstallerOperationPhase::Prepared
        );
        assert!(
            !record_bytes
                .windows(24)
                .any(|value| value == b"authenticated executable")
        );
        let record_metadata = fs::metadata(operation.join(OPERATION_RECORD)).unwrap();
        assert_eq!(record_metadata.permissions().mode() & 0o7777, 0o600);

        let record_value: serde_json::Value = serde_json::from_slice(&record_bytes).unwrap();
        let invalid_identity = serde_json::json!({
            "platform": "unix",
            "filesystem_id": 1,
            "file_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        });
        let noncanonical_unix_identity = serde_json::json!({
            "platform": "unix",
            "filesystem_id": 1,
            "file_id": [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        });
        let windows_identity = serde_json::json!({
            "platform": "windows",
            "filesystem_id": 1,
            "file_id": [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        });
        for (field, replacement) in [
            ("schema", serde_json::json!(4)),
            ("target", serde_json::json!("unknown")),
            ("archive_sha256", serde_json::json!("00")),
            ("executable_size", serde_json::json!(0)),
            ("executable_sha256", serde_json::json!("00")),
            ("release_manifest_sha256", serde_json::json!("00")),
            ("application_state_schema", serde_json::json!("V2")),
            ("lifecycle_lock_protocol", serde_json::json!(2)),
            ("release_tag", serde_json::json!("1.2.3")),
            ("release_version", serde_json::json!("1.2.4")),
            ("signer_identity", serde_json::json!("wrong")),
            ("trust_root_sha256", serde_json::json!("00")),
            ("destination_path_hex", serde_json::json!("00")),
            ("ancestry_identities", serde_json::json!([])),
            ("state_identity", invalid_identity.clone()),
            ("operation_identity", invalid_identity.clone()),
            ("lock_identity", invalid_identity.clone()),
            ("staged_identity", invalid_identity),
            ("state_identity", noncanonical_unix_identity),
            ("state_identity", windows_identity),
        ] {
            let mut changed = record_value.clone();
            changed[field] = replacement;
            assert!(
                InstallerOperationRecord::parse_untrusted(&serde_json::to_vec(&changed).unwrap())
                    .is_err(),
                "accepted changed record field {field}"
            );
        }
        for schema in [1, 2] {
            let mut masquerading_current_record = record_value.clone();
            masquerading_current_record["schema"] = serde_json::json!(schema);
            let error = InstallerOperationRecord::parse_untrusted(
                &serde_json::to_vec(&masquerading_current_record).unwrap(),
            )
            .unwrap_err();
            assert!(!error.is_legacy_schema());
        }
        for path in [b"/a/../b".as_slice(), b"/a//b", b"/a/./b", b"/a\0b"] {
            let encoded = path.iter().fold(String::new(), |mut value, byte| {
                use std::fmt::Write as _;
                write!(value, "{byte:02x}").unwrap();
                value
            });
            let mut changed = record_value.clone();
            changed["destination_path_hex"] = encoded.into();
            assert!(
                InstallerOperationRecord::parse_untrusted(&serde_json::to_vec(&changed).unwrap())
                    .is_err()
            );
        }
        let mut mismatched_ancestry = record_value.clone();
        mismatched_ancestry["ancestry_identities"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(
            InstallerOperationRecord::parse_untrusted(
                &serde_json::to_vec(&mismatched_ancestry).unwrap()
            )
            .is_err()
        );
        let mut unknown = record_value;
        unknown["unexpected"] = serde_json::Value::Null;
        assert!(
            InstallerOperationRecord::parse_untrusted(&serde_json::to_vec(&unknown).unwrap())
                .is_err()
        );
        let mut record_at_limit = record_bytes;
        record_at_limit.resize(MAX_OPERATION_RECORD_BYTES, b' ');
        assert!(InstallerOperationRecord::parse_untrusted(&record_at_limit).is_ok());
        record_at_limit.push(b' ');
        assert!(InstallerOperationRecord::parse_untrusted(&record_at_limit).is_err());
    }

    #[test]
    fn unsafe_destination_and_existing_state_fail_without_permission_repair() {
        let root = private_tempdir();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            stage(root.path(), &input(b"binary")),
            Err(InstallerStageError::UnsafeDestination)
        ));
        assert!(!root.path().join(INSTALLER_STATE_DIRECTORY).exists());

        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.path().join(INSTALLER_STATE_DIRECTORY);
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            stage(root.path(), &input(b"binary")),
            Err(InstallerStageError::UnsafeState)
        ));
        assert_eq!(
            fs::metadata(state).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[test]
    fn symlinked_destination_or_state_is_never_followed() {
        let root = private_tempdir();
        let destination = root.path().join("destination");
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &destination).unwrap();
        assert!(matches!(
            stage(&destination, &input(b"binary")),
            Err(InstallerStageError::UnsafeDestination)
        ));

        let safe = root.path().join("safe");
        fs::create_dir(&safe).unwrap();
        symlink(&outside, safe.join(INSTALLER_STATE_DIRECTORY)).unwrap();
        assert!(matches!(
            stage(&safe, &input(b"binary")),
            Err(InstallerStageError::UnsafeState)
        ));
        assert!(fs::read_dir(outside).unwrap().next().is_none());
    }

    #[test]
    fn prepared_stage_blocks_concurrency_and_requires_recovery_after_guard_drop() {
        let root = private_tempdir();
        let first = stage(root.path(), &input(b"first")).unwrap();
        assert!(matches!(
            stage(root.path(), &input(b"second")),
            Err(InstallerStageError::Conflict)
        ));
        drop(first);
        assert!(matches!(
            stage(root.path(), &input(b"second")),
            Err(InstallerStageError::RecoveryRequired)
        ));
    }

    #[test]
    fn partial_operations_are_retained_for_guarded_recovery_at_every_boundary() {
        for fault in [
            StageFault::AfterOperationCreated,
            StageFault::AfterExecutableSynced,
            StageFault::AfterRecordSynced,
            StageFault::OperationDirectoryParentSync,
        ] {
            let root = private_tempdir();
            assert!(matches!(
                stage_impl(root.path(), &input(b"binary"), fault, || {}),
                Err(InstallerStageError::RecoveryRequired)
            ));
            let state = root.path().join(INSTALLER_STATE_DIRECTORY);
            let entries = fs::read_dir(&state)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 2);
            assert!(entries.contains(&OsString::from(INSTALLER_LOCK)));
            let operation = fs::read_dir(state)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.is_dir())
                .unwrap();
            if fault == StageFault::AfterRecordSynced {
                assert!(operation.join(STAGED_EXECUTABLE).is_file());
                assert!(operation.join(OPERATION_RECORD).is_file());
            }
        }
    }

    #[test]
    fn final_boundary_rejects_leaf_mutation_and_namespace_replacement() {
        for (fault, expected) in [
            (
                StageFault::ReplaceLockAfterAcquisition,
                InstallerStageError::UnsafeState,
            ),
            (
                StageFault::MutateExecutableAfterRecord,
                InstallerStageError::RecoveryRequired,
            ),
            (
                StageFault::MutateRecordAfterRecord,
                InstallerStageError::RecoveryRequired,
            ),
            (
                StageFault::ReplaceExecutableOnFailure,
                InstallerStageError::RecoveryRequired,
            ),
            (
                StageFault::ReplaceStateAfterRecord,
                InstallerStageError::RecoveryRequired,
            ),
            (
                StageFault::ReplaceOperationAfterRecord,
                InstallerStageError::RecoveryRequired,
            ),
            (
                StageFault::AddStateEntryAfterRecord,
                InstallerStageError::RecoveryRequired,
            ),
            (
                StageFault::AddOperationEntryAfterRecord,
                InstallerStageError::RecoveryRequired,
            ),
        ] {
            let root = private_tempdir();
            assert_eq!(
                stage_impl(root.path(), &input(b"binary"), fault, || {}).unwrap_err(),
                expected,
                "unexpected result for {fault:?}"
            );
            if fault == StageFault::AddStateEntryAfterRecord {
                assert!(
                    root.path()
                        .join(INSTALLER_STATE_DIRECTORY)
                        .join("unexpected-operation")
                        .is_dir()
                );
            }
            if fault == StageFault::AddOperationEntryAfterRecord {
                let state = root.path().join(INSTALLER_STATE_DIRECTORY);
                let operation = fs::read_dir(state)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| path.is_dir())
                    .unwrap();
                assert!(operation.join("unexpected-child").is_file());
            }
        }
    }

    #[test]
    fn unknown_or_abandoned_state_requires_recovery() {
        let root = private_tempdir();
        let prepared = stage(root.path(), &input(b"first")).unwrap();
        drop(prepared);
        assert!(matches!(
            stage(root.path(), &input(b"second")),
            Err(InstallerStageError::RecoveryRequired)
        ));

        let other = private_tempdir();
        let state = other.path().join(INSTALLER_STATE_DIRECTORY);
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(state.join("unknown"), b"preserve").unwrap();
        assert!(matches!(
            stage(other.path(), &input(b"binary")),
            Err(InstallerStageError::RecoveryRequired)
        ));
        assert_eq!(fs::read(state.join("unknown")).unwrap(), b"preserve");
    }

    #[test]
    fn destination_replacement_before_mutation_is_refused() {
        let root = private_tempdir();
        let selected = root.path().join("selected");
        let moved = root.path().join("moved");
        fs::create_dir(&selected).unwrap();
        assert!(matches!(
            stage_impl(&selected, &input(b"binary"), StageFault::None, || {
                fs::rename(&selected, &moved).unwrap();
                fs::create_dir(&selected).unwrap();
            }),
            Err(InstallerStageError::UnsafeDestination)
        ));
        assert!(!selected.join(INSTALLER_STATE_DIRECTORY).exists());
        assert!(!moved.join(INSTALLER_STATE_DIRECTORY).exists());
    }

    #[test]
    fn elevated_identity_is_refused_before_filesystem_authority() {
        for identity in [
            (1, 0, 1, 1, false),
            (1, 2, 1, 1, false),
            (1, 1, 1, 2, false),
            (1, 1, 1, 1, true),
        ] {
            assert_eq!(
                require_unprivileged_identity(
                    identity.0, identity.1, identity.2, identity.3, identity.4,
                ),
                Err(InstallerStageError::UnsafeDestination)
            );
        }
        assert_eq!(require_unprivileged_identity(1, 1, 1, 1, false), Ok(()));
        #[cfg(target_os = "linux")]
        for sets in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            assert!(capability_sets_carry_authority(sets.0, sets.1, sets.2));
        }
    }

    #[test]
    fn destination_path_bound_rejects_only_limit_plus_one() {
        let mut exact = vec![b'a'; MAX_DESTINATION_PATH_BYTES];
        exact[0] = b'/';
        assert!(bounded_destination_path_bytes(Path::new(&OsString::from_vec(exact))).is_ok());
        let mut oversized = vec![b'a'; MAX_DESTINATION_PATH_BYTES + 1];
        oversized[0] = b'/';
        assert_eq!(
            bounded_destination_path_bytes(Path::new(&OsString::from_vec(oversized))),
            Err(InstallerStageError::UnsafeDestination)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_grant_acl_on_destination_is_refused_without_mutation() {
        let root = private_tempdir();
        let destination = root.path().join("destination");
        fs::create_dir(&destination).unwrap();
        kitrove_testkit::install_macos_extended_acl(&destination);
        assert!(matches!(
            stage(&destination, &input(b"binary")),
            Err(InstallerStageError::UnsafeDestination)
        ));
        assert!(!destination.join(INSTALLER_STATE_DIRECTORY).exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_grant_acl_on_ancestor_is_refused_without_mutation() {
        let root = private_tempdir();
        let ancestor = root.path().join("ancestor");
        let destination = ancestor.join("destination");
        fs::create_dir(&ancestor).unwrap();
        fs::create_dir(&destination).unwrap();
        kitrove_testkit::install_macos_extended_acl(&ancestor);
        assert!(matches!(
            stage(&destination, &input(b"binary")),
            Err(InstallerStageError::UnsafeDestination)
        ));
        assert!(!destination.join(INSTALLER_STATE_DIRECTORY).exists());
    }
}
