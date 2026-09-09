use std::ffi::OsStr;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use cap_std::fs::Dir;
use sha2::{Digest as _, Sha256};

use crate::record::{
    MAX_DESTINATION_PATH_BYTES, MAX_OPERATION_RECORD_BYTES, PreparedFilesystemEvidence,
    destination_path_component_count, encode_hex,
};
use crate::staging_policy::{
    INSTALLER_LOCK, OPERATION_RECORD, STAGED_EXECUTABLE, inventory_matches, random_operation_id,
};
use crate::{
    INSTALLER_STATE_DIRECTORY, InstallerOperationRecord, InstallerStageError, NativeFileIdentity,
    StagedApplication, StagingInput,
};

pub(crate) struct RetainedStage {
    pub(crate) destination: kitrove_windows_security::ValidatedInstallDirectory,
    pub(crate) state: std::fs::File,
    pub(crate) operation: std::fs::File,
    pub(crate) executable: Option<std::fs::File>,
    pub(crate) record: std::fs::File,
    pub(crate) phase_markers: Vec<std::fs::File>,
    pub(crate) lock: InstallerLock,
}

pub(crate) struct InstallerLock {
    file: std::fs::File,
    identity: NativeFileIdentity,
}

enum OpenedState {
    Existing(std::fs::File),
    Created(std::fs::File),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageBoundary {
    StateCreated,
    OperationCreated,
    ExecutableWritten,
    RecordWritten,
}

impl Drop for InstallerLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

impl RetainedStage {
    pub(crate) fn new(
        destination: kitrove_windows_security::ValidatedInstallDirectory,
        state: std::fs::File,
        operation: std::fs::File,
        executable: std::fs::File,
        record: std::fs::File,
        lock: InstallerLock,
    ) -> Self {
        Self {
            destination,
            state,
            operation,
            executable: Some(executable),
            record,
            phase_markers: Vec::new(),
            lock,
        }
    }

    pub(crate) fn executable(&self) -> Result<&std::fs::File, InstallerStageError> {
        self.executable
            .as_ref()
            .ok_or(InstallerStageError::RecoveryRequired)
    }
}

impl InstallerLock {
    pub(crate) const fn identity(&self) -> NativeFileIdentity {
        self.identity
    }

    pub(crate) const fn file(&self) -> &std::fs::File {
        &self.file
    }
}

pub(crate) fn stage(
    destination_parent: &Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    kitrove_windows_security::require_unelevated_process()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    stage_after_security_preflight(destination_parent, input, |_| Ok(()))
}

fn stage_after_security_preflight(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    mut boundary: impl FnMut(StageBoundary) -> Result<(), InstallerStageError>,
) -> Result<StagedApplication, InstallerStageError> {
    let destination = kitrove_windows_security::validate_install_directory(destination_parent)
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    let destination_path = encode_destination_path(destination.path())?;
    let ancestry_identities = destination
        .identities()
        .iter()
        .copied()
        .map(native_identity)
        .collect::<Vec<_>>();
    let operation_id = random_operation_id()?;
    preflight_record_envelope(
        input,
        &destination_path,
        ancestry_identities.len(),
        &operation_id,
    )?;
    let (state, lock) = open_state_and_lock_with_hook(
        destination.directory().map_err(unsafe_destination)?,
        &mut boundary,
    )?;

    let state_identity = file_identity(&state)?;
    revalidate_control_boundary(&destination, &state, state_identity, &lock)?;
    require_exact_inventory(&state, &[OsStr::new(INSTALLER_LOCK)])?;
    sync_existing_history(&destination)?;

    let operation =
        kitrove_windows_security::create_private_directory(&state, OsStr::new(&operation_id))
            .map_err(map_operation_creation)?;
    let operation_identity = file_identity(&operation)?;
    boundary(StageBoundary::OperationCreated).map_err(|_| InstallerStageError::RecoveryRequired)?;

    let prepared = prepare_operation(
        PreparedOperationContext {
            destination: &destination,
            destination_path: &destination_path,
            ancestry_identities: &ancestry_identities,
            state: &state,
            state_identity,
            lock: &lock,
            operation: &operation,
            operation_identity,
            operation_id: &operation_id,
        },
        input,
        &mut boundary,
    );
    let (record, executable, record_file) = match prepared {
        Ok(prepared) => prepared,
        Err(_) => return Err(InstallerStageError::RecoveryRequired),
    };

    Ok(StagedApplication {
        record,
        manifest: input.manifest.clone(),
        executable_content_hash: kitrove_model::ContentHash::digest(input.executable_bytes),
        _retained: RetainedStage::new(destination, state, operation, executable, record_file, lock),
    })
}

#[cfg(test)]
pub(crate) fn stage_after_security_preflight_for_tests(
    destination_parent: &Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    stage_after_security_preflight(destination_parent, input, |_| Ok(()))
}

#[cfg(test)]
fn open_state_and_lock(
    destination: &std::fs::File,
) -> Result<(std::fs::File, InstallerLock), InstallerStageError> {
    open_state_and_lock_with_hook(destination, &mut |_| Ok(()))
}

fn open_state_and_lock_with_hook(
    destination: &std::fs::File,
    boundary: &mut impl FnMut(StageBoundary) -> Result<(), InstallerStageError>,
) -> Result<(std::fs::File, InstallerLock), InstallerStageError> {
    let opened_state =
        open_or_create_private_directory(destination, OsStr::new(INSTALLER_STATE_DIRECTORY))?;
    let (state, lock) = match opened_state {
        OpenedState::Existing(state) => {
            let lock = if require_exact_inventory(&state, &[OsStr::new(INSTALLER_LOCK)]).is_ok() {
                acquire_existing_installer_lock(&state)?
            } else {
                require_exact_inventory(&state, &[])?;
                create_installer_lock(&state)?
            };
            (state, lock)
        }
        OpenedState::Created(state) => {
            boundary(StageBoundary::StateCreated)
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            let lock = create_installer_lock(&state)?;
            (state, lock)
        }
    };
    Ok((state, lock))
}

fn preflight_record_envelope(
    input: &StagingInput<'_>,
    destination_path: &[u8],
    ancestry_count: usize,
    operation_id: &str,
) -> Result<(), InstallerStageError> {
    let component_count =
        destination_path_component_count(input.target, &encode_hex(destination_path))
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
    if ancestry_count != component_count.saturating_add(1) {
        return Err(InstallerStageError::UnsafeDestination);
    }
    let maximum_identity = NativeFileIdentity::maximum_windows();
    let maximum_ancestry = vec![maximum_identity; ancestry_count];
    let record = InstallerOperationRecord::prepared(
        operation_id.to_owned(),
        input,
        PreparedFilesystemEvidence {
            destination_path,
            ancestry_identities: &maximum_ancestry,
            state_identity: maximum_identity,
            lock_identity: maximum_identity,
            operation_identity: maximum_identity,
            staged_identity: maximum_identity,
        },
    );
    if record
        .to_json()
        .map_err(|_| InstallerStageError::UnsafeDestination)?
        .len()
        > MAX_OPERATION_RECORD_BYTES
    {
        Err(InstallerStageError::UnsafeDestination)
    } else {
        Ok(())
    }
}

struct PreparedOperationContext<'a> {
    destination: &'a kitrove_windows_security::ValidatedInstallDirectory,
    destination_path: &'a [u8],
    ancestry_identities: &'a [NativeFileIdentity],
    state: &'a std::fs::File,
    state_identity: NativeFileIdentity,
    lock: &'a InstallerLock,
    operation: &'a std::fs::File,
    operation_identity: NativeFileIdentity,
    operation_id: &'a str,
}

fn prepare_operation(
    context: PreparedOperationContext<'_>,
    input: &StagingInput<'_>,
    boundary: &mut impl FnMut(StageBoundary) -> Result<(), InstallerStageError>,
) -> Result<(InstallerOperationRecord, std::fs::File, std::fs::File), InstallerStageError> {
    let PreparedOperationContext {
        destination,
        destination_path,
        ancestry_identities,
        state,
        state_identity,
        lock,
        operation,
        operation_identity,
        operation_id,
    } = context;
    let executable = create_written_private_file(
        operation,
        OsStr::new(STAGED_EXECUTABLE),
        input.executable_bytes,
    )?;
    let staged_identity = file_identity(&executable)?;
    require_file_contents(
        &executable,
        input.executable_bytes.len() as u64,
        input.executable_sha256,
    )?;
    boundary(StageBoundary::ExecutableWritten)?;

    let record = InstallerOperationRecord::prepared(
        operation_id.to_owned(),
        input,
        PreparedFilesystemEvidence {
            destination_path,
            ancestry_identities,
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
    let record_file =
        create_written_private_file(operation, OsStr::new(OPERATION_RECORD), &record_bytes)?;
    let record_identity = file_identity(&record_file)?;
    boundary(StageBoundary::RecordWritten)?;

    revalidate_control_boundary(destination, state, state_identity, lock)?;
    require_identity(operation, operation_identity)?;
    require_identity(&executable, staged_identity)?;
    require_identity(&record_file, record_identity)?;
    require_named_directory_identity(state, OsStr::new(operation_id), operation_identity)?;
    require_named_file_identity(
        operation,
        OsStr::new(STAGED_EXECUTABLE),
        staged_identity,
        false,
    )?;
    require_named_file_identity(
        operation,
        OsStr::new(OPERATION_RECORD),
        record_identity,
        false,
    )?;
    require_exact_inventory(
        state,
        &[OsStr::new(INSTALLER_LOCK), OsStr::new(operation_id)],
    )?;
    require_exact_inventory(
        operation,
        &[OsStr::new(STAGED_EXECUTABLE), OsStr::new(OPERATION_RECORD)],
    )?;
    require_file_contents(
        &executable,
        input.executable_bytes.len() as u64,
        input.executable_sha256,
    )?;
    require_file_contents(
        &record_file,
        record_bytes.len() as u64,
        Sha256::digest(&record_bytes).into(),
    )?;
    require_empty_lock(&lock.file)?;
    let unverified = InstallerOperationRecord::parse_untrusted(&record_bytes)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    unverified
        .authenticate_prepared(
            input,
            PreparedFilesystemEvidence {
                destination_path,
                ancestry_identities,
                state_identity,
                lock_identity: lock.identity,
                operation_identity,
                staged_identity,
            },
        )
        .map_err(|_| InstallerStageError::UnsafeState)?;
    Ok((record, executable, record_file))
}

pub(crate) fn encode_destination_path(path: &Path) -> Result<Vec<u8>, InstallerStageError> {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let byte_len = units
        .len()
        .checked_mul(2)
        .ok_or(InstallerStageError::UnsafeDestination)?;
    if byte_len == 0 || byte_len > MAX_DESTINATION_PATH_BYTES {
        return Err(InstallerStageError::UnsafeDestination);
    }
    Ok(units
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>())
}

fn open_or_create_private_directory(
    parent: &std::fs::File,
    name: &OsStr,
) -> Result<OpenedState, InstallerStageError> {
    match kitrove_windows_security::open_private_directory(parent, name) {
        Ok(directory) => Ok(OpenedState::Existing(directory)),
        Err(_) => kitrove_windows_security::create_private_directory(parent, name)
            .map(OpenedState::Created)
            .map_err(|error| match error {
                kitrove_windows_security::ObjectCreationError::AlreadyExists => {
                    InstallerStageError::UnsafeState
                }
                _ => InstallerStageError::RecoveryRequired,
            }),
    }
}

pub(crate) fn acquire_existing_installer_lock(
    state: &std::fs::File,
) -> Result<InstallerLock, InstallerStageError> {
    let file = kitrove_windows_security::open_private_lock_file(state, OsStr::new(INSTALLER_LOCK))
        .map_err(|_| InstallerStageError::UnsafeState)?;
    lock_installer_file(state, file)
}

fn create_installer_lock(state: &std::fs::File) -> Result<InstallerLock, InstallerStageError> {
    let created = kitrove_windows_security::create_private_file(state, OsStr::new(INSTALLER_LOCK))
        .map_err(|error| match error {
            kitrove_windows_security::ObjectCreationError::AlreadyExists => {
                InstallerStageError::UnsafeState
            }
            _ => InstallerStageError::RecoveryRequired,
        })?;
    let expected = kitrove_windows_security::file_identity(&created)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    created
        .sync_all()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    drop(created);
    let reopened =
        kitrove_windows_security::open_private_lock_file(state, OsStr::new(INSTALLER_LOCK))
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
    if native_identity(
        kitrove_windows_security::file_identity(&reopened)
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    ) != native_identity(expected)
    {
        return Err(InstallerStageError::RecoveryRequired);
    }
    lock_installer_file(state, reopened)
}

fn lock_installer_file(
    state: &std::fs::File,
    file: std::fs::File,
) -> Result<InstallerLock, InstallerStageError> {
    require_empty_lock(&file)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(crate::staging_policy::lock_error)?;
    let identity = file_identity(&file)?;
    require_named_file_identity(state, OsStr::new(INSTALLER_LOCK), identity, true)?;
    require_empty_lock(&file)?;
    Ok(InstallerLock { file, identity })
}

pub(crate) fn require_empty_lock(file: &std::fs::File) -> Result<(), InstallerStageError> {
    if file
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?
        .len()
        == 0
    {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

pub(crate) fn sync_directory(
    parent: &std::fs::File,
    name: &OsStr,
    retained: &std::fs::File,
) -> Result<(), InstallerStageError> {
    let identity = kitrove_windows_security::file_identity(retained)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    kitrove_windows_security::flush_private_directory(parent, name, identity)
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

fn sync_existing_history(
    destination: &kitrove_windows_security::ValidatedInstallDirectory,
) -> Result<(), InstallerStageError> {
    let parent = destination.directory().map_err(unsafe_destination)?;
    let directory = Dir::from_std_file(
        parent
            .try_clone()
            .map_err(|_| InstallerStageError::UnsafeState)?,
    );
    let name = OsStr::new(crate::INSTALLER_HISTORY_DIRECTORY);
    match directory.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(InstallerStageError::UnsafeState),
        Ok(_) => {}
    }
    let history = kitrove_windows_security::open_private_directory(parent, name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    sync_directory(parent, name, &history)?;
    destination
        .flush()
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

pub(crate) fn revalidate_control_boundary(
    destination: &kitrove_windows_security::ValidatedInstallDirectory,
    state: &std::fs::File,
    state_identity: NativeFileIdentity,
    lock: &InstallerLock,
) -> Result<(), InstallerStageError> {
    destination
        .revalidate()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    require_identity(state, state_identity)?;
    require_named_directory_identity(
        destination.directory().map_err(unsafe_destination)?,
        OsStr::new(INSTALLER_STATE_DIRECTORY),
        state_identity,
    )?;
    require_named_file_identity(state, OsStr::new(INSTALLER_LOCK), lock.identity(), true)?;
    require_empty_lock(lock.file())
}

pub(crate) fn create_written_private_file(
    parent: &std::fs::File,
    name: &OsStr,
    bytes: &[u8],
) -> Result<std::fs::File, InstallerStageError> {
    let mut created = kitrove_windows_security::create_private_file(parent, name)
        .map_err(|_| InstallerStageError::WriteFailed)?;
    created
        .write_all(bytes)
        .and_then(|()| created.sync_all())
        .map_err(|_| InstallerStageError::WriteFailed)?;
    let expected = file_identity(&created)?;
    drop(created);
    reopen_private_file_with_identity(parent, name, expected)
}

pub(crate) fn reopen_private_file_with_identity(
    parent: &std::fs::File,
    name: &OsStr,
    expected: NativeFileIdentity,
) -> Result<std::fs::File, InstallerStageError> {
    let reopened = kitrove_windows_security::open_private_file(parent, name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_identity(&reopened, expected)?;
    Ok(reopened)
}

/// Consumes the read-only lease before acquiring write access, then rebinds identity
/// and content before any write or flush. Failure never manufactures a replacement lease.
fn with_private_file_write(
    parent: &std::fs::File,
    name: &OsStr,
    retained: std::fs::File,
    size: u64,
    digest: [u8; 32],
    action: impl FnOnce(&mut std::fs::File) -> Result<(), InstallerStageError>,
) -> Result<std::fs::File, InstallerStageError> {
    let identity = kitrove_windows_security::file_identity(&retained)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_named_file_identity(parent, name, native_identity(identity), false)?;
    require_file_contents(&retained, size, digest)?;
    drop(retained);
    let mut writable =
        kitrove_windows_security::open_private_file_for_update(parent, name, identity)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_file_contents(&writable, size, digest)?;
    action(&mut writable)?;
    writable
        .sync_all()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    kitrove_windows_security::inspect_private_single_link_file(&writable)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    require_identity(&writable, native_identity(identity))?;
    drop(writable);
    reopen_private_file_with_identity(parent, name, native_identity(identity))
        .map_err(|_| InstallerStageError::RecoveryRequired)
}

pub(crate) fn flush_retained_private_file(
    parent: &std::fs::File,
    name: &OsStr,
    retained: std::fs::File,
    size: u64,
    digest: [u8; 32],
) -> Result<std::fs::File, InstallerStageError> {
    let file = with_private_file_write(parent, name, retained, size, digest, |_| Ok(()))?;
    require_file_contents(&file, size, digest)?;
    Ok(file)
}

pub(crate) fn complete_private_file_prefix(
    parent: &std::fs::File,
    name: &OsStr,
    retained: std::fs::File,
    prefix: &[u8],
    canonical: &[u8],
) -> Result<std::fs::File, InstallerStageError> {
    if !canonical.starts_with(prefix) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let file = with_private_file_write(
        parent,
        name,
        retained,
        prefix.len() as u64,
        Sha256::digest(prefix).into(),
        |file| {
            file.seek(SeekFrom::Start(prefix.len() as u64))
                .and_then(|_| file.write_all(&canonical[prefix.len()..]))
                .map_err(|_| InstallerStageError::RecoveryRequired)
        },
    )?;
    require_file_contents(
        &file,
        canonical.len() as u64,
        Sha256::digest(canonical).into(),
    )?;
    Ok(file)
}

pub(crate) fn require_file_contents(
    file: &std::fs::File,
    expected_len: u64,
    expected_sha256: [u8; 32],
) -> Result<(), InstallerStageError> {
    if file
        .metadata()
        .map_err(|_| InstallerStageError::UnsafeState)?
        .len()
        != expected_len
    {
        return Err(InstallerStageError::UnsafeState);
    }
    let mut reader = file
        .try_clone()
        .map_err(|_| InstallerStageError::UnsafeState)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallerStageError::UnsafeState)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_len).map_err(|_| InstallerStageError::UnsafeState)?,
    );
    reader
        .take(expected_len.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    if bytes.len() as u64 != expected_len || Sha256::digest(&bytes)[..] != expected_sha256 {
        return Err(InstallerStageError::UnsafeState);
    }
    Ok(())
}

pub(crate) fn require_named_directory_identity(
    parent: &std::fs::File,
    name: &OsStr,
    expected: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    let reopened = kitrove_windows_security::open_private_directory(parent, name)
        .map_err(|_| InstallerStageError::UnsafeState)?;
    require_identity(&reopened, expected)
}

pub(crate) fn require_named_file_identity(
    parent: &std::fs::File,
    name: &OsStr,
    expected: NativeFileIdentity,
    lock: bool,
) -> Result<(), InstallerStageError> {
    let reopened = if lock {
        kitrove_windows_security::open_private_lock_file(parent, name)
    } else {
        kitrove_windows_security::open_private_file(parent, name)
    }
    .map_err(|_| InstallerStageError::UnsafeState)?;
    require_identity(&reopened, expected)
}

pub(crate) fn require_identity(
    file: &std::fs::File,
    expected: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    if file_identity(file)? == expected {
        Ok(())
    } else {
        Err(InstallerStageError::UnsafeState)
    }
}

pub(crate) fn file_identity(
    file: &std::fs::File,
) -> Result<NativeFileIdentity, InstallerStageError> {
    kitrove_windows_security::file_identity(file)
        .map(native_identity)
        .map_err(|_| InstallerStageError::UnsafeState)
}

pub(crate) const fn native_identity(
    identity: kitrove_windows_security::WindowsFileIdentity,
) -> NativeFileIdentity {
    NativeFileIdentity::new_windows(identity.volume_serial_number, identity.file_id)
}

pub(crate) fn require_exact_inventory(
    directory: &std::fs::File,
    expected: &[&OsStr],
) -> Result<(), InstallerStageError> {
    let directory = Dir::from_std_file(
        directory
            .try_clone()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
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
        observed.push(
            entry
                .map_err(|_| InstallerStageError::RecoveryRequired)?
                .file_name(),
        );
    }
    Err(InstallerStageError::RecoveryRequired)
}

fn map_operation_creation(
    error: kitrove_windows_security::ObjectCreationError,
) -> InstallerStageError {
    match error {
        kitrove_windows_security::ObjectCreationError::AlreadyExists => {
            InstallerStageError::Conflict
        }
        _ => InstallerStageError::RecoveryRequired,
    }
}

const fn unsafe_destination(
    _: kitrove_windows_security::WindowsSecurityError,
) -> InstallerStageError {
    InstallerStageError::UnsafeDestination
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::windows_test_support::{authenticated_executable, destination, inventory};

    #[test]
    fn unsafe_existing_state_is_rejected_without_creating_a_lock() {
        let destination = destination();
        let retained =
            kitrove_windows_security::validate_install_directory(destination.path()).unwrap();
        let state = kitrove_windows_security::create_private_directory(
            retained.directory().unwrap(),
            OsStr::new(INSTALLER_STATE_DIRECTORY),
        )
        .unwrap();
        kitrove_windows_security::create_private_file(&state, OsStr::new("foreign")).unwrap();
        drop(state);

        assert!(matches!(
            open_state_and_lock(retained.directory().unwrap()),
            Err(InstallerStageError::RecoveryRequired)
        ));
        assert_eq!(
            inventory(&destination.path().join(INSTALLER_STATE_DIRECTORY)),
            vec![OsString::from("foreign")]
        );
    }

    #[test]
    fn private_file_handoff_rejects_same_bytes_with_another_identity() {
        let destination = destination();
        let retained =
            kitrove_windows_security::validate_install_directory(destination.path()).unwrap();
        let directory = retained.directory().unwrap();
        let name = OsStr::new("handoff");
        let original = create_written_private_file(directory, name, b"expected").unwrap();
        let expected = file_identity(&original).unwrap();
        require_file_contents(&original, 8, Sha256::digest(b"expected").into()).unwrap();
        drop(original);

        std::fs::rename(
            destination.path().join(name),
            destination.path().join("retained-original"),
        )
        .unwrap();
        let replacement = create_written_private_file(directory, name, b"expected").unwrap();
        assert_ne!(file_identity(&replacement).unwrap(), expected);

        assert!(matches!(
            reopen_private_file_with_identity(directory, name, expected),
            Err(InstallerStageError::UnsafeState)
        ));
        assert_eq!(
            std::fs::read(destination.path().join(name)).unwrap(),
            b"expected"
        );
        assert_eq!(
            std::fs::read(destination.path().join("retained-original")).unwrap(),
            b"expected"
        );
    }

    #[test]
    fn retained_lock_blocks_a_second_staging_authority() {
        let destination = destination();
        let retained =
            kitrove_windows_security::validate_install_directory(destination.path()).unwrap();
        let (_state, _lock) = open_state_and_lock(retained.directory().unwrap()).unwrap();

        assert!(matches!(
            open_state_and_lock(retained.directory().unwrap()),
            Err(InstallerStageError::Conflict)
        ));
    }

    #[test]
    fn stages_authenticated_windows_bytes_and_exact_record() {
        let destination = destination();
        let executable = authenticated_executable();
        let staged = stage_after_security_preflight(
            destination.path(),
            &StagingInput::from(&executable),
            |_| Ok(()),
        )
        .unwrap();
        let operation_id = staged.record().operation_id().to_owned();
        assert_eq!(
            staged.record().phase(),
            crate::InstallerOperationPhase::Prepared
        );
        assert_eq!(
            inventory(
                &destination
                    .path()
                    .join(INSTALLER_STATE_DIRECTORY)
                    .join(operation_id)
            ),
            vec![
                OsString::from(STAGED_EXECUTABLE),
                OsString::from(OPERATION_RECORD)
            ]
        );
    }

    #[test]
    fn interrupted_operations_are_preserved_at_every_durable_boundary() {
        for interrupted in [
            StageBoundary::StateCreated,
            StageBoundary::OperationCreated,
            StageBoundary::ExecutableWritten,
            StageBoundary::RecordWritten,
        ] {
            let destination = destination();
            let executable = authenticated_executable();
            let result = stage_after_security_preflight(
                destination.path(),
                &StagingInput::from(&executable),
                |boundary| {
                    if boundary == interrupted {
                        Err(InstallerStageError::WriteFailed)
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));

            let state = destination.path().join(INSTALLER_STATE_DIRECTORY);
            let state_entries = inventory(&state);
            if interrupted == StageBoundary::StateCreated {
                assert!(state_entries.is_empty());
                let retained =
                    kitrove_windows_security::validate_install_directory(destination.path())
                        .unwrap();
                let (_state, _lock) = open_state_and_lock(retained.directory().unwrap()).unwrap();
                assert_eq!(inventory(&state), vec![OsString::from(INSTALLER_LOCK)]);
                continue;
            }
            assert_eq!(state_entries.len(), 2);
            assert!(state_entries.contains(&OsString::from(INSTALLER_LOCK)));
            let operation_id = state_entries
                .iter()
                .find(|name| name.as_os_str() != OsStr::new(INSTALLER_LOCK))
                .unwrap();
            let operation_entries = inventory(&state.join(operation_id));
            let expected = match interrupted {
                StageBoundary::StateCreated => unreachable!(),
                StageBoundary::OperationCreated => Vec::new(),
                StageBoundary::ExecutableWritten => vec![OsString::from(STAGED_EXECUTABLE)],
                StageBoundary::RecordWritten => vec![
                    OsString::from(STAGED_EXECUTABLE),
                    OsString::from(OPERATION_RECORD),
                ],
            };
            assert_eq!(operation_entries, expected);
        }
    }

    #[test]
    fn final_validation_rejects_a_new_hardlink_without_cleanup() {
        let destination = destination();
        let executable = authenticated_executable();
        let mut linked = false;
        let result = stage_after_security_preflight(
            destination.path(),
            &StagingInput::from(&executable),
            |boundary| {
                if boundary == StageBoundary::RecordWritten {
                    let state = destination.path().join(INSTALLER_STATE_DIRECTORY);
                    let operation = std::fs::read_dir(&state)
                        .unwrap()
                        .map(|entry| entry.unwrap())
                        .find(|entry| entry.file_name() != OsStr::new(INSTALLER_LOCK))
                        .unwrap()
                        .path();
                    std::fs::hard_link(
                        operation.join(STAGED_EXECUTABLE),
                        operation.join("foreign-link"),
                    )
                    .unwrap();
                    linked = true;
                }
                Ok(())
            },
        );
        assert!(linked);
        assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
        let state = destination.path().join(INSTALLER_STATE_DIRECTORY);
        let operation = std::fs::read_dir(state)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.file_name() != OsStr::new(INSTALLER_LOCK))
            .unwrap()
            .path();
        assert!(operation.join(STAGED_EXECUTABLE).exists());
        assert!(operation.join("foreign-link").exists());
    }

    #[test]
    fn real_elevation_boundary_refuses_before_creating_state() {
        let destination = destination();
        let executable = authenticated_executable();
        let elevated = kitrove_windows_security::current_process_is_elevated().unwrap();
        let result = stage(destination.path(), &StagingInput::from(&executable));
        if elevated {
            assert!(matches!(
                result,
                Err(InstallerStageError::UnsafeDestination)
            ));
            assert!(!destination.path().join(INSTALLER_STATE_DIRECTORY).exists());
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn record_preflight_rejects_unrepresentable_destination_before_state_creation() {
        let executable = authenticated_executable();
        let input = StagingInput::from(&executable);
        let operation_id = "00".repeat(16);
        let at_limit = format!("C:\\{}", vec!["a"; 127].join("\\"));
        let over_limit = format!("{at_limit}\\a");
        let encode = |path: &str| {
            path.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        assert!(preflight_record_envelope(&input, &encode(&at_limit), 128, &operation_id).is_ok());
        assert!(matches!(
            preflight_record_envelope(&input, &encode(&over_limit), 129, &operation_id),
            Err(InstallerStageError::UnsafeDestination)
        ));

        let maximum_path = format!("C:\\{}", vec!["aaaaaaa"; 127].join("\\"));
        let maximum_path = encode(&maximum_path);
        assert!(maximum_path.len() <= MAX_DESTINATION_PATH_BYTES);
        assert!(
            preflight_record_envelope(&input, &maximum_path, 128, &operation_id).is_ok(),
            "the record limit must represent maximum-width Windows identities and paths"
        );
    }

    #[test]
    fn over_limit_destination_is_rejected_before_installer_state_creation() {
        let destination = destination();
        let mut path = destination.path().to_path_buf();
        let mut parent = kitrove_windows_security::validate_install_directory(destination.path())
            .unwrap()
            .directory()
            .unwrap()
            .try_clone()
            .unwrap();
        for _ in 0..128 {
            parent =
                kitrove_windows_security::create_owned_directory(&parent, OsStr::new("a")).unwrap();
            path.push("a");
        }
        let executable = authenticated_executable();
        assert!(matches!(
            stage_after_security_preflight(&path, &StagingInput::from(&executable), |_| Ok(())),
            Err(InstallerStageError::UnsafeDestination)
        ));
        assert!(
            kitrove_windows_security::open_private_directory(
                &parent,
                OsStr::new(INSTALLER_STATE_DIRECTORY)
            )
            .is_err()
        );
    }
}
