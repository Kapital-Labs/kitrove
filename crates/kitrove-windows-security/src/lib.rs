#![cfg(windows)]
//! Safe, narrow wrappers for Kitrove's handle-bound Windows security requirements.

use std::ffi::c_void;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle, FromRawHandle as _};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation, NtCreateFile,
    NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GENERIC_ALL,
    GENERIC_WRITE, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
#[cfg(test)]
use windows_sys::Win32::Security::GetLengthSid;
#[cfg(feature = "test-support")]
use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;
#[cfg(feature = "test-support")]
use windows_sys::Win32::Security::WinWorldSid;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation, INHERIT_ONLY_ACE,
    InitializeSecurityDescriptor, IsValidAcl, IsValidSid, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
    SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SID, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_DELETE_CHILD, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, FileAttributeTagInfo, FileDispositionInfo,
    FileDispositionInfoEx, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle, VOLUME_NAME_DOS, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Access requested from a capability-relative handle used only for inspection.
pub const PRIVATE_INSPECT_ACCESS: u32 = READ_CONTROL | PRIVATE_OBJECT_CLASSIFY_ACCESS;
/// Access for retaining a directory against rename without reading its security descriptor.
pub const STRUCTURAL_DIRECTORY_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
/// Access for retaining, traversing, and inspecting a private authority directory.
pub const PRIVATE_DIRECTORY_AUTHORITY_ACCESS: u32 =
    PRIVATE_INSPECT_ACCESS | FILE_TRAVERSE | SYNCHRONIZE;
/// Access requested from a capability-relative handle used for authorized DACL repair.
pub const PRIVATE_MUTATE_ACCESS: u32 = READ_CONTROL | WRITE_DAC | PRIVATE_OBJECT_CLASSIFY_ACCESS;
/// Access for reading and inspecting an existing private regular file.
pub const PRIVATE_FILE_INSPECT_ACCESS: u32 = FILE_GENERIC_READ;
/// Access for reading and writing an existing private regular file without descriptor mutation.
pub const PRIVATE_FILE_WRITE_ACCESS: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
/// Share mode for held lock files: peers may read or write, but cannot rename or delete the lock.
pub const PRIVATE_FILE_LOCK_SHARE_MODE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
/// Flags that open the directory itself and never traverse a final reparse point.
pub const PRIVATE_DIRECTORY_OPEN_FLAGS: u32 =
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

const PRIVATE_DIRECTORY_ACE_FLAGS: u8 = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) as u8;
const PRIVATE_FILE_ACE_FLAGS: u8 = 0;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const PRIVATE_OBJECT_CLASSIFY_ACCESS: u32 = FILE_READ_ATTRIBUTES;
const PRIVATE_DELETE_ACCESS: u32 =
    DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
const PRIVATE_PROMOTE_ACCESS: u32 = DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const PRIVATE_DIRECTORY_CHILD_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE;
const MAX_LAUNCH_PATH_COMPONENTS: usize = 256;
const MAX_LAUNCH_PATH_UNITS: usize = 32_767;
const MAX_LAUNCH_COMPONENT_UNITS: usize = 255;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
enum PrivateObjectKind {
    Directory,
    File,
}

#[derive(Clone, Copy)]
enum DaclPolicy {
    Inherited,
    ExactPrivate { ace_flags: u8 },
}

struct ExactPrivateDescriptor {
    system: WellKnownSid,
    acl: LocalAllocation,
    ace_flags: u8,
}

struct ObjectCreationHooks<AfterCreate, Rollback, CreatedIdentity, AfterClose> {
    after_create: AfterCreate,
    rollback: Rollback,
    created_identity: CreatedIdentity,
    after_directory_create_close: AfterClose,
}

struct OwnedObjectPromotionHooks<AfterVerification, AfterPromotion> {
    after_verification: AfterVerification,
    after_promotion: AfterPromotion,
}

/// Complete native identity returned by `FileIdInfo`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WindowsFileIdentity {
    /// Volume identity supplied by the filesystem.
    pub volume_serial_number: u64,
    /// Complete 128-bit filesystem file identifier.
    pub file_id: [u8; 16],
}

/// Opaque failure from the native Windows security boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsSecurityError;

/// Refuses an elevated process before current-user installer authority is acquired.
pub fn require_unelevated_process() -> Result<(), WindowsSecurityError> {
    classify_unelevated(current_process_is_elevated()?)
}

/// Reports whether the current process token is elevated.
pub fn current_process_is_elevated() -> Result<bool, WindowsSecurityError> {
    let token = current_process_token()?;
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut bytes = 0_u32;
    // SAFETY: the fixed-size output buffer and its declared byte length are valid.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut bytes,
        )
    } == 0
        || bytes != size_of::<TOKEN_ELEVATION>() as u32
    {
        return Err(WindowsSecurityError);
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn classify_unelevated(token_is_elevated: bool) -> Result<(), WindowsSecurityError> {
    if token_is_elevated {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

fn current_process_token() -> Result<OwnedHandle, WindowsSecurityError> {
    let mut token = ptr::null_mut();
    // SAFETY: the output pointer is valid, and the pseudo process handle is valid for the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        Err(WindowsSecurityError)
    } else {
        Ok(OwnedHandle(token))
    }
}

/// Semantic result of a bounded, handle-bound integrity-file read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrityFileRead {
    /// The complete file contents were read through retained authority.
    Bytes(Vec<u8>),
    /// The file or one of its containing directories does not exist.
    Missing,
    /// The regular file exceeds the caller's byte bound.
    Limit,
    /// The path, ownership, DACL, sharing, identity, or read could not be proven safe.
    Unsafe,
}

/// Returns the exact canonical DOS spelling of a test-owned directory.
#[cfg(feature = "test-support")]
pub fn canonical_directory_path_for_tests(path: &Path) -> Result<PathBuf, WindowsSecurityError> {
    let directory = open_launch_root_semantic(
        path,
        PathAccessProfile::Structural,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
    .map_err(|_| WindowsSecurityError)?;
    final_dos_path(raw_handle(&directory))
}

/// Returns the operating system's exact DOS spelling for an existing non-reparse directory.
///
/// Every path component is opened relative to its retained parent. No ownership or DACL policy is
/// imposed because a project directory is an identity input, not saved trust authority.
pub fn canonical_nofollow_directory_path(path: &Path) -> Result<PathBuf, WindowsSecurityError> {
    let (_, handles, _) = retain_path_semantic(
        path,
        PrivateObjectKind::Directory,
        PathAccessProfile::Structural,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        |_, _| Ok(()),
    )
    .map_err(|_| WindowsSecurityError)?;
    final_dos_path(raw_handle(handles.last().ok_or(WindowsSecurityError)?))
}

/// Pre-encoded Windows path used for bounded ordinal comparisons.
pub struct WindowsOrdinalPath {
    units: Vec<u16>,
}

impl WindowsOrdinalPath {
    /// Encodes one path once, treating both accepted separator spellings as equivalent.
    pub fn new(value: &std::ffi::OsStr) -> Result<Self, WindowsSecurityError> {
        let units = value
            .encode_wide()
            .map(|unit| {
                if unit == b'/' as u16 {
                    b'\\' as u16
                } else {
                    unit
                }
            })
            .collect::<Vec<_>>();
        if !is_well_formed_utf16(&units) {
            return Err(WindowsSecurityError);
        }
        Ok(Self { units })
    }

    /// Compares two already-encoded paths with Windows ordinal case-insensitive semantics.
    pub fn eq_ignore_case(&self, other: &Self) -> Result<bool, WindowsSecurityError> {
        wide_eq_ignore_case(&self.units, &other.units)
    }
}

/// Reads a current-user-owned integrity file without following reparses or permitting concurrent
/// mutation through any retained path component.
#[must_use]
pub fn read_bounded_integrity_file(path: &Path, max_bytes: usize) -> IntegrityFileRead {
    match read_bounded_integrity_file_inner(path, max_bytes) {
        Ok(result) => result,
        Err(PathOpenError::Missing) => IntegrityFileRead::Missing,
        Err(PathOpenError::Unsafe) => IntegrityFileRead::Unsafe,
    }
}

/// Grants the Windows World SID file mutation authority for an adversarial integration fixture.
#[cfg(feature = "test-support")]
pub fn grant_world_file_mutation_for_tests(path: &Path) -> Result<(), WindowsSecurityError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | WRITE_DAC)
        .open(path)
        .map_err(|_| WindowsSecurityError)?;
    let current = TokenUserBuffer::current()?;
    let world = WellKnownSid::new(WinWorldSid)?;
    install_dacl(
        raw_handle(&file),
        &[current.sid, world.sid],
        PRIVATE_FILE_ACE_FLAGS,
        PROTECTED_DACL_SECURITY_INFORMATION,
    )
}

/// Creates and writes an exact current-user-owned private file for a native integration fixture.
#[cfg(any(test, feature = "test-support"))]
pub fn write_current_user_owned_file_for_tests(
    path: &Path,
    bytes: &[u8],
) -> Result<(), WindowsSecurityError> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::windows::fs::OpenOptionsExt as _;

    let mut file = if path.exists() {
        let file = std::fs::OpenOptions::new()
            .access_mode(PRIVATE_FILE_WRITE_ACCESS)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| WindowsSecurityError)?;
        inspect_private_single_link_file(&file)?;
        file.set_len(0).map_err(|_| WindowsSecurityError)?;
        file
    } else {
        let parent_path = path.parent().ok_or(WindowsSecurityError)?;
        let name = path.file_name().ok_or(WindowsSecurityError)?;
        let parent = open_fixture_parent(parent_path)?;
        create_private_file(&parent, name).map_err(|_| WindowsSecurityError)?
    };
    file.seek(SeekFrom::Start(0))
        .map_err(|_| WindowsSecurityError)?;
    file.write_all(bytes).map_err(|_| WindowsSecurityError)?;
    file.sync_all().map_err(|_| WindowsSecurityError)
}

/// Creates or validates one exact current-user-owned private directory for a native fixture.
#[cfg(any(test, feature = "test-support"))]
pub fn ensure_private_directory_for_tests(path: &Path) -> Result<(), WindowsSecurityError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    if path.exists() {
        let directory = std::fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_READ)
            .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
            .open(path)
            .map_err(|_| WindowsSecurityError)?;
        return inspect_private_directory(&directory);
    }
    let parent_path = path.parent().ok_or(WindowsSecurityError)?;
    let name = path.file_name().ok_or(WindowsSecurityError)?;
    let parent = open_fixture_parent(parent_path)?;
    create_private_directory(&parent, name)
        .map(|_| ())
        .map_err(|_| WindowsSecurityError)
}

#[cfg(any(test, feature = "test-support"))]
fn open_fixture_parent(path: &Path) -> Result<std::fs::File, WindowsSecurityError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE)
        .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
        .open(path)
        .map_err(|_| WindowsSecurityError)
}

/// A Windows executable whose path authority is retained for the full launch lifecycle.
///
/// Values are issued only after handle-bound validation. They deliberately cannot be cloned so the
/// retained authority cannot be separated from its open handles.
pub struct ValidatedExecutable {
    path: PathBuf,
    _retained_handles: Vec<std::fs::File>,
    identity: WindowsFileIdentity,
    leaf_name: std::ffi::OsString,
}

impl ValidatedExecutable {
    /// Returns the exact path bound to the retained executable handle.
    #[must_use]
    pub fn launch_path(&self) -> &Path {
        &self.path
    }

    /// Runs a complete streaming read without exposing a clonable native handle.
    pub fn read_executable<T>(
        &self,
        operation: impl FnOnce(&mut dyn std::io::Read) -> T,
    ) -> Result<T, WindowsSecurityError> {
        use std::io::{Seek as _, SeekFrom};

        let file = self._retained_handles.last().ok_or(WindowsSecurityError)?;
        let expected = file.metadata().map_err(|_| WindowsSecurityError)?.len();
        if expected > MAX_EXECUTABLE_BYTES {
            return Err(WindowsSecurityError);
        }
        let mut reader = file.try_clone().map_err(|_| WindowsSecurityError)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| WindowsSecurityError)?;
        let result = operation(&mut reader);
        if reader.stream_position().map_err(|_| WindowsSecurityError)? != expected {
            return Err(WindowsSecurityError);
        }
        Ok(result)
    }

    /// Reopens the leaf relative to its retained parent and proves its complete identity unchanged.
    pub fn revalidate_path_identity(&self) -> Result<(), WindowsSecurityError> {
        let parent = self
            ._retained_handles
            .get(self._retained_handles.len().saturating_sub(2))
            .ok_or(WindowsSecurityError)?;
        let reopened = open_launch_child(parent, &self.leaf_name, PrivateObjectKind::File)?;
        let trusted = TrustedLaunchSids::current()?;
        require_path_authority(reopened.0, PathLevel::File, OwnerPolicy::Trusted, &trusted)?;
        require_expected_identity(reopened.0, self.identity)
    }
}

/// A trusted Windows working directory retained across contained execution.
pub struct ValidatedLaunchDirectory {
    path: PathBuf,
    _retained_handles: Vec<std::fs::File>,
}

impl ValidatedLaunchDirectory {
    /// Returns the exact retained working-directory path.
    #[must_use]
    pub fn launch_path(&self) -> &Path {
        &self.path
    }
}

/// A current-user-owned installation directory retained through every no-follow ancestor handle.
///
/// The final directory may be mutated by the current user, while untrusted principals cannot
/// rename or delete the retained path or alter its existing components. Unrelated sibling creation
/// may remain permitted. The wrapper deliberately does not implement `Clone` and exposes the final
/// retained handle only by reference.
pub struct ValidatedInstallDirectory {
    path: PathBuf,
    retained_handles: Vec<std::fs::File>,
    identities: Vec<WindowsFileIdentity>,
}

impl ValidatedInstallDirectory {
    /// Flushes the identity-bound installation directory without changing its access policy.
    pub fn flush(&self) -> Result<(), WindowsSecurityError> {
        self.revalidate()?;
        let parent_index = self
            .retained_handles
            .len()
            .checked_sub(2)
            .ok_or(WindowsSecurityError)?;
        let parent = &self.retained_handles[parent_index];
        let name = self.path.file_name().ok_or(WindowsSecurityError)?;
        let expected = *self.identities.last().ok_or(WindowsSecurityError)?;
        let trusted = TrustedLaunchSids::current()?;
        let level = path_level(
            self.retained_handles.len() - 1,
            self.retained_handles.len(),
            PrivateObjectKind::Directory,
        );
        flush_directory_with(parent, name, expected, |directory| {
            require_install_path_authority(raw_handle(directory), level, &trusted)
        })?;
        self.revalidate()
    }

    /// Returns the exact canonical DOS path bound to the retained directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns every retained identity from the drive root through the installation directory.
    #[must_use]
    pub fn identities(&self) -> &[WindowsFileIdentity] {
        &self.identities
    }

    /// Borrows the final directory handle for capability-relative child operations.
    pub fn directory(&self) -> Result<&std::fs::File, WindowsSecurityError> {
        self.retained_handles.last().ok_or(WindowsSecurityError)
    }

    /// Revalidates ownership, mutation policy, and complete identity on every retained handle.
    pub fn revalidate(&self) -> Result<(), WindowsSecurityError> {
        if self.retained_handles.len() != self.identities.len() || self.retained_handles.is_empty()
        {
            return Err(WindowsSecurityError);
        }
        let trusted = TrustedLaunchSids::current()?;
        for (index, (handle, identity)) in self
            .retained_handles
            .iter()
            .zip(&self.identities)
            .enumerate()
        {
            let level = path_level(
                index,
                self.retained_handles.len(),
                PrivateObjectKind::Directory,
            );
            require_install_path_authority(raw_handle(handle), level, &trusted)?;
            require_expected_identity(raw_handle(handle), *identity)?;
        }
        require_exact_opened_path(self.directory()?, &self.path)
    }
}

/// Validates and retains an explicit local Windows executable path without changing permissions.
pub fn validate_executable_path(path: &Path) -> Result<ValidatedExecutable, WindowsSecurityError> {
    let trusted = TrustedLaunchSids::current()?;
    let (path, handles, leaf_name) =
        retain_path(path, PrivateObjectKind::File, |handle, level| {
            require_path_authority(handle, level, OwnerPolicy::Trusted, &trusted)
        })?;
    let identity = file_identity(handles.last().ok_or(WindowsSecurityError)?)?;
    Ok(ValidatedExecutable {
        path,
        _retained_handles: handles,
        identity,
        leaf_name,
    })
}

/// Opens and retains the operating system's trusted System32 directory for use as probe cwd.
pub fn validated_system_launch_directory() -> Result<ValidatedLaunchDirectory, WindowsSecurityError>
{
    let path = system_directory_path()?;
    let trusted = TrustedLaunchSids::current()?;
    let (path, handles, _) = retain_path(&path, PrivateObjectKind::Directory, |handle, level| {
        require_path_authority(handle, level, OwnerPolicy::Trusted, &trusted)
    })?;
    Ok(ValidatedLaunchDirectory {
        path,
        _retained_handles: handles,
    })
}

/// Validates and retains a current-user installation directory without changing its descriptor.
pub fn validate_install_directory(
    path: &Path,
) -> Result<ValidatedInstallDirectory, WindowsSecurityError> {
    let trusted = TrustedLaunchSids::current()?;
    // Rename target resolution opens the destination directory for FILE_WRITE_DATA internally.
    // Permit that sharing while still denying DELETE on every retained path component.
    let (_, handles, _) = retain_path_semantic(
        path,
        PrivateObjectKind::Directory,
        PathAccessProfile::Authority,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        |handle, level| {
            require_install_path_authority(handle, level, &trusted)
                .map_err(|_| PathOpenError::Unsafe)
        },
    )
    .map_err(|_| WindowsSecurityError)?;
    let path = final_dos_path(raw_handle(handles.last().ok_or(WindowsSecurityError)?))?;
    let identities = handles
        .iter()
        .map(file_identity)
        .collect::<Result<Vec<_>, _>>()?;
    let validated = ValidatedInstallDirectory {
        path,
        retained_handles: handles,
        identities,
    };
    validated.revalidate()?;
    Ok(validated)
}

#[derive(Clone, Copy, Debug)]
enum PathLevel {
    Ancestor,
    ImmediateDirectory,
    InstallDirectory,
    File,
}

#[derive(Clone, Copy)]
enum OwnerPolicy {
    Trusted,
    CurrentUser,
}

#[derive(Clone, Copy)]
enum PathAccessProfile {
    Authority,
    Structural,
}

impl PathAccessProfile {
    const fn desired_access(self, kind: PrivateObjectKind) -> u32 {
        match (self, kind) {
            (Self::Authority, PrivateObjectKind::Directory) => PRIVATE_DIRECTORY_AUTHORITY_ACCESS,
            (Self::Authority, PrivateObjectKind::File) => FILE_GENERIC_READ,
            (Self::Structural, PrivateObjectKind::Directory) => STRUCTURAL_DIRECTORY_ACCESS,
            (Self::Structural, PrivateObjectKind::File) => FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PathOpenError {
    Missing,
    Unsafe,
}

fn retain_path(
    requested: &Path,
    final_kind: PrivateObjectKind,
    mut validate: impl FnMut(HANDLE, PathLevel) -> Result<(), WindowsSecurityError>,
) -> Result<(PathBuf, Vec<std::fs::File>, std::ffi::OsString), WindowsSecurityError> {
    retain_path_semantic(
        requested,
        final_kind,
        PathAccessProfile::Authority,
        FILE_SHARE_READ,
        |handle, level| validate(handle, level).map_err(|_| PathOpenError::Unsafe),
    )
    .map_err(|_| WindowsSecurityError)
}

fn retain_path_semantic(
    requested: &Path,
    final_kind: PrivateObjectKind,
    access_profile: PathAccessProfile,
    share_mode: u32,
    mut validate: impl FnMut(HANDLE, PathLevel) -> Result<(), PathOpenError>,
) -> Result<(PathBuf, Vec<std::fs::File>, std::ffi::OsString), PathOpenError> {
    let (root, names) = local_drive_path(requested).map_err(|_| PathOpenError::Unsafe)?;
    if names.is_empty() && matches!(final_kind, PrivateObjectKind::File) {
        return Err(PathOpenError::Unsafe);
    }

    let root_level = path_level(0, names.len() + 1, final_kind);
    let root_handle = open_launch_root_semantic(&root, access_profile, share_mode)
        .map_err(|error| path_open_failure("root open", root_level, error))?;
    validate(raw_handle(&root_handle), root_level)?;
    require_exact_opened_path(&root_handle, &root)
        .map_err(|_| path_open_failure("root path", root_level, PathOpenError::Unsafe))?;
    let mut retained = vec![root_handle];
    let mut selected = root;

    for (index, name) in names.iter().enumerate() {
        let is_final = index + 1 == names.len();
        let kind = if is_final {
            final_kind
        } else {
            PrivateObjectKind::Directory
        };
        let level = path_level(index + 1, names.len() + 1, final_kind);
        let parent = retained.last().ok_or(PathOpenError::Unsafe)?;
        let child = open_launch_child_semantic(parent, name, kind, access_profile, share_mode)
            .map_err(|error| path_open_failure("child open", level, error))?;
        validate(child.0, level)?;
        selected.push(name);
        let child = owned_handle_into_file(child);
        require_exact_opened_path(&child, &selected)
            .map_err(|_| path_open_failure("child path", level, PathOpenError::Unsafe))?;
        retained.push(child);
    }

    let leaf = names.last().cloned().unwrap_or_default();
    Ok((selected, retained, leaf))
}

fn path_open_failure(
    _stage: &'static str,
    _level: PathLevel,
    error: PathOpenError,
) -> PathOpenError {
    #[cfg(test)]
    eprintln!("Windows retained path rejected {_level:?} at {_stage}: {error:?}");
    error
}

fn path_level(index: usize, handle_count: usize, final_kind: PrivateObjectKind) -> PathLevel {
    let is_final = index + 1 == handle_count;
    match (is_final, final_kind) {
        (true, PrivateObjectKind::File) => PathLevel::File,
        (true, PrivateObjectKind::Directory) => PathLevel::ImmediateDirectory,
        (false, PrivateObjectKind::File) if index + 2 == handle_count => {
            PathLevel::ImmediateDirectory
        }
        (false, _) => PathLevel::Ancestor,
    }
}

fn read_bounded_integrity_file_inner(
    path: &Path,
    max_bytes: usize,
) -> Result<IntegrityFileRead, PathOpenError> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let trusted = TrustedLaunchSids::current().map_err(|_| PathOpenError::Unsafe)?;
    let (_, handles, _) = retain_path_semantic(
        path,
        PrivateObjectKind::File,
        PathAccessProfile::Authority,
        FILE_SHARE_READ,
        |handle, level| require_integrity_path_authority(handle, level, &trusted),
    )?;
    let file = handles.last().ok_or(PathOpenError::Unsafe)?;
    let identity = file_identity(file).map_err(|_| PathOpenError::Unsafe)?;
    let initial_len = file.metadata().map_err(|_| PathOpenError::Unsafe)?.len();
    let bound = u64::try_from(max_bytes).map_err(|_| PathOpenError::Unsafe)?;
    if initial_len > bound {
        return Ok(IntegrityFileRead::Limit);
    }

    let mut reader = file.try_clone().map_err(|_| PathOpenError::Unsafe)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| PathOpenError::Unsafe)?;
    let read_bound = bound.checked_add(1).ok_or(PathOpenError::Unsafe)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(initial_len as usize));
    reader
        .take(read_bound)
        .read_to_end(&mut bytes)
        .map_err(|_| PathOpenError::Unsafe)?;
    if bytes.len() > max_bytes {
        return Ok(IntegrityFileRead::Limit);
    }

    let final_len = file.metadata().map_err(|_| PathOpenError::Unsafe)?.len();
    if final_len != initial_len || bytes.len() as u64 != initial_len {
        return Err(PathOpenError::Unsafe);
    }
    if file_identity(file).map_err(|_| PathOpenError::Unsafe)? != identity {
        return Err(PathOpenError::Unsafe);
    }
    for (index, handle) in handles.iter().enumerate() {
        let level = path_level(index, handles.len(), PrivateObjectKind::File);
        require_integrity_path_authority(raw_handle(handle), level, &trusted)?;
    }
    Ok(IntegrityFileRead::Bytes(bytes))
}

fn require_integrity_path_authority(
    handle: HANDLE,
    level: PathLevel,
    trusted: &TrustedLaunchSids,
) -> Result<(), PathOpenError> {
    let owner = if matches!(level, PathLevel::File) {
        OwnerPolicy::CurrentUser
    } else {
        OwnerPolicy::Trusted
    };
    require_path_authority(handle, level, owner, trusted).map_err(|_| PathOpenError::Unsafe)
}

fn local_drive_path(
    path: &Path,
) -> Result<(PathBuf, Vec<std::ffi::OsString>), WindowsSecurityError> {
    let requested: Vec<u16> = path.as_os_str().encode_wide().collect();
    if requested.len() > MAX_LAUNCH_PATH_UNITS || !is_well_formed_utf16(&requested) {
        return Err(WindowsSecurityError);
    }
    let mut components = path.components();
    let Component::Prefix(prefix) = components.next().ok_or(WindowsSecurityError)? else {
        return Err(WindowsSecurityError);
    };
    let Prefix::Disk(drive) = prefix.kind() else {
        return Err(WindowsSecurityError);
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(WindowsSecurityError);
    }

    let mut names = Vec::new();
    for component in components {
        let Component::Normal(name) = component else {
            return Err(WindowsSecurityError);
        };
        if names.len() >= MAX_LAUNCH_PATH_COMPONENTS {
            return Err(WindowsSecurityError);
        }
        let encoded = validated_component_encoding(name)?;
        if encoded.len() > MAX_LAUNCH_COMPONENT_UNITS || !is_canonical_launch_component(&encoded) {
            return Err(WindowsSecurityError);
        }
        names.push(name.to_os_string());
    }

    let root = PathBuf::from(format!("{}:\\", char::from(drive.to_ascii_uppercase())));
    let mut canonical = root.clone();
    for name in &names {
        canonical.push(name);
    }
    let canonical: Vec<u16> = canonical.as_os_str().encode_wide().collect();
    if requested.len() != canonical.len() || !wide_eq_ignore_case(&requested, &canonical)? {
        return Err(WindowsSecurityError);
    }
    Ok((root, names))
}

fn is_canonical_launch_component(encoded: &[u16]) -> bool {
    let Ok(name) = String::from_utf16(encoded) else {
        return false;
    };
    kitrove_windows_names::is_lossless_windows_component(&name)
}

fn open_launch_root_semantic(
    path: &Path,
    access_profile: PathAccessProfile,
    share_mode: u32,
) -> Result<std::fs::File, PathOpenError> {
    let encoded = nul_terminated_path(path).map_err(|_| PathOpenError::Unsafe)?;
    // SAFETY: the path is terminated and all optional pointers are null for this read-only open.
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            access_profile.desired_access(PrivateObjectKind::Directory),
            share_mode,
            ptr::null(),
            OPEN_EXISTING,
            PRIVATE_DIRECTORY_OPEN_FLAGS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: this is called immediately after the failed Win32 operation.
        return Err(match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => PathOpenError::Missing,
            _ => PathOpenError::Unsafe,
        });
    }
    let handle = OwnedHandle(handle);
    require_private_object_kind(handle.0, PrivateObjectKind::Directory)
        .map_err(|_| PathOpenError::Unsafe)?;
    Ok(owned_handle_into_file(handle))
}

fn open_launch_child(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    kind: PrivateObjectKind,
) -> Result<OwnedHandle, WindowsSecurityError> {
    open_launch_child_semantic(
        parent,
        name,
        kind,
        PathAccessProfile::Authority,
        FILE_SHARE_READ,
    )
    .map_err(|_| WindowsSecurityError)
}

fn open_launch_child_semantic(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    kind: PrivateObjectKind,
    access_profile: PathAccessProfile,
    share_mode: u32,
) -> Result<OwnedHandle, PathOpenError> {
    open_capability_child_semantic(
        parent,
        name,
        kind,
        access_profile.desired_access(kind),
        share_mode,
    )
}

fn owned_handle_into_file(handle: OwnedHandle) -> std::fs::File {
    // SAFETY: ownership transfers exactly once from `OwnedHandle` to `File`.
    unsafe { std::fs::File::from_raw_handle(handle.into_raw().cast()) }
}

fn nul_terminated_path(path: &Path) -> Result<Vec<u16>, WindowsSecurityError> {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.is_empty()
        || encoded.len() >= MAX_LAUNCH_PATH_UNITS
        || encoded.contains(&0)
        || !is_well_formed_utf16(&encoded)
    {
        return Err(WindowsSecurityError);
    }
    encoded.push(0);
    Ok(encoded)
}

fn require_exact_opened_path(
    file: &impl AsRawHandle,
    expected: &Path,
) -> Result<(), WindowsSecurityError> {
    let observed = final_dos_path(raw_handle(file))?;
    let expected = comparable_path_components(expected)?;
    let observed = comparable_path_components(&observed)?;
    if expected.len() != observed.len() {
        return Err(WindowsSecurityError);
    }
    for ((expected_kind, expected), (observed_kind, observed)) in expected.iter().zip(&observed) {
        if expected_kind != observed_kind || !wide_eq_ignore_case(expected, observed)? {
            return Err(WindowsSecurityError);
        }
    }
    Ok(())
}

fn final_dos_path(handle: HANDLE) -> Result<PathBuf, WindowsSecurityError> {
    let mut buffer = vec![0_u16; 512];
    loop {
        // SAFETY: `buffer` is writable for its reported length and `handle` remains live.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| WindowsSecurityError)?,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if length == 0 {
            return Err(WindowsSecurityError);
        }
        let length = usize::try_from(length).map_err(|_| WindowsSecurityError)?;
        if length < buffer.len() {
            buffer.truncate(length);
            const VERBATIM_PREFIX: [u16; 4] =
                [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
            let path = buffer
                .strip_prefix(&VERBATIM_PREFIX)
                .ok_or(WindowsSecurityError)?;
            if !is_well_formed_utf16(path) {
                return Err(WindowsSecurityError);
            }
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(path)));
        }
        let required = length.checked_add(1).ok_or(WindowsSecurityError)?;
        if required > MAX_LAUNCH_PATH_UNITS {
            return Err(WindowsSecurityError);
        }
        buffer.resize(required, 0);
    }
}

fn system_directory_path() -> Result<PathBuf, WindowsSecurityError> {
    let mut buffer = vec![0_u16; 512];
    loop {
        // SAFETY: `buffer` is writable for its complete reported length.
        let length = unsafe {
            GetSystemDirectoryW(
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).map_err(|_| WindowsSecurityError)?,
            )
        };
        if length == 0 {
            return Err(WindowsSecurityError);
        }
        let length = usize::try_from(length).map_err(|_| WindowsSecurityError)?;
        if length < buffer.len() {
            buffer.truncate(length);
            if !is_well_formed_utf16(&buffer) {
                return Err(WindowsSecurityError);
            }
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)));
        }
        let required = length.checked_add(1).ok_or(WindowsSecurityError)?;
        if required > MAX_LAUNCH_PATH_UNITS {
            return Err(WindowsSecurityError);
        }
        buffer.resize(required, 0);
    }
}

/// Failure while atomically creating a current-user-owned child object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectCreationError {
    /// A child already occupies the requested name.
    AlreadyExists,
    /// The name, descriptor construction, native creation, or verification failed.
    Failed,
    /// Verification failed and the identity-bound rollback could not be scheduled.
    RollbackFailed,
    /// The verified directory could not be handed off to a confined capability handle.
    HandoffFailed,
}

/// Failure while promoting an owned object through its verified handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedObjectPromotionError {
    /// Validation or promotion failed without leaving the source at the destination.
    ///
    /// A destination that already existed before the call may remain unchanged.
    Failed,
    /// Final verification failed and handle-bound retained-only rollback also failed.
    RollbackFailed,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

struct PendingCreation(Option<OwnedHandle>);

impl PendingCreation {
    fn commit(mut self) -> std::fs::File {
        let handle = self.0.take().expect("pending creation owns its handle");
        // SAFETY: ownership transfers exactly once from `OwnedHandle` to `File`.
        unsafe { std::fs::File::from_raw_handle(handle.into_raw().cast()) }
    }

    fn rollback(mut self) -> Result<(), WindowsSecurityError> {
        let handle = self.0.take().ok_or(WindowsSecurityError)?;
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the new, still-empty object handle has DELETE access and the input is valid.
        let marked = unsafe {
            SetFileInformationByHandle(
                handle.0,
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        drop(handle);
        if marked == 0 {
            Err(WindowsSecurityError)
        } else {
            Ok(())
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `OwnedHandle` is constructed only from a successful handle-returning API and
        // owns that handle exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalAllocation(HLOCAL);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: Win32 security APIs documented to allocate with LocalAlloc returned this pointer,
        // and this owner frees it exactly once after all borrowed ACL/SID pointers are unused.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct TokenUserBuffer {
    _storage: Vec<usize>,
    sid: PSID,
}

impl TokenUserBuffer {
    fn current() -> Result<Self, WindowsSecurityError> {
        let token = current_process_token()?;
        let mut bytes = 0_u32;
        // SAFETY: a null buffer with length zero is the documented size query.
        unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut bytes);
        }
        if bytes < size_of::<TOKEN_USER>() as u32 {
            return Err(WindowsSecurityError);
        }
        let words = (bytes as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        // SAFETY: the aligned allocation has at least `bytes` writable bytes and remains alive.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(WindowsSecurityError);
        }
        // SAFETY: a successful TokenUser query returned a complete TOKEN_USER at the buffer start.
        let sid = unsafe { storage.as_ptr().cast::<TOKEN_USER>().read().User.Sid };
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(WindowsSecurityError);
        }
        Ok(Self {
            _storage: storage,
            sid,
        })
    }
}

struct WellKnownSid {
    _storage: Vec<usize>,
    sid: PSID,
}

impl WellKnownSid {
    fn local_system() -> Result<Self, WindowsSecurityError> {
        Self::new(WinLocalSystemSid)
    }

    fn new(kind: i32) -> Result<Self, WindowsSecurityError> {
        let bytes = SECURITY_MAX_SID_SIZE as usize;
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let mut supplied = bytes as u32;
        let sid = storage.as_mut_ptr().cast();
        // SAFETY: the aligned buffer has the documented maximum SID capacity.
        if unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid, &mut supplied) } == 0
            || supplied as usize > bytes
            || unsafe { IsValidSid(sid) } == 0
        {
            return Err(WindowsSecurityError);
        }
        Ok(Self {
            _storage: storage,
            sid,
        })
    }
}

struct StringSid {
    _allocation: LocalAllocation,
    sid: PSID,
}

impl StringSid {
    fn trusted_installer() -> Result<Self, WindowsSecurityError> {
        Self::parse("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\0")
    }

    #[cfg(test)]
    fn owner_rights() -> Result<Self, WindowsSecurityError> {
        Self::parse("S-1-3-4\0")
    }

    fn parse(value: &str) -> Result<Self, WindowsSecurityError> {
        if !value.ends_with('\0') {
            return Err(WindowsSecurityError);
        }
        let encoded: Vec<u16> = value.encode_utf16().collect();
        let mut sid = ptr::null_mut();
        // SAFETY: the SID string is terminated and the output receives a LocalAlloc allocation.
        if unsafe { ConvertStringSidToSidW(encoded.as_ptr(), &mut sid) } == 0 || sid.is_null() {
            return Err(WindowsSecurityError);
        }
        let allocation = LocalAllocation(sid);
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(WindowsSecurityError);
        }
        Ok(Self {
            _allocation: allocation,
            sid,
        })
    }
}

struct TrustedLaunchSids {
    current: TokenUserBuffer,
    system: WellKnownSid,
    administrators: WellKnownSid,
    trusted_installer: StringSid,
}

impl TrustedLaunchSids {
    fn current() -> Result<Self, WindowsSecurityError> {
        Ok(Self {
            current: TokenUserBuffer::current()?,
            system: WellKnownSid::local_system()?,
            administrators: WellKnownSid::new(WinBuiltinAdministratorsSid)?,
            trusted_installer: StringSid::trusted_installer()?,
        })
    }

    fn contains(&self, sid: PSID) -> bool {
        [
            self.current.sid,
            self.system.sid,
            self.administrators.sid,
            self.trusted_installer.sid,
        ]
        .into_iter()
        // SAFETY: every SID pointer belongs to live validated storage.
        .any(|trusted| unsafe { EqualSid(sid, trusted) } != 0)
    }
}

struct SecurityDescriptor {
    allocation: LocalAllocation,
    owner: PSID,
    dacl: *mut ACL,
}

impl SecurityDescriptor {
    fn read(handle: HANDLE) -> Result<Self, WindowsSecurityError> {
        let mut owner = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        // SAFETY: all output pointers are valid; the returned descriptor owns owner and DACL data.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || dacl.is_null() {
            if !descriptor.is_null() {
                drop(LocalAllocation(descriptor));
            }
            return Err(WindowsSecurityError);
        }
        Ok(Self {
            allocation: LocalAllocation(descriptor),
            owner,
            dacl,
        })
    }

    fn is_protected(&self) -> Result<bool, WindowsSecurityError> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: the descriptor allocation remains alive and both outputs are valid.
        if unsafe { GetSecurityDescriptorControl(self.allocation.0, &mut control, &mut revision) }
            == 0
        {
            return Err(WindowsSecurityError);
        }
        Ok(control & SE_DACL_PROTECTED != 0)
    }

    #[cfg(test)]
    fn snapshot(&self) -> Result<(Vec<u8>, Vec<u8>, bool), WindowsSecurityError> {
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: the DACL belongs to this live descriptor and the fixed output
        // buffer has the exact size requested by `GetAclInformation`.
        if unsafe {
            GetAclInformation(
                self.dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(WindowsSecurityError);
        }
        // SAFETY: `owner` and `dacl` remain live inside this descriptor, and both
        // lengths were reported by the Windows security APIs for these objects.
        let owner = unsafe {
            std::slice::from_raw_parts(self.owner.cast(), GetLengthSid(self.owner) as usize)
        }
        .to_vec();
        let dacl = unsafe {
            std::slice::from_raw_parts(self.dacl.cast(), information.AclBytesInUse as usize)
        }
        .to_vec();
        Ok((owner, dacl, self.is_protected()?))
    }
}

fn require_path_authority(
    handle: HANDLE,
    level: PathLevel,
    owner_policy: OwnerPolicy,
    trusted: &TrustedLaunchSids,
) -> Result<(), WindowsSecurityError> {
    let kind = match level {
        PathLevel::File => PrivateObjectKind::File,
        PathLevel::Ancestor | PathLevel::ImmediateDirectory | PathLevel::InstallDirectory => {
            PrivateObjectKind::Directory
        }
    };
    require_private_object_kind(handle, kind)
        .map_err(|_| path_authority_failure("object kind", level))?;
    let descriptor = SecurityDescriptor::read(handle)
        .map_err(|_| path_authority_failure("descriptor read", level))?;
    let owner_is_accepted = owner_is_accepted(descriptor.owner, owner_policy, trusted);
    if !owner_is_accepted {
        return Err(path_authority_failure("owner", level));
    }
    if unsafe { IsValidAcl(descriptor.dacl) } == 0 {
        return Err(path_authority_failure("DACL validity", level));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the DACL belongs to the live descriptor and the output buffer is exact.
    if unsafe {
        GetAclInformation(
            descriptor.dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(path_authority_failure("DACL information", level));
    }

    let prohibited = prohibited_path_rights(level);
    for index in 0..information.AceCount {
        let mut raw_ace: *mut c_void = ptr::null_mut();
        // SAFETY: the ACL is valid and the index is in its reported range.
        if unsafe { GetAce(descriptor.dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(path_authority_failure("ACE read", level));
        }
        // SAFETY: GetAce returned a live ACE from an IsValidAcl-validated descriptor.
        let header = unsafe { ptr::read_unaligned(raw_ace.cast::<ACE_HEADER>()) };
        if header.AceType == ACCESS_DENIED_ACE_TYPE {
            // SAFETY: GetAce returned a live ACE from an IsValidAcl-validated descriptor.
            unsafe { validated_simple_ace(raw_ace, ACCESS_DENIED_ACE_TYPE)? };
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            return Err(path_authority_failure("ACE type", level));
        }
        // SAFETY: the same validated ACE preconditions hold for the parser.
        let (sid, mask, flags) = unsafe { validated_simple_ace(raw_ace, ACCESS_ALLOWED_ACE_TYPE)? };
        let applies_to_boundary =
            flags & INHERIT_ONLY_ACE as u8 == 0 || matches!(level, PathLevel::InstallDirectory);
        if applies_to_boundary && !trusted.contains(sid) && mask & prohibited != 0 {
            return Err(path_authority_failure("untrusted rights", level));
        }
    }
    Ok(())
}

fn path_authority_failure(_stage: &'static str, _level: PathLevel) -> WindowsSecurityError {
    #[cfg(test)]
    eprintln!("Windows path authority rejected {_level:?} at {_stage}");
    WindowsSecurityError
}

fn require_install_path_authority(
    handle: HANDLE,
    level: PathLevel,
    trusted: &TrustedLaunchSids,
) -> Result<(), WindowsSecurityError> {
    let level = if matches!(level, PathLevel::ImmediateDirectory) {
        PathLevel::InstallDirectory
    } else {
        level
    };
    let owner = if matches!(level, PathLevel::InstallDirectory) {
        OwnerPolicy::CurrentUser
    } else {
        OwnerPolicy::Trusted
    };
    require_path_authority(handle, level, owner, trusted)
}

fn owner_is_accepted(owner: PSID, policy: OwnerPolicy, trusted: &TrustedLaunchSids) -> bool {
    match policy {
        OwnerPolicy::Trusted => trusted.contains(owner),
        OwnerPolicy::CurrentUser => {
            // SAFETY: both pointers refer to live, validated SID storage.
            unsafe { EqualSid(owner, trusted.current.sid) != 0 }
        }
    }
}

fn prohibited_path_rights(level: PathLevel) -> u32 {
    let common = GENERIC_ALL
        | GENERIC_WRITE
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA;
    match level {
        PathLevel::Ancestor => common | FILE_DELETE_CHILD,
        PathLevel::ImmediateDirectory | PathLevel::InstallDirectory => {
            common | FILE_DELETE_CHILD | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
        }
        PathLevel::File => common | FILE_WRITE_DATA | FILE_APPEND_DATA,
    }
}

/// Reads the complete native identity from an already-open file or directory.
pub fn file_identity(file: &impl AsRawHandle) -> Result<WindowsFileIdentity, WindowsSecurityError> {
    identity_from_handle(raw_handle(file))
}

/// Proves that an already-open regular file is non-reparse and owned by the current user.
///
/// This inspection does not validate or change the object's DACL.
pub fn inspect_owned_file(file: &impl AsRawHandle) -> Result<(), WindowsSecurityError> {
    require_current_user_owner(raw_handle(file), PrivateObjectKind::File)
}

/// Proves that an already-open directory is non-reparse and owned by the current user.
///
/// This inspection does not validate or change the object's DACL.
pub fn inspect_owned_directory(file: &impl AsRawHandle) -> Result<(), WindowsSecurityError> {
    require_current_user_owner(raw_handle(file), PrivateObjectKind::Directory)
}

/// Promotes one owned, single-linked file to `destination` through its verified open handle.
pub fn promote_owned_file(
    parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), OwnedObjectPromotionError> {
    promote_owned_object(
        parent,
        source,
        destination,
        rollback,
        expected_identity,
        PrivateObjectKind::File,
    )
}

/// Promotes one owned directory to `destination` through its verified open handle.
pub fn promote_owned_directory(
    parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), OwnedObjectPromotionError> {
    promote_owned_object(
        parent,
        source,
        destination,
        rollback,
        expected_identity,
        PrivateObjectKind::Directory,
    )
}

/// Moves one owned, single-linked file between two open directories through its verified handle.
pub fn move_owned_file(
    source_parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination_parent: &impl AsRawHandle,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), OwnedObjectPromotionError> {
    move_owned_object(
        source_parent,
        source,
        destination_parent,
        destination,
        rollback,
        expected_identity,
        PrivateObjectKind::File,
    )
}

/// Moves one owned directory between two open directories through its verified handle.
pub fn move_owned_directory(
    source_parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination_parent: &impl AsRawHandle,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), OwnedObjectPromotionError> {
    move_owned_object(
        source_parent,
        source,
        destination_parent,
        destination,
        rollback,
        expected_identity,
        PrivateObjectKind::Directory,
    )
}

fn move_owned_object(
    source_parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination_parent: &impl AsRawHandle,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
) -> Result<(), OwnedObjectPromotionError> {
    require_relocation_names(source, destination, rollback)
        .map_err(|_| promotion_failed_at("names"))?;
    relocate_owned_object_with_hooks(
        source_parent,
        source,
        destination_parent,
        destination,
        source_parent,
        rollback,
        expected_identity,
        kind,
        OwnedObjectPromotionHooks {
            after_verification: || {},
            after_promotion: || Ok(()),
        },
    )
}

fn promote_owned_object(
    parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
) -> Result<(), OwnedObjectPromotionError> {
    promote_owned_object_with_hook(
        parent,
        source,
        destination,
        rollback,
        expected_identity,
        kind,
        || {},
    )
}

fn promote_owned_object_with_hook(
    parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
    after_verification: impl FnOnce(),
) -> Result<(), OwnedObjectPromotionError> {
    promote_owned_object_with_hooks(
        parent,
        source,
        destination,
        rollback,
        expected_identity,
        kind,
        OwnedObjectPromotionHooks {
            after_verification,
            after_promotion: || Ok(()),
        },
    )
}

fn promote_owned_object_with_hooks<AfterVerification, AfterPromotion>(
    parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
    hooks: OwnedObjectPromotionHooks<AfterVerification, AfterPromotion>,
) -> Result<(), OwnedObjectPromotionError>
where
    AfterVerification: FnOnce(),
    AfterPromotion: FnOnce() -> Result<(), WindowsSecurityError>,
{
    require_distinct_child_names(source, destination, rollback)
        .map_err(|_| promotion_failed_at("names"))?;
    relocate_owned_object_with_hooks(
        parent,
        source,
        parent,
        destination,
        parent,
        rollback,
        expected_identity,
        kind,
        hooks,
    )
}

#[allow(clippy::too_many_arguments)]
fn relocate_owned_object_with_hooks<AfterVerification, AfterPromotion>(
    source_parent: &impl AsRawHandle,
    source: &std::ffi::OsStr,
    destination_parent: &impl AsRawHandle,
    destination: &std::ffi::OsStr,
    rollback_parent: &impl AsRawHandle,
    rollback: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
    hooks: OwnedObjectPromotionHooks<AfterVerification, AfterPromotion>,
) -> Result<(), OwnedObjectPromotionError>
where
    AfterVerification: FnOnce(),
    AfterPromotion: FnOnce() -> Result<(), WindowsSecurityError>,
{
    let handle = open_capability_child(
        source_parent,
        source,
        kind,
        PRIVATE_PROMOTE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    .map_err(|_| promotion_failed_at("open"))?;
    require_expected_identity(handle.0, expected_identity)
        .map_err(|_| promotion_failed_at("identity"))?;
    require_current_user_owner(handle.0, kind).map_err(|_| promotion_failed_at("owner"))?;
    require_single_link_if_file(handle.0, kind).map_err(|_| promotion_failed_at("links"))?;
    (hooks.after_verification)();
    rename_handle_relative(handle.0, destination_parent, destination)
        .map_err(|_| promotion_failed_at("rename"))?;
    let verified = (hooks.after_promotion)()
        .and_then(|()| require_expected_identity(handle.0, expected_identity))
        .and_then(|()| require_current_user_owner(handle.0, kind))
        .and_then(|()| require_single_link_if_file(handle.0, kind));
    if verified.is_ok() {
        return Ok(());
    }
    rollback_promoted_handle(handle.0, rollback_parent, rollback)
}

fn promotion_failed_at(_stage: &'static str) -> OwnedObjectPromotionError {
    #[cfg(any(test, feature = "test-support"))]
    eprintln!("Windows owned-object promotion failed at stage: {_stage}");
    OwnedObjectPromotionError::Failed
}

fn rollback_promoted_handle(
    handle: HANDLE,
    rollback_parent: &impl AsRawHandle,
    rollback: &std::ffi::OsStr,
) -> Result<(), OwnedObjectPromotionError> {
    rename_handle_relative(handle, rollback_parent, rollback).map_or_else(
        |_| Err(OwnedObjectPromotionError::RollbackFailed),
        |()| Err(OwnedObjectPromotionError::Failed),
    )
}

fn require_distinct_child_names(
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
) -> Result<(), WindowsSecurityError> {
    let source = private_child_name(source).ok_or(WindowsSecurityError)?;
    let destination = private_child_name(destination).ok_or(WindowsSecurityError)?;
    let rollback = private_child_name(rollback).ok_or(WindowsSecurityError)?;
    if wide_eq_ignore_case(&source, &destination)?
        || wide_eq_ignore_case(&source, &rollback)?
        || wide_eq_ignore_case(&destination, &rollback)?
    {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

fn require_relocation_names(
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
    rollback: &std::ffi::OsStr,
) -> Result<(), WindowsSecurityError> {
    let source = private_child_name(source).ok_or(WindowsSecurityError)?;
    let _destination = private_child_name(destination).ok_or(WindowsSecurityError)?;
    let rollback = private_child_name(rollback).ok_or(WindowsSecurityError)?;
    if wide_eq_ignore_case(&source, &rollback)? {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

/// Deletes one identity-matched, current-user-owned regular-file link through the verified handle.
///
/// This does not validate or repair descriptor privacy. Callers that require a private descriptor
/// must establish that separately before granting deletion authority.
pub fn delete_owned_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), WindowsSecurityError> {
    delete_owned_object(
        parent,
        name,
        expected_identity,
        PrivateObjectKind::File,
        false,
    )
}

/// Deletes one identity-matched, current-user-owned single-linked regular file through the handle.
pub fn delete_owned_single_link_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), WindowsSecurityError> {
    delete_owned_object(
        parent,
        name,
        expected_identity,
        PrivateObjectKind::File,
        true,
    )
}

/// Deletes an identity-matched, current-user-owned empty directory through the verified handle.
///
/// This does not validate or repair descriptor privacy. Callers that require a private descriptor
/// must establish that separately before granting deletion authority.
pub fn delete_owned_directory(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
) -> Result<(), WindowsSecurityError> {
    delete_owned_object(
        parent,
        name,
        expected_identity,
        PrivateObjectKind::Directory,
        false,
    )
}

fn delete_owned_object(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
    require_single_link: bool,
) -> Result<(), WindowsSecurityError> {
    delete_owned_object_with_hook(
        parent,
        name,
        expected_identity,
        kind,
        require_single_link,
        || {},
    )
}

fn delete_owned_object_with_hook(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected_identity: WindowsFileIdentity,
    kind: PrivateObjectKind,
    require_single_link: bool,
    after_open: impl FnOnce(),
) -> Result<(), WindowsSecurityError> {
    let handle = open_private_child_for_deletion(parent, name, kind)?;
    after_open();
    require_expected_identity(handle.0, expected_identity)?;
    require_current_user_owner(handle.0, kind)?;
    if require_single_link {
        require_single_link_if_file(handle.0, kind)?;
    }
    require_expected_identity(handle.0, expected_identity)?;
    mark_handle_for_posix_deletion(handle.0)
}

fn open_private_child_for_deletion(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    kind: PrivateObjectKind,
) -> Result<OwnedHandle, WindowsSecurityError> {
    open_capability_child(
        parent,
        name,
        kind,
        PRIVATE_DELETE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

fn open_capability_child(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    kind: PrivateObjectKind,
    access: u32,
    share_mode: u32,
) -> Result<OwnedHandle, WindowsSecurityError> {
    open_capability_child_semantic(parent, name, kind, access, share_mode)
        .map_err(|_| WindowsSecurityError)
}

fn open_capability_child_semantic(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    kind: PrivateObjectKind,
    access: u32,
    share_mode: u32,
) -> Result<OwnedHandle, PathOpenError> {
    let mut name = private_child_name(name).ok_or(PathOpenError::Unsafe)?;
    open_encoded_capability_child_semantic(parent, &mut name, kind, access, share_mode)
}

fn open_encoded_capability_child_semantic(
    parent: &impl AsRawHandle,
    name: &mut [u16],
    kind: PrivateObjectKind,
    access: u32,
    share_mode: u32,
) -> Result<OwnedHandle, PathOpenError> {
    let mut unicode_name = UNICODE_STRING {
        Length: size_of_val(name) as u16,
        MaximumLength: size_of_val(name) as u16,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw_handle(parent),
        ObjectName: &mut unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = INVALID_HANDLE_VALUE;
    let kind_option = match kind {
        PrivateObjectKind::Directory => FILE_DIRECTORY_FILE,
        PrivateObjectKind::File => FILE_NON_DIRECTORY_FILE,
    };
    // SAFETY: every pointer references initialized storage alive for the complete native call.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share_mode,
            FILE_OPEN,
            kind_option | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status != STATUS_SUCCESS || handle == INVALID_HANDLE_VALUE {
        return Err(match status {
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => PathOpenError::Missing,
            _ => PathOpenError::Unsafe,
        });
    }
    let handle = OwnedHandle(handle);
    require_private_object_kind(handle.0, kind).map_err(|_| PathOpenError::Unsafe)?;
    Ok(handle)
}

fn rename_handle_relative(
    handle: HANDLE,
    destination_parent: &impl AsRawHandle,
    destination: &std::ffi::OsStr,
) -> Result<(), WindowsSecurityError> {
    let destination = private_child_name(destination).ok_or(WindowsSecurityError)?;
    let name_bytes = destination
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(WindowsSecurityError)?;
    let buffer_bytes = offset_of!(FILE_RENAME_INFORMATION, FileName)
        .checked_add(name_bytes)
        .ok_or(WindowsSecurityError)?
        .max(size_of::<FILE_RENAME_INFORMATION>());
    let mut buffer = vec![0_usize; buffer_bytes.div_ceil(size_of::<usize>())];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: the aligned zeroed buffer contains the fixed header plus the complete UTF-16 name.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        // The opened destination-directory handle and simple name keep the move capability-bound;
        // the source object handle remains the authority for both promotion and rollback.
        (*information).RootDirectory = raw_handle(destination_parent);
        (*information).FileNameLength =
            u32::try_from(name_bytes).map_err(|_| WindowsSecurityError)?;
        ptr::copy_nonoverlapping(
            destination.as_ptr(),
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset_of!(FILE_RENAME_INFORMATION, FileName))
                .cast::<u16>(),
            destination.len(),
        );
    }
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the handle has DELETE access and the destination-relative variable-length input is
    // valid for its exact size.
    let status = unsafe {
        NtSetInformationFile(
            handle,
            &mut status_block,
            information.cast(),
            u32::try_from(buffer_bytes).map_err(|_| WindowsSecurityError)?,
            FileRenameInformation,
        )
    };
    if status != STATUS_SUCCESS {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

fn require_single_link_if_file(
    handle: HANDLE,
    kind: PrivateObjectKind,
) -> Result<(), WindowsSecurityError> {
    if matches!(kind, PrivateObjectKind::Directory) {
        return Ok(());
    }
    let mut information = FILE_STANDARD_INFO::default();
    // SAFETY: the borrowed handle remains valid and the fixed output buffer is correctly sized.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut information as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
        || information.NumberOfLinks != 1
    {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

fn require_expected_identity(
    handle: HANDLE,
    expected_identity: WindowsFileIdentity,
) -> Result<(), WindowsSecurityError> {
    if identity_from_handle(handle)? == expected_identity {
        Ok(())
    } else {
        Err(WindowsSecurityError)
    }
}

fn require_current_user_owner(
    handle: HANDLE,
    kind: PrivateObjectKind,
) -> Result<(), WindowsSecurityError> {
    let current = TokenUserBuffer::current()?;
    require_object_owner(handle, kind, current.sid)
}

fn require_object_owner(
    handle: HANDLE,
    kind: PrivateObjectKind,
    expected_owner: PSID,
) -> Result<(), WindowsSecurityError> {
    require_private_object_kind(handle, kind)?;
    let descriptor = SecurityDescriptor::read(handle)?;
    require_equal_sid(descriptor.owner, expected_owner)
}

fn mark_handle_for_posix_deletion(handle: HANDLE) -> Result<(), WindowsSecurityError> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: the identity-verified handle has DELETE access and the input is correctly sized.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

fn identity_from_handle(handle: HANDLE) -> Result<WindowsFileIdentity, WindowsSecurityError> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the borrowed file handle remains valid and the fixed output buffer is correctly sized.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(WindowsSecurityError);
    }
    Ok(identity_from_information(information))
}

fn identity_from_information(information: FILE_ID_INFO) -> WindowsFileIdentity {
    WindowsFileIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    }
}

/// Requires the exact current-user private descriptor on an already-open directory handle.
pub fn inspect_private_directory(file: &impl AsRawHandle) -> Result<(), WindowsSecurityError> {
    let current = TokenUserBuffer::current()?;
    let system = WellKnownSid::local_system()?;
    require_distinct_sids(current.sid, system.sid)?;
    inspect_private_descriptor(
        raw_handle(file),
        current.sid,
        system.sid,
        PRIVATE_DIRECTORY_ACE_FLAGS,
        PrivateObjectKind::Directory,
    )
}

/// Atomically creates a current-user-owned private directory below an open parent.
pub fn create_private_directory(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, ObjectCreationError> {
    create_owned_object(
        parent,
        name,
        DaclPolicy::ExactPrivate {
            ace_flags: PRIVATE_DIRECTORY_ACE_FLAGS,
        },
        PrivateObjectKind::Directory,
    )
}

/// Opens an existing exact-private directory relative to retained parent authority.
///
/// The returned handle can enumerate and create children but denies delete sharing, preventing the
/// directory name from being replaced while retained.
pub fn open_private_directory(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, WindowsSecurityError> {
    let handle = open_capability_child(
        parent,
        name,
        PrivateObjectKind::Directory,
        PRIVATE_DIRECTORY_AUTHORITY_ACCESS | PRIVATE_DIRECTORY_CHILD_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    let directory = owned_handle_into_file(handle);
    inspect_private_directory(&directory)?;
    Ok(directory)
}

/// Flushes an exact-private directory through an identity-checked writable capability.
/// Unsupported filesystems and flush failures are errors, never best-effort success.
pub fn flush_private_directory(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected: WindowsFileIdentity,
) -> Result<(), WindowsSecurityError> {
    flush_directory_with(parent, name, expected, |directory| {
        inspect_private_directory(directory)
    })
}

fn flush_directory_with(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected: WindowsFileIdentity,
    validate: impl Fn(&std::fs::File) -> Result<(), WindowsSecurityError>,
) -> Result<(), WindowsSecurityError> {
    let directory = owned_handle_into_file(open_capability_child(
        parent,
        name,
        PrivateObjectKind::Directory,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?);
    validate(&directory)?;
    require_expected_identity(raw_handle(&directory), expected)?;
    directory.sync_all().map_err(|_| WindowsSecurityError)?;
    validate(&directory)?;
    require_expected_identity(raw_handle(&directory), expected)
}

/// Atomically creates a current-user-owned directory with its parent-inherited DACL.
pub fn create_owned_directory(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, ObjectCreationError> {
    create_owned_object(
        parent,
        name,
        DaclPolicy::Inherited,
        PrivateObjectKind::Directory,
    )
}

/// Replaces only the DACL on an owned directory handle, then verifies the exact final descriptor.
pub fn repair_private_directory(file: &impl AsRawHandle) -> Result<(), WindowsSecurityError> {
    repair_private_descriptor(
        file,
        PRIVATE_DIRECTORY_ACE_FLAGS,
        PrivateObjectKind::Directory,
    )
}

/// Makes an owned directory deliberately unprotected for cross-crate security regression tests.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn make_private_directory_unprotected_for_testing(
    file: &impl AsRawHandle,
) -> Result<(), WindowsSecurityError> {
    let current = TokenUserBuffer::current()?;
    let system = WellKnownSid::local_system()?;
    require_distinct_sids(current.sid, system.sid)?;
    require_private_object_kind(raw_handle(file), PrivateObjectKind::Directory)?;
    let descriptor = SecurityDescriptor::read(raw_handle(file))?;
    require_equal_sid(descriptor.owner, current.sid)?;
    drop(descriptor);
    install_dacl(
        raw_handle(file),
        &[current.sid, system.sid],
        PRIVATE_DIRECTORY_ACE_FLAGS,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    )
}

/// Compares absolute path topology with Win32 ordinal case-insensitive component semantics.
pub fn paths_overlap_case_insensitive(
    first: &Path,
    second: &Path,
) -> Result<bool, WindowsSecurityError> {
    let first = comparable_path_components(first)?;
    let second = comparable_path_components(second)?;
    let shared = first.len().min(second.len());
    for ((first_kind, first), (second_kind, second)) in first.iter().zip(second.iter()).take(shared)
    {
        if first_kind != second_kind || !wide_eq_ignore_case(first, second)? {
            return Ok(false);
        }
    }
    Ok(first.len() == shared || second.len() == shared)
}

fn comparable_path_components(path: &Path) -> Result<Vec<(u8, Vec<u16>)>, WindowsSecurityError> {
    let mut components = Vec::new();
    for component in path.components() {
        let (kind, encoded) = match component {
            Component::Prefix(prefix) => (0, prefix.as_os_str().encode_wide().collect()),
            Component::RootDir => (1, Vec::new()),
            Component::Normal(component) => (2, validated_component_encoding(component)?),
            Component::CurDir | Component::ParentDir => return Err(WindowsSecurityError),
        };
        if !is_well_formed_utf16(&encoded) {
            return Err(WindowsSecurityError);
        }
        components.push((kind, encoded));
    }
    Ok(components)
}

fn validated_component_encoding(
    component: &std::ffi::OsStr,
) -> Result<Vec<u16>, WindowsSecurityError> {
    let encoded: Vec<u16> = component.encode_wide().collect();
    if encoded.is_empty()
        || !is_well_formed_utf16(&encoded)
        || encoded.contains(&(b':' as u16))
        || encoded
            .last()
            .is_some_and(|unit| *unit == b'.' as u16 || *unit == b' ' as u16)
    {
        Err(WindowsSecurityError)
    } else {
        Ok(encoded)
    }
}

fn is_well_formed_utf16(units: &[u16]) -> bool {
    std::char::decode_utf16(units.iter().copied()).all(|value| value.is_ok())
}

fn wide_eq_ignore_case(first: &[u16], second: &[u16]) -> Result<bool, WindowsSecurityError> {
    let first_len = i32::try_from(first.len()).map_err(|_| WindowsSecurityError)?;
    let second_len = i32::try_from(second.len()).map_err(|_| WindowsSecurityError)?;
    // SAFETY: both pointers remain valid for their exact lengths for the duration of the call.
    let compared =
        unsafe { CompareStringOrdinal(first.as_ptr(), first_len, second.as_ptr(), second_len, 1) };
    if compared == 0 {
        Err(WindowsSecurityError)
    } else {
        Ok(compared == CSTR_EQUAL)
    }
}

/// Requires the exact current-user private descriptor on an open regular file.
pub fn inspect_private_file(file: &impl AsRawHandle) -> Result<(), WindowsSecurityError> {
    let current = TokenUserBuffer::current()?;
    let system = WellKnownSid::local_system()?;
    require_distinct_sids(current.sid, system.sid)?;
    inspect_private_descriptor(
        raw_handle(file),
        current.sid,
        system.sid,
        PRIVATE_FILE_ACE_FLAGS,
        PrivateObjectKind::File,
    )
}

/// Requires one link and the exact current-user private descriptor on an open regular file.
pub fn inspect_private_single_link_file(
    file: &impl AsRawHandle,
) -> Result<(), WindowsSecurityError> {
    inspect_private_file(file)?;
    require_single_link_if_file(raw_handle(file), PrivateObjectKind::File)
}

/// Atomically creates a current-user-owned private regular file below an open parent.
pub fn create_private_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, ObjectCreationError> {
    create_owned_object(
        parent,
        name,
        DaclPolicy::ExactPrivate {
            ace_flags: PRIVATE_FILE_ACE_FLAGS,
        },
        PrivateObjectKind::File,
    )
}

/// Opens an existing exact-private single-linked file for bounded read-only inspection.
pub fn open_private_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, WindowsSecurityError> {
    open_existing_private_file(parent, name, PRIVATE_FILE_INSPECT_ACCESS, FILE_SHARE_READ)
}

/// Opens one existing private file for an authorized update without granting DACL changes.
/// The expected identity is checked before the writable handle escapes. Competing writes,
/// rename and deletion are excluded while this handle is retained.
pub fn open_private_file_for_update(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    expected: WindowsFileIdentity,
) -> Result<std::fs::File, WindowsSecurityError> {
    let file =
        open_existing_private_file(parent, name, PRIVATE_FILE_WRITE_ACCESS, FILE_SHARE_READ)?;
    require_expected_identity(raw_handle(&file), expected)?;
    Ok(file)
}

/// Opens an existing exact-private single-linked lock file for cooperative read/write locking.
pub fn open_private_lock_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, WindowsSecurityError> {
    open_existing_private_file(
        parent,
        name,
        PRIVATE_FILE_WRITE_ACCESS,
        PRIVATE_FILE_LOCK_SHARE_MODE,
    )
}

fn open_existing_private_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    access: u32,
    share_mode: u32,
) -> Result<std::fs::File, WindowsSecurityError> {
    let handle = open_capability_child(parent, name, PrivateObjectKind::File, access, share_mode)?;
    let file = owned_handle_into_file(handle);
    inspect_private_single_link_file(&file)?;
    Ok(file)
}

/// Atomically creates a current-user-owned regular file with its parent-inherited DACL.
pub fn create_owned_file(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, ObjectCreationError> {
    create_owned_object(parent, name, DaclPolicy::Inherited, PrivateObjectKind::File)
}

fn create_owned_object(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    dacl_policy: DaclPolicy,
    kind: PrivateObjectKind,
) -> Result<std::fs::File, ObjectCreationError> {
    create_owned_object_with_hooks(
        parent,
        name,
        dacl_policy,
        kind,
        ObjectCreationHooks {
            after_create: || Ok(()),
            rollback: PendingCreation::rollback,
            created_identity: identity_from_handle,
            after_directory_create_close: || {},
        },
    )
}

#[cfg(test)]
fn create_private_object_with_hook(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    ace_flags: u8,
    kind: PrivateObjectKind,
    after_create: impl FnOnce() -> Result<(), WindowsSecurityError>,
) -> Result<std::fs::File, ObjectCreationError> {
    create_owned_object_with_hooks(
        parent,
        name,
        DaclPolicy::ExactPrivate { ace_flags },
        kind,
        ObjectCreationHooks {
            after_create,
            rollback: PendingCreation::rollback,
            created_identity: identity_from_handle,
            after_directory_create_close: || {},
        },
    )
}

fn create_owned_object_with_hooks<AfterCreate, Rollback, CreatedIdentity, AfterClose>(
    parent: &impl AsRawHandle,
    name: &std::ffi::OsStr,
    dacl_policy: DaclPolicy,
    kind: PrivateObjectKind,
    hooks: ObjectCreationHooks<AfterCreate, Rollback, CreatedIdentity, AfterClose>,
) -> Result<std::fs::File, ObjectCreationError>
where
    AfterCreate: FnOnce() -> Result<(), WindowsSecurityError>,
    Rollback: FnOnce(PendingCreation) -> Result<(), WindowsSecurityError>,
    CreatedIdentity: FnOnce(HANDLE) -> Result<WindowsFileIdentity, WindowsSecurityError>,
    AfterClose: FnOnce(),
{
    let ObjectCreationHooks {
        after_create,
        rollback,
        created_identity,
        after_directory_create_close,
    } = hooks;
    let failed = |_| ObjectCreationError::Failed;
    let name = private_child_name(name).ok_or(ObjectCreationError::Failed)?;
    let current = TokenUserBuffer::current().map_err(failed)?;
    let private_descriptor = match dacl_policy {
        DaclPolicy::Inherited => None,
        DaclPolicy::ExactPrivate { ace_flags } => {
            let system = WellKnownSid::local_system().map_err(failed)?;
            require_distinct_sids(current.sid, system.sid).map_err(failed)?;
            let acl = build_acl(&[current.sid, system.sid], ace_flags).map_err(failed)?;
            Some(ExactPrivateDescriptor {
                system,
                acl,
                ace_flags,
            })
        }
    };

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_ptr = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    // SAFETY: the descriptor and referenced owner/ACL storage remain alive through creation.
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, 1) } == 0
        || unsafe { SetSecurityDescriptorOwner(descriptor_ptr, current.sid, 0) } == 0
    {
        return Err(ObjectCreationError::Failed);
    }
    if let Some(private) = &private_descriptor {
        if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, private.acl.0.cast(), 0) } == 0
            || unsafe {
                SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            } == 0
        {
            return Err(ObjectCreationError::Failed);
        }
    }

    let mut unicode_name = UNICODE_STRING {
        Length: size_of_val(name.as_slice()) as u16,
        MaximumLength: size_of_val(name.as_slice()) as u16,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw_handle(parent),
        ObjectName: &mut unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: &descriptor,
        SecurityQualityOfService: ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = INVALID_HANDLE_VALUE;
    let (access, file_attributes, create_kind, share_mode) = match (kind, dacl_policy) {
        (PrivateObjectKind::Directory, DaclPolicy::ExactPrivate { .. }) => (
            PRIVATE_MUTATE_ACCESS | PRIVATE_DIRECTORY_CHILD_ACCESS | DELETE | SYNCHRONIZE,
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ),
        (PrivateObjectKind::Directory, DaclPolicy::Inherited) => (
            FILE_GENERIC_READ
                | FILE_GENERIC_WRITE
                | PRIVATE_DIRECTORY_CHILD_ACCESS
                | DELETE
                | SYNCHRONIZE,
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ),
        (PrivateObjectKind::File, DaclPolicy::ExactPrivate { .. }) => (
            PRIVATE_FILE_WRITE_ACCESS | DELETE | SYNCHRONIZE,
            FILE_ATTRIBUTE_NORMAL,
            FILE_NON_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ),
        (PrivateObjectKind::File, DaclPolicy::Inherited) => (
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE,
            FILE_ATTRIBUTE_NORMAL,
            FILE_NON_DIRECTORY_FILE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ),
    };
    // SAFETY: every pointer references initialized storage alive for the complete native call.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            ptr::null(),
            file_attributes,
            share_mode,
            FILE_CREATE,
            create_kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status == STATUS_OBJECT_NAME_COLLISION {
        return Err(ObjectCreationError::AlreadyExists);
    }
    if status != STATUS_SUCCESS || handle == INVALID_HANDLE_VALUE {
        return Err(ObjectCreationError::Failed);
    }
    let handle = PendingCreation(Some(OwnedHandle(handle)));
    let raw = handle
        .0
        .as_ref()
        .expect("pending creation owns its handle")
        .0;
    let hook_result = after_create();
    let descriptor_result = match &private_descriptor {
        Some(private) => inspect_private_descriptor(
            raw,
            current.sid,
            private.system.sid,
            private.ace_flags,
            kind,
        ),
        None => require_current_user_owner(raw, kind),
    };
    let identity_result = if matches!(kind, PrivateObjectKind::Directory) {
        created_identity(raw).map(Some)
    } else {
        Ok(None)
    };
    if hook_result.is_err() || descriptor_result.is_err() || identity_result.is_err() {
        return Err(match rollback(handle) {
            Ok(()) => ObjectCreationError::Failed,
            Err(_) => ObjectCreationError::RollbackFailed,
        });
    }
    if matches!(kind, PrivateObjectKind::File) {
        return Ok(handle.commit());
    }

    let created_identity = identity_result
        .expect("creation validation checked the identity result")
        .expect("directory creation records an identity");
    drop(handle.commit());
    after_directory_create_close();
    let committed =
        open_committed_directory(parent, &name).map_err(|_| ObjectCreationError::HandoffFailed)?;
    if identity_from_handle(raw_handle(&committed))
        .map_err(|_| ObjectCreationError::HandoffFailed)?
        != created_identity
        || match &private_descriptor {
            Some(private) => inspect_private_descriptor(
                raw_handle(&committed),
                current.sid,
                private.system.sid,
                private.ace_flags,
                kind,
            ),
            None => require_current_user_owner(raw_handle(&committed), kind),
        }
        .is_err()
    {
        return Err(ObjectCreationError::HandoffFailed);
    }
    Ok(committed)
}

fn open_committed_directory(
    parent: &impl AsRawHandle,
    name: &[u16],
) -> Result<std::fs::File, WindowsSecurityError> {
    let mut name = name.to_vec();
    open_encoded_capability_child_semantic(
        parent,
        &mut name,
        PrivateObjectKind::Directory,
        FILE_GENERIC_READ | PRIVATE_DIRECTORY_CHILD_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    .map(owned_handle_into_file)
    .map_err(|_| WindowsSecurityError)
}

fn private_child_name(name: &std::ffi::OsStr) -> Option<Vec<u16>> {
    let mut components = Path::new(name).components();
    let component = components.next()?;
    if components.next().is_some()
        || !matches!(component, Component::Normal(component) if component == name)
    {
        return None;
    }
    let encoded = name.encode_wide().collect::<Vec<_>>();
    let byte_len = encoded.len().checked_mul(size_of::<u16>())?;
    if encoded.is_empty()
        || encoded.contains(&0)
        || encoded.contains(&(b':' as u16))
        || byte_len > u16::MAX as usize
    {
        None
    } else {
        Some(encoded)
    }
}

fn repair_private_descriptor(
    file: &impl AsRawHandle,
    ace_flags: u8,
    kind: PrivateObjectKind,
) -> Result<(), WindowsSecurityError> {
    let current = TokenUserBuffer::current()?;
    let system = WellKnownSid::local_system()?;
    require_distinct_sids(current.sid, system.sid)?;
    require_private_object_kind(raw_handle(file), kind)?;
    let descriptor = SecurityDescriptor::read(raw_handle(file))?;
    require_equal_sid(descriptor.owner, current.sid)?;
    drop(descriptor);

    install_private_dacl(raw_handle(file), &[current.sid, system.sid], ace_flags)?;
    inspect_private_descriptor(raw_handle(file), current.sid, system.sid, ace_flags, kind)
}

fn install_private_dacl(
    handle: HANDLE,
    trustees: &[PSID],
    ace_flags: u8,
) -> Result<(), WindowsSecurityError> {
    install_dacl(
        handle,
        trustees,
        ace_flags,
        PROTECTED_DACL_SECURITY_INFORMATION,
    )
}

fn install_dacl(
    handle: HANDLE,
    trustees: &[PSID],
    ace_flags: u8,
    protection: u32,
) -> Result<(), WindowsSecurityError> {
    let acl = build_acl(trustees, ace_flags)?;
    // SAFETY: the handle carries WRITE_DAC and the ACL remains alive for the complete call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | protection,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.0.cast(),
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(WindowsSecurityError);
    }
    Ok(())
}

fn build_acl(trustees: &[PSID], ace_flags: u8) -> Result<LocalAllocation, WindowsSecurityError> {
    let entries = trustees
        .iter()
        .copied()
        .map(|sid| explicit_full_control(sid, ace_flags))
        .collect::<Vec<_>>();
    let mut acl = ptr::null_mut();
    // SAFETY: entries and their SID buffers remain alive through ACL construction; output is valid.
    let status = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            ptr::null(),
            &mut acl,
        )
    };
    if status != ERROR_SUCCESS || acl.is_null() {
        return Err(WindowsSecurityError);
    }
    Ok(LocalAllocation(acl.cast()))
}

fn inspect_private_descriptor(
    handle: HANDLE,
    current_sid: PSID,
    system_sid: PSID,
    expected_ace_flags: u8,
    kind: PrivateObjectKind,
) -> Result<(), WindowsSecurityError> {
    inspect_exact_descriptor(
        handle,
        current_sid,
        &[current_sid, system_sid],
        expected_ace_flags,
        true,
        kind,
    )
}

fn inspect_exact_descriptor(
    handle: HANDLE,
    expected_owner: PSID,
    expected_trustees: &[PSID],
    expected_ace_flags: u8,
    expected_protected: bool,
    kind: PrivateObjectKind,
) -> Result<(), WindowsSecurityError> {
    require_private_object_kind(handle, kind)?;
    let descriptor = SecurityDescriptor::read(handle)?;
    require_equal_sid(descriptor.owner, expected_owner)?;
    if descriptor.is_protected()? != expected_protected
        || unsafe { IsValidAcl(descriptor.dacl) } == 0
    {
        return Err(WindowsSecurityError);
    }
    let expected_ace_count =
        u32::try_from(expected_trustees.len()).map_err(|_| WindowsSecurityError)?;
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the DACL belongs to the live descriptor and the output buffer is correctly sized.
    if unsafe {
        GetAclInformation(
            descriptor.dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != expected_ace_count
        || unsafe { (*descriptor.dacl).AclRevision } != ACL_REVISION as u8
    {
        return Err(WindowsSecurityError);
    }

    let mut seen = vec![false; expected_trustees.len()];
    for index in 0..information.AceCount {
        let mut raw_ace: *mut c_void = ptr::null_mut();
        // SAFETY: the validated ACL and in-range index remain alive for this call.
        if unsafe { GetAce(descriptor.dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(WindowsSecurityError);
        }
        // SAFETY: GetAce returned this pointer from a validated ACL at an in-range index.
        let sid = unsafe { validated_allowed_ace_sid(raw_ace, expected_ace_flags)? };
        let Some(position) = expected_trustees
            .iter()
            .position(|expected| unsafe { EqualSid(sid, *expected) } != 0)
        else {
            return Err(WindowsSecurityError);
        };
        if std::mem::replace(&mut seen[position], true) {
            return Err(WindowsSecurityError);
        }
    }
    if seen.into_iter().all(|saw_expected| saw_expected) {
        Ok(())
    } else {
        Err(WindowsSecurityError)
    }
}

fn require_private_object_kind(
    handle: HANDLE,
    expected: PrivateObjectKind,
) -> Result<(), WindowsSecurityError> {
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the borrowed handle remains valid and the fixed output buffer is correctly sized.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
        || information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(WindowsSecurityError);
    }
    let is_directory = information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    match expected {
        PrivateObjectKind::Directory if is_directory => Ok(()),
        PrivateObjectKind::File if !is_directory => Ok(()),
        PrivateObjectKind::Directory | PrivateObjectKind::File => Err(WindowsSecurityError),
    }
}

/// Returns the SID only after every variable-length field is proven to fit the ACE exactly.
///
/// # Safety
///
/// `raw_ace` must point to a live allocation containing an ACE header and at least the number of
/// bytes declared by that header's `AceSize`. Production callers obtain that proof from `GetAce`
/// on an `IsValidAcl`-validated ACL.
unsafe fn validated_allowed_ace_sid(
    raw_ace: *mut c_void,
    expected_ace_flags: u8,
) -> Result<PSID, WindowsSecurityError> {
    // SAFETY: inherited from this function's caller.
    let (sid, mask, flags) = unsafe { validated_simple_ace(raw_ace, ACCESS_ALLOWED_ACE_TYPE)? };
    if flags == expected_ace_flags && mask == FILE_ALL_ACCESS {
        Ok(sid)
    } else {
        Err(WindowsSecurityError)
    }
}

/// Returns a simple allow or deny ACE's validated SID, mask, and flags.
///
/// # Safety
///
/// `raw_ace` must satisfy the same live, `AceSize`-bounded requirements as
/// `validated_allowed_ace_sid`.
unsafe fn validated_simple_ace(
    raw_ace: *mut c_void,
    expected_type: u8,
) -> Result<(PSID, u32, u8), WindowsSecurityError> {
    // SAFETY: guaranteed by the caller; every later read is additionally AceSize-bounded.
    let header = unsafe { ptr::read_unaligned(raw_ace.cast::<ACE_HEADER>()) };
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let sid_fixed_bytes = offset_of!(SID, SubAuthority);
    if header.AceType != expected_type || (header.AceSize as usize) < sid_offset + sid_fixed_bytes {
        return Err(WindowsSecurityError);
    }
    // SAFETY: the fixed SID prefix is contained in AceSize.
    let sid: PSID = unsafe { raw_ace.cast::<u8>().add(sid_offset).cast() };
    // SAFETY: the fixed SID prefix includes SubAuthorityCount.
    let subauthority_count =
        unsafe { ptr::read_unaligned(sid.cast::<u8>().add(offset_of!(SID, SubAuthorityCount))) }
            as usize;
    let sid_bytes = sid_fixed_bytes
        .checked_add(
            subauthority_count
                .checked_mul(size_of::<u32>())
                .ok_or(WindowsSecurityError)?,
        )
        .ok_or(WindowsSecurityError)?;
    if sid_offset.checked_add(sid_bytes) != Some(header.AceSize as usize) {
        return Err(WindowsSecurityError);
    }
    // SAFETY: the SID's complete declared extent is proven to fit this live ACE.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(WindowsSecurityError);
    }
    // SAFETY: the fixed access mask precedes SidStart and is contained in the validated AceSize.
    let mask = unsafe {
        ptr::read_unaligned(
            raw_ace
                .cast::<u8>()
                .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                .cast::<u32>(),
        )
    };
    Ok((sid, mask, header.AceFlags))
}

fn explicit_full_control(sid: PSID, ace_flags: u8) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: ace_flags as u32,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    }
}

fn require_equal_sid(first: PSID, second: PSID) -> Result<(), WindowsSecurityError> {
    if first.is_null()
        || second.is_null()
        || unsafe { IsValidSid(first) } == 0
        || unsafe { IsValidSid(second) } == 0
        || unsafe { EqualSid(first, second) } == 0
    {
        Err(WindowsSecurityError)
    } else {
        Ok(())
    }
}

fn require_distinct_sids(first: PSID, second: PSID) -> Result<(), WindowsSecurityError> {
    require_equal_sid(first, first)?;
    require_equal_sid(second, second)?;
    if unsafe { EqualSid(first, second) } == 0 {
        Ok(())
    } else {
        Err(WindowsSecurityError)
    }
}

fn raw_handle(file: &impl AsRawHandle) -> HANDLE {
    file.as_raw_handle().cast()
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Read as _, Write as _};
    use std::os::windows::fs::OpenOptionsExt as _;

    use windows_sys::Win32::Security::Authorization::DENY_ACCESS;
    use windows_sys::Win32::Security::{
        INHERITED_ACE, InitializeAcl, UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_ID_128, WRITE_OWNER};

    use super::*;

    fn open_directory(path: &std::path::Path, access: u32) -> std::fs::File {
        let mut options = OpenOptions::new();
        options
            .access_mode(access)
            .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS);
        options.open(path).unwrap()
    }

    fn open_parent(path: &std::path::Path) -> std::fs::File {
        open_directory(path, FILE_GENERIC_READ | FILE_GENERIC_WRITE)
    }

    fn open_file_descriptor_mutator(path: &std::path::Path) -> std::fs::File {
        let mut options = OpenOptions::new();
        options
            .access_mode(PRIVATE_MUTATE_ACCESS)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path).unwrap()
    }

    fn open_directory_descriptor_mutator(path: &std::path::Path) -> std::fs::File {
        open_directory(path, PRIVATE_MUTATE_ACCESS)
    }

    fn canonical_test_directory(path: &Path) -> PathBuf {
        let directory = open_directory(path, FILE_GENERIC_READ);
        final_dos_path(raw_handle(&directory)).unwrap()
    }

    fn install_test_access_dacl(handle: HANDLE, entries: &[(PSID, u32)], ace_flags: u8) {
        let mut explicit: Vec<EXPLICIT_ACCESS_W> = entries
            .iter()
            .map(|(sid, mask)| {
                let mut entry = explicit_full_control(*sid, ace_flags);
                entry.grfAccessPermissions = *mask;
                entry
            })
            .collect();
        install_test_explicit_dacl(handle, &mut explicit);
    }

    fn install_test_structural_only_dacl(handle: HANDLE, current: PSID) {
        let owner_rights = StringSid::owner_rights().unwrap();
        let mut deny_read_control = explicit_full_control(owner_rights.sid, 0);
        deny_read_control.grfAccessPermissions = READ_CONTROL;
        deny_read_control.grfAccessMode = DENY_ACCESS;
        let mut allow_structural = explicit_full_control(current, 0);
        allow_structural.grfAccessPermissions =
            PathAccessProfile::Structural.desired_access(PrivateObjectKind::Directory);
        let mut explicit = [deny_read_control, allow_structural];
        install_test_explicit_dacl(handle, &mut explicit);
    }

    fn install_test_explicit_dacl(handle: HANDLE, explicit: &mut [EXPLICIT_ACCESS_W]) {
        let mut acl = ptr::null_mut();
        // SAFETY: all explicit trustee SID pointers remain live through ACL construction.
        assert_eq!(
            unsafe {
                SetEntriesInAclW(
                    u32::try_from(explicit.len()).unwrap(),
                    explicit.as_mut_ptr(),
                    ptr::null_mut(),
                    &mut acl,
                )
            },
            ERROR_SUCCESS
        );
        let acl = LocalAllocation(acl.cast());
        // SAFETY: the handle has WRITE_DAC and the built ACL remains live through installation.
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl.0.cast(),
                    ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
    }

    fn install_test_empty_dacl(handle: HANDLE) {
        let mut storage = vec![0_usize; size_of::<ACL>().div_ceil(size_of::<usize>())];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        // SAFETY: the aligned allocation is exactly the requested ACL header size.
        assert_ne!(
            unsafe { InitializeAcl(acl, size_of::<ACL>() as u32, ACL_REVISION) },
            0
        );
        // SAFETY: the handle has WRITE_DAC and the initialized ACL remains live through the call.
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
    }

    fn install_test_null_dacl(handle: HANDLE) {
        // SAFETY: DACL_SECURITY_INFORMATION plus a null ACL installs a present NULL DACL.
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    handle,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            },
            ERROR_SUCCESS
        );
    }

    #[test]
    fn launch_validator_retains_a_normal_user_executable_and_system_cwd() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let executable_path = sandbox_path.join("pi.exe");
        std::fs::write(&executable_path, b"fixture").unwrap();

        let executable = validate_executable_path(&executable_path).unwrap();
        assert_eq!(executable.launch_path(), executable_path);
        let observed = executable
            .read_executable(|reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).unwrap();
                bytes
            })
            .unwrap();
        assert_eq!(observed, b"fixture");
        executable.revalidate_path_identity().unwrap();
        assert!(
            OpenOptions::new()
                .write(true)
                .open(&executable_path)
                .is_err()
        );

        let cwd = validated_system_launch_directory().unwrap();
        assert!(cwd.launch_path().is_absolute());
    }

    #[test]
    fn launch_authority_applies_level_specific_untrusted_rights() {
        let sandbox = tempfile::tempdir().unwrap();
        let directory = open_directory(
            sandbox.path(),
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        );
        let file_path = sandbox.path().join("pi.exe");
        std::fs::write(&file_path, b"fixture").unwrap();
        let file = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | WRITE_DAC)
            .open(&file_path)
            .unwrap();
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        let trusted = TrustedLaunchSids::current().unwrap();

        install_test_access_dacl(
            raw_handle(&file),
            &[
                (current.sid, FILE_ALL_ACCESS),
                (system.sid, FILE_ALL_ACCESS),
                (world.sid, FILE_GENERIC_READ),
            ],
            PRIVATE_FILE_ACE_FLAGS,
        );
        assert!(
            require_path_authority(
                raw_handle(&file),
                PathLevel::File,
                OwnerPolicy::Trusted,
                &trusted
            )
            .is_ok()
        );

        install_test_access_dacl(
            raw_handle(&directory),
            &[
                (current.sid, FILE_ALL_ACCESS),
                (system.sid, FILE_ALL_ACCESS),
                (world.sid, FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY),
            ],
            PRIVATE_DIRECTORY_ACE_FLAGS,
        );
        assert!(
            require_path_authority(
                raw_handle(&directory),
                PathLevel::Ancestor,
                OwnerPolicy::Trusted,
                &trusted
            )
            .is_ok()
        );
        assert!(
            require_path_authority(
                raw_handle(&directory),
                PathLevel::ImmediateDirectory,
                OwnerPolicy::Trusted,
                &trusted,
            )
            .is_err()
        );

        install_test_access_dacl(
            raw_handle(&directory),
            &[
                (current.sid, FILE_ALL_ACCESS),
                (system.sid, FILE_ALL_ACCESS),
                (world.sid, DELETE),
            ],
            PRIVATE_DIRECTORY_ACE_FLAGS,
        );
        assert!(
            require_path_authority(
                raw_handle(&directory),
                PathLevel::Ancestor,
                OwnerPolicy::Trusted,
                &trusted
            )
            .is_err()
        );
    }

    #[test]
    fn launch_authority_accepts_safe_inherited_read_only_access() {
        let sandbox = tempfile::tempdir().unwrap();
        let directory = open_directory(
            sandbox.path(),
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        );
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_test_access_dacl(
            raw_handle(&directory),
            &[
                (current.sid, FILE_ALL_ACCESS),
                (system.sid, FILE_ALL_ACCESS),
                (world.sid, FILE_GENERIC_READ),
            ],
            PRIVATE_DIRECTORY_ACE_FLAGS,
        );

        let file_path = sandbox.path().join("pi.exe");
        std::fs::write(&file_path, b"fixture").unwrap();
        let file = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | READ_CONTROL)
            .open(file_path)
            .unwrap();
        let trusted = TrustedLaunchSids::current().unwrap();
        assert!(
            require_path_authority(
                raw_handle(&file),
                PathLevel::File,
                OwnerPolicy::Trusted,
                &trusted
            )
            .is_ok()
        );
    }

    #[test]
    fn fixture_writer_refuses_hardlinked_existing_file_without_mutation() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let path = sandbox_path.join("fixture.json");
        let alias = sandbox_path.join("fixture-alias.json");
        write_current_user_owned_file_for_tests(&path, b"original").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();

        assert!(write_current_user_owned_file_for_tests(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert_eq!(std::fs::read(&alias).unwrap(), b"original");
    }

    #[test]
    fn integrity_read_returns_exact_bytes_and_enforces_bound() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let path = sandbox_path.join("trust.json");
        write_current_user_owned_file_for_tests(&path, b"{\"project\":true}").unwrap();

        assert_eq!(
            read_bounded_integrity_file(&path, 64),
            IntegrityFileRead::Bytes(b"{\"project\":true}".to_vec())
        );
        assert_eq!(
            read_bounded_integrity_file(&path, 4),
            IntegrityFileRead::Limit
        );
        assert_eq!(
            read_bounded_integrity_file(&sandbox_path.join("missing.json"), 64),
            IntegrityFileRead::Missing
        );
    }

    #[test]
    fn integrity_owner_policy_is_current_user_only_for_the_file_leaf() {
        let trusted = TrustedLaunchSids::current().unwrap();
        assert!(owner_is_accepted(
            trusted.current.sid,
            OwnerPolicy::CurrentUser,
            &trusted
        ));
        for owner in [
            trusted.system.sid,
            trusted.administrators.sid,
            trusted.trusted_installer.sid,
        ] {
            assert!(!owner_is_accepted(
                owner,
                OwnerPolicy::CurrentUser,
                &trusted
            ));
            assert!(owner_is_accepted(owner, OwnerPolicy::Trusted, &trusted));
        }
    }

    #[test]
    fn path_authority_accepts_present_empty_dacl_and_rejects_null_dacl() {
        let sandbox = tempfile::tempdir().unwrap();
        let path = sandbox.path().join("trust.json");
        write_current_user_owned_file_for_tests(&path, b"{}").unwrap();
        let file = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
            .open(path)
            .unwrap();
        let trusted = TrustedLaunchSids::current().unwrap();

        install_test_empty_dacl(raw_handle(&file));
        assert!(
            require_path_authority(
                raw_handle(&file),
                PathLevel::File,
                OwnerPolicy::CurrentUser,
                &trusted,
            )
            .is_ok()
        );
        install_test_null_dacl(raw_handle(&file));
        assert!(
            require_path_authority(
                raw_handle(&file),
                PathLevel::File,
                OwnerPolicy::CurrentUser,
                &trusted,
            )
            .is_err()
        );
    }

    #[test]
    fn integrity_read_rejects_untrusted_file_write_without_repair() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let path = sandbox_path.join("trust.json");
        write_current_user_owned_file_for_tests(&path, b"{}").unwrap();
        let file = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | WRITE_DAC)
            .open(&path)
            .unwrap();
        let current = TokenUserBuffer::current().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_test_access_dacl(
            raw_handle(&file),
            &[(current.sid, FILE_ALL_ACCESS), (world.sid, FILE_WRITE_DATA)],
            PRIVATE_FILE_ACE_FLAGS,
        );
        let before = SecurityDescriptor::read(raw_handle(&file))
            .unwrap()
            .snapshot()
            .unwrap();
        drop(file);

        assert_eq!(
            read_bounded_integrity_file(&path, 64),
            IntegrityFileRead::Unsafe
        );
        let reopened = OpenOptions::new()
            .access_mode(FILE_GENERIC_READ | READ_CONTROL)
            .open(path)
            .unwrap();
        assert_eq!(
            SecurityDescriptor::read(raw_handle(&reopened))
                .unwrap()
                .snapshot()
                .unwrap(),
            before
        );
    }

    #[test]
    fn integrity_read_rejects_an_active_writer() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let path = sandbox_path.join("trust.json");
        write_current_user_owned_file_for_tests(&path, b"{}").unwrap();
        let _writer = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();

        assert_eq!(
            read_bounded_integrity_file(&path, 64),
            IntegrityFileRead::Unsafe
        );
    }

    #[test]
    fn integrity_read_rejects_active_directory_mutators() {
        for hold_parent in [false, true] {
            let sandbox = tempfile::tempdir().unwrap();
            let sandbox_path = canonical_test_directory(sandbox.path());
            let ancestor = sandbox_path.join("config");
            let parent = ancestor.join("agent");
            std::fs::create_dir_all(&parent).unwrap();
            let path = parent.join("trust.json");
            write_current_user_owned_file_for_tests(&path, b"{}").unwrap();
            let held = if hold_parent { &parent } else { &ancestor };
            let _mutator = OpenOptions::new()
                .access_mode(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
                .open(held)
                .unwrap();

            assert_eq!(
                read_bounded_integrity_file(&path, 64),
                IntegrityFileRead::Unsafe
            );
        }
    }

    #[test]
    fn canonical_project_path_uses_real_dos_spelling() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let project = sandbox_path.join("MixedCase");
        std::fs::create_dir(&project).unwrap();
        let lower = sandbox_path.join("mixedcase");

        assert_eq!(canonical_nofollow_directory_path(&lower).unwrap(), project);
    }

    #[test]
    fn canonical_project_path_rejects_reparse_aliases() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let target = sandbox_path.join("target");
        let alias = sandbox_path.join("alias");
        std::fs::create_dir(&target).unwrap();
        std::os::windows::fs::symlink_dir(&target, &alias)
            .expect("Windows CI must support creating a test reparse point");

        assert!(canonical_nofollow_directory_path(&alias).is_err());
        assert!(target.is_dir());
    }

    #[test]
    fn structural_canonicalization_allows_writers_but_not_delete_authority() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let ancestor = sandbox_path.join("config");
        let project = ancestor.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let trust_store = project.join("trust.json");
        write_current_user_owned_file_for_tests(&trust_store, b"{}").unwrap();

        let writer = OpenOptions::new()
            .access_mode(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
            .open(&ancestor)
            .unwrap();
        assert_eq!(
            canonical_nofollow_directory_path(&project).unwrap(),
            project
        );
        assert_eq!(
            read_bounded_integrity_file(&trust_store, 64),
            IntegrityFileRead::Unsafe
        );
        drop(writer);

        let _deleter = OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
            .open(&ancestor)
            .unwrap();
        assert!(canonical_nofollow_directory_path(&project).is_err());
    }

    #[test]
    fn structural_canonicalization_does_not_require_dacl_read_authority() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let project = sandbox_path.join("project");
        std::fs::create_dir(&project).unwrap();
        let trust_store = project.join("trust.json");
        write_current_user_owned_file_for_tests(&trust_store, b"{}").unwrap();
        let executable = project.join("pi.exe");
        std::fs::write(&executable, b"fixture").unwrap();
        let directory = open_directory(
            &project,
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
        );
        let current = TokenUserBuffer::current().unwrap();
        install_test_structural_only_dacl(raw_handle(&directory), current.sid);
        drop(directory);

        assert!(
            OpenOptions::new()
                .access_mode(READ_CONTROL)
                .custom_flags(PRIVATE_DIRECTORY_OPEN_FLAGS)
                .open(&project)
                .is_err()
        );
        assert_eq!(
            canonical_nofollow_directory_path(&project).unwrap(),
            project
        );
        assert_eq!(
            read_bounded_integrity_file(&trust_store, 64),
            IntegrityFileRead::Unsafe
        );
        assert!(validate_executable_path(&executable).is_err());
    }

    #[test]
    fn retained_launch_ancestors_cannot_be_renamed() {
        let sandbox = tempfile::tempdir().unwrap();
        let sandbox_path = canonical_test_directory(sandbox.path());
        let bin = sandbox_path.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let executable_path = bin.join("pi.exe");
        std::fs::write(&executable_path, b"fixture").unwrap();
        let executable = validate_executable_path(&executable_path).unwrap();

        assert!(std::fs::rename(&bin, sandbox_path.join("moved")).is_err());
        executable.revalidate_path_identity().unwrap();
    }

    #[test]
    fn launch_validator_rejects_unsupported_namespaces_and_alias_syntax() {
        for path in [
            Path::new("pi.exe"),
            Path::new(r"C:pi.exe"),
            Path::new(r"\\server\share\pi.exe"),
            Path::new(r"\\?\C:\pi.exe"),
            Path::new(r"C:\safe\pi.exe:stream"),
            Path::new(r"C:\safe\..\pi.exe"),
            Path::new(r"C:\safe\.\pi.exe"),
            Path::new(r"C:\safe\\pi.exe"),
            Path::new(r"C:/safe/pi.exe"),
            Path::new(r"C:\safe\NUL.txt"),
            Path::new(r"C:\safe\COM1.exe"),
            Path::new(r"C:\safe\CONIN$.exe"),
            Path::new(r"C:\safe\CONOUT$.exe"),
            Path::new("C:\\safe\\LPT².txt"),
        ] {
            assert!(validate_executable_path(path).is_err(), "{path:?}");
        }
    }

    #[test]
    fn launch_path_parser_enforces_component_and_depth_limits() {
        let oversized_component =
            format!(r"C:\safe\{}", "a".repeat(MAX_LAUNCH_COMPONENT_UNITS + 1));
        assert!(local_drive_path(Path::new(&oversized_component)).is_err());

        let too_deep = format!(
            "C:\\{}",
            std::iter::repeat_n("a", MAX_LAUNCH_PATH_COMPONENTS + 1)
                .collect::<Vec<_>>()
                .join("\\")
        );
        assert!(local_drive_path(Path::new(&too_deep)).is_err());
    }

    #[test]
    fn launch_validator_refuses_untrusted_write_authority_without_repair() {
        let sandbox = tempfile::tempdir().unwrap();
        let executable_path = sandbox.path().join("pi.exe");
        std::fs::write(&executable_path, b"fixture").unwrap();
        let executable = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC)
            .open(&executable_path)
            .unwrap();
        let current = TokenUserBuffer::current().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_dacl(
            raw_handle(&executable),
            &[current.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
            PROTECTED_DACL_SECURITY_INFORMATION,
        )
        .unwrap();
        let before = SecurityDescriptor::read(raw_handle(&executable))
            .unwrap()
            .snapshot()
            .unwrap();
        drop(executable);

        assert!(validate_executable_path(&executable_path).is_err());
        let reopened = OpenOptions::new()
            .read(true)
            .open(&executable_path)
            .unwrap();
        let after = SecurityDescriptor::read(raw_handle(&reopened))
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(after, before);
        let trusted = TrustedLaunchSids::current().unwrap();
        assert!(
            require_path_authority(
                raw_handle(&reopened),
                PathLevel::File,
                OwnerPolicy::Trusted,
                &trusted
            )
            .is_err()
        );
    }

    #[test]
    fn private_directory_repair_is_exact_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        create_private_directory(&parent, std::ffi::OsStr::new("private")).unwrap();
        let directory = open_directory(&root.path().join("private"), PRIVATE_MUTATE_ACCESS);
        repair_private_directory(&directory).unwrap();
        inspect_private_directory(&directory).unwrap();
        repair_private_directory(&directory).unwrap();
        inspect_private_directory(&directory).unwrap();
    }

    #[test]
    fn windows_path_overlap_uses_ordinal_case_and_rejects_ambiguous_components() {
        assert!(
            paths_overlap_case_insensitive(
                Path::new(r"C:\Authority"),
                Path::new(r"c:\authority\State")
            )
            .unwrap()
        );
        assert!(
            paths_overlap_case_insensitive(Path::new(r"C:\Ä"), Path::new(r"c:\ä\State")).unwrap()
        );
        assert!(
            paths_overlap_case_insensitive(Path::new(r"C:\Authority."), Path::new(r"C:\Other"))
                .is_err()
        );
        let ill_formed =
            std::ffi::OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0xd800]);
        assert!(
            paths_overlap_case_insensitive(Path::new(&ill_formed), Path::new(r"C:\Other")).is_err()
        );
    }

    #[test]
    fn inspection_refuses_foreign_access_without_repairing_it() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        create_private_directory(&parent, std::ffi::OsStr::new("private")).unwrap();
        let directory = open_directory(&root.path().join("private"), PRIVATE_MUTATE_ACCESS);
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_private_dacl(
            raw_handle(&directory),
            &[current.sid, system.sid, world.sid],
            PRIVATE_DIRECTORY_ACE_FLAGS,
        )
        .unwrap();
        assert!(inspect_private_directory(&directory).is_err());
        assert!(inspect_private_directory(&directory).is_err());
        repair_private_directory(&directory).unwrap();
        inspect_private_directory(&directory).unwrap();
    }

    #[test]
    fn inspection_refuses_an_unprotected_exact_dacl_until_authorized_repair() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        create_private_directory(&parent, std::ffi::OsStr::new("private")).unwrap();
        let directory = open_directory(&root.path().join("private"), PRIVATE_MUTATE_ACCESS);
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        install_dacl(
            raw_handle(&directory),
            &[current.sid, system.sid],
            PRIVATE_DIRECTORY_ACE_FLAGS,
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        )
        .unwrap();

        assert!(inspect_private_directory(&directory).is_err());
        assert!(inspect_private_directory(&directory).is_err());
        repair_private_directory(&directory).unwrap();
        inspect_private_directory(&directory).unwrap();
    }

    #[test]
    fn single_link_file_inspection_rejects_alias_after_descriptor_validation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private-file");
        let alias = root.path().join("external-alias");
        let parent = open_parent(root.path());
        let file = create_private_file(&parent, std::ffi::OsStr::new("private-file")).unwrap();
        std::fs::hard_link(path, alias).unwrap();

        inspect_private_file(&file).unwrap();
        assert!(inspect_private_single_link_file(&file).is_err());
    }

    #[test]
    fn exact_handle_deletion_removes_identity_matched_private_objects() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        let expected_file_identity = file_identity(&file).unwrap();
        let directory =
            create_private_directory(&parent, std::ffi::OsStr::new("directory")).unwrap();
        let directory_identity = file_identity(&directory).unwrap();
        drop((file, directory));

        delete_owned_file(
            &parent,
            std::ffi::OsStr::new("file"),
            expected_file_identity,
        )
        .unwrap();
        delete_owned_directory(
            &parent,
            std::ffi::OsStr::new("directory"),
            directory_identity,
        )
        .unwrap();

        assert!(!root.path().join("file").exists());
        assert!(!root.path().join("directory").exists());
    }

    #[test]
    fn handle_bound_promotion_renames_exact_files_and_directories() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let file = create_private_file(&parent, std::ffi::OsStr::new("file-staged")).unwrap();
        let expected_file_identity = file_identity(&file).unwrap();
        let directory =
            create_private_directory(&parent, std::ffi::OsStr::new("directory-staged")).unwrap();
        let directory_identity = file_identity(&directory).unwrap();
        drop((file, directory));

        promote_owned_file(
            &parent,
            std::ffi::OsStr::new("file-staged"),
            std::ffi::OsStr::new("file-final"),
            std::ffi::OsStr::new("file-rollback"),
            expected_file_identity,
        )
        .unwrap();
        promote_owned_directory(
            &parent,
            std::ffi::OsStr::new("directory-staged"),
            std::ffi::OsStr::new("directory-final"),
            std::ffi::OsStr::new("directory-rollback"),
            directory_identity,
        )
        .unwrap();

        assert!(!root.path().join("file-staged").exists());
        assert!(root.path().join("file-final").is_file());
        assert!(!root.path().join("directory-staged").exists());
        assert!(root.path().join("directory-final").is_dir());
    }

    #[test]
    fn handle_bound_move_crosses_owned_directories_without_replacement() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source_parent =
            create_private_directory(&parent, std::ffi::OsStr::new("source-parent")).unwrap();
        let destination_parent =
            create_private_directory(&parent, std::ffi::OsStr::new("destination-parent")).unwrap();
        let file = create_owned_file(&source_parent, std::ffi::OsStr::new("file")).unwrap();
        let expected_file_identity = file_identity(&file).unwrap();
        let directory =
            create_owned_directory(&source_parent, std::ffi::OsStr::new("directory")).unwrap();
        let directory_identity = file_identity(&directory).unwrap();
        drop((file, directory));

        move_owned_file(
            &source_parent,
            std::ffi::OsStr::new("file"),
            &destination_parent,
            std::ffi::OsStr::new("file"),
            std::ffi::OsStr::new("file-rollback"),
            expected_file_identity,
        )
        .unwrap();
        move_owned_directory(
            &source_parent,
            std::ffi::OsStr::new("directory"),
            &destination_parent,
            std::ffi::OsStr::new("directory"),
            std::ffi::OsStr::new("directory-rollback"),
            directory_identity,
        )
        .unwrap();

        assert!(!root.path().join("source-parent/file").exists());
        assert!(root.path().join("destination-parent/file").is_file());
        assert!(!root.path().join("source-parent/directory").exists());
        assert!(root.path().join("destination-parent/directory").is_dir());

        let collision =
            create_owned_file(&source_parent, std::ffi::OsStr::new("collision")).unwrap();
        let collision_identity = file_identity(&collision).unwrap();
        create_owned_file(&destination_parent, std::ffi::OsStr::new("collision")).unwrap();
        drop(collision);
        assert_eq!(
            move_owned_file(
                &source_parent,
                std::ffi::OsStr::new("collision"),
                &destination_parent,
                std::ffi::OsStr::new("collision"),
                std::ffi::OsStr::new("collision-rollback"),
                collision_identity,
            ),
            Err(OwnedObjectPromotionError::Failed)
        );
        assert!(root.path().join("source-parent/collision").is_file());
        assert!(root.path().join("destination-parent/collision").is_file());
    }

    #[test]
    fn nonempty_directory_retirement_preserves_identity_and_refuses_collisions() {
        use std::ffi::OsStr;

        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source = create_private_directory(&parent, OsStr::new("active")).unwrap();
        let history = create_private_directory(&parent, OsStr::new("history")).unwrap();
        let operation = create_private_directory(&source, OsStr::new("operation")).unwrap();
        let operation_identity = file_identity(&operation).unwrap();
        let mut record = create_private_file(&operation, OsStr::new("record")).unwrap();
        record.write_all(b"retained terminal evidence").unwrap();
        record.sync_all().unwrap();
        let record_identity = file_identity(&record).unwrap();
        drop(record);

        // The non-delete-sharing directory lease must be released before movement.
        assert_eq!(
            move_owned_directory(
                &source,
                OsStr::new("operation"),
                &history,
                OsStr::new("operation"),
                OsStr::new("retirement-rollback"),
                operation_identity,
            ),
            Err(OwnedObjectPromotionError::Failed)
        );
        assert!(!root.path().join("history/operation").exists());
        drop(operation);

        move_owned_directory(
            &source,
            OsStr::new("operation"),
            &history,
            OsStr::new("operation"),
            OsStr::new("retirement-rollback"),
            operation_identity,
        )
        .unwrap();
        assert!(!root.path().join("active/operation").exists());
        let archived = open_parent(&root.path().join("history/operation"));
        assert_eq!(file_identity(&archived).unwrap(), operation_identity);
        let mut record = open_private_file(&archived, OsStr::new("record")).unwrap();
        assert_eq!(file_identity(&record).unwrap(), record_identity);
        let mut bytes = Vec::new();
        record.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"retained terminal evidence");
        drop((record, archived));

        let collision = create_private_directory(&source, OsStr::new("operation")).unwrap();
        let collision_identity = file_identity(&collision).unwrap();
        drop(collision);
        assert_eq!(
            move_owned_directory(
                &source,
                OsStr::new("operation"),
                &history,
                OsStr::new("operation"),
                OsStr::new("retirement-rollback"),
                collision_identity,
            ),
            Err(OwnedObjectPromotionError::Failed)
        );
        assert_eq!(
            file_identity(&open_parent(&root.path().join("active/operation"))).unwrap(),
            collision_identity
        );
        assert_eq!(
            file_identity(&open_parent(&root.path().join("history/operation"))).unwrap(),
            operation_identity
        );
        assert_eq!(
            std::fs::read(root.path().join("history/operation/record")).unwrap(),
            bytes
        );
    }

    #[test]
    fn private_directory_flush_is_identity_bound_and_preserves_contents() {
        use std::ffi::OsStr;

        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let directory = create_private_directory(&parent, OsStr::new("directory")).unwrap();
        let identity = file_identity(&directory).unwrap();
        let mut child = create_private_file(&directory, OsStr::new("evidence")).unwrap();
        child.write_all(b"retained evidence").unwrap();
        child.sync_all().unwrap();
        let child_identity = file_identity(&child).unwrap();
        drop(child);

        flush_private_directory(&parent, OsStr::new("directory"), identity).unwrap();
        let other = create_private_directory(&parent, OsStr::new("other")).unwrap();
        assert!(
            flush_private_directory(
                &parent,
                OsStr::new("directory"),
                file_identity(&other).unwrap()
            )
            .is_err()
        );
        assert_eq!(file_identity(&directory).unwrap(), identity);
        let mut child = open_private_file(&directory, OsStr::new("evidence")).unwrap();
        assert_eq!(file_identity(&child).unwrap(), child_identity);
        let mut bytes = Vec::new();
        child.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"retained evidence");
        assert!(
            flush_private_directory(&directory, OsStr::new("evidence"), child_identity).is_err()
        );
    }

    #[test]
    fn cross_parent_move_rolls_back_to_source_or_reports_retained_destination() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source_parent =
            create_private_directory(&parent, std::ffi::OsStr::new("source-parent")).unwrap();
        let destination_parent =
            create_private_directory(&parent, std::ffi::OsStr::new("destination-parent")).unwrap();
        let mut file = create_owned_file(&source_parent, std::ffi::OsStr::new("source")).unwrap();
        file.write_all(b"rollback bytes").unwrap();
        file.sync_all().unwrap();
        let identity = file_identity(&file).unwrap();
        drop(file);

        assert_eq!(
            relocate_owned_object_with_hooks(
                &source_parent,
                std::ffi::OsStr::new("source"),
                &destination_parent,
                std::ffi::OsStr::new("destination"),
                &source_parent,
                std::ffi::OsStr::new("rollback"),
                identity,
                PrivateObjectKind::File,
                OwnedObjectPromotionHooks {
                    after_verification: || {},
                    after_promotion: || Err(WindowsSecurityError),
                },
            ),
            Err(OwnedObjectPromotionError::Failed)
        );
        assert!(!root.path().join("source-parent/source").exists());
        assert!(!root.path().join("destination-parent/destination").exists());
        assert_eq!(
            std::fs::read(root.path().join("source-parent/rollback")).unwrap(),
            b"rollback bytes"
        );
        let rollback = OpenOptions::new()
            .read(true)
            .open(root.path().join("source-parent/rollback"))
            .unwrap();
        assert_eq!(file_identity(&rollback).unwrap(), identity);

        let second = create_owned_file(&source_parent, std::ffi::OsStr::new("second")).unwrap();
        let second_identity = file_identity(&second).unwrap();
        create_owned_file(&source_parent, std::ffi::OsStr::new("occupied-rollback")).unwrap();
        drop(second);
        assert_eq!(
            relocate_owned_object_with_hooks(
                &source_parent,
                std::ffi::OsStr::new("second"),
                &destination_parent,
                std::ffi::OsStr::new("retained-destination"),
                &source_parent,
                std::ffi::OsStr::new("occupied-rollback"),
                second_identity,
                PrivateObjectKind::File,
                OwnedObjectPromotionHooks {
                    after_verification: || {},
                    after_promotion: || Err(WindowsSecurityError),
                },
            ),
            Err(OwnedObjectPromotionError::RollbackFailed)
        );
        assert!(!root.path().join("source-parent/second").exists());
        let retained = OpenOptions::new()
            .read(true)
            .open(root.path().join("destination-parent/retained-destination"))
            .unwrap();
        assert_eq!(file_identity(&retained).unwrap(), second_identity);
    }

    #[test]
    fn single_link_deletion_rechecks_links_on_the_exact_handle() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        let identity = file_identity(&file).unwrap();
        drop(file);

        assert!(
            delete_owned_object_with_hook(
                &parent,
                std::ffi::OsStr::new("file"),
                identity,
                PrivateObjectKind::File,
                true,
                || std::fs::hard_link(root.path().join("file"), root.path().join("alias")).unwrap(),
            )
            .is_err()
        );
        assert!(root.path().join("file").is_file());
        assert!(root.path().join("alias").is_file());
    }

    #[test]
    fn handle_bound_promotion_refuses_collisions_and_hardlinked_files() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source = create_private_file(&parent, std::ffi::OsStr::new("source")).unwrap();
        let identity = file_identity(&source).unwrap();
        create_private_file(&parent, std::ffi::OsStr::new("collision")).unwrap();
        drop(source);

        assert_eq!(
            promote_owned_file(
                &parent,
                std::ffi::OsStr::new("source"),
                std::ffi::OsStr::new("collision"),
                std::ffi::OsStr::new("rollback"),
                identity,
            ),
            Err(OwnedObjectPromotionError::Failed)
        );
        std::fs::hard_link(root.path().join("source"), root.path().join("alias")).unwrap();
        assert!(
            promote_owned_file(
                &parent,
                std::ffi::OsStr::new("source"),
                std::ffi::OsStr::new("final"),
                std::ffi::OsStr::new("rollback"),
                identity,
            )
            .is_err()
        );
        assert!(root.path().join("source").is_file());
        assert!(root.path().join("collision").is_file());
        assert!(root.path().join("alias").is_file());
        assert!(!root.path().join("final").exists());
    }

    #[test]
    fn handle_bound_promotion_blocks_a_verified_source_replacement() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source_path = root.path().join("source");
        let displaced_path = root.path().join("displaced");
        let source = create_private_file(&parent, std::ffi::OsStr::new("source")).unwrap();
        let identity = file_identity(&source).unwrap();
        drop(source);

        promote_owned_object_with_hook(
            &parent,
            std::ffi::OsStr::new("source"),
            std::ffi::OsStr::new("final"),
            std::ffi::OsStr::new("rollback"),
            identity,
            PrivateObjectKind::File,
            || assert!(std::fs::rename(&source_path, &displaced_path).is_err()),
        )
        .unwrap();

        assert!(!source_path.exists());
        assert!(!displaced_path.exists());
        assert!(root.path().join("final").is_file());
    }

    #[test]
    fn handle_bound_promotion_rolls_back_if_a_link_appears_after_verification() {
        use std::cell::Cell;

        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source_path = root.path().join("source");
        let alias_path = root.path().join("alias");
        let source = create_private_file(&parent, std::ffi::OsStr::new("source")).unwrap();
        let identity = file_identity(&source).unwrap();
        drop(source);
        let link_created = Cell::new(false);

        let result = promote_owned_object_with_hook(
            &parent,
            std::ffi::OsStr::new("source"),
            std::ffi::OsStr::new("final"),
            std::ffi::OsStr::new("rollback"),
            identity,
            PrivateObjectKind::File,
            || link_created.set(std::fs::hard_link(&source_path, &alias_path).is_ok()),
        );

        assert!(!source_path.exists());
        if link_created.get() {
            assert_eq!(result, Err(OwnedObjectPromotionError::Failed));
            assert!(!root.path().join("final").exists());
            assert!(root.path().join("rollback").is_file());
            assert!(alias_path.is_file());
        } else {
            result.unwrap();
            assert!(root.path().join("final").is_file());
            assert!(!root.path().join("rollback").exists());
            assert!(!alias_path.exists());
        }
    }

    #[test]
    fn handle_bound_promotion_reports_successful_and_failed_rollbacks() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source = create_private_file(&parent, std::ffi::OsStr::new("source")).unwrap();
        let identity = file_identity(&source).unwrap();
        drop(source);
        assert_eq!(
            promote_owned_object_with_hooks(
                &parent,
                std::ffi::OsStr::new("source"),
                std::ffi::OsStr::new("final"),
                std::ffi::OsStr::new("rollback"),
                identity,
                PrivateObjectKind::File,
                OwnedObjectPromotionHooks {
                    after_verification: || {},
                    after_promotion: || Err(WindowsSecurityError),
                },
            ),
            Err(OwnedObjectPromotionError::Failed)
        );
        assert!(!root.path().join("source").exists());
        assert!(!root.path().join("final").exists());
        assert!(root.path().join("rollback").is_file());

        let blocked = create_private_file(&parent, std::ffi::OsStr::new("blocked")).unwrap();
        let identity = file_identity(&blocked).unwrap();
        drop(blocked);
        create_private_file(&parent, std::ffi::OsStr::new("collision")).unwrap();
        assert_eq!(
            promote_owned_object_with_hooks(
                &parent,
                std::ffi::OsStr::new("blocked"),
                std::ffi::OsStr::new("blocked-final"),
                std::ffi::OsStr::new("collision"),
                identity,
                PrivateObjectKind::File,
                OwnedObjectPromotionHooks {
                    after_verification: || {},
                    after_promotion: || Err(WindowsSecurityError),
                },
            ),
            Err(OwnedObjectPromotionError::RollbackFailed)
        );
        assert!(!root.path().join("blocked").exists());
        assert!(root.path().join("blocked-final").is_file());
        assert!(root.path().join("collision").is_file());
        assert!(root.path().join("rollback").is_file());
    }

    #[test]
    fn handle_bound_promotion_accepts_a_one_unit_destination_name() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let source = create_private_file(&parent, std::ffi::OsStr::new("source")).unwrap();
        let identity = file_identity(&source).unwrap();
        drop(source);

        promote_owned_file(
            &parent,
            std::ffi::OsStr::new("source"),
            std::ffi::OsStr::new("x"),
            std::ffi::OsStr::new("rollback"),
            identity,
        )
        .unwrap();

        assert!(root.path().join("x").is_file());
    }

    #[test]
    fn exact_handle_deletion_ignores_only_the_read_only_attribute() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let path = root.path().join("read-only");
        let file = create_private_file(&parent, std::ffi::OsStr::new("read-only")).unwrap();
        let identity = file_identity(&file).unwrap();
        drop(file);
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();

        delete_owned_file(&parent, std::ffi::OsStr::new("read-only"), identity).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn exact_handle_deletion_refuses_nonempty_directories() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let directory =
            create_private_directory(&parent, std::ffi::OsStr::new("nonempty")).unwrap();
        let identity = file_identity(&directory).unwrap();
        create_private_file(&directory, std::ffi::OsStr::new("child")).unwrap();
        drop(directory);

        assert!(
            delete_owned_directory(&parent, std::ffi::OsStr::new("nonempty"), identity).is_err()
        );
        assert!(root.path().join("nonempty/child").is_file());
    }

    #[test]
    fn exact_handle_deletion_refuses_an_identity_mismatch_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let path = root.path().join("file");
        let file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        let mut wrong_identity = file_identity(&file).unwrap();
        wrong_identity.file_id[0] ^= 1;
        drop(file);

        assert!(delete_owned_file(&parent, std::ffi::OsStr::new("file"), wrong_identity).is_err());
        assert!(path.is_file());
    }

    #[test]
    fn exact_handle_deletion_refuses_wrong_object_kinds_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        let expected_file_identity = file_identity(&file).unwrap();
        let directory =
            create_private_directory(&parent, std::ffi::OsStr::new("directory")).unwrap();
        let directory_identity = file_identity(&directory).unwrap();
        drop((file, directory));

        assert!(
            delete_owned_directory(
                &parent,
                std::ffi::OsStr::new("file"),
                expected_file_identity,
            )
            .is_err()
        );
        assert!(
            delete_owned_file(
                &parent,
                std::ffi::OsStr::new("directory"),
                directory_identity,
            )
            .is_err()
        );
        assert!(root.path().join("file").is_file());
        assert!(root.path().join("directory").is_dir());
    }

    #[test]
    fn exact_handle_deletion_unlinks_only_the_selected_hard_link_without_repairing_authority() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let path = root.path().join("file");
        let alias_path = root.path().join("external-alias");
        let mut file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        file.write_all(b"shared-content").unwrap();
        let identity = file_identity(&file).unwrap();
        drop(file);
        let file = open_file_descriptor_mutator(&path);
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_private_dacl(
            raw_handle(&file),
            &[current.sid, system.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
        )
        .unwrap();
        inspect_exact_descriptor(
            raw_handle(&file),
            current.sid,
            &[current.sid, system.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
            true,
            PrivateObjectKind::File,
        )
        .unwrap();
        drop(file);
        std::fs::hard_link(&path, &alias_path).unwrap();

        delete_owned_file(&parent, std::ffi::OsStr::new("file"), identity).unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&alias_path).unwrap(), b"shared-content");
        let mut options = OpenOptions::new();
        options.access_mode(PRIVATE_FILE_INSPECT_ACCESS);
        let alias = options.open(alias_path).unwrap();
        inspect_exact_descriptor(
            raw_handle(&alias),
            current.sid,
            &[current.sid, system.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
            true,
            PrivateObjectKind::File,
        )
        .unwrap();
    }

    #[test]
    fn exact_handle_deletion_refuses_reparse_points_without_touching_the_target() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let target_path = root.path().join("target");
        let link_path = root.path().join("link");
        let target = create_private_file(&parent, std::ffi::OsStr::new("target")).unwrap();
        let target_identity = file_identity(&target).unwrap();
        drop(target);
        std::os::windows::fs::symlink_file(&target_path, &link_path)
            .expect("Windows CI must support creating a test reparse point");

        assert!(delete_owned_file(&parent, std::ffi::OsStr::new("link"), target_identity).is_err());
        assert!(
            link_path
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(target_path.is_file());
    }

    #[test]
    fn exact_handle_deletion_never_deletes_a_same_name_replacement() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let path = root.path().join("file");
        let displaced_path = root.path().join("displaced");
        let file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        let identity = file_identity(&file).unwrap();
        drop(file);

        delete_owned_object_with_hook(
            &parent,
            std::ffi::OsStr::new("file"),
            identity,
            PrivateObjectKind::File,
            false,
            || {
                std::fs::rename(&path, &displaced_path).unwrap();
                std::fs::write(&path, b"replacement").unwrap();
            },
        )
        .unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert!(!displaced_path.exists());
    }

    #[test]
    fn newly_created_private_objects_have_exact_security() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let directory =
            create_private_directory(&parent, std::ffi::OsStr::new("private-dir")).unwrap();
        let file = create_private_file(&parent, std::ffi::OsStr::new("private-file")).unwrap();
        let nested = create_private_file(&directory, std::ffi::OsStr::new("nested-file")).unwrap();

        inspect_private_directory(&directory).unwrap();
        inspect_private_file(&file).unwrap();
        inspect_private_file(&nested).unwrap();
        inspect_owned_directory(&directory).unwrap();
        inspect_owned_file(&file).unwrap();
        inspect_owned_file(&nested).unwrap();
        let concurrent = open_directory(&root.path().join("private-dir"), PRIVATE_MUTATE_ACCESS);
        inspect_private_directory(&concurrent).unwrap();
        drop(concurrent);
        drop((nested, file, directory));

        let directory = open_directory(&root.path().join("private-dir"), PRIVATE_MUTATE_ACCESS);
        let mut options = OpenOptions::new();
        options.access_mode(PRIVATE_FILE_INSPECT_ACCESS);
        let file = options.open(root.path().join("private-file")).unwrap();
        let nested = options
            .open(root.path().join("private-dir/nested-file"))
            .unwrap();
        inspect_private_directory(&directory).unwrap();
        inspect_private_file(&file).unwrap();
        inspect_private_file(&nested).unwrap();
    }

    #[test]
    fn newly_created_owned_objects_inherit_access_but_bind_the_current_owner() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let inherited_parent =
            create_private_directory(&parent, std::ffi::OsStr::new("inherited-parent")).unwrap();
        let directory =
            create_owned_directory(&inherited_parent, std::ffi::OsStr::new("owned-dir")).unwrap();
        let file =
            create_owned_file(&inherited_parent, std::ffi::OsStr::new("owned-file")).unwrap();
        let nested = create_owned_file(&directory, std::ffi::OsStr::new("nested-file")).unwrap();
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();

        inspect_owned_directory(&directory).unwrap();
        inspect_owned_file(&file).unwrap();
        inspect_owned_file(&nested).unwrap();
        inspect_exact_descriptor(
            raw_handle(&directory),
            current.sid,
            &[current.sid, system.sid],
            PRIVATE_DIRECTORY_ACE_FLAGS | INHERITED_ACE as u8,
            false,
            PrivateObjectKind::Directory,
        )
        .unwrap();
        for inherited_file in [&file, &nested] {
            inspect_exact_descriptor(
                raw_handle(inherited_file),
                current.sid,
                &[current.sid, system.sid],
                INHERITED_ACE as u8,
                false,
                PrivateObjectKind::File,
            )
            .unwrap();
        }
    }

    #[test]
    fn owned_inspection_refuses_a_mismatched_expected_owner_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let file = create_private_file(&parent, std::ffi::OsStr::new("file")).unwrap();
        let system = WellKnownSid::local_system().unwrap();

        assert!(
            require_object_owner(raw_handle(&file), PrivateObjectKind::File, system.sid).is_err()
        );
        inspect_private_file(&file).unwrap();
        inspect_owned_file(&file).unwrap();
    }

    #[test]
    fn failed_private_creation_rolls_back_the_identity_bound_object() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let result = create_private_object_with_hook(
            &parent,
            std::ffi::OsStr::new("rolled-back"),
            PRIVATE_DIRECTORY_ACE_FLAGS,
            PrivateObjectKind::Directory,
            || Err(WindowsSecurityError),
        );

        assert_eq!(result.unwrap_err(), ObjectCreationError::Failed);
        assert_eq!(
            std::fs::symlink_metadata(root.path().join("rolled-back"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn rollback_scheduling_failure_is_explicit_and_leaves_exact_empty_state() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let result = create_owned_object_with_hooks(
            &parent,
            std::ffi::OsStr::new("residual"),
            DaclPolicy::ExactPrivate {
                ace_flags: PRIVATE_DIRECTORY_ACE_FLAGS,
            },
            PrivateObjectKind::Directory,
            ObjectCreationHooks {
                after_create: || Err(WindowsSecurityError),
                rollback: |_pending| Err(WindowsSecurityError),
                created_identity: identity_from_handle,
                after_directory_create_close: || {},
            },
        );

        assert_eq!(result.unwrap_err(), ObjectCreationError::RollbackFailed);
        assert_eq!(
            std::fs::read_dir(root.path().join("residual"))
                .unwrap()
                .count(),
            0
        );
        let residual = open_directory(&root.path().join("residual"), PRIVATE_MUTATE_ACCESS);
        inspect_private_directory(&residual).unwrap();
    }

    #[test]
    fn identity_capture_failure_uses_checked_rollback() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let result = create_owned_object_with_hooks(
            &parent,
            std::ffi::OsStr::new("identity-failure"),
            DaclPolicy::ExactPrivate {
                ace_flags: PRIVATE_DIRECTORY_ACE_FLAGS,
            },
            PrivateObjectKind::Directory,
            ObjectCreationHooks {
                after_create: || Ok(()),
                rollback: PendingCreation::rollback,
                created_identity: |_handle| Err(WindowsSecurityError),
                after_directory_create_close: || {},
            },
        );

        assert_eq!(result.unwrap_err(), ObjectCreationError::Failed);
        assert_eq!(
            std::fs::symlink_metadata(root.path().join("identity-failure"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn directory_handoff_refuses_a_replacement_without_mutating_it() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let created_path = root.path().join("created");
        let retained_path = root.path().join("retained");
        let replacement_marker = created_path.join("marker");
        let result = create_owned_object_with_hooks(
            &parent,
            std::ffi::OsStr::new("created"),
            DaclPolicy::ExactPrivate {
                ace_flags: PRIVATE_DIRECTORY_ACE_FLAGS,
            },
            PrivateObjectKind::Directory,
            ObjectCreationHooks {
                after_create: || Ok(()),
                rollback: PendingCreation::rollback,
                created_identity: identity_from_handle,
                after_directory_create_close: || {
                    std::fs::rename(&created_path, &retained_path).unwrap();
                    std::fs::create_dir(&created_path).unwrap();
                    std::fs::write(&replacement_marker, b"replacement").unwrap();
                },
            },
        );

        assert_eq!(result.unwrap_err(), ObjectCreationError::HandoffFailed);
        assert_eq!(std::fs::read(&replacement_marker).unwrap(), b"replacement");
        let retained = open_directory(&retained_path, PRIVATE_MUTATE_ACCESS);
        inspect_private_directory(&retained).unwrap();
    }

    #[test]
    fn repair_access_never_includes_owner_mutation() {
        assert_eq!(PRIVATE_MUTATE_ACCESS & WRITE_OWNER, 0);
        assert_eq!(PRIVATE_FILE_WRITE_ACCESS & WRITE_DAC, 0);
        assert_eq!(PRIVATE_FILE_WRITE_ACCESS & WRITE_OWNER, 0);
        assert_eq!(STRUCTURAL_DIRECTORY_ACCESS & WRITE_DAC, 0);
        assert_eq!(STRUCTURAL_DIRECTORY_ACCESS & WRITE_OWNER, 0);
        assert_eq!(STRUCTURAL_DIRECTORY_ACCESS & DELETE, 0);
        assert_eq!(PRIVATE_DIRECTORY_AUTHORITY_ACCESS & WRITE_DAC, 0);
        assert_eq!(PRIVATE_DIRECTORY_AUTHORITY_ACCESS & WRITE_OWNER, 0);
        assert_eq!(PRIVATE_DIRECTORY_AUTHORITY_ACCESS & DELETE, 0);
        assert_eq!(
            PRIVATE_DIRECTORY_AUTHORITY_ACCESS & STRUCTURAL_DIRECTORY_ACCESS,
            STRUCTURAL_DIRECTORY_ACCESS
        );
    }

    #[test]
    fn create_collision_never_changes_existing_authority_or_content() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let mut existing = create_private_file(&parent, std::ffi::OsStr::new("existing")).unwrap();
        existing.write_all(b"authority").unwrap();
        drop(existing);
        let existing_path = root.path().join("existing");
        let existing = open_file_descriptor_mutator(&existing_path);
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_private_dacl(
            raw_handle(&existing),
            &[current.sid, system.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
        )
        .unwrap();
        drop(existing);

        let collision = create_private_file(&parent, std::ffi::OsStr::new("existing"));
        assert_eq!(collision.unwrap_err(), ObjectCreationError::AlreadyExists);
        let mut options = OpenOptions::new();
        options.access_mode(PRIVATE_FILE_INSPECT_ACCESS);
        let mut existing = options.open(existing_path).unwrap();
        let mut content = Vec::new();
        existing.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"authority");
        assert!(inspect_private_file(&existing).is_err());
    }

    #[test]
    fn private_file_inspection_refuses_foreign_access_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        create_private_file(&parent, std::ffi::OsStr::new("private-file")).unwrap();
        let file = open_file_descriptor_mutator(&root.path().join("private-file"));
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_private_dacl(
            raw_handle(&file),
            &[current.sid, system.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
        )
        .unwrap();

        assert!(inspect_private_file(&file).is_err());
        assert!(inspect_private_file(&file).is_err());
        inspect_exact_descriptor(
            raw_handle(&file),
            current.sid,
            &[current.sid, system.sid, world.sid],
            PRIVATE_FILE_ACE_FLAGS,
            true,
            PrivateObjectKind::File,
        )
        .unwrap();
    }

    #[test]
    fn private_file_inspection_refuses_a_reparse_handle_without_touching_its_target() {
        let root = tempfile::tempdir().unwrap();
        let target_path = root.path().join("target");
        let link_path = root.path().join("link");
        let parent = open_parent(root.path());
        let target = create_private_file(&parent, std::ffi::OsStr::new("target")).unwrap();
        std::os::windows::fs::symlink_file(&target_path, &link_path)
            .expect("Windows CI must support creating a test reparse point");
        let mut link_options = OpenOptions::new();
        link_options
            .read(true)
            .write(true)
            .access_mode(PRIVATE_FILE_INSPECT_ACCESS)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let link = link_options.open(link_path).unwrap();

        assert!(inspect_private_file(&link).is_err());
        assert!(inspect_owned_file(&link).is_err());
        inspect_private_file(&target).unwrap();
    }

    fn synthetic_ace(ace_type: u8, subauthority_count: u8, extra_tail: usize) -> Vec<u8> {
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let sid_bytes = offset_of!(SID, SubAuthority) + size_of::<u32>();
        let ace_size = sid_offset + sid_bytes + extra_tail;
        let mut ace = vec![0_u8; ace_size];
        ace[0] = ace_type;
        ace[1] = PRIVATE_FILE_ACE_FLAGS;
        ace[2..4].copy_from_slice(&(ace_size as u16).to_le_bytes());
        ace[4..8].copy_from_slice(&FILE_ALL_ACCESS.to_le_bytes());
        ace[sid_offset] = 1;
        ace[sid_offset + 1] = subauthority_count;
        ace[sid_offset + 7] = 1;
        ace
    }

    #[test]
    fn bounded_ace_parser_refuses_truncated_oversized_and_trailed_sids() {
        let mut truncated = synthetic_ace(ACCESS_ALLOWED_ACE_TYPE, 1, 0);
        truncated[2..4].copy_from_slice(
            &((offset_of!(ACCESS_ALLOWED_ACE, SidStart) + size_of::<u32>()) as u16).to_le_bytes(),
        );
        let mut oversized = synthetic_ace(ACCESS_ALLOWED_ACE_TYPE, 15, 0);
        let mut trailed = synthetic_ace(ACCESS_ALLOWED_ACE_TYPE, 1, 4);
        let exact = synthetic_ace(ACCESS_ALLOWED_ACE_TYPE, 1, 0);

        for malformed in [&mut truncated, &mut oversized, &mut trailed] {
            // SAFETY: each vector contains at least the ACE header and the helper bounds all later
            // reads against the encoded AceSize before consulting the SID.
            assert!(
                unsafe {
                    validated_allowed_ace_sid(malformed.as_mut_ptr().cast(), PRIVATE_FILE_ACE_FLAGS)
                }
                .is_err()
            );
        }
        // SAFETY: this exact fixture contains a complete one-subauthority SID and access mask.
        assert!(
            unsafe {
                validated_allowed_ace_sid(exact.as_ptr().cast_mut().cast(), PRIVATE_FILE_ACE_FLAGS)
            }
            .is_ok()
        );
    }

    #[test]
    fn bounded_ace_parser_validates_deny_payloads_and_rejects_unknown_types() {
        let exact_deny = synthetic_ace(ACCESS_DENIED_ACE_TYPE, 1, 0);
        let mut malformed_deny = synthetic_ace(ACCESS_DENIED_ACE_TYPE, 1, 4);
        let unknown = synthetic_ace(2, 1, 0);

        // SAFETY: all fixtures contain a complete header; the parser bounds all later reads by it.
        assert!(
            unsafe {
                validated_simple_ace(
                    exact_deny.as_ptr().cast_mut().cast(),
                    ACCESS_DENIED_ACE_TYPE,
                )
            }
            .is_ok()
        );
        // SAFETY: the deliberately trailed fixture remains allocated for its declared ACE size.
        assert!(
            unsafe {
                validated_simple_ace(malformed_deny.as_mut_ptr().cast(), ACCESS_DENIED_ACE_TYPE)
            }
            .is_err()
        );
        // SAFETY: the complete synthetic fixture remains live for the parser call.
        assert!(
            unsafe {
                validated_simple_ace(unknown.as_ptr().cast_mut().cast(), ACCESS_ALLOWED_ACE_TYPE)
            }
            .is_err()
        );
    }

    #[test]
    fn native_identity_is_stable_per_object_and_changes_on_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("object");
        let retained = root.path().join("retained-object");
        std::fs::write(&path, b"first").unwrap();
        let first = std::fs::File::open(&path).unwrap();
        let second = std::fs::File::open(&path).unwrap();
        let first_identity = file_identity(&first).unwrap();
        assert_eq!(first_identity, file_identity(&second).unwrap());
        drop((first, second));
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, b"second").unwrap();
        let replacement = std::fs::File::open(&path).unwrap();
        assert_ne!(first_identity, file_identity(&replacement).unwrap());
    }

    #[test]
    fn native_identity_preserves_every_file_id_byte() {
        let information = FILE_ID_INFO {
            VolumeSerialNumber: 0x0123_4567_89ab_cdef,
            FileId: FILE_ID_128 {
                Identifier: [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
            },
        };

        assert_eq!(
            identity_from_information(information),
            WindowsFileIdentity {
                volume_serial_number: 0x0123_4567_89ab_cdef,
                file_id: [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
            }
        );
    }

    #[test]
    fn install_directory_retains_complete_authority_and_detects_acl_change() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let install = create_private_directory(&parent, std::ffi::OsStr::new("install")).unwrap();
        let install_path = root.path().join("install");
        drop(install);
        drop(parent);
        let install_path = canonical_test_directory(&install_path);
        let mut mixed_case = install_path.as_os_str().encode_wide().collect::<Vec<_>>();
        let unit = mixed_case
            .iter_mut()
            .find(|unit| {
                (**unit >= b'a' as u16 && **unit <= b'z' as u16)
                    || (**unit >= b'A' as u16 && **unit <= b'Z' as u16)
            })
            .unwrap();
        *unit = if *unit >= b'a' as u16 {
            *unit - (b'a' - b'A') as u16
        } else {
            *unit + (b'a' - b'A') as u16
        };
        let mixed_case = PathBuf::from(std::ffi::OsString::from_wide(&mixed_case));
        let validated = validate_install_directory(&mixed_case).unwrap();
        let install = open_directory_descriptor_mutator(&install_path);
        assert_eq!(validated.path(), install_path);
        assert_eq!(
            validated.identities().last(),
            Some(&file_identity(validated.directory().unwrap()).unwrap())
        );
        let child = create_private_directory(
            validated.directory().unwrap(),
            std::ffi::OsStr::new("private-child"),
        )
        .unwrap();
        inspect_private_directory(&child).unwrap();

        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_private_dacl(
            raw_handle(&install),
            &[current.sid, system.sid, world.sid],
            PRIVATE_DIRECTORY_ACE_FLAGS,
        )
        .unwrap();
        assert!(validated.revalidate().is_err());
    }

    #[test]
    fn elevation_classification_and_current_process_boundary_fail_closed() {
        assert_eq!(classify_unelevated(false), Ok(()));
        assert_eq!(classify_unelevated(true), Err(WindowsSecurityError));
        let elevated = current_process_is_elevated().unwrap();
        assert_eq!(require_unelevated_process().is_err(), elevated);
    }

    #[test]
    fn install_directory_guard_permits_child_promotion_but_blocks_directory_replacement() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let install = create_private_directory(&parent, std::ffi::OsStr::new("install")).unwrap();
        let file = create_private_file(&install, std::ffi::OsStr::new("source")).unwrap();
        let identity = file_identity(&file).unwrap();
        drop(file);
        drop(install);
        let path = canonical_test_directory(&root.path().join("install"));
        let validated = validate_install_directory(&path).unwrap();

        promote_owned_file(
            validated.directory().unwrap(),
            std::ffi::OsStr::new("source"),
            std::ffi::OsStr::new("destination"),
            std::ffi::OsStr::new("rollback"),
            identity,
        )
        .unwrap();
        let promoted = open_private_file(
            validated.directory().unwrap(),
            std::ffi::OsStr::new("destination"),
        )
        .unwrap();
        assert_eq!(file_identity(&promoted).unwrap(), identity);
        drop(promoted);
        assert!(!path.join("source").exists());
        assert!(std::fs::rename(&path, root.path().join("displaced-install")).is_err());
        validated.revalidate().unwrap();
    }

    #[test]
    fn install_directory_revalidation_detects_intermediate_ancestor_acl_change() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let ancestor =
            create_private_directory(&parent, std::ffi::OsStr::new("authority")).unwrap();
        let destination =
            create_private_directory(&ancestor, std::ffi::OsStr::new("destination")).unwrap();
        drop(destination);
        let destination_path = root.path().join("authority").join("destination");
        drop(ancestor);
        drop(parent);
        let destination_path = canonical_test_directory(&destination_path);
        let validated = validate_install_directory(&destination_path).unwrap();
        let ancestor = open_directory_descriptor_mutator(&root.path().join("authority"));

        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        install_private_dacl(
            raw_handle(&ancestor),
            &[current.sid, system.sid, world.sid],
            PRIVATE_DIRECTORY_ACE_FLAGS,
        )
        .unwrap();

        assert!(validated.revalidate().is_err());
    }

    #[test]
    fn install_directory_refuses_child_effective_untrusted_write_without_repair() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let directory = create_private_directory(&parent, std::ffi::OsStr::new("install")).unwrap();
        let install_path = root.path().join("install");
        drop(directory);
        drop(parent);
        let install_path = canonical_test_directory(&install_path);
        let directory = open_directory_descriptor_mutator(&install_path);
        let current = TokenUserBuffer::current().unwrap();
        let system = WellKnownSid::local_system().unwrap();
        let world = WellKnownSid::new(WinWorldSid).unwrap();
        let current_access = explicit_full_control(current.sid, 0);
        let system_access = explicit_full_control(system.sid, 0);
        let mut inherited_world_write =
            explicit_full_control(world.sid, (OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE) as u8);
        inherited_world_write.grfAccessPermissions = FILE_WRITE_DATA;
        install_test_explicit_dacl(
            raw_handle(&directory),
            &mut [current_access, system_access, inherited_world_write],
        );
        let trusted = TrustedLaunchSids::current().unwrap();
        assert!(
            require_path_authority(
                raw_handle(&directory),
                PathLevel::ImmediateDirectory,
                OwnerPolicy::Trusted,
                &trusted,
            )
            .is_ok()
        );
        assert!(
            require_path_authority(
                raw_handle(&directory),
                PathLevel::InstallDirectory,
                OwnerPolicy::CurrentUser,
                &trusted,
            )
            .is_err()
        );
        let before = SecurityDescriptor::read(raw_handle(&directory))
            .unwrap()
            .snapshot()
            .unwrap();
        drop(directory);

        assert!(validate_install_directory(&install_path).is_err());

        let directory = open_directory_descriptor_mutator(&install_path);
        let after = SecurityDescriptor::read(raw_handle(&directory))
            .unwrap()
            .snapshot()
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn private_relative_opens_retain_exact_directory_file_and_lock_authority() {
        let root = tempfile::tempdir().unwrap();
        let parent = open_parent(root.path());
        let state = create_private_directory(&parent, std::ffi::OsStr::new("state")).unwrap();
        drop(state);
        let state = open_private_directory(&parent, std::ffi::OsStr::new("state")).unwrap();
        let mut file = create_private_file(&state, std::ffi::OsStr::new("file")).unwrap();
        file.write_all(b"content").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut lock = create_private_file(&state, std::ffi::OsStr::new("lock")).unwrap();
        lock.write_all(b"lock").unwrap();
        lock.sync_all().unwrap();
        drop(lock);

        let mut file = open_private_file(&state, std::ffi::OsStr::new("file")).unwrap();
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"content");
        let mut lock = open_private_lock_file(&state, std::ffi::OsStr::new("lock")).unwrap();
        lock.write_all(b"ed").unwrap();

        std::fs::hard_link(root.path().join("state/file"), root.path().join("alias")).unwrap();
        assert!(open_private_file(&state, std::ffi::OsStr::new("file")).is_err());
    }
}
