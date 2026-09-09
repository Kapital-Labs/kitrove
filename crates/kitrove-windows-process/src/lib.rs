#![cfg(windows)]
//! Safe contained-process lifecycle for explicit Kitrove Windows probes.

use std::ffi::{OsStr, OsString, c_void};
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::FromRawHandle as _;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use kitrove_windows_security::{ValidatedExecutable, ValidatedLaunchDirectory};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(feature = "test-support")]
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, GetLastError};
use windows_sys::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};
#[cfg(feature = "test-support")]
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcess, PROCESS_SYNCHRONIZE, SetEvent,
};

const CONTAINMENT_EXIT_CODE: u32 = 0x4b52_0001;
const CLEANUP_BUDGET: Duration = Duration::from_secs(5);
const JOB_EMPTY_POLL: Duration = Duration::from_millis(5);
const MAX_COMMAND_LINE_UNITS: usize = 32_767;
const MAX_ENVIRONMENT_BLOCK_UNITS: usize = 32_767;
const MAX_ARGUMENTS: usize = 64;
const MAX_ENVIRONMENT_ENTRIES: usize = 64;

/// Opaque failure from the contained Windows process boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainedProcessError {
    kind: ContainedProcessFailure,
}

/// Stable lifecycle classification without exposing native failure details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainedProcessFailure {
    /// The caller-owned deadline elapsed.
    Timeout,
    /// Whole-Job termination or zero-active proof failed.
    Cleanup,
    /// Launch, wait, encoding, or handle setup failed.
    Failed,
}

/// Owned inheritable handle used to verify explicit child handle allowlists.
///
/// This is intentionally opaque: callers can pass its numeric value to a test
/// child, but cannot transfer ownership of the native handle.
#[cfg(feature = "test-support")]
pub struct InheritableHandleCanary(OwnedHandle);

#[cfg(feature = "test-support")]
impl InheritableHandleCanary {
    /// Creates an unnamed event whose handle is eligible for inheritance.
    pub fn new() -> Result<Self, ContainedProcessError> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| ContainedProcessError::failed())?,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        // SAFETY: `attributes` is initialized for the duration of this call and
        // the unnamed event has no borrowed name storage.
        let handle = unsafe { CreateEventW(&attributes, 1, 0, std::ptr::null()) };
        OwnedHandle::new(handle).map(Self)
    }

    /// Returns the process-local numeric value without transferring ownership.
    #[must_use]
    pub fn raw_value(&self) -> usize {
        self.0.0 as usize
    }

    /// Reports whether another process signaled this exact event object.
    pub fn was_signaled(&self) -> Result<bool, ContainedProcessError> {
        // SAFETY: the owned event remains live for this non-blocking wait.
        match unsafe { WaitForSingleObject(self.0.0, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(ContainedProcessError::failed()),
        }
    }
}

/// Attempts to signal an event handle inherited by the current process.
#[cfg(feature = "test-support")]
#[must_use]
pub fn signal_inherited_event(raw_value: usize) -> bool {
    // SAFETY: `SetEvent` validates the process-local handle value and fails if
    // it is absent or is not an event. Ownership remains with its creator.
    (unsafe { SetEvent(raw_value as HANDLE) }) != 0
}

/// Reports whether a process has exited, treating a PID that no longer exists as exited.
#[cfg(feature = "test-support")]
pub fn process_has_exited(pid: u32) -> Result<bool, ContainedProcessError> {
    // SAFETY: the PID is an integer value and only synchronization access is
    // requested. A successful handle is owned below.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        // `OpenProcess` documents ERROR_INVALID_PARAMETER for a process that
        // no longer exists. Every other failure is inconclusive and fails closed.
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            Ok(true)
        } else {
            Err(ContainedProcessError::failed())
        };
    }
    let process = OwnedHandle::new(process)?;
    // SAFETY: `process` remains live for this non-blocking wait.
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(ContainedProcessError::failed()),
    }
}

impl ContainedProcessError {
    const fn failed() -> Self {
        Self {
            kind: ContainedProcessFailure::Failed,
        }
    }

    const fn timeout() -> Self {
        Self {
            kind: ContainedProcessFailure::Timeout,
        }
    }

    const fn cleanup() -> Self {
        Self {
            kind: ContainedProcessFailure::Cleanup,
        }
    }

    /// Returns the stable lifecycle classification.
    #[must_use]
    pub const fn kind(self) -> ContainedProcessFailure {
        self.kind
    }
}

/// Exact contained launch inputs. Filesystem authority remains borrowed for the process lifetime.
pub struct LaunchRequest<'authority, 'input> {
    /// Executable previously validated and retained by the Windows security boundary.
    pub executable: &'authority ValidatedExecutable,
    /// Working directory previously validated and retained by the Windows security boundary.
    pub working_directory: &'authority ValidatedLaunchDirectory,
    /// Complete argument vector after `argv[0]`.
    pub arguments: &'input [OsString],
    /// Complete child environment; the ambient environment is never inherited.
    pub environment: &'input [(OsString, OsString)],
}

/// A Job-contained process plus the only parent-side pipe handles exposed to callers.
pub struct ContainedProcess<'a> {
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    stdout: Option<File>,
    stderr: Option<File>,
    _authority: LaunchAuthority<'a>,
    // Declared last so Rust's field drop order closes kill-on-close containment last.
    job: OwnedHandle,
}

struct LaunchAuthority<'a> {
    _executable: &'a ValidatedExecutable,
    _working_directory: &'a ValidatedLaunchDirectory,
}

impl ContainedProcess<'_> {
    /// Transfers ownership of the captured stdout reader to the shared probe layer.
    pub fn take_stdout(&mut self) -> Result<File, ContainedProcessError> {
        self.stdout.take().ok_or_else(ContainedProcessError::failed)
    }

    /// Transfers ownership of the captured stderr reader to the shared probe layer.
    pub fn take_stderr(&mut self) -> Result<File, ContainedProcessError> {
        self.stderr.take().ok_or_else(ContainedProcessError::failed)
    }

    /// Waits until the caller-owned deadline, then terminates descendants and proves the Job empty.
    pub fn wait_until(mut self, deadline: Instant) -> Result<ExitStatus, ContainedProcessError> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(ContainedProcessError::failed)?
            .0;
        let wait_millis = match remaining_millis(deadline) {
            Ok(wait_millis) => wait_millis,
            Err(RemainingTimeError::Expired) => {
                self.terminate_and_prove_empty()?;
                return Err(ContainedProcessError::timeout());
            }
            Err(RemainingTimeError::Invalid) => {
                self.terminate_and_prove_empty()?;
                return Err(ContainedProcessError::failed());
            }
        };
        let wait = unsafe { WaitForSingleObject(process, wait_millis) };
        if wait == WAIT_TIMEOUT {
            self.terminate_and_prove_empty()?;
            return Err(ContainedProcessError::timeout());
        }
        if wait != WAIT_OBJECT_0 {
            self.terminate_and_prove_empty()?;
            return Err(ContainedProcessError::failed());
        }

        let mut exit_code = 0;
        // SAFETY: `process` is a live process handle owned by `self`.
        if unsafe { GetExitCodeProcess(process, &mut exit_code) } == 0 {
            self.terminate_and_prove_empty()?;
            return Err(ContainedProcessError::failed());
        }
        self.terminate_and_prove_empty()?;
        use std::os::windows::process::ExitStatusExt as _;
        Ok(ExitStatus::from_raw(exit_code))
    }

    fn terminate_and_prove_empty(&mut self) -> Result<(), ContainedProcessError> {
        // Termination also covers descendants left behind after a successful root exit.
        // SAFETY: `job` is an owned Job Object handle.
        if unsafe { TerminateJobObject(self.job.0, CONTAINMENT_EXIT_CODE) } == 0 {
            return Err(ContainedProcessError::cleanup());
        }
        self.thread.take();
        self.process.take();
        let deadline = Instant::now()
            .checked_add(CLEANUP_BUDGET)
            .ok_or_else(ContainedProcessError::cleanup)?;
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: the output buffer exactly matches the selected Job information class.
            let queried = unsafe {
                QueryInformationJobObject(
                    self.job.0,
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            };
            if queried == 0 {
                return Err(ContainedProcessError::cleanup());
            }
            if accounting.ActiveProcesses == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ContainedProcessError::cleanup());
            }
            std::thread::sleep(JOB_EMPTY_POLL);
        }
    }
}

impl Drop for ContainedProcess<'_> {
    fn drop(&mut self) {
        // Best effort only: closing the armed Job handle last preserves kill-on-close containment.
        // SAFETY: duplicate termination requests on the live Job handle are allowed.
        let _ = unsafe { TerminateJobObject(self.job.0, CONTAINMENT_EXIT_CODE) };
        self.thread.take();
        self.process.take();
    }
}

/// Launches a process that belongs to a kill-on-close Job Object atomically from creation.
pub fn launch_contained<'authority>(
    request: LaunchRequest<'authority, '_>,
) -> Result<ContainedProcess<'authority>, ContainedProcessError> {
    let application = nul_terminated(request.executable.launch_path().as_os_str())?;
    let cwd = nul_terminated(request.working_directory.launch_path().as_os_str())?;
    let mut command_line = encode_command_line(
        request.executable.launch_path().as_os_str(),
        request.arguments,
    )?;
    let environment = encode_environment(request.environment)?;

    let job = create_kill_on_close_job()?;
    let stdout = Pipe::new()?;
    let stderr = Pipe::new()?;
    let stdin = inheritable_null_stdin()?;
    let mut attributes = AttributeList::new(2)?;
    attributes.set_handle_list([stdin.0, stdout.write.0, stderr.write.0])?;
    attributes.set_job_list([job.0])?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.0;
    startup.StartupInfo.hStdOutput = stdout.write.0;
    startup.StartupInfo.hStdError = stderr.write.0;
    startup.lpAttributeList = attributes.ptr;
    let mut process_info = PROCESS_INFORMATION::default();

    // SAFETY: all strings and blocks are terminated, startup fields point to live owned handles,
    // and the attribute list remains live across this call.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo as *const _,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(ContainedProcessError::failed());
    }

    // Take native ownership immediately; from this point every unwind closes the Job last.
    let process_info = OwnedProcessInformation::take(process_info);
    drop(stdin);
    drop(stdout.write);
    drop(stderr.write);
    let stdout = stdout.read.into_file();
    let stderr = stderr.read.into_file();
    Ok(ContainedProcess {
        process: Some(process_info.process),
        thread: Some(process_info.thread),
        stdout: Some(stdout),
        stderr: Some(stderr),
        _authority: LaunchAuthority {
            _executable: request.executable,
            _working_directory: request.working_directory,
        },
        job,
    })
}

fn create_kill_on_close_job() -> Result<OwnedHandle, ContainedProcessError> {
    // SAFETY: null security/name pointers request an anonymous Job with default security.
    let job = OwnedHandle::new(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: input layout exactly matches the selected Job information class.
    let configured = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if configured == 0 {
        return Err(ContainedProcessError::failed());
    }
    Ok(job)
}

struct Pipe {
    read: OwnedHandle,
    write: OwnedHandle,
}

impl Pipe {
    fn new() -> Result<Self, ContainedProcessError> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        // SAFETY: both output pointers and the security-attributes pointer are valid.
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(ContainedProcessError::failed());
        }
        // The API guarantees both handles are valid together on success; adopt both immediately.
        let read = OwnedHandle::from_created(read);
        let write = OwnedHandle::from_created(write);
        // SAFETY: `read` is a live handle; clearing inheritance affects only its handle entry.
        if unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(ContainedProcessError::failed());
        }
        Ok(Self { read, write })
    }
}

fn inheritable_null_stdin() -> Result<OwnedHandle, ContainedProcessError> {
    let name = nul_terminated(OsStr::new("NUL"))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: the path and security-attributes pointers are valid for the call duration.
    OwnedHandle::new(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    })
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, ContainedProcessError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(ContainedProcessError::failed())
        } else {
            Ok(Self(handle))
        }
    }

    fn from_created(handle: HANDLE) -> Self {
        debug_assert!(!handle.is_null() && handle != INVALID_HANDLE_VALUE);
        Self(handle)
    }

    fn into_file(self) -> File {
        let handle = self.0;
        std::mem::forget(self);
        // SAFETY: ownership transfers exactly once from this wrapper into `File`.
        unsafe { File::from_raw_handle(handle.cast()) }
    }
}

struct OwnedProcessInformation {
    process: OwnedHandle,
    thread: OwnedHandle,
}

impl OwnedProcessInformation {
    fn take(information: PROCESS_INFORMATION) -> Self {
        Self {
            process: OwnedHandle::from_created(information.hProcess),
            thread: OwnedHandle::from_created(information.hThread),
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: each wrapper owns one non-null native handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct AttributeList {
    _storage: Vec<usize>,
    ptr: *mut c_void,
    handle_values: Vec<HANDLE>,
    job_values: Vec<HANDLE>,
}

impl AttributeList {
    fn new(count: u32) -> Result<Self, ContainedProcessError> {
        let mut bytes = 0;
        // SAFETY: the documented sizing call uses a null list and writes the required byte count.
        let _ = unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), count, 0, &mut bytes)
        };
        if bytes == 0 {
            return Err(ContainedProcessError::failed());
        }
        let words = bytes
            .checked_add(size_of::<usize>() - 1)
            .and_then(|value| value.checked_div(size_of::<usize>()))
            .ok_or_else(ContainedProcessError::failed)?;
        let mut storage = vec![0usize; words];
        let ptr = storage.as_mut_ptr().cast();
        // SAFETY: aligned storage is at least the size reported by the sizing call.
        if unsafe { InitializeProcThreadAttributeList(ptr, count, 0, &mut bytes) } == 0 {
            return Err(ContainedProcessError::failed());
        }
        Ok(Self {
            _storage: storage,
            ptr,
            handle_values: Vec::new(),
            job_values: Vec::new(),
        })
    }

    fn set_handle_list<const N: usize>(
        &mut self,
        handles: [HANDLE; N],
    ) -> Result<(), ContainedProcessError> {
        self.handle_values = handles.into();
        Self::set(
            self.ptr,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            &self.handle_values,
        )
    }

    fn set_job_list<const N: usize>(
        &mut self,
        jobs: [HANDLE; N],
    ) -> Result<(), ContainedProcessError> {
        self.job_values = jobs.into();
        Self::set(
            self.ptr,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            &self.job_values,
        )
    }

    fn set<T>(
        ptr: *mut c_void,
        attribute: usize,
        values: &[T],
    ) -> Result<(), ContainedProcessError> {
        let bytes = size_of::<T>()
            .checked_mul(values.len())
            .ok_or_else(ContainedProcessError::failed)?;
        // SAFETY: the initialized list is uniquely borrowed and `values` remains live through launch.
        let updated = unsafe {
            UpdateProcThreadAttribute(
                ptr,
                0,
                attribute,
                values.as_ptr().cast(),
                bytes,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if updated == 0 {
            Err(ContainedProcessError::failed())
        } else {
            Ok(())
        }
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: `ptr` was successfully initialized and is deleted exactly once.
        unsafe { DeleteProcThreadAttributeList(self.ptr) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemainingTimeError {
    Expired,
    Invalid,
}

fn remaining_millis(deadline: Instant) -> Result<u32, RemainingTimeError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(RemainingTimeError::Expired)?;
    if remaining.is_zero() {
        return Err(RemainingTimeError::Expired);
    }
    duration_to_wait_millis(remaining).map_err(|_| RemainingTimeError::Invalid)
}

fn duration_to_wait_millis(remaining: Duration) -> Result<u32, ContainedProcessError> {
    if remaining.is_zero() {
        return Err(ContainedProcessError::failed());
    }
    let rounded = u128::from(remaining.subsec_nanos() % 1_000_000 != 0);
    let millis = remaining
        .as_millis()
        .checked_add(rounded)
        .ok_or_else(ContainedProcessError::failed)?;
    let millis = u32::try_from(millis).map_err(|_| ContainedProcessError::failed())?;
    if millis == u32::MAX {
        return Err(ContainedProcessError::failed());
    }
    Ok(millis)
}

fn nul_terminated(value: &OsStr) -> Result<Vec<u16>, ContainedProcessError> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.len() >= MAX_COMMAND_LINE_UNITS || !valid_utf16(&wide) {
        return Err(ContainedProcessError::failed());
    }
    wide.push(0);
    Ok(wide)
}

fn valid_utf16(value: &[u16]) -> bool {
    !value.contains(&0) && String::from_utf16(value).is_ok()
}

fn encode_command_line(
    application: &OsStr,
    arguments: &[OsString],
) -> Result<Vec<u16>, ContainedProcessError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(ContainedProcessError::failed());
    }
    let mut encoded = Vec::new();
    append_quoted_argument(&mut encoded, application)?;
    for argument in arguments {
        push_bounded(&mut encoded, b' ' as u16, MAX_COMMAND_LINE_UNITS)?;
        append_quoted_argument(&mut encoded, argument)?;
    }
    push_bounded(&mut encoded, 0, MAX_COMMAND_LINE_UNITS)?;
    Ok(encoded)
}

fn append_quoted_argument(
    output: &mut Vec<u16>,
    argument: &OsStr,
) -> Result<(), ContainedProcessError> {
    let units: Vec<u16> = argument.encode_wide().collect();
    if !valid_utf16(&units) {
        return Err(ContainedProcessError::failed());
    }
    push_bounded(output, b'"' as u16, MAX_COMMAND_LINE_UNITS)?;
    let mut slashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            let escaped = slashes
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(ContainedProcessError::failed)?;
            extend_repeated(output, b'\\' as u16, escaped, MAX_COMMAND_LINE_UNITS)?;
        } else {
            extend_repeated(output, b'\\' as u16, slashes, MAX_COMMAND_LINE_UNITS)?;
        }
        slashes = 0;
        push_bounded(output, unit, MAX_COMMAND_LINE_UNITS)?;
    }
    let trailing = slashes
        .checked_mul(2)
        .ok_or_else(ContainedProcessError::failed)?;
    extend_repeated(output, b'\\' as u16, trailing, MAX_COMMAND_LINE_UNITS)?;
    push_bounded(output, b'"' as u16, MAX_COMMAND_LINE_UNITS)?;
    Ok(())
}

fn push_bounded(
    output: &mut Vec<u16>,
    value: u16,
    maximum: usize,
) -> Result<(), ContainedProcessError> {
    if output.len() >= maximum {
        return Err(ContainedProcessError::failed());
    }
    output.push(value);
    Ok(())
}

fn extend_repeated(
    output: &mut Vec<u16>,
    value: u16,
    count: usize,
    maximum: usize,
) -> Result<(), ContainedProcessError> {
    if output
        .len()
        .checked_add(count)
        .filter(|length| *length <= maximum)
        .is_none()
    {
        return Err(ContainedProcessError::failed());
    }
    output.extend(std::iter::repeat_n(value, count));
    Ok(())
}

fn encode_environment(
    environment: &[(OsString, OsString)],
) -> Result<Vec<u16>, ContainedProcessError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(ContainedProcessError::failed());
    }
    let mut entries = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let name: Vec<u16> = name.encode_wide().collect();
        let value: Vec<u16> = value.encode_wide().collect();
        if name.is_empty()
            || !valid_utf16(&name)
            || name.contains(&(b'=' as u16))
            || !valid_utf16(&value)
        {
            return Err(ContainedProcessError::failed());
        }
        entries.push((name, value));
    }
    for index in 1..entries.len() {
        let mut cursor = index;
        while cursor > 0 {
            match compare_environment_names(&entries[cursor - 1].0, &entries[cursor].0)? {
                std::cmp::Ordering::Greater => entries.swap(cursor - 1, cursor),
                std::cmp::Ordering::Equal => return Err(ContainedProcessError::failed()),
                std::cmp::Ordering::Less => break,
            }
            cursor -= 1;
        }
    }
    let mut block = Vec::new();
    for (name, value) in entries {
        extend_bounded(&mut block, name, MAX_ENVIRONMENT_BLOCK_UNITS)?;
        push_bounded(&mut block, b'=' as u16, MAX_ENVIRONMENT_BLOCK_UNITS)?;
        extend_bounded(&mut block, value, MAX_ENVIRONMENT_BLOCK_UNITS)?;
        push_bounded(&mut block, 0, MAX_ENVIRONMENT_BLOCK_UNITS)?;
    }
    push_bounded(&mut block, 0, MAX_ENVIRONMENT_BLOCK_UNITS)?;
    if environment.is_empty() {
        push_bounded(&mut block, 0, MAX_ENVIRONMENT_BLOCK_UNITS)?;
    }
    Ok(block)
}

fn extend_bounded(
    output: &mut Vec<u16>,
    values: Vec<u16>,
    maximum: usize,
) -> Result<(), ContainedProcessError> {
    if output
        .len()
        .checked_add(values.len())
        .filter(|length| *length <= maximum)
        .is_none()
    {
        return Err(ContainedProcessError::failed());
    }
    output.extend(values);
    Ok(())
}

fn compare_environment_names(
    left: &[u16],
    right: &[u16],
) -> Result<std::cmp::Ordering, ContainedProcessError> {
    let left_len = i32::try_from(left.len()).map_err(|_| ContainedProcessError::failed())?;
    let right_len = i32::try_from(right.len()).map_err(|_| ContainedProcessError::failed())?;
    // SAFETY: both slices are live for the call and their lengths are passed explicitly.
    match unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) } {
        CSTR_LESS_THAN => Ok(std::cmp::Ordering::Less),
        CSTR_EQUAL => Ok(std::cmp::Ordering::Equal),
        CSTR_GREATER_THAN => Ok(std::cmp::Ordering::Greater),
        _ => Err(ContainedProcessError::failed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt as _;

    fn decoded(value: &[u16]) -> String {
        String::from_utf16(value).expect("test data is valid UTF-16")
    }

    #[test]
    fn command_line_quotes_spaces_quotes_and_trailing_backslashes() {
        let arguments = [
            OsString::from("--version"),
            OsString::from("space value"),
            OsString::from("quoted\"value"),
            OsString::from("trailing\\"),
        ];
        let encoded = encode_command_line(OsStr::new(r"C:\Program Files\Pi\pi.exe"), &arguments)
            .expect("command line should encode");

        assert_eq!(
            decoded(&encoded[..encoded.len() - 1]),
            r#""C:\Program Files\Pi\pi.exe" "--version" "space value" "quoted\"value" "trailing\\""#
        );
        assert_eq!(encoded.last(), Some(&0));
    }

    #[test]
    fn environment_is_case_insensitively_sorted_and_double_terminated() {
        let encoded = encode_environment(&[
            (OsString::from("zeta"), OsString::from("2")),
            (OsString::from("Alpha"), OsString::from("1")),
        ])
        .expect("environment should encode");

        assert_eq!(decoded(&encoded), "Alpha=1\0zeta=2\0\0");
    }

    #[test]
    fn environment_rejects_case_insensitive_duplicates() {
        assert_eq!(
            encode_environment(&[
                (OsString::from("Name"), OsString::from("1")),
                (OsString::from("name"), OsString::from("2")),
            ]),
            Err(ContainedProcessError::failed())
        );
    }

    #[test]
    fn command_line_and_environment_preserve_unicode() {
        let command_line = encode_command_line(
            OsStr::new(r"C:\Program Files\パイ\pi.exe"),
            &[OsString::from("版本")],
        )
        .unwrap();
        assert_eq!(
            decoded(&command_line[..command_line.len() - 1]),
            r#""C:\Program Files\パイ\pi.exe" "版本""#
        );

        let environment =
            encode_environment(&[(OsString::from("名前"), OsString::from("値"))]).unwrap();
        assert_eq!(decoded(&environment), "名前=値\0\0");
    }

    #[test]
    fn empty_environment_is_exactly_double_terminated() {
        assert_eq!(encode_environment(&[]), Ok(vec![0, 0]));
    }

    #[test]
    fn encoders_reject_oversized_inputs() {
        let oversized = OsString::from("a".repeat(MAX_COMMAND_LINE_UNITS));
        assert_eq!(
            encode_command_line(OsStr::new("pi.exe"), &[oversized]),
            Err(ContainedProcessError::failed())
        );

        let oversized = OsString::from("a".repeat(MAX_ENVIRONMENT_BLOCK_UNITS));
        assert_eq!(
            encode_environment(&[(OsString::from("NAME"), oversized)]),
            Err(ContainedProcessError::failed())
        );
    }

    #[test]
    fn encoders_reject_unpaired_utf16_surrogates() {
        let malformed = OsString::from_wide(&[0xd800]);
        assert_eq!(
            encode_command_line(OsStr::new("pi.exe"), std::slice::from_ref(&malformed)),
            Err(ContainedProcessError::failed())
        );
        assert_eq!(
            encode_environment(&[(OsString::from("NAME"), malformed)]),
            Err(ContainedProcessError::failed())
        );
    }

    #[test]
    fn deadlines_reject_expired_and_infinite_waits() {
        assert_eq!(
            remaining_millis(Instant::now() - Duration::from_millis(1)),
            Err(RemainingTimeError::Expired)
        );
        assert_eq!(
            remaining_millis(Instant::now() + Duration::from_millis(u64::from(u32::MAX) + 60_000)),
            Err(RemainingTimeError::Invalid)
        );
        assert_eq!(
            duration_to_wait_millis(Duration::from_millis(u32::MAX.into())),
            Err(ContainedProcessError::failed())
        );
        assert_eq!(
            duration_to_wait_millis(Duration::ZERO),
            Err(ContainedProcessError::failed())
        );
        assert_eq!(duration_to_wait_millis(Duration::from_nanos(1)), Ok(1));
        assert_eq!(
            duration_to_wait_millis(Duration::from_millis((u32::MAX - 1).into())),
            Ok(u32::MAX - 1)
        );
    }
}
