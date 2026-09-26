//! Suspended-self lifecycle and cooperative stdio preparation. No resume/readiness.
#![cfg(target_os = "macos")]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::time::{Duration, Instant};

mod system_verifier;
pub use system_verifier::SystemVerifier;
mod launch_gate;
pub use launch_gate::{LaunchGuard, acquire_launch_guard};
mod transport;
pub use transport::{InputProgress, InspectionStream, InspectionTransport, OutputProgress};

/// Exact internal operation selected by suspended-self launch and helper dispatch.
pub const INSPECTION_ARGUMENT: &std::ffi::CStr = c"--internal-native-inspection-v1";

// Public spawn.h signature, available starting with macOS 10.15. Resolve it
// without a strong import so unavailable hosts can refuse before creating a child.
type AddChdir =
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t, *const libc::c_char) -> libc::c_int;

fn resolve_add_chdir() -> Result<AddChdir, ProcessRefused> {
    // SAFETY: fixed NUL-terminated public symbol, searched only in already loaded
    // process images. This does not load a library or accept a caller override.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"posix_spawn_file_actions_addchdir_np".as_ptr(),
        )
    };
    // SAFETY: the exact SDK-declared symbol has the AddChdir ABI; the loaded system
    // implementation remains available for the process lifetime. As with the other
    // native calls, this assumes an already-trusted process and loader state; this
    // availability query does not establish runtime trust. Missing is refused.
    unsafe { decode_add_chdir(symbol) }
}

/// The nonnull pointer must name the public AddChdir function with process lifetime.
unsafe fn decode_add_chdir(symbol: *mut libc::c_void) -> Result<AddChdir, ProcessRefused> {
    if symbol.is_null() {
        return Err(ProcessRefused);
    }
    // SAFETY: Darwin's dlsym function-address representation and the caller's exact
    // symbol/ABI contract permit this conversion, only after the null check.
    Ok(unsafe { std::mem::transmute::<*mut libc::c_void, AddChdir>(symbol) })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRefused;
impl std::fmt::Display for ProcessRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("suspended inspection process refused")
    }
}
impl std::error::Error for ProcessRefused {}

struct Attributes(libc::posix_spawnattr_t);
impl Attributes {
    fn new() -> Result<Self, ProcessRefused> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: writable initialized storage; success transfers attribute ownership.
        if unsafe { libc::posix_spawnattr_init(&mut raw) } != 0 {
            return Err(ProcessRefused);
        }
        Ok(Self(raw))
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: exactly one owner of an initialized attribute object.
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    fn new() -> Result<Self, ProcessRefused> {
        let mut raw = std::ptr::null_mut();
        // SAFETY: writable initialized storage; success transfers action ownership.
        if unsafe { libc::posix_spawn_file_actions_init(&mut raw) } != 0 {
            return Err(ProcessRefused);
        }
        Ok(Self(raw))
    }
}
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: exactly one owner of an initialized action object.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}

/// Owns a new process group and its suspended direct child. This object cannot
/// resume execution and confers no proof of the child's identity. Callers must
/// not externally reap the child, change SIGCHLD handling while it is owned,
/// or transfer ownership of its PID.
pub struct SuspendedSelf {
    pid: libc::pid_t,
    owned: bool,
}

impl SuspendedSelf {
    /// Spawn only the current executable with one fixed internal operation.
    /// No arbitrary executable, argument, environment or working directory is accepted.
    /// The selected path remains untrusted until separate dynamic validation;
    /// this checkpoint never resumes it. No downloaded installer is selected here.
    pub fn spawn() -> Result<Self, ProcessRefused> {
        let launch = acquire_launch_guard(Duration::from_secs(5))?;
        Self::spawn_guarded(&launch, None)
    }

    /// Prepare fixed suspended-self stdio within the cooperative Kitrove gate.
    /// Only for a reviewed standalone caller where every concurrent launch uses
    /// that gate. Foreign/embedding-runtime launches are not covered. No resume.
    pub fn spawn_with_transport() -> Result<(Self, InspectionTransport), ProcessRefused> {
        let launch = acquire_launch_guard(Duration::from_secs(5))?;
        let (parent, child) = transport::create(&launch)?;
        let process = Self::spawn_guarded(&launch, Some(&child))?;
        // Close child-side parent handles before releasing the launch guard.
        drop(child);
        Ok((process, parent))
    }

    fn spawn_guarded(
        _launch: &LaunchGuard<'_>,
        transport: Option<&transport::ChildTransport>,
    ) -> Result<Self, ProcessRefused> {
        require_retained_child_policy()?;
        let add_chdir = resolve_add_chdir()?;
        let executable = std::env::current_exe().map_err(|_| ProcessRefused)?;
        if !executable.is_absolute() {
            return Err(ProcessRefused);
        }
        let executable =
            CString::new(executable.as_os_str().as_bytes()).map_err(|_| ProcessRefused)?;
        let operation = INSPECTION_ARGUMENT;
        let mut attributes = Attributes::new()?;
        let mut actions = Actions::new()?;
        let mut mask: libc::sigset_t = 0;
        let mut defaults: libc::sigset_t = 0;
        let flags = libc::POSIX_SPAWN_START_SUSPENDED
            | libc::POSIX_SPAWN_SETPGROUP
            | libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        let flags = libc::c_short::try_from(flags).map_err(|_| ProcessRefused)?;
        // SAFETY: initialized native objects and writable signal sets; all C strings
        // are fixed NUL-terminated literals, copied by the actions API. No child exists
        // until every configuration call has succeeded.
        let configured = unsafe {
            libc::sigemptyset(&mut mask) == 0
                && libc::sigfillset(&mut defaults) == 0
                && libc::posix_spawnattr_setflags(&mut attributes.0, flags) == 0
                && libc::posix_spawnattr_setpgroup(&mut attributes.0, 0) == 0
                && libc::posix_spawnattr_setsigmask(&mut attributes.0, &mask) == 0
                && libc::posix_spawnattr_setsigdefault(&mut attributes.0, &defaults) == 0
                && add_chdir(&mut actions.0, c"/".as_ptr()) == 0
                && libc::posix_spawn_file_actions_addopen(
                    &mut actions.0,
                    0,
                    c"/dev/null".as_ptr(),
                    libc::O_RDONLY,
                    0,
                ) == 0
                && libc::posix_spawn_file_actions_addopen(
                    &mut actions.0,
                    1,
                    c"/dev/null".as_ptr(),
                    libc::O_WRONLY,
                    0,
                ) == 0
                && libc::posix_spawn_file_actions_addopen(
                    &mut actions.0,
                    2,
                    c"/dev/null".as_ptr(),
                    libc::O_WRONLY,
                    0,
                ) == 0
        };
        if !configured {
            return Err(ProcessRefused);
        }
        if let Some(transport) = transport {
            use std::os::fd::AsRawFd as _;
            for (source, destination) in [
                (&transport.input, 0),
                (&transport.output, 1),
                (&transport.error, 2),
            ] {
                // SAFETY: owned pipe ends survive spawn. Only fixed stdio targets
                // are duplicated; sources are above stdio and close-on-exec.
                if unsafe {
                    libc::posix_spawn_file_actions_adddup2(
                        &mut actions.0,
                        source.as_raw_fd(),
                        destination,
                    )
                } != 0
                {
                    return Err(ProcessRefused);
                }
            }
        }
        let args = [
            executable.as_ptr().cast_mut(),
            operation.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ];
        let environment = [std::ptr::null_mut()];
        let mut pid = 0;
        // SAFETY: all pointers remain valid through spawn; arrays are terminated;
        // native attributes request a fresh process group and suspended startup.
        let status = unsafe {
            libc::posix_spawn(
                &mut pid,
                executable.as_ptr(),
                &actions.0,
                &attributes.0,
                args.as_ptr(),
                environment.as_ptr(),
            )
        };
        if status != 0 {
            return Err(ProcessRefused);
        }
        // A successful posix_spawn returns the positive PID of the owned child.
        Ok(Self { pid, owned: true })
    }

    pub fn id(&self) -> libc::pid_t {
        self.pid
    }

    /// Kill the group and confirm direct-child reaping. Failure is never readiness.
    pub fn terminate(mut self) -> Result<(), ProcessRefused> {
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<(), ProcessRefused> {
        if !self.owned {
            return Ok(());
        }
        // SAFETY: this unreaped child owns the group created at spawn. Negative PID
        // addresses that group, never the caller's group.
        let killed = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        let signal_failed =
            killed != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: exact owned child PID and initialized writable status storage.
            let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if waited == self.pid {
                self.owned = false;
                // Even a refused group signal can leave a dead owned child to
                // reap. Reaping it is cleanup, never proof that the signal worked.
                return if signal_failed {
                    Err(ProcessRefused)
                } else {
                    Ok(())
                };
            }
            if waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                // Ownership is uncertain: do not signal a possibly reused PID again.
                self.owned = false;
                return Err(ProcessRefused);
            }
            if signal_failed || Instant::now() >= deadline {
                return Err(ProcessRefused);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn require_retained_child_policy() -> Result<(), ProcessRefused> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null new-action pointer only queries the process-wide disposition;
    // the initialized output is read only after a successful call.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        return Err(ProcessRefused);
    }
    // SAFETY: successful sigaction initialized the output structure.
    let action = unsafe { action.assume_init() };
    validate_child_policy(action.sa_sigaction, action.sa_flags)
}

fn validate_child_policy(
    handler: libc::sighandler_t,
    flags: libc::c_int,
) -> Result<(), ProcessRefused> {
    if handler != libc::SIG_DFL || flags & libc::SA_NOCLDWAIT != 0 {
        return Err(ProcessRefused);
    }
    Ok(())
}
impl Drop for SuspendedSelf {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_spawn_action_is_refused_without_calling_it() {
        // SAFETY: null is the documented missing-symbol input, never converted
        // into a function pointer or invoked.
        assert!(unsafe { decode_add_chdir(std::ptr::null_mut()) }.is_err());
    }

    #[test]
    fn automatic_or_custom_child_reapers_are_refused_without_changing_signals() {
        assert!(validate_child_policy(libc::SIG_DFL, 0).is_ok());
        assert!(validate_child_policy(libc::SIG_IGN, 0).is_err());
        assert!(validate_child_policy(libc::SIG_DFL, libc::SA_NOCLDWAIT).is_err());
        assert!(validate_child_policy(libc::SIG_ERR, 0).is_err());
    }
    #[test]
    fn suspended_self_is_retained_until_explicit_kill_and_reap() {
        let child = SuspendedSelf::spawn().unwrap();
        // SAFETY: query only; the owned child has not been reaped.
        assert_eq!(unsafe { libc::getpgid(child.id()) }, child.id());
        let mut status = 0;
        // SAFETY: nonblocking wait on the owned suspended child does not reap it.
        assert_eq!(
            unsafe { libc::waitpid(child.id(), &mut status, libc::WNOHANG) },
            0
        );
        child.terminate().unwrap();
    }

    #[test]
    fn drop_reaps_the_suspended_child() {
        let child = SuspendedSelf::spawn().unwrap();
        let pid = child.id();
        drop(child);
        let mut status = 0;
        // SAFETY: query the former child; Drop must already have reaped it.
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn guarded_transport_retains_outputs_until_suspended_child_cleanup() {
        let (child, mut transport) = SuspendedSelf::spawn_with_transport().unwrap();
        let mut byte = [0];
        for output in [transport.output(), transport.error()] {
            assert_eq!(
                rustix::io::read(output, &mut byte),
                Err(rustix::io::Errno::AGAIN)
            );
        }
        assert_eq!(
            rustix::io::write(transport.input().unwrap(), b"x").unwrap(),
            1
        );
        transport.close_input();
        child.terminate().unwrap();
        for output in [transport.output(), transport.error()] {
            assert_eq!(rustix::io::read(output, &mut byte).unwrap(), 0);
        }
    }

    #[test]
    fn competing_native_launch_waits_until_pipe_preparation_guard_is_released() {
        let launch = acquire_launch_guard(Duration::from_secs(5)).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let competing = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = SuspendedSelf::spawn().and_then(SuspendedSelf::terminate);
            done_tx.send(result).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (parent, child) = transport::create(&launch).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        // Simulate refusal after pipe preparation: endpoints close while still
        // holding the same gate that blocks the participating native launch.
        drop(child);
        let mut byte = [0];
        assert_eq!(rustix::io::read(parent.output(), &mut byte).unwrap(), 0);
        assert_eq!(rustix::io::read(parent.error(), &mut byte).unwrap(), 0);
        drop(parent);
        drop(launch);
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        competing.join().unwrap();
    }
}
