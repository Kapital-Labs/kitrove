//! Retained Unix child lifecycle; launch policy stays in the parent module.
use super::inspection_failure::InspectionFailure;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

// Cleanup has its own finite budget, separate from the inspection deadline.
// Drop may make one further best-effort attempt, but never waits indefinitely.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct ProbeProcess {
    child: Child,
    process_group: rustix::process::Pid,
    group_armed: bool,
    reaped: bool,
    #[cfg(all(test, target_os = "macos"))]
    suspended_anchor: Option<kitrove_macos_process::SuspendedSelf>,
}

impl ProbeProcess {
    pub(super) fn new(child: Child) -> Result<Self, InspectionFailure> {
        let process_group = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or(InspectionFailure::Failed)?;
        Ok(Self {
            child,
            process_group,
            group_armed: true,
            reaped: false,
            #[cfg(all(test, target_os = "macos"))]
            suspended_anchor: None,
        })
    }

    pub(super) fn take_stdout(&mut self) -> Result<std::process::ChildStdout, InspectionFailure> {
        self.child.stdout.take().ok_or(InspectionFailure::Failed)
    }

    pub(super) fn take_stderr(&mut self) -> Result<std::process::ChildStderr, InspectionFailure> {
        self.child.stderr.take().ok_or(InspectionFailure::Failed)
    }

    pub(super) fn wait_bounded(
        &mut self,
        timeout: Duration,
    ) -> Result<ExitStatus, InspectionFailure> {
        match wait_for_exit(&mut self.child, timeout) {
            Ok(Some(status)) => {
                self.reaped = true;
                Ok(status)
            }
            Ok(None) => {
                self.terminate_group()?;
                Err(InspectionFailure::Timeout)
            }
            Err(_) => {
                self.terminate_group()?;
                Err(InspectionFailure::Failed)
            }
        }
    }

    pub(super) fn terminate_remaining_group(&mut self) -> Result<(), InspectionFailure> {
        if !self.group_armed {
            return Ok(());
        }
        #[cfg(all(test, target_os = "macos"))]
        if let Some(anchor) = self.suspended_anchor.take() {
            // The anchor is alive and unreaped when its group is signaled. It is
            // consumed by termination, so no later path may signal its numeric ID.
            self.group_armed = false;
            return anchor.terminate().map_err(|_| InspectionFailure::Cleanup);
        }
        self.signal_group()?;
        self.group_armed = false;
        Ok(())
    }

    fn terminate_group(&mut self) -> Result<(), InspectionFailure> {
        self.terminate_remaining_group()?;
        self.reap_bounded(CLEANUP_TIMEOUT)
    }

    fn reap_bounded(&mut self, timeout: Duration) -> Result<(), InspectionFailure> {
        if self.reaped {
            return Ok(());
        }
        wait_for_exit(&mut self.child, timeout)
            .map_err(|_| InspectionFailure::Cleanup)?
            .ok_or(InspectionFailure::Cleanup)?;
        self.reaped = true;
        Ok(())
    }

    fn signal_group(&self) -> Result<(), InspectionFailure> {
        match rustix::process::kill_process_group(self.process_group, rustix::process::Signal::KILL)
        {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(_) => Err(InspectionFailure::Cleanup),
        }
    }
}

// Poll only this owned child. A process-wide SIGCHLD handler would interfere with
// suspended-child ownership policy and other independent child lifecycles.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid inspection deadline",
        )
    })?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(5)));
    }
}

impl Drop for ProbeProcess {
    fn drop(&mut self) {
        if self.group_armed {
            let _ = self.terminate_remaining_group();
            self.group_armed = false;
        }
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.reap_bounded(CLEANUP_TIMEOUT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    #[cfg(target_os = "macos")]
    impl ProbeProcess {
        /// Test-only launch boundary establishes group membership and cleanup
        /// ownership together, never accepting an unrelated child/group pair.
        pub(crate) fn spawn_anchored(command: &mut Command) -> Result<Self, InspectionFailure> {
            let anchor = kitrove_macos_process::SuspendedSelf::spawn()
                .map_err(|_| InspectionFailure::Failed)?;
            let process_group =
                rustix::process::Pid::from_raw(anchor.id()).ok_or(InspectionFailure::Failed)?;
            let child = command
                .process_group(anchor.id())
                .spawn()
                .map_err(|_| InspectionFailure::Failed)?;
            // No fallible work between successful spawn and cleanup ownership.
            // Spawn failure instead drops only the owned anchor.
            Ok(Self {
                child,
                process_group,
                group_armed: true,
                reaped: false,
                suspended_anchor: Some(anchor),
            })
        }
    }

    #[cfg(target_os = "macos")]
    fn anchored_sleep(seconds: &str) -> ProbeProcess {
        let mut command = Command::new("/bin/sleep");
        command
            .arg(seconds)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        ProbeProcess::spawn_anchored(&mut command).unwrap()
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn anchored_launch_overrides_caller_group_selection() {
        let mut command = Command::new("/bin/sleep");
        command.arg("30").process_group(0);
        let mut process = ProbeProcess::spawn_anchored(&mut command).unwrap();
        let child_pid =
            rustix::process::Pid::from_raw(i32::try_from(process.child.id()).unwrap()).unwrap();
        assert_eq!(
            rustix::process::getpgid(Some(child_pid)).unwrap(),
            process.process_group
        );
        assert_ne!(child_pid, process.process_group);
        process.terminate_group().unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn anchored_launch_refuses_missing_executable() {
        let directory = tempfile::tempdir().unwrap();
        let mut command = Command::new(directory.path().join("absent-verifier"));
        assert!(matches!(
            ProbeProcess::spawn_anchored(&mut command),
            Err(InspectionFailure::Failed)
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn suspended_anchor_keeps_group_owned_after_verifier_reaping() {
        let mut process = anchored_sleep("0");
        assert!(
            process
                .wait_bounded(Duration::from_secs(2))
                .unwrap()
                .success()
        );
        assert!(process.reaped);
        let anchor = process.suspended_anchor.as_ref().unwrap();
        let pid = rustix::process::Pid::from_raw(anchor.id()).unwrap();
        assert_eq!(
            rustix::process::getpgid(Some(pid)).unwrap(),
            process.process_group
        );
        process.terminate_remaining_group().unwrap();
        assert!(process.suspended_anchor.is_none());
        assert!(!process.group_armed);
        process.terminate_remaining_group().unwrap();
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn anchored_timeout_reaps_both_owned_children() {
        let mut process = anchored_sleep("30");
        let anchor_pid = process.process_group;
        assert_eq!(
            process.wait_bounded(Duration::ZERO),
            Err(InspectionFailure::Timeout)
        );
        assert!(process.reaped);
        assert!(!process.group_armed);
        assert!(process.suspended_anchor.is_none());
        assert_eq!(
            rustix::process::waitpid(Some(anchor_pid), rustix::process::WaitOptions::NOHANG)
                .unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn anchored_drop_reaps_both_owned_children() {
        let process = anchored_sleep("30");
        let anchor_pid = process.process_group;
        let child_pid =
            rustix::process::Pid::from_raw(i32::try_from(process.child.id()).unwrap()).unwrap();
        drop(process);
        for pid in [anchor_pid, child_pid] {
            assert_eq!(
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
                    .unwrap_err(),
                rustix::io::Errno::CHILD
            );
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn anchored_cleanup_signals_other_live_group_members() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut process = anchored_sleep("30");
        let mut other = Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .process_group(process.process_group.as_raw_pid())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let cleanup = process.terminate_group();
        let observed = wait_for_exit(&mut other, Duration::from_secs(2));
        // Preserve test-fixture cleanup even if the group assertion fails.
        if !matches!(&observed, Ok(Some(_))) {
            let _ = other.kill();
            let _ = wait_for_exit(&mut other, Duration::from_secs(2));
        }
        cleanup.unwrap();
        assert_eq!(
            observed.unwrap().unwrap().signal(),
            Some(rustix::process::Signal::KILL.as_raw())
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn lost_live_anchor_refuses_cleanup_success_but_reaps_the_dead_child() {
        let mut process = anchored_sleep("0");
        assert!(
            process
                .wait_bounded(Duration::from_secs(2))
                .unwrap()
                .success()
        );
        let pid = process.process_group;
        rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let exited = rustix::process::waitid(
                rustix::process::WaitId::Pid(pid),
                rustix::process::WaitIdOptions::EXITED
                    | rustix::process::WaitIdOptions::NOHANG
                    | rustix::process::WaitIdOptions::NOWAIT,
            )
            .unwrap();
            if exited.is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "test anchor did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            process.terminate_remaining_group(),
            Err(InspectionFailure::Cleanup)
        );
        assert!(!process.group_armed);
        assert!(process.suspended_anchor.is_none());
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    fn expired_reap_budget_preserves_ownership_for_termination() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut process = ProbeProcess::new(child).unwrap();
        assert_eq!(
            process.reap_bounded(Duration::ZERO),
            Err(InspectionFailure::Cleanup)
        );
        assert!(!process.reaped);
        process.terminate_group().unwrap();
        assert!(process.reaped);
        assert!(!process.group_armed);
        // An already-reaped child needs no further wait or kill.
        process.reap_bounded(Duration::ZERO).unwrap();
        #[cfg(target_os = "macos")]
        {
            // Waiting must not install a SIGCHLD handler that invalidates the
            // independent suspended-helper ownership contract in this process.
            kitrove_macos_process::SuspendedSelf::spawn()
                .unwrap()
                .terminate()
                .unwrap();
        }
    }
}
