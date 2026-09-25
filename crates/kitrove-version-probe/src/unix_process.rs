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
        self.signal_group()?;
        self.group_armed = false;
        Ok(())
    }

    fn terminate_group(&mut self) -> Result<(), InspectionFailure> {
        self.signal_group()?;
        self.group_armed = false;
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
            let _ = self.signal_group();
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
