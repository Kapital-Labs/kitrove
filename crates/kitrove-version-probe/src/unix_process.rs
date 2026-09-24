//! Retained Unix child lifecycle; launch policy stays in the parent module.
use super::{PROBE_TIMEOUT, ProbeError, probe_failed, termination_failed};
use std::process::{Child, ExitStatus};
use wait_timeout::ChildExt as _;

pub(super) struct ProbeProcess {
    child: Child,
    process_group: rustix::process::Pid,
    group_armed: bool,
    reaped: bool,
}

impl ProbeProcess {
    pub(super) fn new(child: Child) -> Result<Self, ProbeError> {
        let process_group = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(probe_failed)?;
        Ok(Self {
            child,
            process_group,
            group_armed: true,
            reaped: false,
        })
    }

    pub(super) fn take_stdout(&mut self) -> Result<std::process::ChildStdout, ProbeError> {
        self.child.stdout.take().ok_or_else(probe_failed)
    }

    pub(super) fn take_stderr(&mut self) -> Result<std::process::ChildStderr, ProbeError> {
        self.child.stderr.take().ok_or_else(probe_failed)
    }

    pub(super) fn wait_bounded(&mut self) -> Result<ExitStatus, ProbeError> {
        match self.child.wait_timeout(PROBE_TIMEOUT) {
            Ok(Some(status)) => {
                self.reaped = true;
                Ok(status)
            }
            Ok(None) => {
                self.terminate_group()?;
                Err(ProbeError::new(
                    "version.probe_timeout",
                    "the harness version probe did not finish within the time limit",
                ))
            }
            Err(_) => {
                self.terminate_group()?;
                Err(probe_failed())
            }
        }
    }

    pub(super) fn terminate_remaining_group(&mut self) -> Result<(), ProbeError> {
        self.signal_group()?;
        self.group_armed = false;
        Ok(())
    }

    fn terminate_group(&mut self) -> Result<(), ProbeError> {
        self.signal_group()?;
        self.group_armed = false;
        if !self.reaped {
            self.child.wait().map_err(|_| termination_failed())?;
            self.reaped = true;
        }
        Ok(())
    }

    fn signal_group(&self) -> Result<(), ProbeError> {
        match rustix::process::kill_process_group(self.process_group, rustix::process::Signal::KILL)
        {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(_) => Err(termination_failed()),
        }
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
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}
