//! Retained Unix child lifecycle; launch policy stays in the parent module.
use super::inspection_failure::InspectionFailure;
use std::process::{Child, ExitStatus};
use std::time::Duration;
use wait_timeout::ChildExt as _;

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
        match self.child.wait_timeout(timeout) {
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
        if !self.reaped {
            self.child.wait().map_err(|_| InspectionFailure::Cleanup)?;
            self.reaped = true;
        }
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
