//! Pipe ownership only. Protocol limits and deadlines belong to the caller.
use crate::{LaunchGuard, ProcessRefused};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::pipe::pipe;

/// Retained parent endpoints for one fixed helper. Parent I/O is nonblocking.
/// Creating these pipes neither resumes a child nor authorizes a protocol response.
pub struct InspectionTransport {
    input: Option<OwnedFd>,
    output: OwnedFd,
    error: OwnedFd,
}

impl InspectionTransport {
    pub fn input(&self) -> Option<BorrowedFd<'_>> {
        self.input.as_ref().map(AsFd::as_fd)
    }
    /// Close request input to deliver EOF without losing retained output streams.
    pub fn close_input(&mut self) {
        self.input.take();
    }
    pub fn output(&self) -> BorrowedFd<'_> {
        self.output.as_fd()
    }
    pub fn error(&self) -> BorrowedFd<'_> {
        self.error.as_fd()
    }
}

pub(crate) struct ChildTransport {
    pub(crate) input: OwnedFd,
    pub(crate) output: OwnedFd,
    pub(crate) error: OwnedFd,
}

pub(crate) fn create(
    _launch: &LaunchGuard<'_>,
) -> Result<(InspectionTransport, ChildTransport), ProcessRefused> {
    let (child_input, input) = private_pipe()?;
    let (output, child_output) = private_pipe()?;
    let (error, child_error) = private_pipe()?;
    for parent in [&input, &output, &error] {
        let flags = fcntl_getfl(parent).map_err(|_| ProcessRefused)?;
        fcntl_setfl(parent, flags | OFlags::NONBLOCK).map_err(|_| ProcessRefused)?;
    }
    Ok((
        InspectionTransport {
            input: Some(input),
            output,
            error,
        },
        ChildTransport {
            input: child_input,
            output: child_output,
            error: child_error,
        },
    ))
}

fn private_pipe() -> Result<(OwnedFd, OwnedFd), ProcessRefused> {
    let (read, write) = pipe().map_err(|_| ProcessRefused)?;
    // Keep spawn sources above stdio even when the caller has closed fd 0/1/2.
    // Otherwise earlier /dev/null actions could overwrite a pipe source.
    // Darwin has no rustix pipe_with(CLOEXEC). These temporary original ends are
    // not atomically close-on-exec. The caller retains the shared launch guard
    // until these temporary originals close; foreign launches are not covered.
    let read = rustix::io::fcntl_dupfd_cloexec(&read, 3).map_err(|_| ProcessRefused)?;
    let write = rustix::io::fcntl_dupfd_cloexec(&write, 3).map_err(|_| ProcessRefused)?;
    Ok((read, write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::io::{FdFlags, fcntl_getfd};

    #[test]
    fn parent_is_nonblocking_and_child_remains_blocking_with_cloexec_everywhere() {
        let launch = crate::acquire_launch_guard(std::time::Duration::from_secs(5)).unwrap();
        let (mut parent, child) = create(&launch).unwrap();
        for fd in [parent.input().unwrap(), parent.output(), parent.error()] {
            assert!(fcntl_getfl(fd).unwrap().contains(OFlags::NONBLOCK));
            assert!(fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC));
        }
        for fd in [&child.input, &child.output, &child.error] {
            assert!(!fcntl_getfl(fd).unwrap().contains(OFlags::NONBLOCK));
            assert!(fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC));
        }
        let mut byte = [0];
        assert_eq!(
            rustix::io::read(parent.output(), &mut byte),
            Err(rustix::io::Errno::AGAIN)
        );
        assert_eq!(
            rustix::io::read(parent.error(), &mut byte),
            Err(rustix::io::Errno::AGAIN)
        );
        assert_eq!(rustix::io::write(parent.input().unwrap(), b"a").unwrap(), 1);
        assert_eq!(rustix::io::read(&child.input, &mut byte).unwrap(), 1);
        assert_eq!(byte, *b"a");
        parent.close_input();
        parent.close_input();
        assert!(parent.input().is_none());
        assert_eq!(rustix::io::read(&child.input, &mut byte).unwrap(), 0);
        drop(child);
        assert_eq!(rustix::io::read(parent.output(), &mut byte).unwrap(), 0);
        assert_eq!(rustix::io::read(parent.error(), &mut byte).unwrap(), 0);
    }
}
