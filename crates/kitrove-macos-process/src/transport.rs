//! Pipe ownership only. Protocol limits and deadlines belong to the caller.
use crate::{LaunchGuard, ProcessRefused};
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::pipe::pipe;

const IO_CHUNK_BYTES: usize = 1024;

/// Retained parent endpoints for one fixed helper. Parent I/O is nonblocking.
/// Creating these pipes neither resumes a child nor authorizes a protocol response.
pub struct InspectionTransport {
    input: Option<OwnedFd>,
    output: OwnedFd,
    error: OwnedFd,
}

/// Progress from one nonblocking input write. Pending is not request completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputProgress {
    Written(usize),
    Pending,
}

/// The helper's two output streams remain separate throughout inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionStream {
    Output,
    Error,
}

/// EOF is distinct from a temporarily empty pipe and does not establish success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputProgress {
    Read(usize),
    Pending,
    Eof,
}

impl InspectionTransport {
    /// Read one bounded chunk without allocating or waiting. The caller must
    /// enforce cumulative stream limits, a deadline and exact protocol contents.
    /// An empty buffer refuses rather than reporting a misleading EOF.
    pub fn read_output_chunk(
        &self,
        stream: InspectionStream,
        buffer: &mut [u8],
    ) -> Result<OutputProgress, ProcessRefused> {
        let length = buffer.len().min(IO_CHUNK_BYTES);
        if length == 0 {
            return Err(ProcessRefused);
        }
        let fd = match stream {
            InspectionStream::Output => self.output(),
            InspectionStream::Error => self.error(),
        };
        match rustix::io::read(fd, &mut buffer[..length]) {
            Ok(0) => Ok(OutputProgress::Eof),
            Ok(count) => Ok(OutputProgress::Read(count)),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(OutputProgress::Pending),
            Err(_) => Err(ProcessRefused),
        }
    }

    /// Write at most 1024 bytes without blocking. Empty input and closed pipes
    /// refuse. SIGPIPE must remain ignored for the transport lifetime: this check
    /// never changes process signal handling and cannot control foreign changes.
    pub fn write_input_chunk(&self, bytes: &[u8]) -> Result<InputProgress, ProcessRefused> {
        if bytes.is_empty() {
            return Err(ProcessRefused);
        }
        require_ignored_sigpipe()?;
        let input = self.input().ok_or(ProcessRefused)?;
        match rustix::io::write(input, &bytes[..bytes.len().min(IO_CHUNK_BYTES)]) {
            Ok(0) => Err(ProcessRefused),
            Ok(count) => Ok(InputProgress::Written(count)),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(InputProgress::Pending),
            Err(_) => Err(ProcessRefused),
        }
    }
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

fn require_ignored_sigpipe() -> Result<(), ProcessRefused> {
    let mut action = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: null action is a read-only query, old action points to writable
    // storage. Initialized output is read only after the query succeeds.
    if unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), action.as_mut_ptr()) } != 0 {
        return Err(ProcessRefused);
    }
    // SAFETY: successful sigaction initialized the output structure.
    validate_sigpipe(unsafe { action.assume_init() }.sa_sigaction)
}

fn validate_sigpipe(handler: libc::sighandler_t) -> Result<(), ProcessRefused> {
    if handler == libc::SIG_IGN {
        Ok(())
    } else {
        Err(ProcessRefused)
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
    fn output_reads_preserve_streams_bounds_and_eof_after_buffered_bytes() {
        let launch = crate::acquire_launch_guard(std::time::Duration::from_secs(5)).unwrap();
        let (parent, child) = create(&launch).unwrap();
        let mut buffer = [0; 2048];
        for stream in [InspectionStream::Output, InspectionStream::Error] {
            assert!(parent.read_output_chunk(stream, &mut []).is_err());
            assert_eq!(
                parent.read_output_chunk(stream, &mut buffer).unwrap(),
                OutputProgress::Pending
            );
        }
        assert_eq!(rustix::io::write(&child.output, &[7; 1025]).unwrap(), 1025);
        assert_eq!(rustix::io::write(&child.error, &[9]).unwrap(), 1);
        drop(child);
        assert_eq!(
            parent
                .read_output_chunk(InspectionStream::Output, &mut buffer)
                .unwrap(),
            OutputProgress::Read(1024)
        );
        assert_eq!(&buffer[..1024], &[7; 1024]);
        assert_eq!(&buffer[1024..], &[0; 1024]);
        for (stream, expected) in [(InspectionStream::Output, 7), (InspectionStream::Error, 9)] {
            let mut byte = [0];
            assert_eq!(
                parent.read_output_chunk(stream, &mut byte).unwrap(),
                OutputProgress::Read(1)
            );
            assert_eq!(byte, [expected]);
            assert_eq!(
                parent.read_output_chunk(stream, &mut byte).unwrap(),
                OutputProgress::Eof
            );
        }
    }

    #[test]
    fn sigpipe_policy_refuses_default_and_custom_handlers() {
        assert!(validate_sigpipe(libc::SIG_IGN).is_ok());
        assert!(validate_sigpipe(libc::SIG_DFL).is_err());
        assert!(validate_sigpipe(libc::SIG_ERR).is_err());
    }

    #[test]
    fn full_pipe_returns_pending_without_blocking() {
        let launch = crate::acquire_launch_guard(std::time::Duration::from_secs(5)).unwrap();
        let (parent, _child) = create(&launch).unwrap();
        for _ in 0..4096 {
            if parent.write_input_chunk(&[0; 1024]).unwrap() == InputProgress::Pending {
                return;
            }
        }
        panic!("native pipe did not apply backpressure within bounded fixture writes");
    }

    #[test]
    fn writes_are_chunked_and_closed_inputs_refuse_without_signal_changes() {
        let launch = crate::acquire_launch_guard(std::time::Duration::from_secs(5)).unwrap();
        let (mut parent, child) = create(&launch).unwrap();
        require_ignored_sigpipe().unwrap();
        assert!(parent.write_input_chunk(b"").is_err());
        assert_eq!(
            parent.write_input_chunk(&[7; 2048]).unwrap(),
            InputProgress::Written(1024)
        );
        let mut received = [0; 1024];
        assert_eq!(rustix::io::read(&child.input, &mut received).unwrap(), 1024);
        assert_eq!(received, [7; 1024]);
        drop(child);
        assert!(parent.write_input_chunk(b"x").is_err());
        parent.close_input();
        assert!(parent.write_input_chunk(b"x").is_err());
        require_ignored_sigpipe().unwrap();
    }

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
