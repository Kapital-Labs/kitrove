//! Own a console-mode snapshot only for immediate numbered-menu input.
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, OwnedHandle};

use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, FlushConsoleInputBuffer,
    GetConsoleMode, SetConsoleMode,
};

/// Discards input already queued before a new interactive decision is displayed.
pub fn discard_pending_input(input: &impl AsHandle) -> io::Result<()> {
    // SAFETY: the borrowed console handle remains valid for this synchronous call.
    if unsafe { FlushConsoleInputBuffer(input.as_handle().as_raw_handle()) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Restores the exact prior input mode on the same retained console handle.
pub struct ConsoleInputMode {
    handle: OwnedHandle,
    prior: u32,
    active: bool,
}

impl ConsoleInputMode {
    /// Disables line buffering, echo and signal handling for one menu read.
    pub fn single_key(input: &impl AsHandle) -> io::Result<Self> {
        let handle = input.as_handle().try_clone_to_owned()?;
        let mut prior = 0;
        // SAFETY: the owned duplicate remains valid; the output is one live u32.
        if unsafe { GetConsoleMode(handle.as_raw_handle(), &mut prior) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mode = prior & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        // SAFETY: only the same retained input console's documented mode bits change.
        if unsafe { SetConsoleMode(handle.as_raw_handle(), mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            prior,
            active: true,
        })
    }

    /// Refuses continuation when restoring the exact original mode fails.
    pub fn restore(&mut self) -> io::Result<()> {
        if self.active {
            // SAFETY: the handle is retained and prior came from GetConsoleMode.
            if unsafe { SetConsoleMode(self.handle.as_raw_handle(), self.prior) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for ConsoleInputMode {
    fn drop(&mut self) {
        // Explicit restore reports failures; this is also attempted during unwinding.
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_regular_file_is_not_a_console_and_is_never_a_fallback_input() {
        let file = tempfile::tempfile().unwrap();
        assert!(ConsoleInputMode::single_key(&file).is_err());
        assert!(discard_pending_input(&file).is_err());
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
}
