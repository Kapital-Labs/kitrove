//! Terminal input isolation and the inline picker's temporary Unix mode.
use std::io;

#[cfg(unix)]
pub(super) fn discard_pending() -> io::Result<()> {
    rustix::termios::tcflush(io::stdin(), rustix::termios::QueueSelector::IFlush)?;
    Ok(())
}

#[cfg(windows)]
pub(super) fn discard_pending() -> io::Result<()> {
    kitrove_windows_security::console_input::discard_pending_input(&io::stdin())
}

#[cfg(not(any(unix, windows)))]
pub(super) fn discard_pending() -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(unix)]
pub(super) struct Mode {
    input: io::Stdin,
    prior: rustix::termios::Termios,
    active: bool,
}

#[cfg(unix)]
impl Mode {
    pub(super) fn enter() -> io::Result<Self> {
        let input = io::stdin();
        let prior = rustix::termios::tcgetattr(&input)?;
        let mut mode = prior.clone();
        mode.make_raw();
        rustix::termios::tcsetattr(&input, rustix::termios::OptionalActions::Now, &mode)?;
        Ok(Self {
            input,
            prior,
            active: true,
        })
    }

    // Only the scan arrow decoder uses this two-byte, bounded continuation mode.
    pub(super) fn timed_continuation(&mut self, timed: bool) -> io::Result<()> {
        use rustix::termios::SpecialCodeIndex;
        let mut mode = rustix::termios::tcgetattr(&self.input)?;
        mode.special_codes[SpecialCodeIndex::VMIN] = if timed { 0 } else { 1 };
        mode.special_codes[SpecialCodeIndex::VTIME] = u8::from(timed);
        rustix::termios::tcsetattr(&self.input, rustix::termios::OptionalActions::Now, &mode)?;
        Ok(())
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        if self.active {
            rustix::termios::tcsetattr(
                &self.input,
                rustix::termios::OptionalActions::Now,
                &self.prior,
            )?;
            self.active = false;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for Mode {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
