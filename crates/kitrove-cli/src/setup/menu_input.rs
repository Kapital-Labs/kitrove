//! Immediate navigation and explicit adoption decisions; other input stays line based.
use std::io::{self, BufRead};

use super::{cancelled, io_error};
use crate::args::CliError;

pub(super) fn read(
    input: &mut dyn BufRead,
    keys: &[u8],
    accept_enter: bool,
) -> Result<String, CliError> {
    loop {
        let available = match input.fill_buf() {
            Ok(available) if !available.is_empty() => available,
            Ok(_) => return Err(cancelled()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
                    cancelled()
                } else {
                    io_error()
                });
            }
        };
        let queued = available.len();
        let key = available[0].to_ascii_lowercase();
        input.consume(1);
        let answer = match key {
            b'\r' | b'\n' if accept_enter => Some(Ok(String::new())),
            // Escape cancels instead of interpreting digits inside an escape sequence.
            b'q' | 3 | 4 | 27 => Some(Err(cancelled())),
            key if keys.contains(&key) => Some(Ok(char::from(key).to_string())),
            _ => None,
        };
        if let Some(answer) = answer {
            // A trailing Enter/yes or repeat cannot become another prompt's approval.
            input.consume(queued - 1);
            return answer;
        }
    }
}

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

#[cfg(windows)]
pub(super) struct Mode(kitrove_windows_security::console_input::ConsoleInputMode);

#[cfg(windows)]
impl Mode {
    pub(super) fn enter() -> io::Result<Self> {
        kitrove_windows_security::console_input::ConsoleInputMode::single_key(&io::stdin())
            .map(Self)
    }

    pub(super) fn restore(&mut self) -> io::Result<()> {
        self.0.restore()
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) struct Mode;

#[cfg(not(any(unix, windows)))]
impl Mode {
    pub(super) fn enter() -> io::Result<Self> {
        Err(io::ErrorKind::Unsupported.into())
    }
    pub(super) fn restore(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for Mode {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_number_returns_without_a_newline_and_discards_queued_answers() {
        for number in b'1'..=b'5' {
            let mut input = io::Cursor::new(vec![number, b'n', b'\n']);
            assert_eq!(
                read(&mut input, b"12345", false).unwrap(),
                char::from(number).to_string()
            );
            assert_eq!(input.position(), 3);
            assert!(input.fill_buf().unwrap().is_empty());
        }
    }

    #[test]
    fn enter_uses_only_the_existing_finish_default() {
        for enter in *b"\n\r" {
            assert_eq!(
                read(&mut io::Cursor::new([enter]), b"12345", true).unwrap(),
                ""
            );
            assert_eq!(
                read(&mut io::Cursor::new([enter, b'2']), b"12345", false).unwrap(),
                "2"
            );
        }
    }

    #[test]
    fn invalid_keys_cannot_approve_and_controls_or_eof_cancel() {
        assert_eq!(
            read(&mut io::Cursor::new(b"0yYn96\t2"), b"12345", true).unwrap(),
            "2"
        );
        for key in [b'q', 3, 4, 27] {
            assert_eq!(
                read(&mut io::Cursor::new([key, b'1']), b"12345", true)
                    .unwrap_err()
                    .code,
                "setup.cancelled"
            );
        }
        assert_eq!(
            read(&mut io::Cursor::new([]), b"12345", true)
                .unwrap_err()
                .code,
            "setup.cancelled"
        );
    }

    #[test]
    fn adoption_letters_and_enter_are_immediate_but_eof_is_not_an_enter() {
        for queued in [b"r\r".as_slice(), b"y\n", b"yes\n", b"rr\r"] {
            let mut input = io::Cursor::new(queued);
            assert_eq!(
                read(&mut input, b"ysrdn", true).unwrap(),
                char::from(queued[0]).to_string()
            );
            assert!(input.fill_buf().unwrap().is_empty());
        }
        for key in *b"ysrdnYSRDN" {
            let mut input = io::Cursor::new([key]);
            assert_eq!(
                read(&mut input, b"ysrdn", true).unwrap(),
                char::from(key.to_ascii_lowercase()).to_string()
            );
        }
        assert_eq!(
            read(&mut io::Cursor::new(b"\n"), b"ysrdn", true).unwrap(),
            ""
        );
        assert_eq!(
            read(&mut io::Cursor::new([]), b"ysrdn", true)
                .unwrap_err()
                .code,
            "setup.cancelled"
        );
    }
}
