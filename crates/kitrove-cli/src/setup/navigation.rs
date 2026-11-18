//! Scan navigation only: arrows select an action; write approvals use the existing prompts.
#[cfg(unix)]
use std::io::IsTerminal as _;
use std::io::Write;
#[cfg(any(unix, test))]
use std::io::{self, BufRead};

use super::{Dialog, PromptInput};
#[cfg(any(unix, test))]
use super::{cancelled, io_error};
#[cfg(unix)]
use super::{menu_input, presentation};
use crate::args::CliError;

pub(super) fn choose(
    dialog: &mut Dialog<impl PromptInput, impl Write>,
    title: &str,
    choices: &[(u8, String)],
    default: usize,
) -> Result<u8, CliError> {
    let keys: Vec<_> = choices.iter().map(|(key, _)| *key).collect();
    let arrows = dialog.single_key && supports_arrows(choices.len());
    let menu = message(title, choices, default, arrows);
    if !arrows {
        let answer = dialog.decision(&menu, &keys, true)?;
        return Ok(answer.as_bytes().first().copied().unwrap_or(keys[default]));
    }
    #[cfg(unix)]
    {
        menu_input::discard_pending().map_err(|_| io_error())?;
        presentation::prompt(&mut dialog.output, dialog.color, &menu).map_err(|_| io_error())?;
        dialog.output.flush().map_err(|_| io_error())?;
        let mut mode = menu_input::Mode::enter().map_err(|_| io_error())?;
        let mut selected = default;
        let result = loop {
            let event = dialog
                .input
                .with_reader(|reader| read_event(reader, |timed| mode.timed_continuation(timed)));
            match event {
                Ok(Event::Up) => selected = (selected + choices.len() - 1) % choices.len(),
                Ok(Event::Down) => selected = (selected + 1) % choices.len(),
                Ok(Event::Enter) => break Ok(keys[selected]),
                Ok(Event::Key(key)) if keys.contains(&key) => break Ok(key),
                Ok(Event::Key(_)) => continue,
                Err(error) => break Err(error),
            }
            if redraw(&mut dialog.output, choices, selected, dialog.color).is_err() {
                break Err(io_error());
            }
        };
        let discarded = menu_input::discard_pending();
        mode.restore().map_err(|_| io_error())?;
        discarded.map_err(|_| io_error())?;
        writeln!(dialog.output).map_err(|_| io_error())?;
        result
    }
    #[cfg(not(unix))]
    unreachable!("arrow navigation is enabled only on supported Unix terminals")
}

fn supports_arrows(count: usize) -> bool {
    // Native Windows and unknown/narrow terminals retain the immediate-key menu.
    #[cfg(unix)]
    {
        io::stdin().is_terminal()
            && io::stdout().is_terminal()
            && presentation::enabled(true, false, std::env::var("TERM").ok().as_deref())
            && rustix::termios::tcgetwinsize(io::stdout())
                .is_ok_and(|size| size.ws_col >= 70 && usize::from(size.ws_row) >= count + 5)
    }
    #[cfg(not(unix))]
    {
        let _ = count;
        false
    }
}

fn row(key: u8, label: &str, selected: bool) -> String {
    format!(
        "{} [{}] {label}",
        if selected { ">" } else { " " },
        char::from(key)
    )
}

fn message(title: &str, choices: &[(u8, String)], selected: usize, arrows: bool) -> String {
    let mut text = title.to_owned();
    for (index, (key, label)) in choices.iter().enumerate() {
        text.push('\n');
        text.push_str(&row(*key, label, index == selected));
    }
    text.push_str(if arrows {
        "\nUp/Down to move; Enter to select; or press a shortcut."
    } else {
        "\nPress a shortcut; Enter selects the marked action."
    });
    text
}

#[cfg(unix)]
fn redraw(
    out: &mut impl Write,
    choices: &[(u8, String)],
    selected: usize,
    color: bool,
) -> io::Result<()> {
    // This bounded region contains compiled menu labels only. Raw mode needs explicit CRLF.
    write!(out, "\x1b[{}A\r", choices.len() + 1)?;
    for (index, (key, label)) in choices.iter().enumerate() {
        write!(out, "\x1b[2K  ")?;
        presentation::styled(
            out,
            color && index == selected,
            presentation::Tone::Prompt,
            &row(*key, label, index == selected),
        )?;
        write!(out, "\r\n")?;
    }
    write!(
        out,
        "\x1b[2K  Up/Down to move; Enter to select; or press a shortcut.\r\n\x1b[2K> "
    )?;
    out.flush()
}

#[cfg(any(unix, test))]
#[derive(Debug, Eq, PartialEq)]
enum Event {
    Up,
    Down,
    Enter,
    Key(u8),
}

#[cfg(any(unix, test))]
fn read_event(
    input: &mut dyn BufRead,
    mut timed: impl FnMut(bool) -> io::Result<()>,
) -> Result<Event, CliError> {
    let mut queued = 0;
    let mut next = |input: &mut dyn BufRead| -> Result<u8, CliError> {
        let bytes = input.fill_buf().map_err(|_| io_error())?;
        let byte = bytes.first().copied().ok_or_else(cancelled)?;
        queued = bytes.len() - 1;
        input.consume(1);
        Ok(byte)
    };
    let first = next(input)?;
    let event = match first {
        27 => {
            // At most two continuation reads, each with the native 100ms timer.
            timed(true).map_err(|_| io_error())?;
            let decoded = (|| {
                let prefix = next(input)?;
                if !matches!(prefix, b'[' | b'O') {
                    return Err(cancelled());
                }
                match next(input)? {
                    b'A' => Ok(Event::Up),
                    b'B' => Ok(Event::Down),
                    _ => Err(cancelled()),
                }
            })();
            timed(false).map_err(|_| io_error())?;
            decoded
        }
        b'\r' | b'\n' => Ok(Event::Enter),
        b'q' | b'Q' | 3 | 4 => Err(cancelled()),
        key => Ok(Event::Key(key.to_ascii_lowercase())),
    };
    // No queued answer can cross from navigation into a collection confirmation.
    if !matches!(event, Ok(Event::Up | Event::Down)) {
        input.consume(queued);
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fragmented(Vec<u8>);
    impl io::Read for Fragmented {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unreachable!()
        }
    }
    impl BufRead for Fragmented {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(&self.0[..self.0.len().min(1)])
        }
        fn consume(&mut self, n: usize) {
            self.0.drain(..n);
        }
    }

    #[test]
    fn fragmented_arrows_are_navigation_not_escape_or_approval() {
        for (sequence, event) in [
            (b"\x1b[A", Event::Up),
            (b"\x1b[B", Event::Down),
            (b"\x1bOA", Event::Up),
        ] {
            let mut toggles = Vec::new();
            assert_eq!(
                read_event(&mut Fragmented(sequence.to_vec()), |timed| {
                    toggles.push(timed);
                    Ok(())
                })
                .unwrap(),
                event
            );
            assert_eq!(toggles, [true, false]);
        }
    }

    #[test]
    fn cancellation_and_unknown_sequences_cannot_select_or_leak_later_answers() {
        for bytes in [
            b"\x1b[15~ay".as_slice(),
            b"qay",
            b"\x03ay",
            b"\x04ay",
            b"\x1b",
            b"\x1b[",
            b"",
        ] {
            let mut input = io::Cursor::new(bytes);
            assert_eq!(
                read_event(&mut input, |_| Ok(())).unwrap_err().code,
                "setup.cancelled"
            );
            assert!(input.fill_buf().unwrap().is_empty());
        }
        for bytes in [b"ay\ny\n".as_slice(), b"\ry\n"] {
            let mut input = io::Cursor::new(bytes);
            read_event(&mut input, |_| Ok(())).unwrap();
            assert!(input.fill_buf().unwrap().is_empty());
        }
    }

    #[test]
    fn failed_continuation_restores_blocking_mode_before_returning() {
        let mut toggles = Vec::new();
        assert!(
            read_event(&mut io::Cursor::new(b"\x1b["), |timed| {
                toggles.push(timed);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(toggles, [true, false]);
    }
}
