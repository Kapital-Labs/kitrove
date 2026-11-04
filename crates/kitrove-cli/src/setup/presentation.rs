//! Fixed terminal styles only; no color or text is taken from untrusted control sequences.
use std::io::{self, Write};

#[derive(Clone, Copy)]
pub(super) enum Tone {
    Heading,
    Prompt,
    Hint,
    Success,
    Warning,
    Error,
}

pub(super) fn enabled(terminal: bool, no_color: bool, term: Option<&str>) -> bool {
    terminal
        && !no_color
        && term.is_some_and(|term| {
            [
                "xterm",
                "screen",
                "tmux",
                "rxvt",
                "alacritty",
                "kitty",
                "wezterm",
            ]
            .iter()
            .any(|prefix| term.starts_with(prefix))
                || matches!(term, "ansi" | "vt100" | "linux")
        })
}

pub(super) fn detect(terminal: bool) -> bool {
    enabled(
        terminal,
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("TERM").ok().as_deref(),
    )
}

pub(super) fn styled<W: Write>(out: &mut W, color: bool, tone: Tone, text: &str) -> io::Result<()> {
    if color {
        let sequence = match tone {
            Tone::Heading => "\x1b[1m",
            Tone::Prompt => "\x1b[1;36m",
            Tone::Hint => "\x1b[2m",
            Tone::Success => "\x1b[32m",
            Tone::Warning => "\x1b[33m",
            Tone::Error => "\x1b[31m",
        };
        write!(out, "{sequence}{text}\x1b[0m")
    } else {
        write!(out, "{text}")
    }
}

pub(super) fn prompt<W: Write>(out: &mut W, color: bool, message: &str) -> io::Result<()> {
    writeln!(out)?;
    let mut lines = message.trim_start_matches('\n').lines();
    let first = lines.next().unwrap_or_default();
    styled(out, color, Tone::Prompt, &format!("? {first}"))?;
    writeln!(out)?;
    for line in lines {
        writeln!(out, "  {line}")?;
    }
    styled(out, color, Tone::Prompt, "> ")
}

// Callers supply already escaped human output, never raw provider output or JSON automation.
pub(super) fn block<W: Write>(out: &mut W, color: bool, title: &str, text: &str) -> io::Result<()> {
    writeln!(out)?;
    styled(out, color, Tone::Heading, title)?;
    writeln!(out)?;
    for line in text.lines() {
        writeln!(out, "  | {line}")?;
    }
    Ok(())
}

pub(super) fn notice<W: Write>(
    out: &mut W,
    color: bool,
    tone: Tone,
    label: &str,
    text: &str,
) -> io::Result<()> {
    styled(out, color, tone, label)?;
    writeln!(out, ": {text}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_is_opt_in_to_a_recognized_terminal_and_never_overrides_no_color() {
        for term in [Some("xterm-256color"), Some("screen"), Some("ansi")] {
            assert!(enabled(true, false, term));
            assert!(!enabled(false, false, term));
            assert!(!enabled(true, true, term));
        }
        for term in [None, Some(""), Some("dumb"), Some("unknown")] {
            assert!(!enabled(true, false, term));
        }
    }

    #[test]
    fn colored_prompt_resets_style_before_user_input() {
        let mut out = Vec::new();
        prompt(&mut out, true, "Continue?\nn skips").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\n\x1b[1;36m? Continue?\x1b[0m\n  n skips\n\x1b[1;36m> \x1b[0m"
        );
    }

    #[test]
    fn statuses_have_text_labels_in_color_and_plain_modes() {
        for color in [false, true] {
            let mut out = Vec::new();
            for (tone, label) in [
                (Tone::Success, "Completed"),
                (Tone::Warning, "Warning"),
                (Tone::Error, "Error"),
            ] {
                notice(&mut out, color, tone, label, "fixture").unwrap();
            }
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains("Completed"));
            assert!(text.contains("Warning"));
            assert!(text.contains("Error"));
            assert_eq!(text.contains('\x1b'), color);
        }
    }
}
