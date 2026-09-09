#![forbid(unsafe_code)]
//! Shared lossless ordinary-Win32 path-component policy.

/// Returns whether one component has lossless ordinary Win32 path semantics.
#[must_use]
pub fn is_lossless_windows_component(component: &str) -> bool {
    if component.is_empty()
        || component.ends_with('.')
        || component.ends_with(' ')
        || component.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
        })
    {
        return false;
    }

    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches([' ', '.']);
    let folded = stem.to_ascii_uppercase();
    !matches!(
        folded.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "CONIN$"
            | "CONOUT$"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_devices_aliases_and_lossy_win32_spelling() {
        for component in [
            "",
            "NUL",
            "con.txt",
            "CLOCK$",
            "CONIN$.exe",
            "CONOUT$.exe",
            "CON .txt",
            "COM1 .log",
            "COM1",
            "COM¹.txt",
            "LPT9.log",
            "LPT³",
            "trailing.",
            "trailing ",
            "bad:name",
            "a/b",
            "a\\b",
            "control\u{1f}",
        ] {
            assert!(!is_lossless_windows_component(component), "{component:?}");
        }
        for component in ["pi.exe", "console.txt", "COM10", "LPT0", "normal name"] {
            assert!(is_lossless_windows_component(component), "{component:?}");
        }
    }
}
