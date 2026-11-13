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

/// Returns whether a path spells a parent-directory segment under either Windows separator.
///
/// Verbatim Windows paths do not treat `/` as a separator, so `std::path` reports
/// `other/../target` as one normal component. Other platforms have no such spelling.
#[cfg(windows)]
#[must_use]
pub fn raw_parent_component(path: &std::path::Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| segment == "..")
}

/// Returns whether a path spells a parent-directory segment under either Windows separator.
#[cfg(not(windows))]
#[must_use]
pub const fn raw_parent_component(_path: &std::path::Path) -> bool {
    false
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

    #[test]
    fn raw_parent_segments_are_found_only_under_windows_separator_rules() {
        use std::path::Path;

        for path in ["/root/other/../target", "relative/..", ".."] {
            assert_eq!(
                raw_parent_component(Path::new(path)),
                cfg!(windows),
                "{path}"
            );
        }
        for path in ["/root/a..b", "/root/...", "/root/..hidden", ""] {
            assert!(!raw_parent_component(Path::new(path)), "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn raw_parent_segments_are_found_inside_verbatim_components() {
        use std::path::Path;

        for path in [
            r"\?\C:\root\other/../target",
            r"C:\root\..\target",
            r"\?\C:\root\..",
        ] {
            assert!(raw_parent_component(Path::new(path)), "{path}");
        }
    }
}
