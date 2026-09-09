#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    #[cfg(any(unix, windows))]
    {
        kitrove_installer::main_entry()
    }
    #[cfg(not(any(unix, windows)))]
    {
        eprintln!("installer is unsupported on this platform");
        std::process::ExitCode::FAILURE
    }
}
