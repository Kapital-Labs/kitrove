#[cfg(windows)]
mod shared {
    include!("shared_windows_fixture.rs");
}

#[cfg(windows)]
fn main() {
    shared::run(kitrove_windows_process::signal_inherited_event);
}

#[cfg(not(windows))]
fn main() {}
