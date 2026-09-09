#[cfg(windows)]
mod shared {
    include!("../../kitrove-version-probe/test-fixtures/shared_windows_fixture.rs");
}

#[cfg(windows)]
fn main() {
    shared::run(|_| false);
}

#[cfg(not(windows))]
fn main() {}
