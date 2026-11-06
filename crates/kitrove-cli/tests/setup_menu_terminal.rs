//! Real terminal regression; only disposable synthetic homes and collections.
#[cfg(unix)]
#[test]
fn numbered_menus_advance_without_enter_and_restore_line_input() {
    // State fixtures require trusted ancestry, including on Linux where /tmp is shared.
    let fixture = kitrove_testkit::trusted_tempdir(".kitrove-menu-terminal-");
    let result = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/menu_terminal.py"
        ))
        .arg(env!("CARGO_BIN_EXE_kitrove"))
        .arg(fixture.path())
        .output()
        .expect("Python is a required repository test prerequisite");
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
