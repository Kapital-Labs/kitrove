//! Real terminal regression; only disposable synthetic homes and collections.
#[cfg(unix)]
#[test]
fn menus_submit_with_enter_and_restore_line_input() {
    // State fixtures require trusted ancestry, including on Linux where /tmp is shared.
    let fixture = kitrove_testkit::trusted_tempdir(".kitrove-menu-terminal-");
    isolate_project_discovery(fixture.path());
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

// A synthetic Git marker bounds project discovery; no Git process or remote is used.
#[cfg(unix)]
fn isolate_project_discovery(root: &std::path::Path) {
    std::fs::create_dir(root.join(".git")).expect("create the synthetic project boundary");
}

#[cfg(unix)]
#[test]
fn terminal_fixture_boundary_excludes_ambient_ancestor_skills() {
    let outer = kitrove_testkit::trusted_tempdir(".kitrove-terminal-boundary-");
    std::fs::create_dir(outer.path().join(".git")).unwrap();
    let ambient = outer.path().join("ambient");
    let source = ambient.join(".agents/skills/terminal-ambient-sentinel");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("SKILL.md"),
        "---\nname: terminal-ambient-sentinel\ndescription: Synthetic ancestor.\n---\nNot part of the terminal fixture.\n",
    )
    .unwrap();
    let fixture = ambient.join("fixture");
    std::fs::create_dir(&fixture).unwrap();
    let home = fixture.join("home");
    std::fs::create_dir(&home).unwrap();
    isolate_project_discovery(&fixture);
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["scan", "--harness", "pi", "--scope", "project", "--json"])
        .current_dir(&fixture)
        .env("HOME", &home)
        .env("KITROVE_STATE_HOME", fixture.join("state"))
        .env_remove("KITROVE_ENV")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap();
    assert!(matches!(result.status.code(), Some(0 | 3)));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        !report.to_string().contains("terminal-ambient-sentinel"),
        "terminal fixture scanned its synthetic ambient ancestor"
    );
    assert!(!fixture.join("state").exists());
}
