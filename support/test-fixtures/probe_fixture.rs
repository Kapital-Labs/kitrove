//! Test-only Pi executable publication without parent-process writable handles.

use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) fn write_pi(root: &Path, version: &str) {
    assert!(root.is_absolute());
    assert!(matches!(version, "0.83.0" | "0.84.0"));
    // A parallel spawn can retain a parent's writer until exec. Only this
    // selected child opens the script for writing; reap it before any real probe.
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "probe_fixture::writer_child", "--ignored"])
        .env_clear()
        .env("KITROVE_CORE_PROBE_ROOT", root)
        .env("KITROVE_CORE_PROBE_VERSION", version)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = {
        #[cfg(target_os = "macos")]
        let _launch =
            kitrove_macos_process::acquire_launch_guard(std::time::Duration::from_secs(5))
                .expect("existing test fixture launch gate");
        command.spawn().unwrap()
    };
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "isolated core fixture writer failed: {status}"
    );
}

#[test]
#[ignore = "invoked only by the isolated core fixture parent"]
fn writer_child() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = std::env::var_os("KITROVE_CORE_PROBE_ROOT").unwrap();
    let version = std::env::var("KITROVE_CORE_PROBE_VERSION").unwrap();
    assert!(Path::new(&root).is_absolute());
    assert!(matches!(version.as_str(), "0.83.0" | "0.84.0"));
    let binary = Path::new(&root).join("pi");
    std::fs::write(&binary, format!("#!/bin/sh\nprintf '{version}\\n'\n")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
}
