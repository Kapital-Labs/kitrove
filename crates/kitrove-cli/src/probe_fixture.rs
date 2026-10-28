//! Test-only executable publication without parent-process writable handles.
#![cfg(unix)]
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) fn write_probes(root: &Path) {
    // A parallel spawn can inherit a parent's close-on-exec writer until exec.
    // Create fixtures in an isolated writer and reap it before any real probe.
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe_fixture::writer_child", "--ignored"])
        .env_clear()
        .env("KITROVE_TEST_PROBE_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "isolated probe fixture writer failed: {status}"
    );
}

#[test]
#[ignore = "invoked only by the isolated parent fixture"]
fn writer_child() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    let root = std::env::var_os("KITROVE_TEST_PROBE_ROOT").unwrap();
    for (name, version) in [
        ("pi", "0.83.0"),
        ("opencode2", "opencode2 v0.0.0-beta-18387"),
    ] {
        let binary = Path::new(&root).join(name);
        fs::write(&binary, format!("#!/bin/sh\nprintf '{version}\\n'\n")).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn parallel_isolated_fixtures_still_require_real_verified_versions() {
    let workers = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..10 {
                    let root = tempfile::tempdir().unwrap();
                    write_probes(root.path());
                    let binary = root.path().join("pi");
                    let version = kitrove_version_probe::probe_pi_version(&binary).unwrap();
                    assert_eq!(version.evidence().observed().as_str(), "0.83.0");
                    assert_eq!(
                        std::fs::read(binary).unwrap(),
                        b"#!/bin/sh\nprintf '0.83.0\\n'\n"
                    );
                    assert!(
                        version.evidence().evidence().as_str().ends_with(
                            version
                                .executable_hash()
                                .as_str()
                                .trim_start_matches("blake3:")
                        )
                    );
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
}
