//! Test-only writer isolation. No production probe policy or execution retry.
#![cfg(unix)]
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) fn write_script(root: &Path, name: &str, body: &str) {
    assert!(root.is_absolute());
    assert!(matches!(
        name,
        "pi" | "opencode2" | "kitrove" | "kitrove-other"
    ));
    assert!(body.len() <= 16 * 1024);
    // Only the isolated child opens the executable for writing. Reaping it
    // closes that writer before any real probe, including under parallel spawn.
    let mut child = crate::unix_process::spawn_test_child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "probe_fixture::writer_child", "--ignored"])
            .env_clear()
            .env("KITROVE_LIBRARY_FIXTURE_ROOT", root)
            .env("KITROVE_LIBRARY_FIXTURE_NAME", name)
            .env("KITROVE_LIBRARY_FIXTURE_BODY", body)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .unwrap();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "isolated library fixture writer failed: {status}"
    );
}

#[test]
#[ignore = "invoked only by the isolated library fixture parent"]
fn writer_child() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::var_os("KITROVE_LIBRARY_FIXTURE_ROOT").unwrap();
    let name = std::env::var("KITROVE_LIBRARY_FIXTURE_NAME").unwrap();
    let body = std::env::var("KITROVE_LIBRARY_FIXTURE_BODY").unwrap();
    assert!(Path::new(&root).is_absolute());
    assert!(matches!(
        name.as_str(),
        "pi" | "opencode2" | "kitrove" | "kitrove-other"
    ));
    assert!(body.len() <= 16 * 1024);
    let binary = Path::new(&root).join(name);
    std::fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn isolated_writer_publishes_real_hash_bound_probe() {
    let root = tempfile::tempdir().unwrap();
    write_script(root.path(), "pi", "printf '0.83.0\\n'");
    let binary = root.path().join("pi");
    assert!(
        binary.is_file(),
        "isolated writer must publish the fixture before returning"
    );
    assert_eq!(
        std::fs::read(&binary).unwrap(),
        b"#!/bin/sh\nprintf '0.83.0\\n'\n"
    );
    let result = crate::probe_pi_version(&binary).unwrap();
    assert_eq!(result.evidence().observed().as_str(), "0.83.0");
    assert!(
        result.evidence().evidence().as_str().ends_with(
            result
                .executable_hash()
                .as_str()
                .trim_start_matches("blake3:")
        )
    );
}

#[test]
fn parallel_isolated_library_fixtures_require_real_verified_evidence() {
    let (sender, receiver) = std::sync::mpsc::channel();
    let workers = (0..4)
        .map(|_| {
            let sender = sender.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    let root = tempfile::tempdir().unwrap();
                    write_script(root.path(), "pi", "printf '0.83.0\\n'");
                    sender.send(root).unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    drop(sender);
    // Concurrent writers overlap ONE real probe consumer. This targets writer
    // inheritance, not extra concurrent inspections under the1s test budget.
    let outcomes = receiver
        .into_iter()
        .map(|root| {
            let binary = root.path().join("pi");
            let result = crate::probe_pi_version(&binary);
            let bytes = std::fs::read(binary);
            (root, result, bytes)
        })
        .collect::<Vec<_>>();
    let joined = workers
        .into_iter()
        .map(|worker| worker.join())
        .collect::<Vec<_>>();
    for worker in joined {
        worker.unwrap();
    }
    assert_eq!(outcomes.len(), 40);
    for (_root, result, bytes) in outcomes {
        let result = result.unwrap();
        assert_eq!(result.evidence().observed().as_str(), "0.83.0");
        assert_eq!(bytes.unwrap(), b"#!/bin/sh\nprintf '0.83.0\\n'\n");
        assert!(
            result.evidence().evidence().as_str().ends_with(
                result
                    .executable_hash()
                    .as_str()
                    .trim_start_matches("blake3:")
            )
        );
    }
}
