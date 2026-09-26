//! Synthetic retained-file crash tests, not native-signature or release acceptance.
//! All process controls and environment inputs are compiled only into unit tests.

use super::*;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

const BYTES: &[u8] = b"synthetic installer publication crash fixture";
const CHILD_TEST: &str = "installer_payload::crash_tests::child";

struct OwnedChild(Child);

impl OwnedChild {
    fn spawn(root: &Path, action: &str, boundary: &str) -> Self {
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
                .env("KITROVE_TEST_PUBLICATION_ROOT", root)
                .env("KITROVE_TEST_PUBLICATION_ACTION", action)
                .env("KITROVE_TEST_PUBLICATION_BOUNDARY", boundary)
                .spawn()
                .unwrap(),
        )
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "publication test child timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Own only this exact direct child. Reap even on assertion failure.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn selected_boundary(value: &str) -> PublicationBoundary {
    match value {
        "before-rename" => PublicationBoundary::BeforeRename,
        "renamed" => PublicationBoundary::Renamed,
        "executable" => PublicationBoundary::Executable,
        "synced" => PublicationBoundary::Synced,
        _ => panic!("unknown publication boundary"),
    }
}

#[test]
#[ignore = "source-built subprocess entry point; requires test fixture inputs"]
fn child() {
    let root = std::path::PathBuf::from(
        std::env::var_os("KITROVE_TEST_PUBLICATION_ROOT").expect("test fixture root"),
    );
    let boundary = selected_boundary(
        &std::env::var("KITROVE_TEST_PUBLICATION_BOUNDARY").expect("test boundary"),
    );
    match std::env::var("KITROVE_TEST_PUBLICATION_ACTION")
        .unwrap()
        .as_str()
    {
        "publish" => {
            let retained = stage(&root, BYTES, |_| Ok(())).unwrap();
            retained
                .publish_with(BYTES, |at| {
                    if at == boundary {
                        // Outside the bootstrap directory's exact one-leaf inventory.
                        std::fs::write(root.join("ready"), b"at boundary").unwrap();
                        // Parent kills us without running destructors. A finite fallback
                        // prevents an abandoned test fixture from sleeping indefinitely.
                        std::thread::sleep(Duration::from_secs(30));
                        panic!("parent did not interrupt publication");
                    }
                    Ok(())
                })
                .unwrap();
            panic!("selected publication boundary was not interrupted");
        }
        "reopen" => {
            let result = RetainedPayload::reopen_published(&root, BYTES);
            let complete = matches!(
                boundary,
                PublicationBoundary::Executable | PublicationBoundary::Synced
            );
            assert_eq!(result.is_ok(), complete);
            if let Ok(retained) = result {
                retained.revalidate_named(BYTES, EXECUTABLE, 0o700).unwrap();
            }
            // Also prove a retry cannot overwrite a partial or completed directory.
            assert!(stage(&root, BYTES, |_| Ok(())).is_err());
            std::fs::write(root.join("checked"), b"reopening checked").unwrap();
        }
        _ => panic!("unknown publication test action"),
    }
}

#[test]
fn killed_publication_is_reopened_or_refused_by_a_fresh_process() {
    use std::os::unix::process::ExitStatusExt;

    for boundary in ["before-rename", "renamed", "executable", "synced"] {
        let root = crate::test_support::private_tempdir();
        let mut publisher = OwnedChild::spawn(root.path(), "publish", boundary);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.path().join("ready").exists() {
            assert!(
                publisher.0.try_wait().unwrap().is_none(),
                "publisher exited before boundary"
            );
            assert!(
                Instant::now() < deadline,
                "publisher never reached boundary"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        publisher.0.kill().unwrap();
        assert_eq!(publisher.wait().signal(), Some(9));

        let (name, mode) = match boundary {
            "before-rename" => (PAYLOAD, 0o600),
            "renamed" => (EXECUTABLE, 0o600),
            _ => (EXECUTABLE, 0o700),
        };
        let directory = root.path().join(DIRECTORY);
        let path = directory.join(name);
        let before = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(before.mode() & 0o777, mode);
        assert_eq!(std::fs::read(&path).unwrap(), BYTES);

        let mut verifier = OwnedChild::spawn(root.path(), "reopen", boundary);
        assert!(verifier.wait().success());
        // A successful libtest process with an accidentally wrong selector is not proof.
        assert_eq!(
            std::fs::read(root.path().join("checked")).unwrap(),
            b"reopening checked"
        );
        let after = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode(), after.len()),
            (before.dev(), before.ino(), before.mode(), before.len())
        );
        assert_eq!(std::fs::read(&path).unwrap(), BYTES);
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 1);
    }
}
