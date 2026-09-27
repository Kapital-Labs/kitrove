//! Actual process termination at private test hooks, followed by production CLI recovery.
use super::*;

struct OwnedChild(std::process::Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
#[ignore = "operator-only; requires pinned artifacts and explicitly selected source-built libtest"]
fn real_upgrade_process_cuts_recover_in_fresh_cli() {
    replacement_process_cuts(false, false, false);
}

#[test]
#[ignore = "operator-only; requires pinned artifacts and explicitly selected source-built libtest"]
fn real_rollback_process_cuts_recover_in_fresh_cli() {
    replacement_process_cuts(true, false, false);
}

#[test]
#[ignore = "operator-only; requires pinned artifacts and explicitly selected source-built libtest"]
fn real_populated_upgrade_process_cuts_recover_in_fresh_cli() {
    replacement_process_cuts(false, true, false);
}

#[test]
#[ignore = "operator-only; requires pinned artifacts and explicitly selected source-built libtest"]
fn real_populated_rollback_process_cuts_recover_in_fresh_cli() {
    replacement_process_cuts(true, true, false);
}

#[test]
#[ignore = "operator-only; requires pinned artifacts and explicitly selected source-built libtest"]
fn real_repeated_upgrade_recovery_cuts() {
    replacement_process_cuts(false, true, true);
}

#[test]
#[ignore = "operator-only; requires pinned artifacts and explicitly selected source-built libtest"]
fn real_repeated_rollback_recovery_cuts() {
    replacement_process_cuts(true, true, true);
}

fn replacement_process_cuts(rollback: bool, populated: bool, repeated: bool) {
    use std::os::unix::process::ExitStatusExt as _;
    let direction = if rollback { "rollback" } else { "upgrade" };
    let evidence = PathBuf::from(
        std::env::var_os("KITROVE_TEST_RELEASE_EVIDENCE").expect("evidence directory"),
    );
    // The operator selects the local cargo --lib --no-run output, never a download.
    let child_binary = PathBuf::from(
        std::env::var_os("KITROVE_TEST_UPGRADE_LIBTEST").expect("source-built libtest path"),
    );
    assert!(child_binary.is_absolute());
    assert!(fs::symlink_metadata(&child_binary).unwrap().is_file());
    for cut in ["before-exchange", "exchanged", "replaced-recorded"] {
        let root = tempfile::Builder::new()
            .prefix(&format!(
                "real-{direction}-{}{}cut-",
                if repeated { "repeated-" } else { "" },
                if populated { "populated-" } else { "" }
            ))
            .tempdir_in(&evidence)
            .unwrap()
            .keep();
        println!(
            "preserved interrupted-upgrade evidence: {} ({cut})",
            root.display()
        );
        let destination = root.join("destination");
        fs::create_dir(&destination).unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
        let first = root.join("state-a");
        let second = root.join("state-b");
        let harness = root.join("synthetic-harness");
        fs::create_dir(&harness).unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o700)).unwrap();
        if populated {
            super::populated_state::populated(&first, &harness);
        } else {
            let _first = state(&first, VALID);
        }
        let _second = state(&second, VALID);
        let before = [snapshot(&first), snapshot(&second), snapshot(&harness)];
        fs::write(destination.join("unmanaged.txt"), CANARY).unwrap();
        let roots = vec![
            "--destination".to_owned(),
            destination.to_str().unwrap().to_owned(),
            "--state-root".into(),
            first.to_str().unwrap().into(),
            "--state-root".into(),
            second.to_str().unwrap().into(),
        ];
        for action in ["install", "retire-install"] {
            let mut args = vec![action.to_owned()];
            args.extend(release(&evidence, false, rollback));
            args.extend(roots.clone());
            invoke(&root, action, &args, None);
            assert_eq!(
                before,
                [snapshot(&first), snapshot(&second), snapshot(&harness)]
            );
        }
        let unmanaged = snapshot(&destination.join("unmanaged.txt"));
        let phases = if repeated {
            &["prepare", "recover"][..]
        } else {
            &["prepare"][..]
        };
        for phase in phases {
            let (ready_leaf, ready_value) = if *phase == "recover" {
                ("recovery-ready", "before-verification")
            } else {
                ("cut-ready", cut)
            };
            let mut child = OwnedChild(
                Command::new(&child_binary)
                    .env_clear()
                    .env("KITROVE_TEST_RELEASE_EVIDENCE", &evidence)
                    .env("KITROVE_TEST_UPGRADE_CUT_ROOT", &root)
                    .env("KITROVE_TEST_UPGRADE_CUT", cut)
                    .env("KITROVE_TEST_REPLACEMENT_DIRECTION", direction)
                    .env("KITROVE_TEST_CUT_ACTION", phase)
                    .args([
                        "--exact",
                        "upgrade_transaction::real_interruption_tests::real_upgrade_cut_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdin(Stdio::null())
                    .stdout(fs::File::create(root.join(format!("{phase}-child.stdout"))).unwrap())
                    .stderr(fs::File::create(root.join(format!("{phase}-child.stderr"))).unwrap())
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "child exited before interruption"
                );
                if fs::read(root.join(ready_leaf))
                    .is_ok_and(|bytes| bytes == ready_value.as_bytes())
                {
                    break;
                }
                assert!(Instant::now() < deadline, "child readiness timed out");
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().unwrap();
            assert_eq!(child.0.wait().unwrap().signal(), Some(9));
            assert_eq!(
                before,
                [snapshot(&first), snapshot(&second), snapshot(&harness)]
            );
            assert_eq!(unmanaged, snapshot(&destination.join("unmanaged.txt")));
            for path in [
                format!("{phase}-child.stdout"),
                format!("{phase}-child.stderr"),
            ] {
                assert!(
                    !fs::read_to_string(root.join(path))
                        .unwrap()
                        .contains(CANARY)
                );
            }
        }
        for action in [
            format!("recover-{direction}"),
            format!("retire-{direction}"),
        ] {
            let mut args = vec![action.clone()];
            args.extend(release(&evidence, false, !rollback));
            for pair in release(&evidence, true, rollback).chunks_exact(2) {
                if !matches!(pair[0].as_str(), "--prior-archive" | "--prior-bundle") {
                    args.extend_from_slice(pair);
                }
            }
            args.extend(roots.clone());
            invoke(&root, &action, &args, None);
            assert_eq!(
                before,
                [snapshot(&first), snapshot(&second), snapshot(&harness)]
            );
            assert_eq!(unmanaged, snapshot(&destination.join("unmanaged.txt")));
            let expected = if rollback {
                "766afbe0279cf6a1f623a8a69bb122cfdcb3206f26a7b7c1acceff749e905e7e"
            } else {
                "54ac690c5ae5b0bcc480f4925b0f7ef5fe4e9b777a6b9390ca0ead593715bed2"
            };
            let actual = Sha256::digest(fs::read(destination.join("kitrove")).unwrap());
            for (index, byte) in actual.iter().enumerate() {
                assert_eq!(
                    *byte,
                    u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16).unwrap()
                );
            }
        }
        println!(
            "{direction}/{cut}: SIGKILL observed, fresh recovery/retirement passed, candidate digest and state preserved"
        );
    }
}
