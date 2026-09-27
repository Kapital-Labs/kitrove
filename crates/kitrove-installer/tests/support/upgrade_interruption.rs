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
    use std::os::unix::process::ExitStatusExt as _;
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
            .prefix("real-upgrade-cut-")
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
        let _first = state(&first, VALID);
        let _second = state(&second, VALID);
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
            args.extend(release(&evidence, false, false));
            args.extend(roots.clone());
            invoke(&root, action, &args, None);
        }
        let before = [snapshot(&first), snapshot(&second)];
        let unmanaged = snapshot(&destination.join("unmanaged.txt"));
        let mut child = OwnedChild(
            Command::new(&child_binary)
                .env_clear()
                .env("KITROVE_TEST_RELEASE_EVIDENCE", &evidence)
                .env("KITROVE_TEST_UPGRADE_CUT_ROOT", &root)
                .env("KITROVE_TEST_UPGRADE_CUT", cut)
                .args([
                    "--exact",
                    "upgrade_transaction::real_interruption_tests::real_upgrade_cut_child",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(Stdio::null())
                .stdout(fs::File::create(root.join("child.stdout")).unwrap())
                .stderr(fs::File::create(root.join("child.stderr")).unwrap())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before interruption"
            );
            if fs::read(root.join("cut-ready")).is_ok_and(|bytes| bytes == cut.as_bytes()) {
                break;
            }
            assert!(Instant::now() < deadline, "child readiness timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        assert_eq!(before, [snapshot(&first), snapshot(&second)]);
        assert_eq!(unmanaged, snapshot(&destination.join("unmanaged.txt")));
        for path in ["child.stdout", "child.stderr"] {
            assert!(
                !fs::read_to_string(root.join(path))
                    .unwrap()
                    .contains(CANARY)
            );
        }
        for action in ["recover-upgrade", "retire-upgrade"] {
            let mut args = vec![action.to_owned()];
            args.extend(release(&evidence, false, true));
            for pair in release(&evidence, true, false).chunks_exact(2) {
                if !matches!(pair[0].as_str(), "--prior-archive" | "--prior-bundle") {
                    args.extend_from_slice(pair);
                }
            }
            args.extend(roots.clone());
            invoke(&root, action, &args, None);
            assert_eq!(before, [snapshot(&first), snapshot(&second)]);
            assert_eq!(unmanaged, snapshot(&destination.join("unmanaged.txt")));
            let expected = "54ac690c5ae5b0bcc480f4925b0f7ef5fe4e9b777a6b9390ca0ead593715bed2";
            let actual = Sha256::digest(fs::read(destination.join("kitrove")).unwrap());
            for (index, byte) in actual.iter().enumerate() {
                assert_eq!(
                    *byte,
                    u8::from_str_radix(&expected[index * 2..index * 2 + 2], 16).unwrap()
                );
            }
        }
        println!(
            "{cut}: SIGKILL observed, fresh recovery/retirement passed, B digest and state preserved"
        );
    }
}
