//! Explicit operator acceptance using pinned public artifacts and synthetic state only.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use kitrove_state_lifecycle::StateAuthority;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VALID: &[u8] =
    br#"{"schema_version":1,"machine":{"id":"refusal-fixture","active_profile":null}}"#;
const CANARY: &str = "KITROVE_FAKE_REFUSAL_CREDENTIAL_NOT_A_SECRET";

fn release(evidence: &Path, prior: bool, b: bool) -> Vec<String> {
    let (directory, bundle, tag, commit, digest) = if b {
        (
            "rc2-public-20260924",
            "rc2-public-attestations-20260924/kitrove-cli-aarch64-apple-darwin.tar.xz.bundle.json",
            "v0.1.0-rc.2",
            "11f2d7b7daa1115e23d95121a6f7c923153b3190",
            "45701c8b18120cb0906586eb8371b5041618d1cf226b2f9ab40b52689af86ca5",
        )
    } else {
        (
            "rc1-public-20260924",
            "rc1-public-attestations-20260924/kitrove-cli-aarch64-apple-darwin.tar.xz.corrected.bundle.json",
            "v0.1.0-rc.1.3",
            "31b4657a8742756f26aa0596e2c57a4f357c8295",
            "e8c32f13cd4d6a115a86cfe3192d8863b2e1b2e87fff9052486921c2ef771c3c",
        )
    };
    let prefix = if prior { "--prior-" } else { "--" };
    [
        (
            "archive",
            evidence
                .join(directory)
                .join("kitrove-cli-aarch64-apple-darwin.tar.xz")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
        ("bundle", evidence.join(bundle).to_str().unwrap().to_owned()),
        ("tag", tag.to_owned()),
        ("commit", commit.to_owned()),
        ("sha256", digest.to_owned()),
    ]
    .into_iter()
    .flat_map(|(key, value)| [format!("{prefix}{key}"), value])
    .collect()
}

fn state(path: &Path, bytes: &[u8]) -> StateAuthority {
    let (authority, guard) = StateAuthority::initialize_absent(path).unwrap();
    authority
        .exclusive_access(&guard)
        .unwrap()
        .create_initial_state(bytes)
        .unwrap();
    drop(guard);
    authority
}

#[derive(Debug, Eq, PartialEq)]
struct Entry {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    digest: Option<[u8; 32]>,
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Entry>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let digest = if metadata.is_file() {
            assert!(metadata.len() <= 32 * 1024 * 1024);
            Some(Sha256::digest(fs::read(path).unwrap()).into())
        } else {
            assert!(metadata.is_dir());
            None
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            Entry {
                device: metadata.dev(),
                inode: metadata.ino(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                digest,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn invoke(logs: &Path, name: &str, args: &[String], expected_error: Option<&str>) {
    let stdout = fs::File::create(logs.join(format!("{name}.stdout"))).unwrap();
    let stderr = fs::File::create(logs.join(format!("{name}.stderr"))).unwrap();
    // Cargo supplies this source-built executable, never a downloaded installer.
    let mut child = Command::new(env!("CARGO_BIN_EXE_kitrove-installer"))
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("installer timed out: {name}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let out = fs::read_to_string(logs.join(format!("{name}.stdout"))).unwrap();
    let err = fs::read_to_string(logs.join(format!("{name}.stderr"))).unwrap();
    assert!(
        !out.contains(CANARY) && !err.contains(CANARY),
        "canary leaked"
    );
    match expected_error {
        None => assert!(status.success(), "{name}: {err}"),
        Some(expected) => {
            assert!(!status.success(), "unexpected success: {name}");
            assert_eq!(
                err.trim(),
                format!(
                    "{expected}. No cleanup was attempted. Preserve existing installer state; use the same authenticated release inputs for guarded recovery."
                )
            );
        }
    }
}

#[test]
#[ignore = "requires pinned public A/B archives, bundles and a durable evidence directory"]
fn real_upgrade_refuses_busy_and_invalid_state_without_mutation() {
    let evidence = PathBuf::from(
        std::env::var_os("KITROVE_TEST_RELEASE_EVIDENCE").expect("evidence directory"),
    );
    let root = tempfile::Builder::new()
        .prefix("lifecycle-refusal-")
        .tempdir_in(&evidence)
        .unwrap()
        .keep();
    println!("preserved refusal evidence: {}", root.display());
    let destination = root.join("destination");
    fs::create_dir(&destination).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
    let first = root.join("state-a");
    let second = root.join("state-b");
    let _first = state(&first, VALID);
    let second_authority = state(&second, VALID);
    let roots = vec![
        "--destination".into(),
        destination.to_str().unwrap().into(),
        "--state-root".into(),
        first.to_str().unwrap().into(),
        "--state-root".into(),
        second.to_str().unwrap().into(),
    ];
    for action in ["preflight-install", "install", "retire-install"] {
        let mut args = vec![action.to_owned()];
        args.extend(release(&evidence, false, false));
        args.extend(roots.clone());
        invoke(&root, action, &args, None);
    }
    let mut upgrade = release(&evidence, false, true);
    upgrade.extend(release(&evidence, true, false));
    upgrade.extend(roots);
    let mut control = vec!["preflight-upgrade".into()];
    control.extend(upgrade.clone());
    invoke(&root, "valid-control", &control, None);
    for case in ["busy", "malformed", "schema", "unknown-field"] {
        let shared = if case == "busy" {
            Some(second_authority.try_lock_shared().unwrap())
        } else {
            None
        };
        let invalid = match case {
            "busy" => None,
            "malformed" => Some(CANARY.to_owned()),
            "schema" => Some(
                String::from_utf8(VALID.to_vec())
                    .unwrap()
                    .replace("\"schema_version\":1", "\"schema_version\":2"),
            ),
            _ => Some(format!(
                "{{\"schema_version\":1,\"machine\":{{\"id\":\"fixture\"}},\"foreign\":\"{CANARY}\"}}"
            )),
        };
        if let Some(bytes) = invalid {
            fs::write(second.join("state.json"), bytes).unwrap();
        }
        let before = [snapshot(&destination), snapshot(&first), snapshot(&second)];
        for action in ["preflight-upgrade", "upgrade"] {
            let mut args = vec![action.to_owned()];
            args.extend(upgrade.clone());
            invoke(
                &root,
                &format!("{case}-{action}"),
                &args,
                Some(if case == "busy" {
                    "installer operation identifier already exists"
                } else {
                    "installer state authority is unsafe"
                }),
            );
            assert_eq!(
                before,
                [snapshot(&destination), snapshot(&first), snapshot(&second)]
            );
            let authority = StateAuthority::open_existing(&first).unwrap();
            drop(authority.try_lock_exclusive().unwrap());
        }
        drop(shared);
        fs::write(second.join("state.json"), VALID).unwrap();
    }
    invoke(&root, "valid-control-after-refusals", &control, None);
    println!(
        "eight real-artifact refusal cases passed, snapshots unchanged and first-root locks released"
    );
}
