#![cfg(target_os = "macos")]
#![forbid(unsafe_code)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kitrove_core::RETAINED_HOLD_PATH;
use kitrove_state_lifecycle::StateAuthority;
use serde_json::Value;

const QUARANTINE: &str = ".kitrove/removal-quarantine";
const RETAINED_BYTES: &[u8] = b"SYNTHETIC_RETAINED_FILE_BODY";

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    collection: PathBuf,
    private: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = kitrove_testkit::trusted_tempdir(".kitrove-recover-");
        let root = fs::canonicalize(temporary.path()).unwrap();
        let home = root.join("home");
        let collection = home.join("Kitrove");
        let private = root.join("private");
        fs::create_dir(&home).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join(".git")).unwrap();
        let fixture = Self {
            _temporary: temporary,
            root,
            home,
            collection,
            private,
        };
        assert!(
            fixture
                .run(
                    &["init", "--machine-id", "recovery-fixture", "--json"],
                    None
                )
                .status
                .success()
        );
        fixture
    }

    fn run(&self, args: &[&str], input: Option<&[u8]>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kitrove"))
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("KITROVE_STATE_HOME", &self.private)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .current_dir(&self.root)
            .args(args)
            .arg("--environment")
            .arg(&self.collection)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        child.wait_with_output().unwrap()
    }

    fn skill(&self, name: &str) {
        let source = self.home.join(".pi/agent/skills").join(name);
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("SKILL.md"),
            format!(
                "---\nname: {name}\ndescription: Synthetic recovery skill.\n---\nReview changes.\n"
            ),
        )
        .unwrap();
    }

    fn adopt(&self, name: &str) -> Output {
        self.run(
            &[
                "--json-errors",
                "adopt",
                name,
                "--harness",
                "pi",
                "--scope",
                "user",
                "--json",
            ],
            Some(b"yes\n"),
        )
    }

    fn quote(&self, role: &str) -> Value {
        let output = self.run(&["recover", "plan", "--root", role, "--json"], None);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn preserve(&self, role: &str, digest: &str) -> Output {
        self.run(
            &[
                "--json-errors",
                "recover",
                "preserve",
                "--root",
                role,
                "--confirm",
                digest,
                "--json",
            ],
            None,
        )
    }
}

fn quarantine(root: &Path) -> PathBuf {
    let path = root.join(QUARANTINE);
    fs::create_dir_all(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn retained(root: &Path, device_delta: u64, file_delta: u64, nonce: u128) -> PathBuf {
    let dir = quarantine(root);
    let seed = dir.join("fixture-seed");
    fs::write(&seed, RETAINED_BYTES).unwrap();
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    let m = fs::symlink_metadata(&seed).unwrap();
    let entry = dir.join(format!(
        ".kitrove-removed-v1-unix-f-{:016x}-{:016x}-{nonce:032x}",
        m.dev() ^ device_delta,
        m.ino() ^ file_delta,
    ));
    fs::rename(seed, &entry).unwrap();
    entry
}

fn failure(output: &Output, code: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    let line = stderr.lines().last().expect(stderr);
    let record = &line[line.find('{').expect(stderr)..];
    let result: Value = serde_json::from_str(record).unwrap();
    assert_eq!(result["error"]["code"], code, "{output:?}");
}

fn digest(plan: &Value) -> &str {
    plan["plan_digest"].as_str().unwrap()
}

#[test]
fn both_roots_preserve_original_entries_and_unblock_collection_and_codex() {
    let f = Fixture::new();
    f.skill("alpha");
    let collection = retained(&f.collection, 1, 0, 5);
    let local = retained(&f.private, 1, 0, 6);
    let state_before = fs::read(f.private.join("state.json")).unwrap();
    let manifest_before = fs::read(f.collection.join("kitrove.toml")).unwrap();

    failure(&f.adopt("alpha"), "transaction.cleanup_failed");
    let report = f.run(&["doctor"], None);
    assert_eq!(report.status.code(), Some(3));
    assert_eq!(
        String::from_utf8_lossy(&report.stdout)
            .matches("device ID differs")
            .count(),
        2
    );

    for (role, root, entry) in [
        ("collection", &f.collection, collection),
        ("private-state", &f.private, local),
    ] {
        let path_before = fs::metadata(&entry).unwrap();
        let plan = f.quote(role);
        assert_eq!(plan["outcome"], "preview");
        assert_eq!(plan["device_mismatches"], 1);
        assert!(entry.is_file() && !root.join(RETAINED_HOLD_PATH).exists());

        let approved = f.preserve(role, digest(&plan));
        assert!(approved.status.success(), "{approved:?}");
        assert!(!root.join(QUARANTINE).exists());
        let preserved = root
            .join(RETAINED_HOLD_PATH)
            .join(entry.file_name().unwrap());
        let path_after = fs::metadata(&preserved).unwrap();
        assert_eq!(
            (path_before.dev(), path_before.ino()),
            (path_after.dev(), path_after.ino())
        );
        assert_eq!(fs::read(&preserved).unwrap(), RETAINED_BYTES);
        failure(&f.preserve(role, digest(&plan)), "recover.hold_exists");
        assert_eq!(fs::read(&preserved).unwrap(), RETAINED_BYTES);
    }

    assert_eq!(
        fs::read(f.private.join("state.json")).unwrap(),
        state_before
    );
    assert_eq!(
        fs::read(f.collection.join("kitrove.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(f.run(&["doctor"], None).status.code(), Some(0));
    let adopted = f.adopt("alpha");
    assert!(adopted.status.success(), "{adopted:?}");

    let planned = f.run(
        &[
            "plan", "--asset", "alpha", "--target", "codex", "--scope", "user", "--json",
        ],
        None,
    );
    assert!(planned.status.success(), "{planned:?}");
    let evidence: Value = serde_json::from_slice(&planned.stdout).unwrap();
    let approval = evidence["batch_digest"].as_str().unwrap();
    let applied = f.run(
        &[
            "apply",
            "--asset",
            "alpha",
            "--target",
            "codex",
            "--scope",
            "user",
            "--confirm",
            approval,
            "--json",
        ],
        None,
    );
    assert!(applied.status.success(), "{applied:?}");
    assert!(f.home.join(".agents/skills/alpha/SKILL.md").is_file());
    for path in [&f.collection, &f.private] {
        assert_eq!(
            fs::read_dir(path.join(RETAINED_HOLD_PATH)).unwrap().count(),
            1
        );
    }
}

#[test]
fn recovery_refuses_stale_plans_pending_journals_and_a_held_state_lock() {
    let f = Fixture::new();
    let entry = retained(&f.collection, 1, 0, 5);
    let initial = f.quote("collection");
    let added = retained(&f.collection, 1, 0, 6);
    failure(
        &f.preserve("collection", digest(&initial)),
        "recover.plan_changed",
    );

    let current = f.quote("collection");
    let pending = f.private.join(".kitrove/atomic-apply-journal.pending");
    fs::write(&pending, b"synthetic pending transaction").unwrap();
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600)).unwrap();
    failure(
        &f.preserve("collection", digest(&current)),
        "recover.pending_transaction",
    );
    assert_eq!(
        fs::read(&pending).unwrap(),
        b"synthetic pending transaction"
    );
    fs::remove_file(&pending).unwrap();

    let authority = StateAuthority::open_existing(&f.private).unwrap();
    let _guard = authority.try_lock_shared().unwrap();
    failure(
        &f.preserve("collection", digest(&current)),
        "recover.lock_unavailable",
    );
    assert!(entry.exists() && added.exists() && !f.collection.join(RETAINED_HOLD_PATH).exists());
}

#[test]
fn recovery_refuses_changed_file_identity_unrecognized_links_and_unfinished_cleanup() {
    let role = ["--json-errors", "recover", "plan", "--root", "collection"];
    let f = Fixture::new();
    let valid = retained(&f.collection, 1, 0, 5);
    let changed = retained(&f.collection, 1, 1, 6);
    failure(&f.run(&role, None), "recover.file_identity_changed");
    assert!(changed.exists());
    fs::remove_file(&changed).unwrap();

    let link = f.collection.join(QUARANTINE).join("unrecognized-link");
    symlink(&valid, &link).unwrap();
    failure(&f.run(&role, None), "recover.unsupported_entry");
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    fs::remove_file(&link).unwrap();

    let pending = f
        .collection
        .join(QUARANTINE)
        .join(".kitrove-cleanup-pending-v1-00112233445566778899aabbccddeeff");
    fs::create_dir(&pending).unwrap();
    failure(&f.run(&role, None), "recover.incomplete_cleanup");
    assert_eq!(fs::read(&valid).unwrap(), RETAINED_BYTES);
    assert!(pending.is_dir() && !f.collection.join(RETAINED_HOLD_PATH).exists());
}

#[test]
fn directory_preservation_keeps_contents_and_refuses_an_unsafe_child_or_occupied_hold() {
    let f = Fixture::new();
    let active = quarantine(&f.collection);
    let seed = active.join("fixture-directory");
    fs::create_dir(&seed).unwrap();
    fs::write(seed.join("body"), RETAINED_BYTES).unwrap();
    let before = fs::metadata(&seed).unwrap();
    let name = format!(
        ".kitrove-removed-v1-unix-d-{:016x}-{:016x}-00112233445566778899aabbccddeeff",
        before.dev() ^ 1,
        before.ino()
    );
    let entry = active.join(&name);
    fs::rename(seed, &entry).unwrap();
    let outside = f.root.join("outside-content");
    fs::write(&outside, b"outside").unwrap();
    let nested_link = entry.join("unsafe-child");
    symlink(&outside, &nested_link).unwrap();
    let args = ["--json-errors", "recover", "plan", "--root", "collection"];
    failure(&f.run(&args, None), "recover.unsupported_entry");
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    fs::remove_file(&nested_link).unwrap();

    let plan = f.quote("collection");
    let hold = f.collection.join(RETAINED_HOLD_PATH);
    symlink(&outside, &hold).unwrap();
    failure(
        &f.preserve("collection", digest(&plan)),
        "recover.hold_exists",
    );
    assert_eq!(fs::read_link(&hold).unwrap(), outside);
    assert!(entry.is_dir());
    fs::remove_file(&hold).unwrap();

    let applied = f.preserve("collection", digest(&plan));
    assert!(applied.status.success(), "{applied:?}");
    let entry = hold.join(name);
    let after = fs::metadata(&entry).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(fs::read(entry.join("body")).unwrap(), RETAINED_BYTES);
}
