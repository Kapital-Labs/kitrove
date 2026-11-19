#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kitrove_core::derive_lockfile;
use kitrove_model::{Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest};
use kitrove_testkit::owned_fixture;
use serde_json::Value;

const CANARY: &str = "PRIVATE_DOCTOR_BODY_CANARY";
const ASSET_CANARY: &str = "doctor-private-asset-canary";

type Snapshot = BTreeMap<PathBuf, (u32, u64, Vec<u8>)>;

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    kitrove_windows_security::ensure_private_directory_for_tests(path).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    owned_fixture::create(path, bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn snapshot(root: &Path) -> Snapshot {
    fn visit(root: &Path, path: &Path, result: &mut Snapshot) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            #[cfg(unix)]
            let (mode, links) = {
                use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
                (metadata.permissions().mode(), metadata.nlink())
            };
            #[cfg(not(unix))]
            let (mode, links) = (u32::from(metadata.permissions().readonly()), 1);
            let bytes = if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec()
            } else if metadata.is_file() {
                fs::read(&path).unwrap()
            } else {
                Vec::new()
            };
            result.insert(
                path.strip_prefix(root).unwrap().to_owned(),
                (mode, links, bytes),
            );
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                visit(root, &path, result);
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    collection: PathBuf,
    state: PathBuf,
    working: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = kitrove_testkit::trusted_tempdir(".kitrove-doctor-");
        let root = fs::canonicalize(temporary.path()).unwrap();
        let home = root.join("home");
        let collection = home.join("Kitrove");
        let state = root.join("private-state");
        let working = root.join("working");
        for directory in [&home, &collection, &state, &working] {
            private_directory(directory);
        }
        for directory in [&home, &collection, &state] {
            private_directory(&directory.join(".kitrove"));
        }
        let mut manifest = EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let mut asset = Asset {
            id: AssetId::parse(ASSET_CANARY).unwrap(),
            kind: AssetKind::Skill,
            content_hash: ContentHash::digest(b"pending"),
            provenance: BTreeMap::new(),
            portable: None,
            native_variants: BTreeMap::new(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        };
        asset.refresh_content_hash();
        manifest.assets.insert(asset.id.clone(), asset);
        private_file(
            &collection.join("kitrove.toml"),
            manifest.to_toml().unwrap().as_bytes(),
        );
        private_file(
            &collection.join("kitrove.lock.json"),
            derive_lockfile(&manifest)
                .unwrap()
                .to_json()
                .unwrap()
                .as_bytes(),
        );
        // Doctor must observe storage without parsing machine-local authority bodies.
        private_file(&state.join("state.json"), CANARY.as_bytes());
        Self {
            _temporary: temporary,
            root,
            home,
            collection,
            state,
            working,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state)
            .current_dir(&self.working)
            .stdin(Stdio::null());
        command
    }

    fn explicit(&self, json: bool) -> Output {
        let mut command = self.command();
        command
            .args(["doctor", "--environment"])
            .arg(&self.collection);
        if json {
            command.arg("--json");
        }
        command.output().unwrap()
    }
}

fn decoded(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_redacted(fixture: &Fixture, output: &Output) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for forbidden in [CANARY, ASSET_CANARY, fixture.root.to_str().unwrap()] {
        assert!(!text.contains(forbidden), "diagnostic leaked fixture data");
    }
}

#[test]
fn doctor_closed_json_is_read_only_and_redacted() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.root);
    let output = fixture.explicit(true);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = decoded(&output);
    let keys: BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "schema_version",
            "version",
            "inspection",
            "mutation_access",
            "checks"
        ])
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["inspection"], "unlocked");
    assert_eq!(value["mutation_access"], "not_tested");
    let checks = value["checks"].as_array().unwrap();
    assert!(!checks.is_empty());
    for check in checks {
        let keys: BTreeSet<_> = check
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            keys == BTreeSet::from(["role", "stage", "status", "code"])
                || keys == BTreeSet::from(["role", "stage", "status", "code", "count"])
        );
        for field in ["role", "stage", "status", "code"] {
            let value = check[field].as_str().unwrap();
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
        if let Some(count) = check.get("count") {
            assert!(count.as_u64().is_some());
        }
    }
    assert_redacted(&fixture, &output);
    assert_eq!(snapshot(&fixture.root), before);
    for root in [&fixture.home, &fixture.collection, &fixture.state] {
        assert!(!root.join(".kitrove/environment.lock").exists());
    }
}

#[test]
fn doctor_default_collection_and_explicit_override_are_distinct() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.root);
    let default = fixture
        .command()
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert_eq!(default.status.code(), Some(0));
    let explicit = fixture.explicit(true);
    assert_eq!(default.stdout, explicit.stdout);
    let missing = fixture
        .command()
        .args(["doctor", "--environment"])
        .arg(fixture.root.join("missing-private-name"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3));
    let value = decoded(&missing);
    assert!(
        value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["role"] == "collection" && check["status"] != "ok")
    );
    assert_redacted(&fixture, &missing);
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn doctor_pending_private_body_is_only_a_metadata_finding() {
    let fixture = Fixture::new();
    private_file(
        &fixture.state.join(".kitrove/atomic-apply-journal.json"),
        CANARY.as_bytes(),
    );
    let before = snapshot(&fixture.root);
    let output = fixture.explicit(true);
    assert_eq!(output.status.code(), Some(3));
    let value = decoded(&output);
    assert!(
        value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["role"] == "private_state"
                && check["stage"] == "recovery_markers"
                && check["code"] == "recovery_present"
                && check["count"] == 1)
    );
    let repeated = fixture.explicit(true);
    assert_eq!(output.stdout, repeated.stdout);
    assert_redacted(&fixture, &output);
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn doctor_human_report_is_concise_and_status_stays_unchanged() {
    let fixture = Fixture::new();
    let status = || {
        fixture
            .command()
            .args(["status", "--environment"])
            .arg(&fixture.collection)
            .arg("--json")
            .output()
            .unwrap()
    };
    let old = status();
    let before = snapshot(&fixture.root);
    let output = fixture.explicit(false);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(text.contains("Kitrove doctor"));
    assert!(text.contains("No changes made."));
    assert!(text.contains("Write access and lock availability were not tested."));
    assert!(text.lines().count() <= 8);
    assert_redacted(&fixture, &output);
    let new = status();
    assert_eq!(old.status.code(), new.status.code());
    assert_eq!(old.stdout, new.stdout);
    assert_eq!(old.stderr, new.stderr);
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn doctor_accepts_only_read_only_arguments() {
    let fixture = Fixture::new();
    let before = snapshot(&fixture.root);
    for arguments in [
        vec!["--json", "--json"],
        vec!["--repair"],
        vec!["--yes"],
        vec![CANARY],
        vec!["--environment"],
    ] {
        let output = fixture
            .command()
            .args(["--json-errors", "doctor"])
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error.as_object().unwrap().len(), 3);
        assert_redacted(&fixture, &output);
    }
    assert_eq!(snapshot(&fixture.root), before);
}

#[cfg(unix)]
#[test]
fn doctor_inspect_refusal_is_an_observation_and_does_not_normalize_modes() {
    use std::os::unix::fs::PermissionsExt as _;
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o755)).unwrap();
    let before = snapshot(&fixture.root);
    let machine = fixture.explicit(true);
    assert_eq!(machine.status.code(), Some(3));
    let value = decoded(&machine);
    assert!(
        value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["role"] == "private_state"
                && check["stage"] == "private_boundary"
                && check["status"] == "blocked"
                && check["code"] == "inspect_rejected")
    );
    let human = fixture.explicit(false);
    assert_eq!(human.status.code(), Some(3));
    let text = String::from_utf8(human.stdout.clone()).unwrap();
    assert!(text.contains("needs attention"));
    assert!(text.contains("did not pass inspection"));
    assert!(text.contains("Write access and lock availability were not tested."));
    assert_eq!(text.matches("Next:").count(), 1);
    assert!(!text.contains("cannot apply"));
    assert!(!text.contains("pending transaction"), "{text}");
    assert!(!text.contains("Run kitrove doctor"));
    assert_redacted(&fixture, &human);
    assert_eq!(snapshot(&fixture.root), before);
}

#[test]
fn doctor_help_is_static_with_unusable_roots_and_rejects_extra_flags() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-doctor-help-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let unusable_home = root.join("not-a-home-directory");
    private_file(&unusable_home, CANARY.as_bytes());
    let absent_state = root.join("absent-private-state");
    let before = snapshot(&root);
    let invoke = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kitrove"))
            .env_clear()
            .env("HOME", &unusable_home)
            .env("USERPROFILE", &unusable_home)
            .env("KITROVE_STATE_HOME", &absent_state)
            .current_dir(&root)
            .stdin(Stdio::null())
            .args(arguments)
            .output()
            .unwrap()
    };
    for help in ["--help", "-h"] {
        let output = invoke(&["doctor", help]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("kitrove doctor [--environment <path>] [--json]"));
        assert!(text.contains("Default collection: ~/Kitrove"));
        assert!(text.lines().count() <= 8);
        assert!(!text.contains(CANARY));
        assert!(!text.contains(root.to_str().unwrap()));
    }
    for arguments in [
        vec!["--json-errors", "doctor", "--help", "--repair"],
        vec!["--json-errors", "doctor", "-h", "--json"],
        vec!["--json-errors", "doctor", "--repair", "--help"],
    ] {
        let output = invoke(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error.as_object().unwrap().len(), 3);
    }
    assert!(!absent_state.exists());
    assert_eq!(snapshot(&root), before);
}

#[test]
fn doctor_reports_missing_machine_state_without_initializing_it() {
    let fixture = Fixture::new();
    let state_file = fixture.state.join("state.json");
    fs::remove_file(&state_file).unwrap();
    let before = snapshot(&fixture.root);
    let output = fixture.explicit(true);
    assert_eq!(output.status.code(), Some(3));
    let value = decoded(&output);
    assert!(value["checks"].as_array().unwrap().iter().any(|check| {
        check["role"] == "private_state"
            && check["stage"] == "state_file"
            && check["status"] == "absent"
            && check["code"] == "state_file_missing"
    }));
    let human = fixture.explicit(false);
    assert_eq!(human.status.code(), Some(3));
    let text = String::from_utf8(human.stdout.clone()).unwrap();
    assert!(text.contains("machine-local state"));
    assert!(text.contains("state file is missing"));
    assert_redacted(&fixture, &output);
    assert_redacted(&fixture, &human);
    assert!(!state_file.exists());
    assert_eq!(snapshot(&fixture.root), before);
}
