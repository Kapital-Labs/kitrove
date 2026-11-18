#![forbid(unsafe_code)]
use kitrove_model::{EnvironmentManifest, LocalState};
use serde_json::Value;
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    collection: PathBuf,
    state: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = kitrove_testkit::trusted_tempdir(".scripted-skill-cli-");
        let root = fs::canonicalize(temp.path()).unwrap();
        let f = Self {
            home: root.join("home"),
            collection: root.join("collection"),
            state: root.join("state"),
            root,
            _temp: temp,
        };
        fs::create_dir_all(&f.home).unwrap();
        f.ok(&["init", "--machine-id", "script-test", "--json"], None);
        f
    }
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        c.current_dir(&self.root)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state)
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME");
        c
    }
    fn run(&self, args: &[&str], input: Option<&[u8]>) -> Output {
        let mut c = self.command();
        c.args(args).arg("--environment").arg(&self.collection);
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        } else {
            drop(child.stdin.take());
        }
        child.wait_with_output().unwrap()
    }
    fn ok(&self, args: &[&str], input: Option<&[u8]>) -> Value {
        let o = self.run(args, input);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        serde_json::from_slice(&o.stdout).unwrap()
    }
    fn source(&self, mode: bool) -> Vec<u8> {
        let source = self.home.join(".claude/skills/rv");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("SKILL.md"), "---\nname: rv\ndescription: A synthetic review helper.\n---\nRun helper.py only with the tool user's permission.\n").unwrap();
        let bytes = b"from pathlib import Path\nPath('SCRIPT_EXECUTED').write_text('bad')\nraise SystemExit('must never execute')\n".to_vec();
        fs::write(source.join("helper.py"), &bytes).unwrap();
        #[cfg(unix)]
        if mode {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(source.join("helper.py"), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        bytes
    }
    fn collect(&self) {
        self.ok(
            &[
                "adopt",
                "rv",
                "--harness",
                "claude",
                "--scope",
                "user",
                "--json",
            ],
            Some(b"yes\n"),
        );
    }
    fn decision(&self, decision: &str) {
        let p = self.ok(
            &[
                "trust",
                "plan",
                "--asset",
                "rv",
                "--decision",
                decision,
                "--json",
            ],
            None,
        );
        assert_eq!(p["kind"], "skill");
        self.ok(
            &[
                "trust",
                "apply",
                "--asset",
                "rv",
                "--decision",
                decision,
                "--confirm",
                p["plan_digest"].as_str().unwrap(),
                "--json",
            ],
            None,
        );
    }
    fn state(&self) -> LocalState {
        LocalState::from_json(&fs::read_to_string(self.state.join("state.json")).unwrap()).unwrap()
    }
    fn manifest(&self) -> EnvironmentManifest {
        EnvironmentManifest::from_toml(
            &fs::read_to_string(self.collection.join("kitrove.toml")).unwrap(),
        )
        .unwrap()
    }
    fn no_execution(&self) {
        assert!(!self.root.join("SCRIPT_EXECUTED").exists());
        assert!(!self.home.join("SCRIPT_EXECUTED").exists());
    }
    fn sync(&self, remote: &Path) {
        let remote = remote.to_str().unwrap();
        let p = self.ok(&["sync", "plan", "--filesystem", remote, "--json"], None);
        self.ok(
            &[
                "sync",
                "apply",
                "--filesystem",
                remote,
                "--confirm",
                p["plan_digest"].as_str().unwrap(),
                "--json",
            ],
            None,
        );
    }
}
#[test]
fn exact_review_gates_each_tool_and_denial_does_not_prevent_owned_removal() {
    for (tool, folder) in [
        ("claude", ".claude/skills"),
        ("codex", ".agents/skills"),
        ("pi", ".pi/agent/skills"),
        ("opencode", ".config/opencode/skills"),
    ] {
        let f = Fixture::new();
        let bytes = f.source(false);
        f.collect();
        fs::remove_dir_all(f.home.join(".claude/skills/rv")).unwrap();
        let manifest = fs::read(f.collection.join("kitrove.toml")).unwrap();
        let args = ["plan", "--asset", "rv", "--target", tool, "--json"];
        let refused = f.run(&args, None);
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("apply.skill_trust_required"));
        assert!(f.state().trust.is_empty() && f.state().receipts.is_empty());
        f.decision("trusted");
        assert_eq!(
            fs::read(f.collection.join("kitrove.toml")).unwrap(),
            manifest
        );
        let p = f.ok(&args, None);
        let digest = p["batch_digest"].as_str().unwrap();
        f.ok(
            &[
                "apply",
                "--asset",
                "rv",
                "--target",
                tool,
                "--confirm",
                digest,
                "--json",
            ],
            None,
        );
        let target = f.home.join(folder).join("rv/helper.py");
        assert_eq!(fs::read(&target).unwrap(), bytes);
        f.decision("denied");
        let refused = f.run(
            &[
                "apply",
                "--asset",
                "rv",
                "--target",
                tool,
                "--confirm",
                digest,
                "--json",
            ],
            None,
        );
        assert!(!refused.status.success());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        f.ok(
            &["remove", "--asset", "rv", "--target", tool, "--json"],
            Some(b"yes\n"),
        );
        assert!(!target.exists());
        f.no_execution();
    }
}
#[test]
fn changed_helper_requires_new_review_and_sync_does_not_transfer_approval() {
    let f = Fixture::new();
    f.source(false);
    f.collect();
    f.decision("trusted");
    let remote = f.root.join("shared");
    fs::create_dir(&remote).unwrap();
    f.sync(&remote);
    let b = Fixture::new();
    b.sync(&remote);
    assert_eq!(f.manifest(), b.manifest());
    assert!(b.state().trust.is_empty());
    let refused = b.run(
        &["plan", "--asset", "rv", "--target", "opencode", "--json"],
        None,
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("apply.skill_trust_required"));
    let old = f.manifest().assets[&kitrove_model::AssetId::parse("rv").unwrap()]
        .content_hash
        .clone();
    fs::write(
        f.home.join(".claude/skills/rv/helper.py"),
        "raise SystemExit('new version must never execute')\n",
    )
    .unwrap();
    let explicit = f.root.join("update-source");
    fs::create_dir(&explicit).unwrap();
    fs::rename(f.home.join(".claude/skills/rv"), explicit.join("rv")).unwrap();
    let root_arg = format!("claude:user:{}", explicit.display());
    f.ok(
        &[
            "adopt",
            "rv",
            "--update",
            "rv",
            "--expected-prior",
            old.as_str(),
            "--harness",
            "claude",
            "--scope",
            "user",
            "--root",
            &root_arg,
            "--json",
        ],
        Some(b"yes\n"),
    );
    let new = f.manifest().assets[&kitrove_model::AssetId::parse("rv").unwrap()]
        .content_hash
        .clone();
    assert_ne!(old, new);
    assert!(f.state().trust.contains_key(&old));
    assert!(!f.state().trust.contains_key(&new));
    let refused = f.run(
        &["plan", "--asset", "rv", "--target", "opencode", "--json"],
        None,
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("apply.skill_trust_required"));
    f.no_execution();
    b.no_execution();
}
#[cfg(unix)]
#[test]
fn unix_script_mode_is_preserved_after_exact_approval() {
    use std::os::unix::fs::PermissionsExt as _;
    let f = Fixture::new();
    let bytes = f.source(true);
    f.collect();
    f.decision("trusted");
    let p = f.ok(
        &["plan", "--asset", "rv", "--target", "opencode", "--json"],
        None,
    );
    f.ok(
        &[
            "apply",
            "--asset",
            "rv",
            "--target",
            "opencode",
            "--confirm",
            p["batch_digest"].as_str().unwrap(),
            "--json",
        ],
        None,
    );
    let path = f.home.join(".config/opencode/skills/rv/helper.py");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    f.no_execution();
}
#[test]
fn stale_trust_plan_and_tampered_stored_object_are_refused() {
    let f = Fixture::new();
    f.source(false);
    f.collect();
    let p = f.ok(
        &[
            "trust",
            "plan",
            "--asset",
            "rv",
            "--decision",
            "trusted",
            "--json",
        ],
        None,
    );
    f.decision("denied");
    let stale = f.run(
        &[
            "trust",
            "apply",
            "--asset",
            "rv",
            "--decision",
            "trusted",
            "--confirm",
            p["plan_digest"].as_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(String::from_utf8_lossy(&stale.stderr).contains("trust.confirmation_mismatch"));
    let before = fs::read(f.state.join("state.json")).unwrap();
    let asset = &f.manifest().assets[&kitrove_model::AssetId::parse("rv").unwrap()];
    let directory = f
        .collection
        .join(asset.portable.as_ref().unwrap().root.as_str());
    fn corrupt(path: &Path) -> bool {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if corrupt(&path) {
                    return true;
                }
            } else {
                fs::write(path, b"tampered").unwrap();
                return true;
            }
        }
        false
    }
    assert!(corrupt(&directory));
    let refused = f.run(
        &[
            "trust",
            "plan",
            "--asset",
            "rv",
            "--decision",
            "trusted",
            "--json",
        ],
        None,
    );
    assert!(!refused.status.success());
    assert_eq!(fs::read(f.state.join("state.json")).unwrap(), before);
    f.no_execution();
}

#[test]
fn denied_shared_script_releases_only_one_pack_claim_without_replacing_files() {
    let f = Fixture::new();
    f.source(cfg!(unix));
    f.collect();
    for pack in ["one", "two"] {
        f.ok(
            &[
                "pack",
                "create",
                "--authored",
                "--pack",
                pack,
                "--member",
                "rv",
                "--json",
            ],
            Some(b"yes\n"),
        );
    }
    f.decision("trusted");
    let plan = f.ok(
        &[
            "plan", "--pack", "one", "--pack", "two", "--target", "opencode", "--json",
        ],
        None,
    );
    f.ok(
        &[
            "apply",
            "--pack",
            "one",
            "--pack",
            "two",
            "--target",
            "opencode",
            "--confirm",
            plan["batch_digest"].as_str().unwrap(),
            "--json",
        ],
        None,
    );
    f.decision("denied");
    let before = f.state();
    assert_eq!(before.pack_applications.len(), 2);
    let target = f.home.join(".config/opencode/skills/rv/helper.py");
    let bytes = fs::read(&target).unwrap();
    let modified = fs::metadata(&target).unwrap().modified().unwrap();
    for (pack, retained) in [("one", true), ("two", false)] {
        let manifest = f.manifest();
        let revision = manifest.packs[&kitrove_model::AssetId::parse(pack).unwrap()]
            .content_hash
            .clone();
        f.ok(
            &[
                "pack",
                "remove",
                "--pack",
                pack,
                "--expected-prior",
                revision.as_str(),
                "--json",
            ],
            Some(b"yes\n"),
        );
        let state = f.state();
        assert_eq!(state.trust, before.trust);
        if retained {
            assert_eq!(state.receipts, before.receipts);
            assert_eq!(state.pack_applications.len(), 1);
            assert_eq!(fs::read(&target).unwrap(), bytes);
            assert_eq!(fs::metadata(&target).unwrap().modified().unwrap(), modified);
        } else {
            assert!(state.receipts.is_empty() && state.pack_applications.is_empty());
            assert!(!target.exists());
        }
    }
    f.no_execution();
}
