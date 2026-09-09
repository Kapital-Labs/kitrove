#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const EMPTY_MANIFEST: &str = "schema_version = 1\n";
const EMPTY_LOCAL_STATE: &str = r#"{
  "schema_version": 1,
  "machine": {
    "id": "acceptance-machine",
    "active_profile": null,
    "enabled_targets": [],
    "harness_roots": {}
  },
  "bindings": {},
  "receipts": {},
  "trust": {},
  "scans": []
}
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
struct FilesystemSnapshot {
    entries: BTreeMap<String, SnapshotEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SnapshotEntry {
    Directory { mode: Option<u32> },
    File { bytes: Vec<u8>, mode: Option<u32> },
    Symlink { target: PathBuf },
}

impl FilesystemSnapshot {
    fn capture(root: &Path) -> std::io::Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "snapshot root must be a directory",
            ));
        }
        let mut entries = BTreeMap::new();
        entries.insert(
            ".".to_owned(),
            SnapshotEntry::Directory {
                mode: permission_mode(&metadata),
            },
        );
        capture_directory(root, Path::new(""), &mut entries)?;
        Ok(Self { entries })
    }
}

fn capture_directory(
    directory: &Path,
    relative: &Path,
    entries: &mut BTreeMap<String, SnapshotEntry>,
) -> std::io::Result<()> {
    let mut children = BTreeMap::new();
    for child in fs::read_dir(directory)? {
        let child = child?;
        let name = child.file_name().into_string().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snapshot paths must use valid UTF-8",
            )
        })?;
        children.insert(name, child.path());
    }

    for (name, path) in children {
        let child_relative = relative.join(name);
        let stable_name = stable_relative_name(&child_relative)?;
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            entries.insert(
                stable_name,
                SnapshotEntry::Symlink {
                    target: fs::read_link(&path)?,
                },
            );
        } else if file_type.is_dir() {
            entries.insert(
                stable_name,
                SnapshotEntry::Directory {
                    mode: permission_mode(&metadata),
                },
            );
            capture_directory(&path, &child_relative, entries)?;
        } else if file_type.is_file() {
            entries.insert(
                stable_name,
                SnapshotEntry::File {
                    bytes: fs::read(&path)?,
                    mode: permission_mode(&metadata),
                },
            );
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "snapshot encountered a special file",
            ));
        }
    }
    Ok(())
}

fn stable_relative_name(path: &Path) -> std::io::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "snapshot entry escaped its root",
            ));
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "snapshot paths must use valid UTF-8",
                    )
                })?
                .to_owned(),
        );
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;

    Some(metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

struct FullMachineFixture {
    _tempdir: TempDir,
    root: PathBuf,
    home: PathBuf,
    working: PathBuf,
    environment: Option<PathBuf>,
    state_home: PathBuf,
    temporary: PathBuf,
}

impl FullMachineFixture {
    fn create(with_environment_and_state: bool) -> Self {
        let tempdir = tempfile::tempdir().expect("temporary fixture root");
        let root = fs::canonicalize(tempdir.path()).expect("canonical fixture root");
        let home = root.join("home");
        let working = root.join("project");
        let state_home = root.join("state-home");
        let temporary = root.join("temporary");

        fs::create_dir_all(&home).expect("fixture home");
        fs::create_dir_all(working.join(".git")).expect("repository marker");
        fs::create_dir_all(&temporary).expect("temporary sentinel root");
        directory_skill(&home.join(".claude/skills"), "claude-user");
        directory_skill(&working.join(".claude/skills"), "claude-project");
        directory_skill(&home.join(".agents/skills"), "codex-user");
        directory_skill(&working.join(".agents/skills"), "codex-project");
        directory_skill(&home.join(".pi/agent/skills"), "pi-user");
        directory_skill(&working.join(".pi/skills"), "pi-project");
        directory_skill(&home.join(".config/opencode/skills"), "opencode-user");
        directory_skill(&working.join(".opencode/skills"), "opencode-project");
        fs::create_dir_all(working.join(".claude/commands")).expect("Claude command root");
        fs::write(
            working.join(".claude/commands/review.md"),
            "# Related command\n",
        )
        .expect("related Claude command");
        seed_snapshot_contract(&home);

        let environment = with_environment_and_state.then(|| {
            let environment = root.join("environment");
            fs::create_dir_all(&environment).expect("environment root");
            fs::write(environment.join("kitrove.toml"), EMPTY_MANIFEST)
                .expect("environment manifest");
            fs::create_dir_all(&state_home).expect("state root");
            fs::write(state_home.join("state.json"), EMPTY_LOCAL_STATE).expect("local state input");
            environment
        });

        Self {
            _tempdir: tempdir,
            root,
            home,
            working,
            environment,
            state_home,
            temporary,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.working)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.root.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state_home)
            .env("XDG_DATA_HOME", self.root.join("xdg-data"))
            .env("XDG_CACHE_HOME", self.root.join("xdg-cache"))
            .env("TMPDIR", &self.temporary)
            .env("TMP", &self.temporary)
            .env("TEMP", &self.temporary)
            .env_remove("KITROVE_ENV");
        command
    }

    fn run_scan(&self, json: bool) -> Output {
        let mut command = self.command();
        command.args(["scan", "--scope", "all"]);
        if let Some(environment) = &self.environment {
            command.args(["--environment", environment.to_str().unwrap()]);
        }
        if json {
            command.arg("--json");
        }
        command.output().expect("run kitrove scan")
    }

    fn assert_no_generated_paths(&self) {
        let absent = [
            self.working.join("kitrove.toml"),
            self.working.join("kitrove.lock"),
            self.working.join("kitrove.lock.json"),
            self.working.join(".kitrove"),
            self.root.join("cache"),
            self.root.join("history"),
            self.root.join("receipts"),
            self.root.join("scan-records"),
            self.root.join("scan-history"),
            self.state_home.join("cache"),
            self.state_home.join("history"),
            self.state_home.join("receipts"),
            self.state_home.join("tmp"),
            self.state_home.join("scan-records"),
            self.root.join("xdg-cache"),
            self.root.join("xdg-data"),
            self.root.join("local-app-data"),
        ];
        for path in absent {
            assert!(!path.exists(), "scan created forbidden path {path:?}");
        }
        assert_eq!(
            fs::read_dir(&self.temporary)
                .expect("temporary sentinel root remains readable")
                .count(),
            0,
            "scan created temporary output"
        );
        if self.environment.is_none() {
            assert!(!self.root.join("environment").exists());
            assert!(!self.state_home.exists());
        }
    }

    fn assert_snapshot_contract(&self, snapshot: &FilesystemSnapshot) {
        let directory = "home/.claude/skills/claude-user";
        let file = "home/.claude/skills/claude-user/SKILL.md";
        assert_eq!(
            snapshot.entries.get(directory),
            Some(&SnapshotEntry::Directory {
                mode: expected_seeded_mode(0o751),
            })
        );
        assert_eq!(
            snapshot.entries.get(file),
            Some(&SnapshotEntry::File {
                bytes: b"---\nname: claude-user\ndescription: A read-only acceptance fixture.\n---\n# claude-user\n"
                    .to_vec(),
                mode: expected_seeded_mode(0o640),
            })
        );
        #[cfg(unix)]
        assert_eq!(
            snapshot.entries.get("home/.claude/skills/snapshot-link"),
            Some(&SnapshotEntry::Symlink {
                target: PathBuf::from("claude-user"),
            })
        );
    }
}

fn directory_skill(parent: &Path, name: &str) {
    let package = parent.join(name);
    fs::create_dir_all(&package).expect("skill package");
    fs::write(
        package.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: A read-only acceptance fixture.\n---\n# {name}\n"),
    )
    .expect("skill document");
}

#[cfg(unix)]
fn seed_snapshot_contract(home: &Path) {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let package = home.join(".claude/skills/claude-user");
    fs::set_permissions(&package, fs::Permissions::from_mode(0o751))
        .expect("seeded acceptance directory mode");
    fs::set_permissions(package.join("SKILL.md"), fs::Permissions::from_mode(0o640))
        .expect("seeded acceptance file mode");
    symlink("claude-user", home.join(".claude/skills/snapshot-link"))
        .expect("seeded acceptance symlink");
}

#[cfg(not(unix))]
fn seed_snapshot_contract(_home: &Path) {}

#[cfg(unix)]
const fn expected_seeded_mode(mode: u32) -> Option<u32> {
    Some(mode)
}

#[cfg(not(unix))]
const fn expected_seeded_mode(_mode: u32) -> Option<u32> {
    None
}

fn assert_attention_or_success(output: &Output) {
    assert!(
        output.status.success() || output.status.code() == Some(3),
        "unexpected status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn filesystem_snapshot_distinguishes_exact_file_and_directory_modes() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let tempdir = tempfile::tempdir().expect("snapshot sensitivity root");
    let root = fs::canonicalize(tempdir.path()).expect("canonical snapshot sensitivity root");
    let directory = root.join("seeded-directory");
    let file = directory.join("seeded-file.txt");
    fs::create_dir_all(&directory).expect("seeded directory");
    fs::write(&file, b"seeded bytes").expect("seeded file");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o751))
        .expect("seeded directory mode");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).expect("seeded file mode");
    symlink("seeded-file.txt", directory.join("seeded-link")).expect("seeded symlink");
    let before = FilesystemSnapshot::capture(&root).expect("snapshot before mode change");
    assert_eq!(
        before.entries.get("seeded-directory"),
        Some(&SnapshotEntry::Directory { mode: Some(0o751) })
    );
    assert_eq!(
        before.entries.get("seeded-directory/seeded-file.txt"),
        Some(&SnapshotEntry::File {
            bytes: b"seeded bytes".to_vec(),
            mode: Some(0o640),
        })
    );
    assert_eq!(
        before.entries.get("seeded-directory/seeded-link"),
        Some(&SnapshotEntry::Symlink {
            target: PathBuf::from("seeded-file.txt"),
        })
    );

    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("changed directory mode");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("changed file mode");
    let after = FilesystemSnapshot::capture(&root).expect("snapshot after mode change");

    assert_ne!(before, after, "exact Unix mode changes were invisible");
}

#[test]
fn inventory_scan_leaves_the_complete_fixture_tree_byte_identical_and_creates_nothing() {
    let fixture = FullMachineFixture::create(false);
    let before = FilesystemSnapshot::capture(&fixture.root).expect("before snapshot");
    fixture.assert_snapshot_contract(&before);

    let output = fixture.run_scan(false);

    let after = FilesystemSnapshot::capture(&fixture.root).expect("after snapshot");
    assert_attention_or_success(&output);
    assert_eq!(before, after);
    fixture.assert_no_generated_paths();
}

#[test]
fn classified_scan_leaves_manifest_state_and_parent_tree_byte_identical() {
    let fixture = FullMachineFixture::create(true);
    let before = FilesystemSnapshot::capture(&fixture.root).expect("before snapshot");
    fixture.assert_snapshot_contract(&before);

    let output = fixture.run_scan(true);

    let after = FilesystemSnapshot::capture(&fixture.root).expect("after snapshot");
    assert_attention_or_success(&output);
    assert_eq!(before, after);
    fixture.assert_no_generated_paths();
    assert_eq!(
        fs::read_to_string(
            fixture
                .environment
                .as_ref()
                .expect("classified fixture environment")
                .join("kitrove.toml")
        )
        .expect("manifest remains readable"),
        EMPTY_MANIFEST
    );
    assert_eq!(
        fs::read_to_string(fixture.state_home.join("state.json"))
            .expect("local state remains readable"),
        EMPTY_LOCAL_STATE
    );
}
