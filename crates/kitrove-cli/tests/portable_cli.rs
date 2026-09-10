#![forbid(unsafe_code)]

#[path = "support/owned_fixture.rs"]
mod owned_fixture;
mod support;

use std::fs;
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use std::collections::{BTreeMap, BTreeSet};

use kitrove_adapter_api::{HarnessAdapter as _, RootId, RootTier, VersionObservation};
use kitrove_adapter_claude::ClaudeAdapter;
use kitrove_adapter_codex::CodexAdapter;
use kitrove_adapter_opencode::OpenCodeAdapter;
use kitrove_adapter_pi::PiAdapter;
use kitrove_agent_skills::{CaptureLimits, CapturedFile, CapturedTree, FileMode, hash_tree};
#[cfg(unix)]
use kitrove_core::{
    AtomicApplyBatchPlan, AtomicApplyItem, ExtensionApplyAuthority, commit_atomic_apply_batch,
    load_native_extension_object, observe_extension_destination, plan_extension_apply,
};
use kitrove_core::{
    CapturedNativeExtension, InstructionAdoptionOutcome, NativeExtensionLayout,
    NativeExtensionObservation, ObjectStore, PortableSnapshotV1, TierOneInstructionCapabilities,
    commit_instruction_adoption, derive_lockfile, observe_instruction_document,
    plan_instruction_adoption, plan_native_extension_adoption,
};
use kitrove_model::{
    AssetId, BindingName, BindingResolver, ContentClass, ContentHash, EnvironmentManifest,
    EnvironmentVariableName, HarnessId, HarnessScope, LocalState, MachineConfig, MachineId,
    NormalizedDestination, Pack, PortablePath, Profile, ProfileId, Revision, SchemaVersion, Source,
};
#[cfg(unix)]
use kitrove_model::{PackApplicationClaim, TrustDecision};
#[cfg(unix)]
use kitrove_version_probe::probe_pi_version;
use serde_json::Value;
use tempfile::TempDir;

use support::read_until_prompt;

const EMPTY_MANIFEST: &str = "schema_version = 1\n";

struct Fixture {
    _tempdir: TempDir,
    home: PathBuf,
    working: PathBuf,
    environment: PathBuf,
    state_home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tempdir = kitrove_testkit::trusted_tempdir(".kitrove-portable-cli-");
        let root = fs::canonicalize(tempdir.path()).unwrap();
        let home = root.join("home");
        let working = root.join("working");
        let environment = root.join("environment");
        let state_home = root.join("state-home-absent");
        for directory in [
            home.join(".claude/skills"),
            home.join(".claude/commands"),
            home.join(".agents/skills"),
            home.join(".pi/agent/skills"),
            home.join(".pi/agent/prompts"),
            home.join(".config/opencode/skills"),
            working.clone(),
            environment.clone(),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        owned_fixture::create(&environment.join("kitrove.toml"), EMPTY_MANIFEST.as_bytes());
        Self {
            _tempdir: tempdir,
            home,
            working,
            environment,
            state_home,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.working)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state_home)
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME");
        command
    }

    fn skill(&self, harness_root: &Path, id: &str, body: &str) -> PathBuf {
        let root = harness_root.join(id);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("SKILL.md"),
            format!("---\nname: {id}\ndescription: A portable command fixture.\n---\n{body}\n"),
        )
        .unwrap();
        root
    }

    fn scan_observation(&self, harness: &str, native_id: &str) -> String {
        let output = self
            .command()
            .args([
                "scan",
                "--harness",
                harness,
                "--scope",
                "user",
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        json(&output)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["native_id"] == native_id)
            .and_then(|entry| entry["observation_id"].as_str())
            .unwrap()
            .to_owned()
    }

    fn scan_prompt_command_observation(&self, harness: &str, native_id: &str) -> String {
        let output = self
            .command()
            .args([
                "scan",
                "--harness",
                harness,
                "--scope",
                "user",
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        json(&output)["prompt_commands"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == native_id)
            .and_then(|entry| entry["observation_id"].as_str())
            .unwrap()
            .to_owned()
    }

    fn scan_agent_observation(&self, harness: &str, name: &str) -> String {
        let output = self
            .command()
            .args([
                "scan",
                "--harness",
                harness,
                "--scope",
                "user",
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        json(&output)["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .and_then(|entry| entry["observation_id"].as_str())
            .unwrap()
            .to_owned()
    }

    fn scan_mcp_observation(&self, harness: &str, portable_name: &str) -> String {
        let output = self
            .command()
            .args([
                "scan",
                "--harness",
                harness,
                "--scope",
                "user",
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        json(&output)["mcp_servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["portable_name"] == portable_name)
            .and_then(|entry| entry["exact_entry_hash"].as_str())
            .unwrap()
            .to_owned()
    }

    fn adopt(&self, observation: &str, id: Option<&str>) -> Output {
        self.adopt_with_selection(observation, id, &[])
    }

    fn adopt_with_selection(
        &self,
        observation: &str,
        id: Option<&str>,
        selection: &[&str],
    ) -> Output {
        let mut command = self.command();
        command.args([
            "adopt",
            "--environment",
            self.environment.to_str().unwrap(),
            "--json",
        ]);
        if let Some(id) = id {
            command.args(["--id", id]);
        }
        command.args(selection);
        command
            .arg(observation)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        child.wait_with_output().unwrap()
    }

    fn update_with_selection(
        &self,
        observation: &str,
        asset_id: &str,
        expected_prior: &str,
        selection: &[&str],
        confirmation: &[u8],
    ) -> Output {
        self.update_with_selection_format(
            observation,
            asset_id,
            expected_prior,
            selection,
            confirmation,
            true,
        )
    }

    fn update_with_selection_format(
        &self,
        observation: &str,
        asset_id: &str,
        expected_prior: &str,
        selection: &[&str],
        confirmation: &[u8],
        json: bool,
    ) -> Output {
        let mut command = self.command();
        command.args([
            "adopt",
            "--update",
            asset_id,
            "--expected-prior",
            expected_prior,
            "--environment",
            self.environment.to_str().unwrap(),
        ]);
        if json {
            command.arg("--json");
        }
        command.args(selection).arg(observation);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(confirmation).unwrap();
        child.wait_with_output().unwrap()
    }

    fn scan_explicit_observation(
        &self,
        harness: &str,
        root_argument: &str,
        native_id: &str,
    ) -> String {
        let output = self
            .command()
            .args([
                "scan",
                "--harness",
                harness,
                "--scope",
                "user",
                "--root",
                root_argument,
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        json(&output)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["native_id"] == native_id)
            .and_then(|entry| entry["observation_id"].as_str())
            .unwrap()
            .to_owned()
    }

    fn initialize_local_state(&self) {
        self.initialize_local_state_for("cli-fixture");
    }

    fn initialize_local_state_for(&self, machine_id: &str) {
        let state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse(machine_id).unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::<BindingName, BindingResolver>::new(),
            receipts: BTreeMap::new(),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: Vec::new(),
        };
        let bootstrap_environment = self
            .state_home
            .parent()
            .unwrap()
            .join("state-bootstrap-environment");
        let manifest = EnvironmentManifest::from_toml(EMPTY_MANIFEST).unwrap();
        kitrove_testkit::initialize_empty_authority_fixture(
            &bootstrap_environment,
            &self.state_home,
            &manifest,
            &state,
        )
        .unwrap();
    }

    fn initialize_nested_pack_assets(&self) {
        for id in ["pack-alpha", "pack-beta"] {
            self.skill(
                &self.home.join(".claude/skills"),
                id,
                &format!("# {id} fixture"),
            );
            let observation = self.scan_observation("claude", id);
            let adopted = self.adopt(&observation, None);
            assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
        }
        self.initialize_local_state();

        let mut manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(self.environment.join("kitrove.toml")).unwrap(),
        )
        .unwrap();
        let alpha = AssetId::parse("pack-alpha").unwrap();
        let beta = AssetId::parse("pack-beta").unwrap();
        let inner_id = AssetId::parse("inner-pack").unwrap();
        let outer_id = AssetId::parse("outer-pack").unwrap();
        let make_pack = |id: AssetId, members: BTreeMap<AssetId, ContentHash>| Pack {
            source: Source::Local {
                path: PortablePath::parse(format!("packs/{}", id.as_str())).unwrap(),
            },
            revision: Revision::parse(format!("local:{}", id.as_str())).unwrap(),
            exact_source_hash: ContentHash::digest(id.as_str().as_bytes()),
            content_hash: ContentHash::digest(b"pending-pack-cli-fixture"),
            id,
            members,
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        };
        manifest.packs.insert(
            inner_id.clone(),
            make_pack(
                inner_id.clone(),
                BTreeMap::from([
                    (alpha.clone(), manifest.assets[&alpha].content_hash.clone()),
                    (beta.clone(), manifest.assets[&beta].content_hash.clone()),
                ]),
            ),
        );
        manifest.refresh_pack_revisions().unwrap();
        manifest.packs.insert(
            outer_id.clone(),
            make_pack(
                outer_id,
                BTreeMap::from([
                    (alpha.clone(), manifest.assets[&alpha].content_hash.clone()),
                    (
                        inner_id.clone(),
                        manifest.packs[&inner_id].content_hash.clone(),
                    ),
                ]),
            ),
        );
        manifest.refresh_pack_revisions().unwrap();
        fs::write(
            self.environment.join("kitrove.toml"),
            manifest.to_toml().unwrap(),
        )
        .unwrap();
    }

    fn install_pack(&self, pack_id: &str, asset_ids: &[&str]) -> ContentHash {
        let mut manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(self.environment.join("kitrove.toml")).unwrap(),
        )
        .unwrap();
        let pack_id = AssetId::parse(pack_id).unwrap();
        let members = asset_ids
            .iter()
            .map(|asset_id| {
                let asset_id = AssetId::parse(*asset_id).unwrap();
                let content_hash = manifest.assets[&asset_id].content_hash.clone();
                (asset_id, content_hash)
            })
            .collect();
        manifest.packs.insert(
            pack_id.clone(),
            Pack {
                id: pack_id.clone(),
                source: Source::Local {
                    path: PortablePath::parse(format!("packs/{}", pack_id.as_str())).unwrap(),
                },
                revision: Revision::parse(format!("local:{}", pack_id.as_str())).unwrap(),
                exact_source_hash: ContentHash::digest(pack_id.as_str().as_bytes()),
                content_hash: ContentHash::digest(b"pending-pack-cli-fixture"),
                members,
                compatibility: BTreeMap::new(),
                content_class: ContentClass::DataOnly,
                required_bindings: BTreeSet::new(),
            },
        );
        manifest.refresh_pack_revisions().unwrap();
        let revision = manifest.packs[&pack_id].content_hash.clone();
        fs::write(
            self.environment.join("kitrove.toml"),
            manifest.to_toml().unwrap(),
        )
        .unwrap();
        fs::write(
            self.environment.join("kitrove.lock.json"),
            derive_lockfile(&manifest).unwrap().to_json().unwrap(),
        )
        .unwrap();
        revision
    }

    fn adopt_instruction_asset(&self, source: &Path, id: &str) {
        let policy = CodexAdapter
            .instruction_target_policy(HarnessScope::Project, VersionObservation::Unknown)
            .unwrap();
        let observation =
            observe_instruction_document(source, &policy, Default::default()).unwrap();
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(self.environment.join("kitrove.toml")).unwrap(),
        )
        .unwrap();
        let capabilities = TierOneInstructionCapabilities::new(BTreeMap::from([
            (HarnessId::Claude, ClaudeAdapter.capability_matrix(None)),
            (HarnessId::Codex, CodexAdapter.capability_matrix(None)),
            (HarnessId::Pi, PiAdapter.capability_matrix(None)),
            (HarnessId::OpenCode, OpenCodeAdapter.capability_matrix(None)),
        ]))
        .unwrap();
        let asset_id = AssetId::parse(id).unwrap();
        let InstructionAdoptionOutcome::Ready(adoption) =
            plan_instruction_adoption(&observation, &asset_id, &manifest, &capabilities).unwrap()
        else {
            panic!("valid instruction fixture must be adoptable");
        };
        commit_instruction_adoption(
            &adoption,
            &observation,
            &self.environment,
            CaptureLimits::default(),
        )
        .unwrap();
    }

    fn apply(&self, target: &str) -> Output {
        let mut command = self.command();
        command
            .args([
                "apply",
                "--target",
                target,
                "--scope",
                "user",
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        child.wait_with_output().unwrap()
    }

    fn confirmed_apply(&self, selection: &[&str]) -> Output {
        let mut command = self.command();
        command
            .arg("apply")
            .args(selection)
            .arg("--environment")
            .arg(&self.environment)
            .arg("--json")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        child.wait_with_output().unwrap()
    }

    #[cfg(unix)]
    fn opencode_v2_binary(&self) -> PathBuf {
        self.opencode_v2_binary_fixture("bin", "")
    }

    #[cfg(unix)]
    fn opencode_v2_binary_fixture(&self, directory: &str, marker: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let binary_root = self.home.join(directory);
        fs::create_dir_all(&binary_root).unwrap();
        let binary = binary_root.join("opencode2");
        fs::write(
            &binary,
            format!("#!/bin/sh\n{marker}\nprintf 'opencode2 v0.0.0-beta-18387\\n'\n"),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        binary
    }

    fn confirmed_pack_remove(&self, pack_id: &str, expected_prior: &ContentHash) -> Output {
        let mut command = self.command();
        command
            .args([
                "pack",
                "remove",
                "--pack",
                pack_id,
                "--expected-prior",
                expected_prior.as_str(),
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        child.wait_with_output().unwrap()
    }

    fn sync_plan(&self, remote: &Path) -> Output {
        self.command()
            .args([
                "sync",
                "plan",
                "--filesystem",
                remote.to_str().unwrap(),
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap()
    }

    fn sync_apply(&self, remote: &Path, digest: &str) -> Output {
        self.command()
            .args([
                "sync",
                "apply",
                "--filesystem",
                remote.to_str().unwrap(),
                "--environment",
                self.environment.to_str().unwrap(),
                "--confirm",
                digest,
                "--json",
            ])
            .output()
            .unwrap()
    }

    fn initialize_colliding_batch(&self) {
        for (harness, harness_root, asset_id, body) in [
            (
                "claude",
                self.home.join(".claude/skills"),
                "batch-one",
                "# First collision",
            ),
            (
                "pi",
                self.home.join(".pi/agent/skills"),
                "batch-two",
                "# Second collision",
            ),
        ] {
            let root = harness_root.join("shared-destination");
            fs::create_dir_all(&root).unwrap();
            fs::write(
                root.join("SKILL.md"),
                format!(
                    "---\nname: shared-destination\ndescription: A collision fixture.\n---\n{body}\n"
                ),
            )
            .unwrap();
            let observation = self.scan_observation(harness, "shared-destination");
            let adopted = self.adopt(&observation, Some(asset_id));
            assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
        }
        self.initialize_local_state();
    }

    fn apply_colliding_batch(&self, json_output: bool) -> Output {
        let mut command = self.command();
        command.args([
            "apply",
            "--asset",
            "batch-one",
            "--asset",
            "batch-two",
            "--target",
            "codex",
            "--scope",
            "user",
            "--environment",
            self.environment.to_str().unwrap(),
        ]);
        if json_output {
            command.arg("--json");
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        child.wait_with_output().unwrap()
    }
}

#[test]
fn extension_plan_requires_machine_local_trust_authority() {
    let fixture = Fixture::new();
    let files = BTreeMap::from([(
        PortablePath::parse("review.ts").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: b"export default {};\n".to_vec(),
        },
    )]);
    let observation = NativeExtensionObservation::new(
        HarnessScope::User,
        RootTier::User,
        RootId::parse("pi.user.native.extensions").unwrap(),
        15,
        PortablePath::parse("review.ts").unwrap(),
        "review",
        CapturedNativeExtension {
            layout: NativeExtensionLayout::Standalone,
            entrypoint: "review.ts".to_owned(),
            exact: CapturedTree {
                hash: hash_tree(&files),
                files,
            },
            content_class: ContentClass::Executable,
        },
    )
    .unwrap();
    let manifest = EnvironmentManifest::from_toml(EMPTY_MANIFEST).unwrap();
    let plan = plan_native_extension_adoption(
        &observation,
        Some(AssetId::parse("native-review").unwrap()),
        &manifest,
    )
    .unwrap();
    fs::write(
        fixture.environment.join("kitrove.toml"),
        plan.proposed_manifest().to_toml().unwrap(),
    )
    .unwrap();

    let output = fixture
        .command()
        .args([
            "plan",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--target",
            "pi",
            "--scope",
            "user",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(error.contains("apply.local_state_missing"));
    assert!(!fixture.state_home.join("state.json").exists());

    fixture.initialize_local_state();
    let object = plan.native_object();
    let object_root = &plan.proposed_manifest().assets[&AssetId::parse("native-review").unwrap()]
        .native_variants[&kitrove_model::HarnessId::Pi]
        .root;
    let staging = PortablePath::parse(".kitrove/test-cli-extension-staging").unwrap();
    let store = ObjectStore::open(&fixture.environment).unwrap();
    store
        .stage_native_extension(&staging, object, CaptureLimits::default())
        .unwrap();
    store
        .install_native_extension(
            &staging,
            object_root,
            object.hash(),
            CaptureLimits::default(),
        )
        .unwrap();
    fs::remove_dir_all(&fixture.home).unwrap();

    let output = fixture
        .command()
        .args([
            "plan",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--target",
            "pi",
            "--scope",
            "user",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error = stderr(&output);
    assert!(
        error.contains("apply.harness_version_unverified"),
        "unexpected error: {error}"
    );
    assert!(!error.contains("apply.target_anchor_unsafe"));
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            stderr(output),
        )
    })
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn normalized_destination(path: &Path) -> String {
    let encoded = path.to_str().unwrap();
    let encoded = encoded
        .strip_prefix(r"\\?\")
        .filter(|stripped| {
            let bytes = stripped.as_bytes();
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'/' | b'\\')
        })
        .unwrap_or(encoded);
    NormalizedDestination::parse(encoded)
        .unwrap()
        .as_str()
        .to_owned()
}

fn sync_plan_and_apply(fixture: &Fixture, remote: &Path, expected_disposition: &str, stage: &str) {
    let plan = fixture.sync_plan(remote);
    assert_eq!(plan.status.code(), Some(0), "{stage}: {}", stderr(&plan));
    assert_eq!(json(&plan)["disposition"], expected_disposition);
    let digest = json(&plan)["plan_digest"].as_str().unwrap().to_owned();
    let applied = fixture.sync_apply(remote, &digest);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["status"], "committed");
}

#[test]
fn cross_machine_reverse_edit_round_trips_through_explicit_update_adoption() {
    let remote_root = tempfile::tempdir().unwrap();
    let remote = fs::canonicalize(remote_root.path()).unwrap();
    let machine_a = Fixture::new();
    let machine_b = Fixture::new();
    let empty_snapshot = PortableSnapshotV1::new(
        EnvironmentManifest::from_toml(EMPTY_MANIFEST).unwrap(),
        BTreeSet::new(),
        kitrove_model::SyncLimits::default(),
    )
    .unwrap();
    fs::write(
        machine_b.environment.join("kitrove.toml"),
        empty_snapshot.manifest_toml(),
    )
    .unwrap();
    owned_fixture::create(
        &machine_b.environment.join("kitrove.lock.json"),
        empty_snapshot.lock_json().as_bytes(),
    );
    let source_container = machine_a._tempdir.path().join("outside-source");
    fs::create_dir_all(&source_container).unwrap();
    let source_container = fs::canonicalize(source_container).unwrap();
    machine_a.skill(&source_container, "round-trip", "# Initial portable source");
    let root_argument = format!("pi:user:{}", source_container.display());
    let observation = machine_a.scan_explicit_observation("pi", &root_argument, "round-trip");
    let adopted = machine_a.adopt_with_selection(
        &observation,
        None,
        &[
            "--harness",
            "pi",
            "--scope",
            "user",
            "--root",
            &root_argument,
        ],
    );
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));

    machine_a.initialize_local_state_for("machine-a");
    let applied_a = machine_a.apply("codex");
    assert_eq!(applied_a.status.code(), Some(0), "{}", stderr(&applied_a));
    sync_plan_and_apply(&machine_a, &remote, "publish", "machine A initial publish");

    machine_b.initialize_local_state_for("machine-b");
    sync_plan_and_apply(&machine_b, &remote, "receive", "machine B initial receive");
    let applied_b = machine_b.apply("codex");
    assert_eq!(applied_b.status.code(), Some(0), "{}", stderr(&applied_b));

    let asset_id = kitrove_model::AssetId::parse("round-trip").unwrap();
    let before_update = EnvironmentManifest::from_toml(
        &fs::read_to_string(machine_b.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let prior_revision = before_update.assets[&asset_id].content_hash.clone();
    let deployed_b = machine_b.home.join(".agents/skills/round-trip/SKILL.md");
    fs::write(
        &deployed_b,
        "---\nname: round-trip\ndescription: A portable command fixture.\n---\n# Reviewed on machine B\n",
    )
    .unwrap();
    let update_observation = machine_b.scan_observation("codex", "round-trip");
    let updated = machine_b.update_with_selection(
        &update_observation,
        "round-trip",
        prior_revision.as_str(),
        &["--harness", "codex", "--scope", "user"],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["outcome"], "committed_with_receipt");
    sync_plan_and_apply(&machine_b, &remote, "publish", "machine B reverse publish");

    sync_plan_and_apply(&machine_a, &remote, "receive", "machine A reverse receive");
    let managed_update = machine_a.apply("codex");
    assert_eq!(
        managed_update.status.code(),
        Some(0),
        "{}",
        stderr(&managed_update)
    );
    let deployed_a =
        fs::read_to_string(machine_a.home.join(".agents/skills/round-trip/SKILL.md")).unwrap();
    assert!(deployed_a.contains("# Reviewed on machine B"));

    let final_a = EnvironmentManifest::from_toml(
        &fs::read_to_string(machine_a.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let final_b = EnvironmentManifest::from_toml(
        &fs::read_to_string(machine_b.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(final_a, final_b);
    assert_eq!(
        fs::read(machine_a.environment.join("kitrove.lock.json")).unwrap(),
        fs::read(machine_b.environment.join("kitrove.lock.json")).unwrap()
    );
    assert_ne!(final_a.assets[&asset_id].content_hash, prior_revision);
    assert_eq!(final_a.assets[&asset_id].native_variants.len(), 2);
    assert_eq!(
        final_a.assets[&asset_id].native_variants[&kitrove_model::HarnessId::Pi].object_hash,
        before_update.assets[&asset_id].native_variants[&kitrove_model::HarnessId::Pi].object_hash
    );
    for machine in [&machine_a, &machine_b] {
        let state = LocalState::from_json(
            &fs::read_to_string(machine.state_home.join("state.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(state.receipts.len(), 1);
        assert_eq!(
            state.receipts.values().next().unwrap().source_hash,
            final_a.assets[&asset_id].content_hash
        );
    }
}

#[test]
fn every_tier_one_origin_round_trips_through_every_tier_one_target() {
    let harnesses = ["claude", "codex", "pi", "opencode"];
    let targets = [
        ("claude", ".claude/skills"),
        ("codex", ".agents/skills"),
        ("pi", ".pi/agent/skills"),
        ("opencode", ".config/opencode/skills"),
    ];

    for origin in harnesses {
        for (target, relative_root) in targets {
            let fixture = Fixture::new();
            let id = format!("from-{origin}-to-{target}");
            let source = fixture._tempdir.path().join("outside-source");
            fs::create_dir_all(&source).unwrap();
            let source = fs::canonicalize(source).unwrap();
            fixture.skill(&source, &id, "Inspect the change.");
            let root_argument = format!("{origin}:user:{}", source.display());
            let observation = fixture.scan_explicit_observation(origin, &root_argument, &id);
            let adopted = fixture.adopt_with_selection(
                &observation,
                None,
                &[
                    "--harness",
                    origin,
                    "--scope",
                    "user",
                    "--root",
                    &root_argument,
                ],
            );
            assert_eq!(
                adopted.status.code(),
                Some(0),
                "origin={origin} target={target}: {}",
                stderr(&adopted)
            );
            let manifest = EnvironmentManifest::from_toml(
                &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
            )
            .unwrap();
            let asset = &manifest.assets[&kitrove_model::AssetId::parse(&id).unwrap()];
            for harness in harnesses {
                let expected = if harness == origin {
                    kitrove_model::Fidelity::Native
                } else {
                    kitrove_model::Fidelity::Portable
                };
                assert_eq!(
                    asset.compatibility[&kitrove_model::HarnessId::parse(harness).unwrap()]
                        .fidelity(),
                    expected,
                    "origin={origin} target={target} harness={harness}"
                );
            }
            let manifest_after_adoption =
                fs::read(fixture.environment.join("kitrove.toml")).unwrap();
            fixture.initialize_local_state();

            let plan = fixture
                .command()
                .args([
                    "plan",
                    "--target",
                    target,
                    "--scope",
                    "user",
                    "--environment",
                    fixture.environment.to_str().unwrap(),
                    "--json",
                ])
                .output()
                .unwrap();
            assert_eq!(plan.status.code(), Some(0), "{}", stderr(&plan));
            assert_eq!(json(&plan)["disposition"], "install");
            assert_eq!(
                json(&plan)["destination"],
                normalized_destination(&fixture.home.join(relative_root).join(&id))
            );

            let applied = fixture.apply(target);
            assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
            assert_eq!(json(&applied)["outcome"], "committed");
            assert_eq!(
                fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
                manifest_after_adoption,
                "origin-native authority changed while applying {origin} to {target}"
            );

            let scan = fixture
                .command()
                .args([
                    "scan",
                    "--harness",
                    target,
                    "--scope",
                    "user",
                    "--environment",
                    fixture.environment.to_str().unwrap(),
                    "--json",
                ])
                .output()
                .unwrap();
            let entries = json(&scan)["entries"].as_array().unwrap().clone();
            assert!(
                entries.iter().any(|entry| {
                    entry["native_id"] == id && entry["classification"] == "managed_unchanged"
                }),
                "origin={origin} target={target}\nstdout={}\nstderr={}",
                String::from_utf8_lossy(&scan.stdout),
                stderr(&scan)
            );
        }
    }
}

#[test]
fn adopted_prompt_command_plans_applies_and_becomes_a_no_op() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "---\ndescription: Review the selected change.\n---\nReview $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    assert_eq!(json(&adopted)["asset_id"], "review");
    fixture.initialize_local_state();

    let selection = [
        "--asset",
        "review",
        "--target",
        "pi",
        "--scope",
        "user",
        "--environment",
        fixture.environment.to_str().unwrap(),
        "--json",
    ];
    let planned = fixture
        .command()
        .arg("plan")
        .args(selection)
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let plan = json(&planned);
    assert_eq!(plan["operation"], "apply_prompt_command");
    assert_eq!(plan["relative_destination"], ".pi/agent/prompts/review.md");
    assert_eq!(plan["disposition"], "install");

    let mut command = fixture.command();
    command
        .arg("apply")
        .args(selection)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["outcome"], "committed");
    assert!(
        fs::read_to_string(fixture.home.join(".pi/agent/prompts/review.md"))
            .unwrap()
            .contains("Review $ARGUMENTS carefully.")
    );

    let repeated = fixture
        .command()
        .arg("plan")
        .args(selection)
        .output()
        .unwrap();
    assert_eq!(repeated.status.code(), Some(0), "{}", stderr(&repeated));
    assert_eq!(json(&repeated)["disposition"], "no_op");
}

#[cfg(unix)]
#[test]
fn verified_opencode_v2_binary_unlocks_project_command_apply() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "---\ndescription: Review the selected change.\n---\nReview $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();

    let opencode = fixture.opencode_v2_binary();

    let selection = [
        "--asset",
        "review",
        "--target",
        "opencode",
        "--scope",
        "project",
        "--project-root",
        fixture.working.to_str().unwrap(),
        "--version-binary",
        opencode.to_str().unwrap(),
    ];
    let planned = fixture
        .command()
        .arg("plan")
        .args(selection)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let first_digest = json(&planned)["plan_digest"].as_str().unwrap().to_owned();

    let replacement = fixture.opencode_v2_binary_fixture("bin-replacement", "# distinct bytes");
    let replacement_selection = [
        "--asset",
        "review",
        "--target",
        "opencode",
        "--scope",
        "project",
        "--project-root",
        fixture.working.to_str().unwrap(),
        "--version-binary",
        replacement.to_str().unwrap(),
    ];
    let replacement_plan = fixture
        .command()
        .arg("plan")
        .args(replacement_selection)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        replacement_plan.status.code(),
        Some(0),
        "{}",
        stderr(&replacement_plan)
    );
    assert_ne!(
        json(&replacement_plan)["plan_digest"].as_str().unwrap(),
        first_digest
    );

    let applied = fixture.confirmed_apply(&selection);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["outcome"], "committed");
    assert!(
        fs::read_to_string(fixture.working.join(".opencode/commands/review.md"))
            .unwrap()
            .contains("Review $ARGUMENTS carefully.")
    );

    let mut command = fixture.command();
    command
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "opencode",
            "--scope",
            "project",
            "--project-root",
            fixture.working.to_str().unwrap(),
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(
        !fixture
            .working
            .join(".opencode/commands/review.md")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn opencode_version_change_from_external_state_invalidates_confirmation() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();

    let binary_root = fixture.home.join("stateful-bin");
    fs::create_dir(&binary_root).unwrap();
    let version_state = binary_root.join("reported-version");
    fs::write(&version_state, "0.0.0-beta-1\n").unwrap();
    let opencode = binary_root.join("opencode2");
    fs::write(
        &opencode,
        format!(
            "#!/bin/sh\nIFS= read -r version < '{}'\nprintf 'opencode2 v%s\\n' \"$version\"\n",
            version_state.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&opencode, fs::Permissions::from_mode(0o700)).unwrap();

    let mut command = fixture.command();
    command
        .args([
            "apply",
            "--asset",
            "review",
            "--target",
            "opencode",
            "--scope",
            "project",
            "--project-root",
            fixture.working.to_str().unwrap(),
            "--version-binary",
            opencode.to_str().unwrap(),
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut error_stream = child.stderr.take().unwrap();
    let mut error_bytes = Vec::new();
    read_until_prompt(
        &mut error_stream,
        &mut error_bytes,
        b"Confirm apply by typing 'yes': ",
    );

    fs::write(&version_state, "0.0.0-beta-2\n").unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    error_stream.read_to_end(&mut error_bytes).unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&error_bytes).contains("error[apply.plan_stale]"));
    assert!(
        !fixture
            .working
            .join(".opencode/commands/review.md")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn verified_opencode_v2_binary_unlocks_user_instruction_apply() {
    let fixture = Fixture::new();
    let source = fixture.home.join("instruction-source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("AGENTS.md"),
        concat!(
            "<!-- kitrove:instruction review-instruction begin -->\n",
            "Review carefully.\n",
            "<!-- kitrove:instruction review-instruction end -->\n",
        ),
    )
    .unwrap();
    fixture.adopt_instruction_asset(&source, "review-instruction");
    fixture.initialize_local_state();
    let opencode = fixture.opencode_v2_binary();

    let applied = fixture.confirmed_apply(&[
        "--asset",
        "review-instruction",
        "--target",
        "opencode",
        "--scope",
        "user",
        "--version-binary",
        opencode.to_str().unwrap(),
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(
        fs::read_to_string(fixture.home.join(".config/opencode/AGENTS.md"))
            .unwrap()
            .contains("Review carefully.")
    );
    assert!(!fixture.home.join("AGENTS.md").exists());

    let mut command = fixture.command();
    command
        .args([
            "remove",
            "--asset",
            "review-instruction",
            "--target",
            "opencode",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(
        !fs::read_to_string(fixture.home.join(".config/opencode/AGENTS.md"))
            .unwrap_or_default()
            .contains("Review carefully.")
    );
}

#[cfg(unix)]
#[test]
fn opencode_pack_removal_preserves_retained_instruction_without_reprobing() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let command_observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&command_observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));

    let source = fixture.home.join("retained-instruction-source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("AGENTS.md"),
        concat!(
            "<!-- kitrove:instruction retained-review begin -->\n",
            "Retain this review instruction.\n",
            "<!-- kitrove:instruction retained-review end -->\n",
        ),
    )
    .unwrap();
    fixture.adopt_instruction_asset(&source, "retained-review");
    fixture.initialize_local_state();
    let inner_revision = fixture.install_pack("opencode-inner", &["retained-review"]);
    let outer_revision = fixture.install_pack("opencode-outer", &["retained-review", "review"]);
    let opencode = fixture.opencode_v2_binary();

    let applied = fixture.confirmed_apply(&[
        "--pack",
        "opencode-inner",
        "--pack",
        "opencode-outer",
        "--target",
        "opencode",
        "--scope",
        "user",
        "--version-binary",
        opencode.to_str().unwrap(),
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let configuration = fixture.home.join(".config/opencode");
    let instruction = configuration.join("AGENTS.md");
    let command = configuration.join("commands/review.md");
    assert!(instruction.exists());
    assert!(command.exists());

    let outer_removed = fixture.confirmed_pack_remove("opencode-outer", &outer_revision);
    assert_eq!(
        outer_removed.status.code(),
        Some(0),
        "{}",
        stderr(&outer_removed)
    );
    assert!(
        fs::read_to_string(&instruction)
            .unwrap()
            .contains("Retain this review instruction.")
    );
    assert!(!command.exists());
    let state_path = fixture.state_home.join("state.json");
    let state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.pack_applications.len(), 1);
    assert_eq!(
        state.receipts.values().next().unwrap().asset_id.as_str(),
        "retained-review"
    );

    let inner_removed = fixture.confirmed_pack_remove("opencode-inner", &inner_revision);
    assert_eq!(
        inner_removed.status.code(),
        Some(0),
        "{}",
        stderr(&inner_removed)
    );
    let state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
    assert!(
        !fs::read_to_string(instruction)
            .unwrap_or_default()
            .contains("kitrove:instruction retained-review")
    );
}

#[test]
fn adopted_agent_is_materialized_through_pack_application_and_claimed_atomically() {
    let fixture = Fixture::new();
    let agents = fixture.home.join(".claude/agents");
    fs::create_dir_all(&agents).unwrap();
    fs::write(
        agents.join("review.md"),
        "---\nname: review\ndescription: Review changes carefully.\n---\nReview the selected changes.\n",
    )
    .unwrap();
    let observation = fixture.scan_agent_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    assert_eq!(json(&adopted)["asset_id"], "review");
    let prior = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap()
    .assets[&AssetId::parse("review").unwrap()]
        .content_hash
        .clone();
    fs::write(
        agents.join("review.md"),
        "---\nname: review\ndescription: Review changes carefully.\n---\nReview the updated changes.\n",
    )
    .unwrap();
    let changed = fixture.scan_agent_observation("claude", "review");
    let updated = fixture.update_with_selection(
        &changed,
        "review",
        prior.as_str(),
        &["--harness", "claude", "--scope", "user"],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["operation"], "update_agent");
    assert_eq!(json(&updated)["old_asset_revision"], prior.as_str());
    fixture.initialize_local_state();
    let pack_revision = fixture.install_pack("review-team", &["review"]);

    let selection = [
        "--pack",
        "review-team",
        "--target",
        "codex",
        "--scope",
        "user",
        "--environment",
        fixture.environment.to_str().unwrap(),
        "--json",
    ];
    let planned = fixture
        .command()
        .arg("plan")
        .args(selection)
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let plan = json(&planned);
    assert_eq!(plan["operation"], "apply_agent");
    assert_eq!(plan["relative_destination"], ".codex/agents/review.toml");
    assert_eq!(
        plan["selected_packs"][0]["revision"],
        pack_revision.as_str()
    );
    assert_eq!(plan["disposition"], "install");

    let applied = fixture.confirmed_apply(&[
        "--pack",
        "review-team",
        "--target",
        "codex",
        "--scope",
        "user",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["outcome"], "committed");
    assert!(
        fs::read_to_string(fixture.home.join(".codex/agents/review.toml"))
            .unwrap()
            .contains("Review the updated changes.")
    );
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 1);
    let claim = state.pack_applications.values().next().unwrap();
    assert_eq!(claim.pack_id.as_str(), "review-team");
    assert_eq!(claim.pack_revision, pack_revision);
    assert_eq!(claim.receipts, state.receipts.keys().cloned().collect());

    let removed = fixture.confirmed_pack_remove("review-team", &pack_revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert_eq!(json(&removed)["operation"], "pack_remove");
    assert!(!fixture.home.join(".codex/agents/review.toml").exists());
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert!(
        manifest
            .assets
            .contains_key(&AssetId::parse("review").unwrap())
    );
    assert!(
        manifest
            .packs
            .contains_key(&AssetId::parse("review-team").unwrap())
    );

    let applied = fixture.confirmed_apply(&["--asset", "review", "--target", "codex"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let mut command = fixture.command();
    command
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "codex",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert_eq!(json(&removed)["operation"], "remove_agent");
    assert!(!fixture.home.join(".codex/agents/review.toml").exists());
}

#[test]
fn remote_mcp_adoption_maps_native_environment_authority_to_a_logical_binding() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude.json"),
        r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${NATIVE_MCP_SECRET}"}}}}"#,
    )
    .unwrap();
    let observation = fixture.scan_mcp_observation("claude", "docs");
    let blocked = fixture.adopt(&observation, None);
    assert_eq!(blocked.status.code(), Some(1), "{}", stderr(&blocked));
    assert_eq!(json(&blocked)["reason"], "binding_choice_required");
    assert_eq!(
        fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
        EMPTY_MANIFEST
    );
    let adopted =
        fixture.adopt_with_selection(&observation, None, &["--binding", "company_mcp_token"]);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    let result = json(&adopted);
    assert_eq!(result["operation"], "adopt_mcp");
    assert_eq!(result["asset_id"], "docs");

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let binding = BindingName::parse("company_mcp_token").unwrap();
    assert!(manifest.required_bindings.contains(&binding));
    assert_eq!(
        manifest.assets[&AssetId::parse("docs").unwrap()].required_bindings,
        BTreeSet::from([binding])
    );
    assert!(
        kitrove_core::verify_referenced_objects(
            &manifest,
            &fixture.environment,
            CaptureLimits::default(),
        )
        .unwrap()
        .is_clean()
    );

    let expected_prior = manifest.assets[&AssetId::parse("docs").unwrap()]
        .content_hash
        .clone();
    fs::write(
        fixture.home.join(".claude.json"),
        r#"{"mcpServers":{"docs":{"type":"http","url":"https://new.example.com/mcp","headers":{"Authorization":"Bearer ${NATIVE_MCP_SECRET}"}}}}"#,
    )
    .unwrap();
    let changed = fixture.scan_mcp_observation("claude", "docs");
    let updated = fixture.update_with_selection(
        &changed,
        "docs",
        expected_prior.as_str(),
        &["--binding", "company_mcp_token"],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["operation"], "update_mcp");
    let updated_manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_ne!(
        updated_manifest.assets[&AssetId::parse("docs").unwrap()].content_hash,
        expected_prior
    );
}

#[test]
fn prompt_command_cli_removal_is_exact_receipt_backed_and_retains_portable_authority() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();
    let applied = fixture.apply("pi");
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = AssetId::parse("review").unwrap();
    let portable_root = manifest.assets[&asset_id]
        .portable
        .as_ref()
        .unwrap()
        .root
        .clone();
    let mut command = fixture.command();
    command
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert_eq!(json(&removed)["operation"], "remove_prompt_command");
    assert!(!fixture.home.join(".pi/agent/prompts/review.md").exists());
    assert!(fixture.environment.join(portable_root.as_str()).exists());
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());

    let repeated = fixture
        .command()
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(repeated.status.code(), Some(1));
    assert!(stderr(&repeated).contains("error[remove.receipt_unavailable]"));
}

#[test]
fn prompt_command_cli_removal_refuses_a_modified_managed_file() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    assert_eq!(fixture.adopt(&observation, None).status.code(), Some(0));
    fixture.initialize_local_state();
    assert_eq!(fixture.apply("pi").status.code(), Some(0));
    let destination = fixture.home.join(".pi/agent/prompts/review.md");
    fs::write(&destination, "Locally changed command.\n").unwrap();

    let refused = fixture
        .command()
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("error[command_remove.destination_modified]"));
    assert_eq!(
        fs::read_to_string(destination).unwrap(),
        "Locally changed command.\n"
    );
}

#[test]
fn prompt_command_cli_removal_honors_the_selected_project_boundary() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    assert_eq!(fixture.adopt(&observation, None).status.code(), Some(0));
    fixture.initialize_local_state();
    let selection = [
        "--asset",
        "review",
        "--target",
        "pi",
        "--scope",
        "project",
        "--project-root",
        fixture.working.to_str().unwrap(),
        "--environment",
        fixture.environment.to_str().unwrap(),
        "--json",
    ];
    let mut apply = fixture.command();
    apply
        .arg("apply")
        .args(selection)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = apply.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let destination = fixture.working.join(".pi/prompts/review.md");
    assert!(destination.exists());

    let mut remove = fixture.command();
    remove
        .arg("remove")
        .args(selection)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = remove.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!destination.exists());
}

#[test]
fn prompt_command_cli_removal_uses_receipt_destination_after_a_portable_rename() {
    let fixture = Fixture::new();
    let original = fixture.home.join(".claude/commands/review.md");
    fs::write(&original, "Review $ARGUMENTS carefully.\n").unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    assert_eq!(fixture.adopt(&observation, None).status.code(), Some(0));
    fixture.initialize_local_state();
    assert_eq!(fixture.apply("pi").status.code(), Some(0));
    let old_destination = fixture.home.join(".pi/agent/prompts/review.md");
    assert!(old_destination.exists());

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let prior = manifest.assets[&AssetId::parse("review").unwrap()]
        .content_hash
        .clone();
    fs::remove_file(original).unwrap();
    fs::write(
        fixture.home.join(".claude/commands/renamed.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let renamed = fixture.scan_prompt_command_observation("claude", "renamed");
    let updated = fixture.update_with_selection(
        &renamed,
        "review",
        prior.as_str(),
        &["--harness", "claude", "--scope", "user"],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));

    let mut remove = fixture.command();
    remove
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = remove.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!old_destination.exists());
    assert!(!fixture.home.join(".pi/agent/prompts/renamed.md").exists());
}

#[test]
fn prompt_command_plan_refuses_an_unmanaged_destination() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();
    fs::write(
        fixture.home.join(".pi/agent/prompts/review.md"),
        "User-owned command.\n",
    )
    .unwrap();

    let planned = fixture
        .command()
        .args([
            "plan",
            "--asset",
            "review",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(1));
    assert!(stderr(&planned).contains("error[command_apply.destination_unmanaged]"));
}

#[test]
fn prompt_command_exact_prior_update_flows_into_a_managed_target_update() {
    let fixture = Fixture::new();
    let source = fixture.home.join(".claude/commands/review.md");
    fs::write(&source, "Review $ARGUMENTS carefully.\n").unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();
    let installed = fixture.apply("pi");
    assert_eq!(installed.status.code(), Some(0), "{}", stderr(&installed));

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let prior = manifest.assets[&AssetId::parse("review").unwrap()]
        .content_hash
        .clone();
    fs::write(&source, "Review $ARGUMENTS thoroughly.\n").unwrap();
    let changed = fixture.scan_prompt_command_observation("claude", "review");
    let updated = fixture.update_with_selection(
        &changed,
        "review",
        prior.as_str(),
        &["--harness", "claude", "--scope", "user"],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["operation"], "update_prompt_command");
    assert_eq!(json(&updated)["outcome"], "committed_without_receipt");

    let planned = fixture
        .command()
        .args([
            "plan",
            "--asset",
            "review",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    assert_eq!(json(&planned)["disposition"], "managed_update");

    let applied = fixture.apply("pi");
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(
        fs::read_to_string(fixture.home.join(".pi/agent/prompts/review.md"))
            .unwrap()
            .contains("Review $ARGUMENTS thoroughly.")
    );
}

#[test]
fn project_plan_is_non_mutating_and_apply_stays_beneath_the_selected_project() {
    let fixture = Fixture::new();
    let source = fixture._tempdir.path().join("outside-project-source");
    fs::create_dir_all(&source).unwrap();
    let source = fs::canonicalize(source).unwrap();
    fixture.skill(&source, "review", "Inspect the project change.");
    let root_argument = format!("claude:user:{}", source.display());
    let observation = fixture.scan_explicit_observation("claude", &root_argument, "review");
    let adopted = fixture.adopt_with_selection(
        &observation,
        None,
        &[
            "--harness",
            "claude",
            "--scope",
            "user",
            "--root",
            &root_argument,
        ],
    );
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();
    let state_before = fs::read(fixture.state_home.join("state.json")).unwrap();
    let destination = fixture.working.join(".pi/skills/review");

    let plan = fixture
        .command()
        .args([
            "plan",
            "--target",
            "pi",
            "--scope",
            "project",
            "--project-root",
            fixture.working.to_str().unwrap(),
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(plan.status.code(), Some(0), "{}", stderr(&plan));
    assert_eq!(
        json(&plan)["destination"],
        normalized_destination(&destination)
    );
    assert!(!destination.exists());
    assert_eq!(
        fs::read(fixture.state_home.join("state.json")).unwrap(),
        state_before
    );

    let mut command = fixture.command();
    command
        .args([
            "apply",
            "--target",
            "pi",
            "--scope",
            "project",
            "--project-root",
            fixture.working.to_str().unwrap(),
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert!(destination.join("SKILL.md").is_file());
}

#[test]
fn lock_and_status_share_manifest_authority_and_stable_json() {
    let fixture = Fixture::new();
    let status = fixture
        .command()
        .args([
            "status",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(3), "{}", stderr(&status));
    assert_eq!(json(&status)["lock"], "missing");

    let repaired = fixture
        .command()
        .args([
            "lock",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(repaired.status.code(), Some(0), "{}", stderr(&repaired));
    assert_eq!(json(&repaired)["outcome"], "repaired");

    let clean = fixture
        .command()
        .args([
            "status",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(clean.status.code(), Some(0), "{}", stderr(&clean));
    assert_eq!(json(&clean)["clean"], true);
    assert_eq!(json(&clean)["lock"], "in_sync");
}

#[test]
fn adoption_is_confirmed_then_idempotent_and_persists_both_objects() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "portable-one",
        "# One",
    );
    let observation = fixture.scan_observation("claude", "portable-one");

    let first = fixture.adopt(&observation, None);
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(json(&first)["outcome"], "committed");
    assert!(stderr(&first).contains("Confirm adoption"));

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset = &manifest.assets[&kitrove_model::AssetId::parse("portable-one").unwrap()];
    assert!(
        fixture
            .environment
            .join(asset.portable.as_ref().unwrap().root.as_str())
            .is_dir()
    );
    assert!(
        fixture
            .environment
            .join(asset.native_variants.values().next().unwrap().root.as_str())
            .is_dir()
    );

    let second = fixture.adopt(&observation, None);
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    assert_eq!(json(&second)["outcome"], "repaired");
}

#[test]
fn explicit_update_is_confirmed_and_replaces_the_exact_prior_revision() {
    let fixture = Fixture::new();
    let source = fixture._tempdir.path().join("explicit-update-source");
    fs::create_dir_all(&source).unwrap();
    let source = fs::canonicalize(source).unwrap();
    let first_source = source.join("before.md");
    fs::write(
        &first_source,
        "---\nname: updatable\ndescription: A portable command fixture.\n---\n# Before\n",
    )
    .unwrap();
    let first_root = format!("pi:user:{}", first_source.display());
    let first_observation = fixture.scan_explicit_observation("pi", &first_root, "updatable");
    let first_selection = [
        "--harness",
        "pi",
        "--scope",
        "user",
        "--root",
        first_root.as_str(),
    ];
    let adopted = fixture.adopt_with_selection(&first_observation, None, &first_selection);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    let prior_manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let prior = prior_manifest.assets[&kitrove_model::AssetId::parse("updatable").unwrap()]
        .content_hash
        .clone();

    let updated_source = source.join("after.md");
    fs::rename(&first_source, &updated_source).unwrap();
    let updated_root = format!("pi:user:{}", updated_source.display());
    let updated_selection = [
        "--harness",
        "pi",
        "--scope",
        "user",
        "--root",
        updated_root.as_str(),
    ];
    let update_observation = fixture.scan_explicit_observation("pi", &updated_root, "updatable");
    let updated = fixture.update_with_selection(
        &update_observation,
        "updatable",
        prior.as_str(),
        &updated_selection,
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    let output = json(&updated);
    assert_eq!(output["operation"], "update_adoption");
    assert_eq!(output["old_asset_revision"], prior.as_str());
    assert_eq!(output["outcome"], "committed");
    assert!(stderr(&updated).contains("source_authority"));
    assert!(stderr(&updated).contains(r#""portable":"retained""#));

    let current = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_ne!(
        current.assets[&kitrove_model::AssetId::parse("updatable").unwrap()].content_hash,
        prior
    );
    assert!(!fixture.state_home.join("state.json").exists());
}

#[test]
fn update_text_json_and_error_surfaces_redact_all_review_canaries() {
    const AUTHORED: &str = "KITROVE_D2_AUTHORED_CANARY_6f91";
    const NATIVE_ID: &str = "d2-native-canary-6f91";
    const PATH_CANARY: &str = "KITROVE_D2_ABSOLUTE_PATH_CANARY_6f91";
    const DESTINATION: &str = "KITROVE_D2_DESTINATION_CANARY_6f91";
    const SECRET: &str = "KITROVE_D2_SECRET_VALUE_CANARY_6f91";

    for json_output in [false, true] {
        let fixture = Fixture::new();
        let source = fixture._tempdir.path().join(PATH_CANARY).join(DESTINATION);
        fs::create_dir_all(&source).unwrap();
        let source = fs::canonicalize(source).unwrap();
        let document = source.join("source.md");
        fs::write(
            &document,
            format!(
                "---\nname: {NATIVE_ID}\ndescription: A portable command fixture.\n---\n# Before\n"
            ),
        )
        .unwrap();
        let root = format!("pi:user:{}", document.display());
        let selection = [
            "--harness",
            "pi",
            "--scope",
            "user",
            "--root",
            root.as_str(),
        ];
        let observation = fixture.scan_explicit_observation("pi", &root, NATIVE_ID);
        let adopted =
            fixture.adopt_with_selection(&observation, Some("redaction-asset"), &selection);
        assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
        let manifest = EnvironmentManifest::from_toml(
            &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
        )
        .unwrap();
        let asset_id = kitrove_model::AssetId::parse("redaction-asset").unwrap();
        let prior = manifest.assets[&asset_id].content_hash.clone();

        fs::write(
            &document,
            format!(
                "---\nname: {NATIVE_ID}\ndescription: A portable command fixture.\n---\n{AUTHORED}\n{SECRET}\n"
            ),
        )
        .unwrap();
        let update_observation = fixture.scan_explicit_observation("pi", &root, NATIVE_ID);
        let output = fixture.update_with_selection_format(
            &update_observation,
            "redaction-asset",
            prior.as_str(),
            &selection,
            b"no\n",
            json_output,
        );
        assert_eq!(output.status.code(), Some(1));
        let rendered = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(rendered.contains("update.confirmation_required"));
        for canary in [AUTHORED, NATIVE_ID, PATH_CANARY, DESTINATION, SECRET] {
            assert!(
                !rendered.contains(canary),
                "update output disclosed {canary}: {rendered}"
            );
        }
    }
}

#[test]
fn managed_modified_update_rebases_its_exact_receipt() {
    let fixture = Fixture::new();
    let source = fixture._tempdir.path().join("managed-update-source");
    fs::create_dir_all(&source).unwrap();
    let source = fs::canonicalize(source).unwrap();
    fixture.skill(&source, "managed-update", "# Portable source");
    let root_argument = format!("claude:user:{}", source.display());
    let observation = fixture.scan_explicit_observation("claude", &root_argument, "managed-update");
    let adopted = fixture.adopt_with_selection(
        &observation,
        None,
        &[
            "--harness",
            "claude",
            "--scope",
            "user",
            "--root",
            &root_argument,
        ],
    );
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    let prior_manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = kitrove_model::AssetId::parse("managed-update").unwrap();
    let prior = prior_manifest.assets[&asset_id].content_hash.clone();

    fixture.initialize_local_state();
    let applied = fixture.apply("codex");
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let deployed = fixture.home.join(".agents/skills/managed-update/SKILL.md");
    fs::write(
        &deployed,
        "---\nname: managed-update\ndescription: A portable command fixture.\n---\n# Locally reviewed change\n",
    )
    .unwrap();
    let update_observation = fixture.scan_observation("codex", "managed-update");
    let updated = fixture.update_with_selection(
        &update_observation,
        "managed-update",
        prior.as_str(),
        &["--harness", "codex", "--scope", "user"],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["outcome"], "committed_with_receipt");
    assert!(stderr(&updated).contains("managed_modified"));

    let current = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(current.assets[&asset_id].native_variants.len(), 2);
    assert_eq!(
        current.assets[&asset_id].native_variants[&kitrove_model::HarnessId::Claude].object_hash,
        prior_manifest.assets[&asset_id].native_variants[&kitrove_model::HarnessId::Claude]
            .object_hash
    );
    let current_revision = current.assets[&asset_id].content_hash.clone();
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    let receipt = state.receipts.values().next().unwrap();
    assert_eq!(receipt.source_hash, current_revision);
    let rescanned = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "codex",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        json(&rescanned)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["native_id"] == "managed-update"
                && entry["classification"] == "managed_unchanged")
    );
}

#[test]
fn unconfirmed_update_does_not_create_state_or_change_portable_authority() {
    let fixture = Fixture::new();
    let source = fixture._tempdir.path().join("declined-update-source");
    fs::create_dir_all(&source).unwrap();
    let source = fs::canonicalize(source).unwrap();
    let skill = fixture.skill(&source, "declined-update", "# Before");
    let root_argument = format!("pi:user:{}", source.display());
    let selection = [
        "--harness",
        "pi",
        "--scope",
        "user",
        "--root",
        root_argument.as_str(),
    ];
    let observation = fixture.scan_explicit_observation("pi", &root_argument, "declined-update");
    let adopted = fixture.adopt_with_selection(&observation, None, &selection);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let prior = manifest.assets[&kitrove_model::AssetId::parse("declined-update").unwrap()]
        .content_hash
        .clone();
    fs::write(
        skill.join("SKILL.md"),
        "---\nname: declined-update\ndescription: A portable command fixture.\n---\n# After\n",
    )
    .unwrap();
    let update_observation =
        fixture.scan_explicit_observation("pi", &root_argument, "declined-update");
    let manifest_before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();
    let lock_before = fs::read(fixture.environment.join("kitrove.lock.json")).unwrap();
    let declined = fixture.update_with_selection(
        &update_observation,
        "declined-update",
        prior.as_str(),
        &selection,
        b"no\n",
    );
    assert_eq!(declined.status.code(), Some(1));
    assert!(stderr(&declined).contains("error[update.confirmation_required]"));
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.lock.json")).unwrap(),
        lock_before
    );
    assert!(!fixture.state_home.exists());
}

#[test]
fn unconfirmed_adoption_makes_no_portable_changes() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "declined",
        "# Declined",
    );
    let observation = fixture.scan_observation("claude", "declined");
    let before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();
    let mut command = fixture.command();
    command
        .args([
            "adopt",
            "--environment",
            fixture.environment.to_str().unwrap(),
            &observation,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"no\n").unwrap();
    let declined = child.wait_with_output().unwrap();

    assert_eq!(declined.status.code(), Some(1));
    assert!(stderr(&declined).contains("error[adoption.confirmation_required]"));
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        before
    );
    assert!(!fixture.environment.join("objects").exists());
    assert!(!fixture.environment.join("kitrove.lock.json").exists());
}

#[test]
fn every_tier_one_origin_can_be_adopted_through_the_same_command_contract() {
    let fixture = Fixture::new();
    for (harness, root, id) in [
        ("claude", ".claude/skills", "from-claude"),
        ("codex", ".agents/skills", "from-codex"),
        ("pi", ".pi/agent/skills", "from-pi"),
        ("opencode", ".config/opencode/skills", "from-opencode"),
    ] {
        fixture.skill(&fixture.home.join(root), id, "# Inert");
        let observation = fixture.scan_observation(harness, id);
        let adopted = fixture.adopt(&observation, None);
        assert_eq!(
            adopted.status.code(),
            Some(0),
            "{harness}: {}",
            stderr(&adopted)
        );
        assert_eq!(json(&adopted)["asset_id"], id);
        assert_eq!(json(&adopted)["outcome"], "committed");
    }

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.assets.len(), 4);
}

#[test]
fn explicit_directory_and_standalone_scan_context_can_be_reproduced_for_adoption() {
    let fixture = Fixture::new();
    let directory_container = fixture.working.join("outside-directory-root");
    fs::create_dir_all(&directory_container).unwrap();
    fixture.skill(&directory_container, "explicit-directory", "# Directory");
    let directory_root = format!("claude:user:{}", directory_container.display());
    let directory_observation =
        fixture.scan_explicit_observation("claude", &directory_root, "explicit-directory");
    let directory = fixture.adopt_with_selection(
        &directory_observation,
        None,
        &[
            "--harness",
            "claude",
            "--scope",
            "user",
            "--root",
            &directory_root,
        ],
    );
    assert_eq!(directory.status.code(), Some(0), "{}", stderr(&directory));
    assert_eq!(json(&directory)["asset_id"], "explicit-directory");

    let standalone = fixture.working.join("outside-standalone.md");
    fs::write(
        &standalone,
        "---\nname: explicit-standalone\ndescription: Explicit standalone fixture.\n---\n# Standalone\n",
    )
    .unwrap();
    let standalone_root = format!("pi:user:{}", standalone.display());
    let standalone_observation =
        fixture.scan_explicit_observation("pi", &standalone_root, "explicit-standalone");
    let standalone_result = fixture.adopt_with_selection(
        &standalone_observation,
        None,
        &[
            "--harness",
            "pi",
            "--scope",
            "user",
            "--root",
            &standalone_root,
        ],
    );
    assert_eq!(
        standalone_result.status.code(),
        Some(0),
        "{}",
        stderr(&standalone_result)
    );
    assert_eq!(json(&standalone_result)["asset_id"], "explicit-standalone");
}

#[test]
fn same_explicit_id_with_different_content_is_a_nonmutating_conflict() {
    let fixture = Fixture::new();
    let skill = fixture.skill(&fixture.home.join(".claude/skills"), "first", "# First");
    let first_observation = fixture.scan_observation("claude", "first");
    let first = fixture.adopt(&first_observation, Some("shared"));
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    let before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();

    fs::write(
        skill.join("SKILL.md"),
        "---\nname: first\ndescription: A portable command fixture.\n---\n# Different\n",
    )
    .unwrap();
    let second_observation = fixture.scan_observation("claude", "first");
    let conflict = fixture.adopt(&second_observation, Some("shared"));
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(json(&conflict)["phase"], "blocked");
    assert_eq!(json(&conflict)["reason"], "asset_conflict");
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        before
    );
}

#[test]
fn unavailable_projection_returns_a_deterministic_blocked_plan_without_prompting() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "Not Portable",
        "# Native only",
    );
    let observation = fixture.scan_observation("claude", "Not Portable");
    let before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();

    let blocked = fixture.adopt(&observation, None);
    assert_eq!(blocked.status.code(), Some(1));
    assert_eq!(json(&blocked)["phase"], "blocked");
    assert_eq!(json(&blocked)["reason"], "portable_projection_unavailable");
    assert!(!stderr(&blocked).contains("Confirm adoption"));
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        before
    );
    assert!(!fixture.environment.join("objects").exists());
}

#[test]
fn source_change_while_confirmation_is_pending_is_rejected_as_stale() {
    let fixture = Fixture::new();
    let skill = fixture.skill(&fixture.home.join(".claude/skills"), "stale", "# Before");
    let observation = fixture.scan_observation("claude", "stale");
    let before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();

    let mut command = fixture.command();
    command
        .args([
            "adopt",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
            &observation,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut error_stream = child.stderr.take().unwrap();
    let mut error_bytes = Vec::new();
    read_until_prompt(
        &mut error_stream,
        &mut error_bytes,
        b"Confirm adoption by typing 'yes': ",
    );

    fs::write(
        skill.join("SKILL.md"),
        "---\nname: stale\ndescription: A portable command fixture.\n---\n# After\n",
    )
    .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    error_stream.read_to_end(&mut error_bytes).unwrap();
    let mut output_bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut output_bytes)
        .unwrap();
    let status = child.wait().unwrap();

    assert_eq!(status.code(), Some(1));
    assert!(String::from_utf8_lossy(&error_bytes).contains("error[adoption.observation_stale]"));
    assert!(output_bytes.is_empty());
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        before
    );
}

#[test]
fn explicit_multi_asset_multi_target_apply_commits_each_selected_item() {
    let fixture = Fixture::new();
    for id in ["batch-one", "batch-two"] {
        fixture.skill(&fixture.home.join(".claude/skills"), id, "# Batch fixture");
        let observation = fixture.scan_observation("claude", id);
        let adopted = fixture.adopt(&observation, None);
        assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    }
    fixture.initialize_local_state();

    let selection = [
        "--asset",
        "batch-one",
        "--asset",
        "batch-two",
        "--target",
        "codex",
        "--target",
        "opencode",
        "--scope",
        "user",
        "--environment",
        fixture.environment.to_str().unwrap(),
        "--json",
    ];
    let planned = fixture
        .command()
        .arg("plan")
        .args(selection)
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let plan = json(&planned);
    assert_eq!(plan["operation"], "apply_batch");
    assert_eq!(plan["semantics"], "atomic");
    assert_eq!(plan["items"].as_array().unwrap().len(), 4);

    let mut command = fixture.command();
    command
        .arg("apply")
        .args(selection)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["items"].as_array().unwrap().len(), 4);

    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 4);
    for id in ["batch-one", "batch-two"] {
        assert!(fixture.home.join(".agents/skills").join(id).exists());
        assert!(
            fixture
                .home
                .join(".config/opencode/skills")
                .join(id)
                .exists()
        );
    }
}

#[test]
fn adopted_instruction_plan_and_apply_coalesce_shared_project_document() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "batch-skill",
        "# Batch skill",
    );
    let skill_observation = fixture.scan_observation("claude", "batch-skill");
    let adopted_skill = fixture.adopt(&skill_observation, None);
    assert_eq!(
        adopted_skill.status.code(),
        Some(0),
        "{}",
        stderr(&adopted_skill)
    );
    let source = fixture.home.join("instruction-source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("AGENTS.md"),
        concat!(
            "<!-- kitrove:instruction review begin -->\n",
            "Review carefully.\n",
            "<!-- kitrove:instruction review end -->\n",
        ),
    )
    .unwrap();
    fixture.adopt_instruction_asset(&source, "review");
    let asset_id = AssetId::parse("review").unwrap();
    fixture.initialize_local_state();

    let selection = [
        "--asset",
        "review",
        "--asset",
        "batch-skill",
        "--target",
        "codex",
        "--target",
        "pi",
        "--scope",
        "project",
        "--project-root",
        fixture.working.to_str().unwrap(),
        "--environment",
        fixture.environment.to_str().unwrap(),
        "--json",
    ];
    let planned = fixture
        .command()
        .arg("plan")
        .args(selection)
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let plan = json(&planned);
    assert_eq!(plan["operation"], "apply_batch");
    assert_eq!(plan["items"].as_array().unwrap().len(), 3);
    let instruction = plan["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["operation"] == "apply_instruction_document")
        .unwrap();
    assert_eq!(
        instruction["regions"][0]["targets"],
        serde_json::json!(["codex", "pi"])
    );

    let mut command = fixture.command();
    command
        .arg("apply")
        .args(selection)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["participant_count"], 3);
    let installed = fs::read_to_string(fixture.working.join("AGENTS.md")).unwrap();
    assert_eq!(
        installed
            .matches("kitrove:instruction review begin")
            .count(),
        1
    );
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 3);
    let instruction_receipt = state
        .receipts
        .values()
        .find(|receipt| receipt.asset_id == asset_id)
        .unwrap();
    assert_eq!(instruction_receipt.consumers().count(), 2);
    assert!(fixture.working.join(".agents/skills/batch-skill").exists());
    assert!(fixture.working.join(".pi/skills/batch-skill").exists());

    let scan_project = || {
        fixture
            .command()
            .args([
                "scan",
                "--harness",
                "codex",
                "--harness",
                "pi",
                "--scope",
                "project",
                "--project-root",
            ])
            .arg(&fixture.working)
            .arg("--environment")
            .arg(&fixture.environment)
            .arg("--json")
            .output()
            .unwrap()
    };
    let scanned = scan_project();
    assert_eq!(scanned.status.code(), Some(3), "{}", stderr(&scanned));
    let scan = json(&scanned);
    let instructions = scan["instructions"].as_array().unwrap();
    assert_eq!(instructions.len(), 2);
    assert!(instructions.iter().all(|instruction| {
        instruction["asset_id"] == "review" && instruction["classification"] == "managed_unchanged"
    }));
    assert_eq!(instructions[0]["receipt_id"], instructions[1]["receipt_id"]);
    assert!(scan["entries"].as_array().unwrap().iter().all(|entry| {
        entry["normalized_destination"]
            .as_str()
            .is_none_or(|destination| !destination.ends_with("/AGENTS.md"))
    }));
    assert!(
        scan["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| { finding["code"] != "scan.receipt_invalid" })
    );

    let mut stale_state = state.clone();
    stale_state
        .receipts
        .values_mut()
        .find(|receipt| receipt.asset_id == asset_id)
        .unwrap()
        .environment_revision = kitrove_model::Revision::parse(format!(
        "manifest:{}",
        kitrove_model::ContentHash::digest(b"stale manifest authority")
    ))
    .unwrap();
    fs::write(
        fixture.state_home.join("state.json"),
        stale_state.to_json().unwrap(),
    )
    .unwrap();
    let stale_scan = scan_project();
    assert_eq!(stale_scan.status.code(), Some(3));
    let stale_report = json(&stale_scan);
    assert!(
        stale_report["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|instruction| instruction["classification"] == "unknown")
    );
    assert!(
        stale_report["instructions"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|instruction| instruction["findings"].as_array().unwrap())
            .any(|finding| finding["code"] == "instruction.receipt_manifest_stale")
    );

    fs::write(
        fixture.state_home.join("state.json"),
        state.to_json().unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.working.join("AGENTS.md"),
        format!("{installed}\nHuman-owned suffix.\n"),
    )
    .unwrap();
    let mut remove = fixture.command();
    remove
        .args([
            "remove",
            "--asset",
            "review",
            "--target",
            "codex",
            "--scope",
            "project",
            "--project-root",
        ])
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = remove.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let removed = child.wait_with_output().unwrap();
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    let result = json(&removed);
    assert_eq!(result["operation"], "remove_instruction");
    assert_eq!(result["phase"], "complete");
    let document = fs::read_to_string(fixture.working.join("AGENTS.md")).unwrap();
    assert!(!document.contains("kitrove:instruction review"));
    assert!(document.ends_with("Human-owned suffix.\n"));
    let removed_state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(removed_state.receipts.len(), 2);
    assert!(
        EnvironmentManifest::from_toml(
            &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
        )
        .unwrap()
        .assets
        .contains_key(&asset_id)
    );
}

#[test]
fn scan_and_adopt_manage_a_project_instruction_region_through_the_cli() {
    let fixture = Fixture::new();
    fs::write(
        fixture.working.join("AGENTS.md"),
        concat!(
            "Human-owned preface.\n\n",
            "<!-- kitrove:instruction review begin -->\n",
            "Review carefully.\n",
            "<!-- kitrove:instruction review end -->\n",
        ),
    )
    .unwrap();

    let scan = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "codex",
            "--scope",
            "project",
            "--project-root",
        ])
        .arg(&fixture.working)
        .args(["--environment"])
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(3), "{}", stderr(&scan));
    let report = json(&scan);
    let instruction = &report["instructions"][0];
    assert_eq!(instruction["harness"], "codex");
    assert_eq!(instruction["scope"], "project");
    assert_eq!(instruction["asset_id"], "review");
    assert_eq!(instruction["classification"], "unmanaged");
    let revision = instruction["observation_revision"].as_str().unwrap();

    let mut command = fixture.command();
    command
        .arg("adopt")
        .arg(revision)
        .args(["--harness", "codex", "--scope", "project", "--project-root"])
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let adopted = child.wait_with_output().unwrap();
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    let result = json(&adopted);
    assert_eq!(result["operation"], "adopt_instruction");
    assert_eq!(result["phase"], "complete");
    assert_eq!(result["asset_id"], "review");

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset = &manifest.assets[&AssetId::parse("review").unwrap()];
    assert_eq!(asset.kind, kitrove_model::AssetKind::Instruction);
    assert!(asset.portable.is_some());
    assert!(asset.native_variants.contains_key(&HarnessId::Codex));
}

#[test]
fn managed_instruction_update_rebases_receipt_and_preserves_human_text() {
    let fixture = Fixture::new();
    let document = fixture.working.join("AGENTS.md");
    owned_fixture::create(
        &document,
        concat!(
            "Human-owned preface.\n\n",
            "<!-- kitrove:instruction review begin -->\n",
            "Review carefully.\n",
            "<!-- kitrove:instruction review end -->\n",
            "\nHuman-owned suffix.\n",
        )
        .as_bytes(),
    );
    let selection = ["--harness", "codex", "--scope", "project", "--project-root"];
    let initial_scan = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "codex",
            "--scope",
            "project",
            "--project-root",
        ])
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();
    let initial = json(&initial_scan);
    let initial_revision = initial["instructions"][0]["observation_revision"]
        .as_str()
        .unwrap();

    let mut adopt = fixture.command();
    adopt
        .arg("adopt")
        .arg(initial_revision)
        .args(selection)
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = adopt.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let adopted = child.wait_with_output().unwrap();
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();
    fs::write(&document, "Human-owned preface.\n\nHuman-owned suffix.\n").unwrap();

    let apply_selection = [
        "--asset",
        "review",
        "--target",
        "codex",
        "--scope",
        "project",
        "--project-root",
    ];
    let mut apply = fixture.command();
    apply
        .arg("apply")
        .args(apply_selection)
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = apply.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let prior_manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = AssetId::parse("review").unwrap();
    let prior = prior_manifest.assets[&asset_id].content_hash.clone();
    fs::write(
        &document,
        concat!(
            "Human-owned preface.\n\n",
            "<!-- kitrove:instruction review begin -->\n",
            "Review more carefully after local approval.\n",
            "<!-- kitrove:instruction review end -->\n",
            "\nHuman-owned suffix.\n",
        ),
    )
    .unwrap();
    let modified = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "codex",
            "--scope",
            "project",
            "--project-root",
        ])
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();
    let modified_report = json(&modified);
    assert_eq!(
        modified_report["instructions"][0]["classification"],
        "managed_modified"
    );
    let revision = modified_report["instructions"][0]["observation_revision"]
        .as_str()
        .unwrap();
    let updated = fixture.update_with_selection(
        revision,
        "review",
        prior.as_str(),
        &[
            "--harness",
            "codex",
            "--scope",
            "project",
            "--project-root",
            fixture.working.to_str().unwrap(),
        ],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["operation"], "update_instruction");
    assert_eq!(json(&updated)["outcome"], "committed_with_receipt");
    let installed = fs::read_to_string(&document).unwrap();
    assert!(installed.starts_with("Human-owned preface."));
    assert!(installed.ends_with("Human-owned suffix.\n"));

    let current = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    let receipt = state
        .receipts
        .values()
        .find(|receipt| receipt.asset_id == asset_id)
        .unwrap();
    assert_eq!(receipt.source_hash, current.assets[&asset_id].content_hash);

    let rescanned = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "codex",
            "--scope",
            "project",
            "--project-root",
        ])
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(
        json(&rescanned)["instructions"][0]["classification"],
        "managed_unchanged"
    );
}

#[test]
fn malformed_instruction_regions_are_reported_without_losing_the_scan() {
    let fixture = Fixture::new();
    fs::write(
        fixture.working.join("AGENTS.md"),
        "<!-- kitrove:instruction malformed -->\n",
    )
    .unwrap();

    let scan = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "codex",
            "--scope",
            "project",
            "--project-root",
        ])
        .arg(&fixture.working)
        .arg("--environment")
        .arg(&fixture.environment)
        .arg("--json")
        .output()
        .unwrap();

    assert_eq!(scan.status.code(), Some(3), "{}", stderr(&scan));
    let report = json(&scan);
    assert!(report["instructions"].as_array().unwrap().is_empty());
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["code"] == "instruction.document_invalid"
                    && finding["subject"]["harness"] == "codex"
            })
    );
}

#[test]
fn profile_apply_resolves_portable_selection_and_commits_active_profile_atomically() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "profile-review",
        "# Profile review fixture",
    );
    let observation = fixture.scan_observation("claude", "profile-review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();

    let mut manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let profile_id = ProfileId::parse("workstation").unwrap();
    manifest.profiles.insert(
        profile_id.clone(),
        Profile {
            id: profile_id.clone(),
            extends: None,
            assets: BTreeSet::from([AssetId::parse("profile-review").unwrap()]),
            targets: BTreeSet::from([HarnessId::Codex]),
        },
    );
    fs::write(
        fixture.environment.join("kitrove.toml"),
        manifest.to_toml().unwrap(),
    )
    .unwrap();

    let mut command = fixture.command();
    command
        .args([
            "apply",
            "--profile",
            "workstation",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["outcome"], "committed");
    assert_eq!(json(&applied)["active_profile"], "workstation");
    assert!(fixture.home.join(".agents/skills/profile-review").exists());
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.machine.active_profile, Some(profile_id));
    assert_eq!(state.receipts.len(), 1);
}

#[test]
fn pack_apply_expands_nested_leaf_assets_into_one_atomic_batch() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();

    let planned = fixture
        .command()
        .args([
            "plan",
            "--pack",
            "outer-pack",
            "--target",
            "codex",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    assert_eq!(json(&planned)["selected_packs"][0]["pack_id"], "outer-pack");
    assert!(
        json(&planned)["selected_packs"][0]["revision"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );

    let mut command = fixture.command();
    command
        .args([
            "apply",
            "--pack",
            "outer-pack",
            "--target",
            "codex",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();

    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["outcome"], "committed");
    assert_eq!(json(&applied)["active_profile"], Value::Null);
    assert!(fixture.home.join(".agents/skills/pack-alpha").exists());
    assert!(fixture.home.join(".agents/skills/pack-beta").exists());
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 2);
    assert_eq!(state.pack_applications.len(), 1);
    let (application_id, claim) = state.pack_applications.iter().next().unwrap();
    assert_eq!(claim.pack_id.as_str(), "outer-pack");
    assert_eq!(
        claim.pack_revision,
        manifest_pack_revision(&fixture, "outer-pack")
    );
    assert_eq!(claim.targets, BTreeSet::from([HarnessId::Codex]));
    assert_eq!(claim.receipts, state.receipts.keys().cloned().collect());
    assert_eq!(&claim.application_id().unwrap(), application_id);
}

#[test]
fn direct_apply_takes_retention_precedence_over_an_existing_pack_claim() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    assert_eq!(
        fixture
            .confirmed_apply(&["--pack", "outer-pack", "--target", "codex"])
            .status
            .code(),
        Some(0)
    );

    let direct = fixture.confirmed_apply(&["--asset", "pack-alpha", "--target", "codex"]);
    assert_eq!(direct.status.code(), Some(0), "{}", stderr(&direct));
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    let claim = state.pack_applications.values().next().unwrap();
    assert_eq!(claim.receipts.len(), 1);
    let retained = &state.receipts[claim.receipts.first().unwrap()];
    assert_eq!(retained.asset_id.as_str(), "pack-beta");
    assert!(
        state
            .receipts
            .values()
            .any(|receipt| receipt.asset_id.as_str() == "pack-alpha")
    );
}

#[test]
fn pack_apply_does_not_claim_a_preexisting_direct_receipt() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let direct = fixture.confirmed_apply(&["--asset", "pack-alpha", "--target", "codex"]);
    assert_eq!(direct.status.code(), Some(0), "{}", stderr(&direct));
    let packed = fixture.confirmed_apply(&["--pack", "outer-pack", "--target", "codex"]);
    assert_eq!(packed.status.code(), Some(0), "{}", stderr(&packed));

    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    let claim = state.pack_applications.values().next().unwrap();
    assert_eq!(claim.receipts.len(), 1);
    assert_eq!(
        state.receipts[claim.receipts.first().unwrap()]
            .asset_id
            .as_str(),
        "pack-beta"
    );
}

#[test]
fn overlapping_selected_packs_share_exact_receipt_ownership() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let applied = fixture.confirmed_apply(&[
        "--pack",
        "inner-pack",
        "--pack",
        "outer-pack",
        "--target",
        "codex",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.pack_applications.len(), 2);
    for claim in state.pack_applications.values() {
        assert_eq!(claim.receipts, state.receipts.keys().cloned().collect());
    }
}

#[test]
fn pack_application_claims_cover_multiple_targets() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let applied = fixture.confirmed_apply(&[
        "--pack",
        "outer-pack",
        "--target",
        "codex",
        "--target",
        "pi",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 4);
    assert_eq!(state.pack_applications.len(), 1);
    for claim in state.pack_applications.values() {
        assert_eq!(
            claim.targets,
            BTreeSet::from([HarnessId::Codex, HarnessId::Pi])
        );
        assert_eq!(claim.receipts.len(), 4);
        assert!(claim.receipts.iter().all(|receipt_id| {
            claim
                .target_anchor
                .is_ancestor_of(&state.receipts[receipt_id].destination)
        }));
    }
}

#[test]
fn pack_remove_deletes_exclusively_owned_skills_and_retains_portable_authority() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let revision = manifest_pack_revision(&fixture, "outer-pack");
    let applied = fixture.confirmed_apply(&["--pack", "outer-pack", "--target", "codex"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let removed = fixture.confirmed_pack_remove("outer-pack", &revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert_eq!(json(&removed)["operation"], "pack_remove");
    assert_eq!(json(&removed)["outcome"], "committed");
    assert!(!fixture.home.join(".agents/skills/pack-alpha").exists());
    assert!(!fixture.home.join(".agents/skills/pack-beta").exists());
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
    assert!(
        EnvironmentManifest::from_toml(
            &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap()
        )
        .unwrap()
        .packs
        .contains_key(&AssetId::parse("outer-pack").unwrap())
    );
}

#[test]
fn pack_remove_retains_receipts_owned_by_an_overlapping_pack() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let outer_revision = manifest_pack_revision(&fixture, "outer-pack");
    let inner_revision = manifest_pack_revision(&fixture, "inner-pack");
    let applied = fixture.confirmed_apply(&[
        "--pack",
        "inner-pack",
        "--pack",
        "outer-pack",
        "--target",
        "codex",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let outer_removed = fixture.confirmed_pack_remove("outer-pack", &outer_revision);
    assert_eq!(
        outer_removed.status.code(),
        Some(0),
        "{}",
        stderr(&outer_removed)
    );
    assert!(fixture.home.join(".agents/skills/pack-alpha").exists());
    assert!(fixture.home.join(".agents/skills/pack-beta").exists());
    let retained_state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(retained_state.receipts.len(), 2);
    assert_eq!(retained_state.pack_applications.len(), 1);
    assert_eq!(
        retained_state
            .pack_applications
            .values()
            .next()
            .unwrap()
            .pack_id
            .as_str(),
        "inner-pack"
    );

    let inner_removed = fixture.confirmed_pack_remove("inner-pack", &inner_revision);
    assert_eq!(
        inner_removed.status.code(),
        Some(0),
        "{}",
        stderr(&inner_removed)
    );
    assert!(!fixture.home.join(".agents/skills/pack-alpha").exists());
    assert!(!fixture.home.join(".agents/skills/pack-beta").exists());
}

#[test]
fn pack_remove_uses_historical_claim_revision_after_portable_pack_update() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let applied_revision = manifest_pack_revision(&fixture, "outer-pack");
    let applied = fixture.confirmed_apply(&["--pack", "outer-pack", "--target", "codex"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let mut manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let outer = AssetId::parse("outer-pack").unwrap();
    let alpha = AssetId::parse("pack-alpha").unwrap();
    manifest.packs.get_mut(&outer).unwrap().members =
        BTreeMap::from([(alpha.clone(), manifest.assets[&alpha].content_hash.clone())]);
    manifest.refresh_pack_revisions().unwrap();
    fs::write(
        fixture.environment.join("kitrove.toml"),
        manifest.to_toml().unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.environment.join("kitrove.lock.json"),
        derive_lockfile(&manifest).unwrap().to_json().unwrap(),
    )
    .unwrap();
    assert_ne!(
        manifest_pack_revision(&fixture, "outer-pack"),
        applied_revision
    );

    let removed = fixture.confirmed_pack_remove("outer-pack", &applied_revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!fixture.home.join(".agents/skills/pack-alpha").exists());
    assert!(!fixture.home.join(".agents/skills/pack-beta").exists());
}

#[test]
fn unconfirmed_pack_remove_is_byte_for_byte_nonmutating() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let revision = manifest_pack_revision(&fixture, "outer-pack");
    let applied = fixture.confirmed_apply(&["--pack", "outer-pack", "--target", "codex"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let state_before = fs::read(fixture.state_home.join("state.json")).unwrap();
    let alpha_before = fs::read(fixture.home.join(".agents/skills/pack-alpha/SKILL.md")).unwrap();

    let declined = fixture
        .command()
        .args([
            "pack",
            "remove",
            "--pack",
            "outer-pack",
            "--expected-prior",
            revision.as_str(),
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(declined.status.code(), Some(1));
    assert_eq!(
        fs::read(fixture.state_home.join("state.json")).unwrap(),
        state_before
    );
    assert_eq!(
        fs::read(fixture.home.join(".agents/skills/pack-alpha/SKILL.md")).unwrap(),
        alpha_before
    );
}

#[test]
fn pack_remove_refuses_a_modified_skill_without_releasing_claims() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();
    let revision = manifest_pack_revision(&fixture, "outer-pack");
    let applied = fixture.confirmed_apply(&["--pack", "outer-pack", "--target", "codex"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let destination = fixture.home.join(".agents/skills/pack-alpha/SKILL.md");
    fs::write(&destination, "locally modified\n").unwrap();
    let state_before = fs::read(fixture.state_home.join("state.json")).unwrap();

    let refused = fixture.confirmed_pack_remove("outer-pack", &revision);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        fs::read_to_string(destination).unwrap(),
        "locally modified\n"
    );
    assert_eq!(
        fs::read(fixture.state_home.join("state.json")).unwrap(),
        state_before
    );
}

#[test]
fn pack_remove_deletes_an_exclusively_owned_prompt_command() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude/commands/review.md"),
        "Review $ARGUMENTS carefully.\n",
    )
    .unwrap();
    let observation = fixture.scan_prompt_command_observation("claude", "review");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();

    let mut manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = AssetId::parse("review").unwrap();
    let pack_id = AssetId::parse("command-pack").unwrap();
    manifest.packs.insert(
        pack_id.clone(),
        Pack {
            id: pack_id.clone(),
            source: Source::Local {
                path: PortablePath::parse("packs/command-pack").unwrap(),
            },
            revision: Revision::parse("local:command-pack").unwrap(),
            exact_source_hash: ContentHash::digest(b"command-pack-source"),
            content_hash: ContentHash::digest(b"pending-command-pack"),
            members: BTreeMap::from([(
                asset_id.clone(),
                manifest.assets[&asset_id].content_hash.clone(),
            )]),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        },
    );
    manifest.refresh_pack_revisions().unwrap();
    fs::write(
        fixture.environment.join("kitrove.toml"),
        manifest.to_toml().unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.environment.join("kitrove.lock.json"),
        derive_lockfile(&manifest).unwrap().to_json().unwrap(),
    )
    .unwrap();
    let revision = manifest.packs[&pack_id].content_hash.clone();

    let applied = fixture.confirmed_apply(&["--pack", "command-pack", "--target", "pi"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let destination = fixture.home.join(".pi/agent/prompts/review.md");
    assert!(destination.exists());
    let removed = fixture.confirmed_pack_remove("command-pack", &revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!destination.exists());
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
}

#[test]
fn pack_remove_deletes_an_exclusively_owned_instruction_region() {
    let fixture = Fixture::new();
    let source = fixture.home.join("instruction-pack-source");
    fs::create_dir(&source).unwrap();
    fs::write(
        source.join("AGENTS.md"),
        concat!(
            "<!-- kitrove:instruction packed-review begin -->\n",
            "Review packed changes carefully.\n",
            "<!-- kitrove:instruction packed-review end -->\n",
        ),
    )
    .unwrap();
    fixture.adopt_instruction_asset(&source, "packed-review");
    fixture.initialize_local_state();
    let revision = fixture.install_pack("instruction-pack", &["packed-review"]);
    let project_root = fixture.working.to_str().unwrap();

    let applied = fixture.confirmed_apply(&[
        "--pack",
        "instruction-pack",
        "--target",
        "codex",
        "--scope",
        "project",
        "--project-root",
        project_root,
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let destination = fixture.working.join("AGENTS.md");
    assert!(
        fs::read_to_string(&destination)
            .unwrap()
            .contains("kitrove:instruction packed-review")
    );

    let removed = fixture.confirmed_pack_remove("instruction-pack", &revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(
        !destination.exists()
            || !fs::read_to_string(destination)
                .unwrap()
                .contains("kitrove:instruction packed-review")
    );
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
}

#[test]
fn pack_remove_deletes_an_exclusively_owned_mcp_entry() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude.json"),
        r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${NATIVE_MCP_SECRET}"}}}}"#,
    )
    .unwrap();
    let observation = fixture.scan_mcp_observation("claude", "docs");
    let adopted =
        fixture.adopt_with_selection(&observation, None, &["--binding", "company_mcp_token"]);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();
    let state_path = fixture.state_home.join("state.json");
    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state.bindings.insert(
        BindingName::parse("company_mcp_token").unwrap(),
        BindingResolver::Environment {
            variable: EnvironmentVariableName::parse("COMPANY_MCP_TOKEN").unwrap(),
        },
    );
    fs::write(&state_path, state.to_json().unwrap()).unwrap();
    let revision = fixture.install_pack("mcp-pack", &["docs"]);

    let applied = fixture.confirmed_apply(&["--pack", "mcp-pack", "--target", "codex"]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let destination = fixture.home.join(".codex/config.toml");
    assert!(fs::read_to_string(&destination).unwrap().contains("docs"));

    let removed = fixture.confirmed_pack_remove("mcp-pack", &revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!fs::read_to_string(destination).unwrap().contains("docs"));
    let state = LocalState::from_json(&fs::read_to_string(state_path).unwrap()).unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
}

#[test]
fn pack_remove_coalesces_retained_and_removed_instruction_regions() {
    let fixture = Fixture::new();
    for id in ["keep-review", "drop-review"] {
        let source = fixture.home.join(format!("{id}-source"));
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("AGENTS.md"),
            format!(
                "<!-- kitrove:instruction {id} begin -->\n{id} body.\n<!-- kitrove:instruction {id} end -->\n"
            ),
        )
        .unwrap();
        fixture.adopt_instruction_asset(&source, id);
    }
    fixture.initialize_local_state();
    let inner_revision = fixture.install_pack("instruction-inner", &["keep-review"]);
    let outer_revision = fixture.install_pack("instruction-outer", &["keep-review", "drop-review"]);
    let project_root = fixture.working.to_str().unwrap();
    let applied = fixture.confirmed_apply(&[
        "--pack",
        "instruction-inner",
        "--pack",
        "instruction-outer",
        "--target",
        "codex",
        "--scope",
        "project",
        "--project-root",
        project_root,
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let state_path = fixture.state_home.join("state.json");
    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state.machine.active_profile = Some(ProfileId::parse("workstation").unwrap());
    fs::write(&state_path, state.to_json().unwrap()).unwrap();

    let removed = fixture.confirmed_pack_remove("instruction-outer", &outer_revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    let document = fs::read_to_string(fixture.working.join("AGENTS.md")).unwrap();
    assert!(document.contains("kitrove:instruction keep-review"));
    assert!(!document.contains("kitrove:instruction drop-review"));
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.pack_applications.len(), 1);
    assert_eq!(
        state.machine.active_profile,
        Some(ProfileId::parse("workstation").unwrap())
    );

    let removed = fixture.confirmed_pack_remove("instruction-inner", &inner_revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(
        !fs::read_to_string(fixture.working.join("AGENTS.md"))
            .unwrap_or_default()
            .contains("kitrove:instruction keep-review")
    );
}

#[test]
fn pack_remove_coalesces_retained_and_removed_mcp_entries() {
    let fixture = Fixture::new();
    fs::write(
        fixture.home.join(".claude.json"),
        r#"{"mcpServers":{"docs":{"type":"http","url":"https://docs.example.com/mcp"},"search":{"type":"http","url":"https://search.example.com/mcp"}}}"#,
    )
    .unwrap();
    for id in ["docs", "search"] {
        let observation = fixture.scan_mcp_observation("claude", id);
        let adopted = fixture.adopt(&observation, None);
        assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    }
    fixture.initialize_local_state();
    let inner_revision = fixture.install_pack("mcp-inner", &["docs"]);
    let outer_revision = fixture.install_pack("mcp-outer", &["docs", "search"]);
    let applied = fixture.confirmed_apply(&[
        "--pack",
        "mcp-inner",
        "--pack",
        "mcp-outer",
        "--target",
        "codex",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));

    let removed = fixture.confirmed_pack_remove("mcp-outer", &outer_revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    let destination = fixture.home.join(".codex/config.toml");
    let document = fs::read_to_string(&destination).unwrap();
    assert!(document.contains("docs"));
    assert!(!document.contains("search"));
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.pack_applications.len(), 1);

    let removed = fixture.confirmed_pack_remove("mcp-inner", &inner_revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!fs::read_to_string(destination).unwrap().contains("docs"));
}

#[cfg(unix)]
#[test]
fn pack_remove_deletes_an_exact_extension_claim_after_trust_revocation() {
    let fixture = Fixture::new();
    let extension_root = fixture.home.join(".pi/agent/extensions");
    fs::create_dir_all(&extension_root).unwrap();
    let source = extension_root.join("review.ts");
    fs::write(&source, "export const review = true;\n").unwrap();
    fs::write(
        fixture.environment.join("kitrove.toml"),
        EnvironmentManifest::from_toml(EMPTY_MANIFEST)
            .unwrap()
            .to_toml()
            .unwrap(),
    )
    .unwrap();
    let lock = fixture
        .command()
        .args([
            "lock",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(lock.status.code(), Some(0), "{}", stderr(&lock));
    let observation = scan_extension_observation(&fixture, "review");
    let adopted = fixture.adopt(&observation, Some("review-extension"));
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fs::remove_file(&source).unwrap();
    fixture.initialize_local_state();
    let revision = fixture.install_pack("extension-pack", &["review-extension"]);
    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = AssetId::parse("review-extension").unwrap();
    let object = load_native_extension_object(
        &manifest,
        &asset_id,
        &HarnessId::Pi,
        &fixture.environment,
        CaptureLimits::default(),
    )
    .unwrap();
    let state_path = fixture.state_home.join("state.json");
    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state.trust.insert(
        object.hash().clone(),
        TrustDecision::Trusted {
            rationale: "test installation".to_owned(),
        },
    );
    fs::write(&state_path, state.to_json().unwrap()).unwrap();
    let version_root = tempfile::tempdir().unwrap();
    let binary = version_root.path().join("pi");
    fs::write(&binary, "#!/bin/sh\nprintf '0.83.0\\n'\n").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let version = probe_pi_version(&binary).unwrap();
    let policy = PiAdapter
        .extension_target_policy(
            HarnessScope::User,
            VersionObservation::Verified(version.evidence()),
        )
        .unwrap();
    let plan = plan_extension_apply(
        &manifest,
        &asset_id,
        &object,
        &policy,
        ExtensionApplyAuthority::new(&fixture.home, &version, None),
        &fs::read_to_string(&state_path).unwrap(),
        observe_extension_destination(&source, &object, CaptureLimits::default()),
    )
    .unwrap();
    let batch = AtomicApplyBatchPlan::new(vec![AtomicApplyItem::Extension(plan)], None).unwrap();
    commit_atomic_apply_batch(
        &batch,
        &fixture.environment,
        &fixture.state_home,
        CaptureLimits::default(),
    )
    .unwrap();
    assert!(source.exists());

    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    let receipt_id = state.receipts.keys().next().unwrap().clone();
    let claim = PackApplicationClaim {
        pack_id: AssetId::parse("extension-pack").unwrap(),
        pack_revision: revision.clone(),
        scope: HarnessScope::User,
        target_anchor: NormalizedDestination::parse(fixture.home.display().to_string()).unwrap(),
        targets: BTreeSet::from([HarnessId::Pi]),
        receipts: BTreeSet::from([receipt_id]),
    };
    let application_id = claim.application_id().unwrap();
    state.pack_applications.insert(application_id, claim);
    state.trust.insert(
        object.hash().clone(),
        TrustDecision::Denied {
            rationale: "revoked after installation".to_owned(),
        },
    );
    fs::write(&state_path, state.to_json().unwrap()).unwrap();

    let removed = fixture.confirmed_pack_remove("extension-pack", &revision);
    assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
    assert!(!source.exists());
    let state = LocalState::from_json(&fs::read_to_string(state_path).unwrap()).unwrap();
    assert!(state.receipts.is_empty());
    assert!(state.pack_applications.is_empty());
    assert!(matches!(
        state.trust.get(object.hash()),
        Some(TrustDecision::Denied { .. })
    ));
}

#[cfg(unix)]
#[test]
fn verified_pi_and_saved_project_trust_unlock_project_extension_apply() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let extension_root = fixture.home.join(".pi/agent/extensions");
    fs::create_dir_all(&extension_root).unwrap();
    let source = extension_root.join("review.ts");
    fs::write(&source, "export const review = true;\n").unwrap();
    fs::write(
        fixture.environment.join("kitrove.toml"),
        EnvironmentManifest::from_toml(EMPTY_MANIFEST)
            .unwrap()
            .to_toml()
            .unwrap(),
    )
    .unwrap();
    let lock = fixture
        .command()
        .args([
            "lock",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(lock.status.code(), Some(0), "{}", stderr(&lock));
    let observation = scan_extension_observation(&fixture, "review");
    let adopted = fixture.adopt(&observation, Some("review-extension"));
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fs::remove_file(&source).unwrap();
    fixture.initialize_local_state();

    let manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = AssetId::parse("review-extension").unwrap();
    let object = load_native_extension_object(
        &manifest,
        &asset_id,
        &HarnessId::Pi,
        &fixture.environment,
        CaptureLimits::default(),
    )
    .unwrap();
    let state_path = fixture.state_home.join("state.json");
    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state.trust.insert(
        object.hash().clone(),
        TrustDecision::Trusted {
            rationale: "test project installation".to_owned(),
        },
    );
    fs::write(&state_path, state.to_json().unwrap()).unwrap();

    let trust_store = fixture.home.join(".pi/agent/trust.json");
    fs::write(
        &trust_store,
        format!("{{\"{}\":true}}\n", fixture.working.display()),
    )
    .unwrap();
    fs::set_permissions(&trust_store, fs::Permissions::from_mode(0o600)).unwrap();
    let binary_root = fixture.home.join("bin");
    fs::create_dir(&binary_root).unwrap();
    let pi = binary_root.join("pi");
    fs::write(&pi, "#!/bin/sh\nprintf '0.83.0\\n'\n").unwrap();
    fs::set_permissions(&pi, fs::Permissions::from_mode(0o700)).unwrap();

    let applied = fixture.confirmed_apply(&[
        "--asset",
        "review-extension",
        "--target",
        "pi",
        "--scope",
        "project",
        "--project-root",
        fixture.working.to_str().unwrap(),
        "--version-binary",
        pi.to_str().unwrap(),
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let destination = fixture.working.join(".pi/extensions/review.ts");
    assert_eq!(
        fs::read_to_string(destination).unwrap(),
        "export const review = true;\n"
    );
    let state = LocalState::from_json(&fs::read_to_string(state_path).unwrap()).unwrap();
    let receipt = state.receipts.values().next().unwrap();
    assert_eq!(receipt.scope, HarnessScope::Project);
}

fn manifest_pack_revision(fixture: &Fixture, pack_id: &str) -> ContentHash {
    EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap()
    .packs[&AssetId::parse(pack_id).unwrap()]
        .content_hash
        .clone()
}

#[test]
fn pack_apply_rejects_aggregate_revision_change_while_confirmation_is_pending() {
    let fixture = Fixture::new();
    fixture.initialize_nested_pack_assets();

    let mut command = fixture.command();
    command
        .args([
            "apply",
            "--pack",
            "outer-pack",
            "--target",
            "codex",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut error_stream = child.stderr.take().unwrap();
    let mut error_bytes = Vec::new();
    read_until_prompt(
        &mut error_stream,
        &mut error_bytes,
        b"Confirm apply by typing 'yes': ",
    );

    let manifest_path = fixture.environment.join("kitrove.toml");
    let mut manifest =
        EnvironmentManifest::from_toml(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest
        .packs
        .get_mut(&AssetId::parse("outer-pack").unwrap())
        .unwrap()
        .exact_source_hash = ContentHash::digest(b"changed-after-confirmation");
    manifest.refresh_pack_revisions().unwrap();
    fs::write(&manifest_path, manifest.to_toml().unwrap()).unwrap();

    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    error_stream.read_to_end(&mut error_bytes).unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&error_bytes).contains("error[apply.plan_stale]"));
    assert!(!fixture.home.join(".agents/skills/pack-alpha").exists());
    assert!(!fixture.home.join(".agents/skills/pack-beta").exists());
}

#[test]
fn ad_hoc_apply_preserves_the_active_profile() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "profile-preservation",
        "# Profile preservation fixture",
    );
    let observation = fixture.scan_observation("claude", "profile-preservation");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();

    let profile_id = ProfileId::parse("already-active").unwrap();
    let state_path = fixture.state_home.join("state.json");
    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state.machine.active_profile = Some(profile_id.clone());
    fs::write(&state_path, state.to_json().unwrap()).unwrap();

    let applied = fixture.apply("codex");
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    assert_eq!(json(&applied)["active_profile"], "already-active");
    let state = LocalState::from_json(&fs::read_to_string(state_path).unwrap()).unwrap();
    assert_eq!(state.machine.active_profile, Some(profile_id));
}

#[test]
fn atomic_batch_json_failure_has_no_committed_prefix() {
    let fixture = Fixture::new();
    fixture.initialize_colliding_batch();

    let output = fixture.apply_colliding_batch(true);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = stderr(&output);
    assert!(error.contains("error[apply.batch_destination_duplicate]"));
    assert!(!error.contains(fixture.home.to_str().unwrap()));

    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());
}

#[test]
fn atomic_batch_text_failure_is_nonmutating_and_redacted() {
    let fixture = Fixture::new();
    fixture.initialize_colliding_batch();

    let output = fixture.apply_colliding_batch(false);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let error = stderr(&output);
    assert!(error.contains("error[apply.batch_destination_duplicate]"));
    assert!(!error.contains(fixture.home.to_str().unwrap()));
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state_home.join("state.json")).unwrap())
            .unwrap();
    assert!(state.receipts.is_empty());
}

#[test]
fn apply_rejects_exact_local_state_change_while_confirmation_is_pending() {
    let fixture = Fixture::new();
    fixture.skill(
        &fixture.home.join(".claude/skills"),
        "apply-stale",
        "# Apply stale fixture",
    );
    let observation = fixture.scan_observation("claude", "apply-stale");
    let adopted = fixture.adopt(&observation, None);
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    fixture.initialize_local_state();

    let mut command = fixture.command();
    command
        .args([
            "apply",
            "--asset",
            "apply-stale",
            "--target",
            "codex",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut error_stream = child.stderr.take().unwrap();
    let mut error_bytes = Vec::new();
    read_until_prompt(
        &mut error_stream,
        &mut error_bytes,
        b"Confirm apply by typing 'yes': ",
    );

    let state_path = fixture.state_home.join("state.json");
    let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    state.machine.id = MachineId::parse("changed-during-confirmation").unwrap();
    fs::write(&state_path, state.to_json().unwrap()).unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    error_stream.read_to_end(&mut error_bytes).unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&error_bytes).contains("error[apply.plan_stale]"));
    assert!(!fixture.home.join(".agents/skills/apply-stale").exists());
}

#[test]
fn pi_extension_cli_adoption_and_exact_prior_update_preserve_the_full_catalog() {
    let fixture = Fixture::new();
    let extension_root = fixture.home.join(".pi/agent/extensions");
    fs::create_dir_all(&extension_root).unwrap();
    let extension = extension_root.join("review.ts");
    fs::write(&extension, "export const review = 'first';\n").unwrap();
    fs::write(
        fixture.environment.join("kitrove.toml"),
        EnvironmentManifest::from_toml(EMPTY_MANIFEST)
            .unwrap()
            .to_toml()
            .unwrap(),
    )
    .unwrap();
    let lock = fixture
        .command()
        .args([
            "lock",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(lock.status.code(), Some(0), "{}", stderr(&lock));

    let first_observation = scan_extension_observation(&fixture, "review");
    let adopted = fixture.adopt(&first_observation, Some("review-extension"));
    assert_eq!(adopted.status.code(), Some(0), "{}", stderr(&adopted));
    assert_eq!(json(&adopted)["outcome"], "preserved_without_trust");

    let first_manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    let asset_id = AssetId::parse("review-extension").unwrap();
    let prior = first_manifest.assets[&asset_id].content_hash.to_string();
    assert_eq!(first_manifest.assets.len(), 1);

    fs::write(&extension, "export const review = 'second';\n").unwrap();
    let second_observation = scan_extension_observation(&fixture, "review");
    let updated = fixture.update_with_selection(
        &second_observation,
        "review-extension",
        &prior,
        &[],
        b"yes\n",
    );
    assert_eq!(updated.status.code(), Some(0), "{}", stderr(&updated));
    assert_eq!(json(&updated)["outcome"], "preserved_without_trust");

    let updated_manifest = EnvironmentManifest::from_toml(
        &fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(updated_manifest.assets.len(), 1);
    assert_ne!(
        updated_manifest.assets[&asset_id].content_hash.to_string(),
        prior
    );
    let object_root =
        &updated_manifest.assets[&asset_id].native_variants[&kitrove_model::HarnessId::Pi].root;
    assert!(fixture.environment.join(object_root.as_str()).exists());
}

fn scan_extension_observation(fixture: &Fixture, native_id: &str) -> String {
    let output = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        matches!(output.status.code(), Some(0 | 3)),
        "{}",
        stderr(&output)
    );
    let report = json(&output);
    report["native_extensions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["native_id"] == native_id)
        .and_then(|entry| entry["observation_identity"].as_str())
        .unwrap_or_else(|| panic!("missing extension {native_id}: {report}"))
        .to_owned()
}

#[test]
fn credential_canary_never_becomes_adoption_authority_or_output() {
    let fixture = Fixture::new();
    let skill = fixture.skill(
        &fixture.home.join(".claude/skills"),
        "credential-canary",
        "# Inert",
    );
    let canary = "KITROVE_C3_SECRET_CANARY_7e3a1d";
    fs::write(skill.join(".env"), format!("TOKEN={canary}\n")).unwrap();
    let before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();

    let scan = fixture
        .command()
        .args([
            "scan",
            "--harness",
            "claude",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(scan.status.code(), Some(3));
    assert!(!String::from_utf8_lossy(&scan.stdout).contains(canary));
    assert!(!stderr(&scan).contains(canary));
    let report = json(&scan);
    assert!(report.to_string().contains("skill.credential_artifact"));
    let display_id = report["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|entry| entry["observation_id"].as_str())
        .unwrap_or("display-only-failed-observation");

    let refused = fixture.adopt(display_id, None);
    assert_eq!(refused.status.code(), Some(1));
    assert!(stderr(&refused).contains("error[adoption.observation_unavailable]"));
    assert_eq!(
        fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        before
    );
    assert!(!fixture.environment.join("objects").exists());
}
