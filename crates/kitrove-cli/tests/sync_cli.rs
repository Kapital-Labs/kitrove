#![forbid(unsafe_code)]

#[path = "support/owned_fixture.rs"]
mod owned_fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kitrove_agent_skills::{
    CapturedFile, CapturedTree, FileMode, NativeSkillObject, SkillSourceLayout, StoredSkillTree,
    assess_native_skill_object_risk, assess_portable_tree_risk, hash_tree,
};
use kitrove_core::{PortableSnapshotV1, VerifiedObjectEnvelope, derive_lockfile};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, BindingResolver, ComponentProvenance, ContentClass,
    ContentHash, EnvironmentManifest, HarnessId, LocalState, MachineConfig, MachineId,
    NativeVariant, PortableContent, PortablePath, Profile, ProfileId, Revision, SchemaVersion,
    Source, SyncLimits,
};
use serde_json::Value;

struct Machine {
    environment: PathBuf,
    state: PathBuf,
    home: PathBuf,
    working: PathBuf,
    local_files: BTreeMap<PathBuf, Vec<u8>>,
    local_canaries: Vec<String>,
}

impl Machine {
    fn new(root: &Path, name: &str, snapshot: &PortableSnapshotV1, canary: &str) -> Self {
        let machine = root.join(name);
        let environment = machine.join("environment");
        let state = machine.join("state");
        let home = machine.join("home");
        let working = machine.join("working");
        for directory in [&environment, &home, &working] {
            fs::create_dir_all(directory).unwrap();
        }
        kitrove_testkit::initialize_empty_authority_fixture(
            &machine.join("state-bootstrap-environment"),
            &state,
            &empty_manifest(),
            &empty_local_state(name),
        )
        .unwrap();
        owned_fixture::create(
            &environment.join("kitrove.toml"),
            snapshot.manifest_toml().as_bytes(),
        );
        owned_fixture::create(
            &environment.join("kitrove.lock.json"),
            snapshot.lock_json().as_bytes(),
        );
        let local_specs = [
            (state.join("state.json"), "MACHINE-CONFIG"),
            (state.join("receipts.json"), "RECEIPT"),
            (state.join("trust.json"), "TRUST"),
            (state.join("bindings.json"), "BINDING"),
            (state.join("destinations.json"), "DESTINATION"),
            (state.join("scan-history.json"), "SCAN-HISTORY"),
        ];
        let mut local_files = BTreeMap::new();
        let mut local_canaries = Vec::new();
        for (path, category) in local_specs {
            let value = format!("{canary}-{category}");
            fs::write(&path, &value).unwrap();
            local_files.insert(path, value.as_bytes().to_vec());
            local_canaries.push(value);
        }
        Self {
            environment,
            state,
            home,
            working,
            local_files,
            local_canaries,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.working)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state)
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME");
        command
    }

    fn plan(&self, remote: &Path) -> Output {
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

    fn plan_human(&self, remote: &Path) -> Output {
        self.command()
            .args([
                "sync",
                "plan",
                "--filesystem",
                remote.to_str().unwrap(),
                "--environment",
                self.environment.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    }

    fn apply(&self, remote: &Path, digest: &str) -> Output {
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

    fn apply_human(&self, remote: &Path, digest: &str) -> Output {
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
            ])
            .output()
            .unwrap()
    }

    fn replace_snapshot(&self, snapshot: &PortableSnapshotV1) {
        fs::write(
            self.environment.join("kitrove.toml"),
            snapshot.manifest_toml(),
        )
        .unwrap();
        fs::write(
            self.environment.join("kitrove.lock.json"),
            snapshot.lock_json(),
        )
        .unwrap();
    }

    fn assert_local_files_unchanged(&self) {
        for (path, expected) in &self.local_files {
            assert_eq!(
                &fs::read(path).unwrap(),
                expected,
                "{} changed",
                path.display()
            );
        }
    }

    fn assert_canaries_absent(&self, bytes: &[u8]) {
        for canary in &self.local_canaries {
            assert!(
                !bytes
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "machine-local canary leaked"
            );
        }
    }

    fn initialize_apply_state(&self, machine_id: &str) {
        fs::write(
            self.state.join("state.json"),
            empty_local_state(machine_id).to_json().unwrap(),
        )
        .unwrap();
    }

    fn apply_target(&self, target: &str) -> Output {
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
}

fn empty_manifest() -> EnvironmentManifest {
    EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    }
}

fn empty_local_state(machine_id: &str) -> LocalState {
    LocalState {
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
    }
}

fn snapshot(binding: Option<&str>) -> PortableSnapshotV1 {
    snapshot_bindings(binding)
}

fn snapshot_bindings<'a>(bindings: impl IntoIterator<Item = &'a str>) -> PortableSnapshotV1 {
    PortableSnapshotV1::new(
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: bindings
                .into_iter()
                .map(|name| BindingName::parse(name).unwrap())
                .collect(),
        },
        BTreeSet::new(),
        SyncLimits::default(),
    )
    .unwrap()
}

fn snapshot_profile(target: HarnessId) -> PortableSnapshotV1 {
    let profile_id = ProfileId::parse("review").unwrap();
    PortableSnapshotV1::new(
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::from([(
                profile_id.clone(),
                Profile {
                    id: profile_id,
                    extends: None,
                    assets: BTreeSet::new(),
                    targets: BTreeSet::from([target]),
                },
            )]),
            required_bindings: BTreeSet::new(),
        },
        BTreeSet::new(),
        SyncLimits::default(),
    )
    .unwrap()
}

const CLI_AUTHORED_CANARY: &str = "D3-CLI-AUTHORED-CONTENT-CANARY-9182";
const CLI_NATIVE_ID_CANARY: &str = "d3-cli-native-id-canary-8273";
const CLI_RAW_OBJECT_CANARY: &str = "D3-CLI-RAW-OBJECT-BYTES-CANARY-7364";

fn install_canary_snapshot(machine: &Machine) {
    let files = BTreeMap::from([
        (
            PortablePath::parse("SKILL.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: format!(
                    "---\nname: review\ndescription: Review carefully\n---\n{CLI_AUTHORED_CANARY}\n"
                )
                .into_bytes(),
            },
        ),
        (
            PortablePath::parse("notes.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: CLI_RAW_OBJECT_CANARY.as_bytes().to_vec(),
            },
        ),
    ]);
    let tree = CapturedTree {
        hash: hash_tree(&files),
        files,
    };
    let portable = StoredSkillTree::new(tree.clone()).unwrap();
    let native = NativeSkillObject::new(
        SkillSourceLayout::Directory,
        "SKILL.md",
        CLI_NATIVE_ID_CANARY,
        tree,
    )
    .unwrap();
    let provenance = ComponentProvenance::new(
        Source::Local {
            path: PortablePath::parse("sources/review").unwrap(),
        },
        Revision::parse("source-review-v1").unwrap(),
        ContentHash::digest(b"review-source"),
        None,
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    let portable_root = PortablePath::parse("objects/review/portable").unwrap();
    let native_root = PortablePath::parse("objects/review/native/claude").unwrap();
    let mut asset = Asset {
        id: AssetId::parse("review").unwrap(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"pending"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: portable_root.clone(),
            object_hash: portable.tree().hash.clone(),
            provenance: provenance_id.clone(),
        }),
        native_variants: BTreeMap::from([(
            HarnessId::Claude,
            NativeVariant {
                harness: HarnessId::Claude,
                format: "kitrove-native-skill-object/v1".to_owned(),
                root: native_root.clone(),
                object_hash: native.hash().clone(),
                content_class: ContentClass::AgentActive,
                provenance: provenance_id,
            },
        )]),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    let portable_envelope =
        VerifiedObjectEnvelope::portable(portable_root.clone(), portable.clone()).unwrap();
    let native_envelope =
        VerifiedObjectEnvelope::native(native_root.clone(), native.clone()).unwrap();
    let snapshot = PortableSnapshotV1::new(
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::from([(asset.id.clone(), asset)]),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        },
        BTreeSet::from([
            portable_envelope.descriptor().clone(),
            native_envelope.descriptor().clone(),
        ]),
        SyncLimits::default(),
    )
    .unwrap();
    for (root, metadata, object_tree) in [
        (portable_root, portable.metadata_json(), portable.tree()),
        (native_root, native.metadata_json(), native.tree()),
    ] {
        let object_root = machine.environment.join(root.as_str());
        fs::create_dir_all(object_root.join("payload")).unwrap();
        fs::write(object_root.join("metadata.json"), metadata).unwrap();
        for (path, file) in &object_tree.files {
            let destination = object_root.join("payload").join(path.as_str());
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(destination, &file.bytes).unwrap();
        }
    }
    machine.replace_snapshot(&snapshot);
}

fn plan_and_apply(machine: &Machine, remote: &Path) -> Value {
    let plan = machine.plan(remote);
    assert!(
        plan.status.success(),
        "{}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let digest = json(&plan)["plan_digest"].as_str().unwrap().to_owned();
    let applied = machine.apply(remote, &digest);
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    json(&plan)
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "invalid JSON stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn all_regular_bytes(root: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                bytes.extend(fs::read(entry.path()).unwrap());
            }
        }
    }
    bytes
}

fn regular_file_map(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
            if relative == Path::new(".kitrove/removal-quarantine") {
                continue;
            }
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                collect(root, &entry.path(), files);
            } else if kind.is_file() {
                files.insert(relative, fs::read(entry.path()).unwrap());
            }
        }
    }

    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

fn authoritative_file_map(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = regular_file_map(root);
    files.retain(|path, _| {
        !path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|name| name.starts_with(".kitrove-removed-directory-"))
        })
    });
    files
}

struct ComponentSnapshot {
    snapshot: PortableSnapshotV1,
    portable: StoredSkillTree,
    native: BTreeMap<HarnessId, NativeSkillObject>,
}

fn review_skill_document(body: &str) -> Vec<u8> {
    format!("---\nname: review\ndescription: Review carefully\n---\n{body}").into_bytes()
}

fn component_snapshot(
    portable_body: &str,
    portable_mode: FileMode,
    native_specs: &[(HarnessId, &str, &str)],
) -> ComponentSnapshot {
    let portable_bytes = review_skill_document(portable_body);
    let portable_files = BTreeMap::from([(
        PortablePath::parse("SKILL.md").unwrap(),
        CapturedFile {
            mode: portable_mode,
            bytes: portable_bytes.clone(),
        },
    )]);
    let portable = StoredSkillTree::new(CapturedTree {
        hash: hash_tree(&portable_files),
        files: portable_files,
    })
    .unwrap();
    let mut asset_content_class = assess_portable_tree_risk(portable.tree()).unwrap();
    let portable_hash_suffix = &portable.tree().hash.as_str().rsplit(':').next().unwrap()[..16];
    let portable_root =
        PortablePath::parse(format!("objects/review/portable/{portable_hash_suffix}")).unwrap();
    let portable_provenance = ComponentProvenance::new(
        Source::Local {
            path: PortablePath::parse("sources/portable").unwrap(),
        },
        Revision::parse(format!(
            "portable-{}",
            &ContentHash::digest(&portable_bytes).as_str()[..24]
        ))
        .unwrap(),
        ContentHash::digest(&portable_bytes),
        None,
    )
    .unwrap();
    let portable_provenance_id = portable_provenance.provenance_id();
    let mut provenance = BTreeMap::from([(portable_provenance_id.clone(), portable_provenance)]);
    let mut native = BTreeMap::new();
    let mut native_variants = BTreeMap::new();
    let mut descriptors =
        BTreeSet::from([
            VerifiedObjectEnvelope::portable(portable_root.clone(), portable.clone())
                .unwrap()
                .descriptor()
                .clone(),
        ]);
    for (harness, native_id, body) in native_specs {
        let native_bytes = review_skill_document(body);
        let files = BTreeMap::from([(
            PortablePath::parse("SKILL.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: native_bytes.clone(),
            },
        )]);
        let object = NativeSkillObject::new(
            SkillSourceLayout::Directory,
            "SKILL.md",
            *native_id,
            CapturedTree {
                hash: hash_tree(&files),
                files,
            },
        )
        .unwrap();
        let native_content_class = assess_native_skill_object_risk(&object).unwrap();
        asset_content_class = asset_content_class.max(native_content_class);
        let native_hash_suffix = &object.hash().as_str().rsplit(':').next().unwrap()[..16];
        let root = PortablePath::parse(format!(
            "objects/review/native/{}/{native_hash_suffix}",
            harness.as_str()
        ))
        .unwrap();
        let component_provenance = ComponentProvenance::new(
            Source::Local {
                path: PortablePath::parse(format!("sources/native/{}", harness.as_str())).unwrap(),
            },
            Revision::parse(format!(
                "native-{}-{}",
                harness.as_str(),
                &ContentHash::digest(&native_bytes).as_str()[..16]
            ))
            .unwrap(),
            ContentHash::digest(&native_bytes),
            None,
        )
        .unwrap();
        let provenance_id = component_provenance.provenance_id();
        provenance.insert(provenance_id.clone(), component_provenance);
        descriptors.insert(
            VerifiedObjectEnvelope::native(root.clone(), object.clone())
                .unwrap()
                .descriptor()
                .clone(),
        );
        native_variants.insert(
            harness.clone(),
            NativeVariant {
                harness: harness.clone(),
                format: "kitrove-native-skill-object/v1".to_owned(),
                root,
                object_hash: object.hash().clone(),
                content_class: native_content_class,
                provenance: provenance_id,
            },
        );
        native.insert(harness.clone(), object);
    }
    let mut asset = Asset {
        id: AssetId::parse("review").unwrap(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"pending"),
        provenance,
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: portable_root,
            object_hash: portable.tree().hash.clone(),
            provenance: portable_provenance_id,
        }),
        native_variants,
        compatibility: BTreeMap::new(),
        content_class: asset_content_class,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    let snapshot = PortableSnapshotV1::new(
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::from([(asset.id.clone(), asset)]),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        },
        descriptors,
        SyncLimits::default(),
    )
    .unwrap();
    ComponentSnapshot {
        snapshot,
        portable,
        native,
    }
}

fn install_component_snapshot(machine: &Machine, fixture: &ComponentSnapshot) {
    machine.replace_snapshot(&fixture.snapshot);
    let asset = fixture
        .snapshot
        .manifest()
        .assets
        .get(&AssetId::parse("review").unwrap())
        .unwrap();
    let portable = asset.portable.as_ref().unwrap();
    write_skill_object(
        &machine.environment.join(portable.root.as_str()),
        &fixture.portable.metadata_json(),
        fixture.portable.tree(),
    );
    for (harness, object) in &fixture.native {
        let variant = &asset.native_variants[harness];
        write_skill_object(
            &machine.environment.join(variant.root.as_str()),
            &object.metadata_json(),
            object.tree(),
        );
    }
}

fn write_skill_object(root: &Path, metadata: &str, tree: &CapturedTree) {
    if root.exists() {
        fs::remove_dir_all(root).unwrap();
    }
    fs::create_dir_all(root.join("payload")).unwrap();
    fs::write(root.join("metadata.json"), metadata).unwrap();
    for (path, file) in &tree.files {
        let destination = root.join("payload").join(path.as_str());
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(destination, &file.bytes).unwrap();
    }
}

#[test]
fn two_isolated_machines_publish_then_receive_without_copying_local_state() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let source = snapshot(Some("workspace"));
    let empty = snapshot(None);
    let machine_a = Machine::new(&root, "machine-a", &source, "MACHINE-A-STATE-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &empty, "MACHINE-B-STATE-CANARY");

    let before_a = fs::read(machine_a.state.join("state.json")).unwrap();
    let plan_a = machine_a.plan(&remote);
    assert!(
        plan_a.status.success(),
        "{}",
        String::from_utf8_lossy(&plan_a.stderr)
    );
    assert_eq!(json(&plan_a)["disposition"], "publish");
    machine_a.assert_canaries_absent(&plan_a.stdout);
    machine_a.assert_canaries_absent(&plan_a.stderr);
    assert!(
        !plan_a
            .stdout
            .windows(before_a.len())
            .any(|bytes| bytes == before_a)
    );
    assert_eq!(
        fs::read(machine_a.state.join("state.json")).unwrap(),
        before_a
    );
    let remote_bytes = all_regular_bytes(&remote);
    machine_a.assert_canaries_absent(&remote_bytes);
    assert!(
        !remote_bytes
            .windows(before_a.len())
            .any(|bytes| bytes == before_a)
    );
    let digest_a = json(&plan_a)["plan_digest"].as_str().unwrap().to_owned();
    let apply_a = machine_a.apply(&remote, &digest_a);
    assert!(
        apply_a.status.success(),
        "{}",
        String::from_utf8_lossy(&apply_a.stderr)
    );
    assert_eq!(json(&apply_a)["status"], "committed");
    machine_a.assert_canaries_absent(&apply_a.stdout);
    machine_a.assert_canaries_absent(&apply_a.stderr);
    assert_eq!(
        fs::read(machine_a.state.join("state.json")).unwrap(),
        before_a
    );
    machine_a.assert_local_files_unchanged();

    let before_b = fs::read(machine_b.state.join("state.json")).unwrap();
    let plan_b = machine_b.plan(&remote);
    assert!(
        plan_b.status.success(),
        "{}",
        String::from_utf8_lossy(&plan_b.stderr)
    );
    assert_eq!(json(&plan_b)["disposition"], "receive");
    machine_b.assert_canaries_absent(&plan_b.stdout);
    machine_b.assert_canaries_absent(&plan_b.stderr);
    assert_eq!(
        fs::read(machine_b.state.join("state.json")).unwrap(),
        before_b
    );
    let remote_bytes = all_regular_bytes(&remote);
    machine_b.assert_canaries_absent(&remote_bytes);
    assert!(
        !remote_bytes
            .windows(before_b.len())
            .any(|bytes| bytes == before_b)
    );
    let digest_b = json(&plan_b)["plan_digest"].as_str().unwrap().to_owned();
    let apply_b = machine_b.apply(&remote, &digest_b);
    assert!(
        apply_b.status.success(),
        "{}",
        String::from_utf8_lossy(&apply_b.stderr)
    );
    assert_eq!(json(&apply_b)["status"], "committed");
    machine_b.assert_canaries_absent(&apply_b.stdout);
    machine_b.assert_canaries_absent(&apply_b.stderr);
    assert_eq!(
        fs::read(machine_b.state.join("state.json")).unwrap(),
        before_b
    );
    assert_eq!(
        fs::read_to_string(machine_b.environment.join("kitrove.toml")).unwrap(),
        source.manifest_toml()
    );
    assert_eq!(
        fs::read_to_string(machine_b.environment.join("kitrove.lock.json")).unwrap(),
        source.lock_json()
    );
    machine_b.assert_local_files_unchanged();
}

#[test]
fn stale_confirmation_and_bootstrap_conflict_are_nonmutating() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let source = snapshot(Some("workspace"));
    let different = snapshot(Some("other-binding"));
    let machine_a = Machine::new(&root, "machine-a", &source, "A-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &different, "B-CANARY");
    let plan_a = machine_a.plan(&remote);
    let digest_a = json(&plan_a)["plan_digest"].as_str().unwrap().to_owned();

    let stale = machine_a.apply(&remote, &format!("blake3:{}", "f".repeat(64)));
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("error[sync.plan_stale]"));
    assert!(!remote.join(".kitrove-sync/current.json").exists());
    assert_eq!(fs::read_dir(&remote).unwrap().count(), 0);
    let published = machine_a.apply(&remote, &digest_a);
    assert!(
        published.status.success(),
        "{}",
        String::from_utf8_lossy(&published.stderr)
    );

    let before_manifest = fs::read(machine_b.environment.join("kitrove.toml")).unwrap();
    let before_state = fs::read(machine_b.state.join("state.json")).unwrap();
    let blocked = machine_b.plan(&remote);
    assert_eq!(blocked.status.code(), Some(3));
    assert_eq!(json(&blocked)["status"], "blocked");
    assert_eq!(
        fs::read(machine_b.environment.join("kitrove.toml")).unwrap(),
        before_manifest
    );
    assert_eq!(
        fs::read(machine_b.state.join("state.json")).unwrap(),
        before_state
    );
    machine_a.assert_local_files_unchanged();
    machine_b.assert_local_files_unchanged();
    machine_a.assert_canaries_absent(&stale.stdout);
    machine_a.assert_canaries_absent(&stale.stderr);
    machine_b.assert_canaries_absent(&blocked.stdout);
    machine_b.assert_canaries_absent(&blocked.stderr);
    let remote_bytes = all_regular_bytes(&remote);
    machine_a.assert_canaries_absent(&remote_bytes);
    machine_b.assert_canaries_absent(&remote_bytes);
}

#[test]
fn identical_second_machine_establishes_base_without_copying_local_state() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let shared = snapshot(Some("workspace"));
    let machine_a = Machine::new(&root, "machine-a", &shared, "A-BASE-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &shared, "B-BASE-CANARY");
    plan_and_apply(&machine_a, &remote);

    let plan = machine_b.plan(&remote);
    assert!(plan.status.success());
    assert_eq!(json(&plan)["disposition"], "establish_base");
    let digest = json(&plan)["plan_digest"].as_str().unwrap().to_owned();
    let applied = machine_b.apply(&remote, &digest);
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    assert_eq!(json(&applied)["status"], "committed");
    machine_a.assert_local_files_unchanged();
    machine_b.assert_local_files_unchanged();
    for bytes in [&plan.stdout, &plan.stderr, &applied.stdout, &applied.stderr] {
        machine_a.assert_canaries_absent(bytes);
        machine_b.assert_canaries_absent(bytes);
    }
    let remote_bytes = all_regular_bytes(&remote);
    machine_a.assert_canaries_absent(&remote_bytes);
    machine_b.assert_canaries_absent(&remote_bytes);
}

#[test]
fn cli_surfaces_redact_remote_revision_publication_and_machine_local_canaries() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("REMOTE-PATH-CANARY-7f31");
    fs::create_dir(&remote).unwrap();
    let machine = Machine::new(
        &root,
        "machine",
        &snapshot(Some("workspace")),
        "LOCAL-SURFACE-CANARY-4d82",
    );
    let plan = machine.plan(&remote);
    assert!(plan.status.success());
    let digest = json(&plan)["plan_digest"].as_str().unwrap().to_owned();
    let publication = format!("publication:blake3:{}", digest.rsplit(':').next().unwrap());
    let applied = machine.apply(&remote, &digest);
    assert!(applied.status.success());
    let current: Value =
        serde_json::from_slice(&fs::read(remote.join(".kitrove-sync/current.json")).unwrap())
            .unwrap();
    let revision = current["revision"].as_str().unwrap();
    let remote_path = remote.to_string_lossy();

    for bytes in [&plan.stdout, &plan.stderr, &applied.stdout, &applied.stderr] {
        let surface = String::from_utf8_lossy(bytes);
        assert!(!surface.contains(remote_path.as_ref()));
        assert!(!surface.contains(revision));
        assert!(!surface.contains(&publication));
        machine.assert_canaries_absent(bytes);
    }
    machine.assert_local_files_unchanged();
}

#[test]
fn human_and_json_cli_never_render_authored_native_or_raw_object_canaries() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let canaries = [
        CLI_AUTHORED_CANARY,
        CLI_NATIVE_ID_CANARY,
        CLI_RAW_OBJECT_CANARY,
    ];

    for json_output in [false, true] {
        let label = if json_output { "json" } else { "human" };
        let remote = root.join(format!("remote-{label}"));
        fs::create_dir(&remote).unwrap();
        let machine = Machine::new(
            &root,
            &format!("machine-{label}"),
            &snapshot(None),
            &format!("D3-CLI-LOCAL-{label}-CANARY"),
        );
        install_canary_snapshot(&machine);

        let plan = if json_output {
            machine.plan(&remote)
        } else {
            machine.plan_human(&remote)
        };
        assert!(
            plan.status.success(),
            "{}",
            String::from_utf8_lossy(&plan.stderr)
        );
        let digest = if json_output {
            json(&plan)["plan_digest"].as_str().unwrap().to_owned()
        } else {
            String::from_utf8_lossy(&plan.stdout)
                .lines()
                .find_map(|line| line.strip_prefix("Plan digest: "))
                .unwrap()
                .to_owned()
        };
        let applied = if json_output {
            machine.apply(&remote, &digest)
        } else {
            machine.apply_human(&remote, &digest)
        };
        assert!(
            applied.status.success(),
            "{}",
            String::from_utf8_lossy(&applied.stderr)
        );

        for bytes in [&plan.stdout, &plan.stderr, &applied.stdout, &applied.stderr] {
            let surface = String::from_utf8_lossy(bytes);
            for canary in canaries {
                assert!(
                    !surface.contains(canary),
                    "{label} CLI surface disclosed {canary}: {surface}"
                );
            }
            machine.assert_canaries_absent(bytes);
        }
        machine.assert_local_files_unchanged();
    }
}

#[test]
fn independent_machine_changes_merge_then_reverse_sync() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let shared = snapshot_bindings(["shared"]);
    let empty = snapshot(None);
    let machine_a = Machine::new(&root, "machine-a", &shared, "MACHINE-A-MERGE-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &empty, "MACHINE-B-MERGE-CANARY");
    plan_and_apply(&machine_a, &remote);
    plan_and_apply(&machine_b, &remote);

    let changed_a = snapshot_bindings(["shared", "machine-a"]);
    let changed_b = snapshot_bindings(["shared", "machine-b"]);
    machine_a.replace_snapshot(&changed_a);
    machine_b.replace_snapshot(&changed_b);
    assert_eq!(
        plan_and_apply(&machine_a, &remote)["disposition"],
        "publish"
    );
    assert_eq!(plan_and_apply(&machine_b, &remote)["disposition"], "merge");

    let merged = snapshot_bindings(["shared", "machine-a", "machine-b"]);
    assert_eq!(
        fs::read_to_string(machine_b.environment.join("kitrove.toml")).unwrap(),
        merged.manifest_toml()
    );
    assert_eq!(
        plan_and_apply(&machine_a, &remote)["disposition"],
        "receive"
    );
    assert_eq!(
        fs::read_to_string(machine_a.environment.join("kitrove.toml")).unwrap(),
        merged.manifest_toml()
    );
    assert_eq!(
        fs::read_to_string(machine_a.state.join("state.json")).unwrap(),
        "MACHINE-A-MERGE-CANARY-MACHINE-CONFIG"
    );
    assert_eq!(
        fs::read_to_string(machine_b.state.join("state.json")).unwrap(),
        "MACHINE-B-MERGE-CANARY-MACHINE-CONFIG"
    );
    machine_a.assert_local_files_unchanged();
    machine_b.assert_local_files_unchanged();
}

#[test]
fn semantic_profile_deletion_conflicts_without_mutating_either_machine_or_remote() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let base = snapshot_profile(HarnessId::Claude);
    let empty = snapshot(None);
    let machine_a = Machine::new(&root, "machine-a", &base, "MACHINE-A-CONFLICT-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &empty, "MACHINE-B-CONFLICT-CANARY");
    plan_and_apply(&machine_a, &remote);
    plan_and_apply(&machine_b, &remote);

    machine_b.replace_snapshot(&empty);
    let remote_before = all_regular_bytes(&remote);
    let manifest_before = fs::read(machine_b.environment.join("kitrove.toml")).unwrap();
    let lock_before = fs::read(machine_b.environment.join("kitrove.lock.json")).unwrap();
    let blocked = machine_b.plan(&remote);

    assert_eq!(blocked.status.code(), Some(3));
    assert_eq!(json(&blocked)["status"], "blocked");
    assert_eq!(
        json(&blocked)["conflicts"][0]["code"],
        "deletion_unsupported"
    );
    assert_eq!(
        fs::read(machine_b.environment.join("kitrove.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(machine_b.environment.join("kitrove.lock.json")).unwrap(),
        lock_before
    );
    assert_eq!(all_regular_bytes(&remote), remote_before);
    machine_a.assert_local_files_unchanged();
    machine_b.assert_local_files_unchanged();
    machine_a.assert_canaries_absent(&blocked.stdout);
    machine_b.assert_canaries_absent(&blocked.stdout);
    machine_a.assert_canaries_absent(&remote_before);
    machine_b.assert_canaries_absent(&remote_before);
}

#[test]
fn two_machine_component_merge_preserves_exact_objects_and_derived_lock() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let pi = HarnessId::parse("pi").unwrap();
    let codex = HarnessId::parse("codex").unwrap();
    let base = component_snapshot(
        "# Portable base\n",
        FileMode::Regular,
        &[(pi.clone(), "review-pi", "# Pi base\n")],
    );
    let empty = snapshot(None);
    let machine_a = Machine::new(&root, "machine-a", &base.snapshot, "A-COMPONENT-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &empty, "B-COMPONENT-CANARY");
    install_component_snapshot(&machine_a, &base);
    plan_and_apply(&machine_a, &remote);
    plan_and_apply(&machine_b, &remote);

    let changed_on_a = component_snapshot(
        "# Portable from A\n",
        FileMode::Regular,
        &[(pi.clone(), "review-pi", "# Pi base\n")],
    );
    let changed_on_b = component_snapshot(
        "# Portable base\n",
        FileMode::Regular,
        &[
            (pi.clone(), "review-pi", "# Pi base\n"),
            (codex.clone(), "review-codex", "# Codex from B\n"),
        ],
    );
    install_component_snapshot(&machine_a, &changed_on_a);
    install_component_snapshot(&machine_b, &changed_on_b);

    assert_eq!(plan_and_apply(&machine_a, &remote)["disposition"], "merge");
    assert_eq!(plan_and_apply(&machine_b, &remote)["disposition"], "merge");
    assert_eq!(
        plan_and_apply(&machine_a, &remote)["disposition"],
        "receive"
    );

    let manifest_text = fs::read_to_string(machine_a.environment.join("kitrove.toml")).unwrap();
    let manifest = EnvironmentManifest::from_toml(&manifest_text).unwrap();
    let asset = manifest
        .assets
        .get(&AssetId::parse("review").unwrap())
        .unwrap();
    assert_eq!(
        asset.portable.as_ref().unwrap().object_hash,
        changed_on_a.portable.tree().hash
    );
    assert_eq!(
        asset.native_variants[&pi].object_hash,
        base.native[&pi].hash().clone()
    );
    assert_eq!(
        asset.native_variants[&codex].object_hash,
        changed_on_b.native[&codex].hash().clone()
    );
    assert_eq!(
        fs::read_to_string(machine_a.environment.join("kitrove.lock.json")).unwrap(),
        derive_lockfile(&manifest).unwrap().to_json().unwrap()
    );
    assert_eq!(
        authoritative_file_map(&machine_a.environment),
        authoritative_file_map(&machine_b.environment)
    );
    assert_eq!(
        fs::read(
            machine_a
                .environment
                .join(asset.portable.as_ref().unwrap().root.as_str())
                .join("payload/SKILL.md")
        )
        .unwrap(),
        review_skill_document("# Portable from A\n")
    );
    assert_eq!(
        fs::read(
            machine_a
                .environment
                .join(asset.native_variants[&pi].root.as_str())
                .join("payload/SKILL.md")
        )
        .unwrap(),
        review_skill_document("# Pi base\n")
    );
    assert_eq!(
        fs::read(
            machine_a
                .environment
                .join(asset.native_variants[&codex].root.as_str())
                .join("payload/SKILL.md")
        )
        .unwrap(),
        review_skill_document("# Codex from B\n")
    );
    machine_a.assert_local_files_unchanged();
    machine_b.assert_local_files_unchanged();
}

#[test]
fn same_component_divergence_is_typed_and_byte_for_byte_nonmutating() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let pi = HarnessId::parse("pi").unwrap();
    let base = component_snapshot(
        "# Portable base\n",
        FileMode::Regular,
        &[(pi.clone(), "review-pi", "# Pi base\n")],
    );
    let empty = snapshot(None);
    let machine_a = Machine::new(&root, "machine-a", &base.snapshot, "A-DIVERGENCE-CANARY");
    let machine_b = Machine::new(&root, "machine-b", &empty, "B-DIVERGENCE-CANARY");
    install_component_snapshot(&machine_a, &base);
    plan_and_apply(&machine_a, &remote);
    plan_and_apply(&machine_b, &remote);

    let changed_on_a = component_snapshot(
        "# Portable from A\n",
        FileMode::Regular,
        &[(pi.clone(), "review-pi", "# Pi base\n")],
    );
    let changed_on_b = component_snapshot(
        "# Portable from B\n",
        FileMode::Regular,
        &[(pi, "review-pi", "# Pi base\n")],
    );
    install_component_snapshot(&machine_a, &changed_on_a);
    install_component_snapshot(&machine_b, &changed_on_b);
    plan_and_apply(&machine_a, &remote);

    let environment_before = regular_file_map(&machine_b.environment);
    let state_before = regular_file_map(&machine_b.state);
    let remote_before = regular_file_map(&remote);
    let blocked = machine_b.plan(&remote);

    assert_eq!(blocked.status.code(), Some(3));
    assert_eq!(json(&blocked)["status"], "blocked");
    assert!(
        json(&blocked)["conflicts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|conflict| conflict["code"] == "divergent_component")
    );
    assert_eq!(regular_file_map(&machine_b.environment), environment_before);
    assert_eq!(regular_file_map(&machine_b.state), state_before);
    assert_eq!(regular_file_map(&remote), remote_before);
    machine_a.assert_local_files_unchanged();
    machine_b.assert_local_files_unchanged();
}

#[test]
fn received_executable_is_blocked_before_apply_without_running_or_mutating() {
    let temporary = kitrove_testkit::trusted_tempdir(".kitrove-sync-cli-");
    let root = fs::canonicalize(temporary.path()).unwrap();
    let remote = root.join("remote");
    fs::create_dir(&remote).unwrap();
    let sentinel = root.join("EXECUTION-SENTINEL");
    let executable_body = format!(
        "#!/bin/sh\nprintf executed > '{}'\n",
        sentinel.to_string_lossy()
    );
    let executable = component_snapshot(&executable_body, FileMode::Executable, &[]);
    let machine_a = Machine::new(
        &root,
        "machine-a",
        &executable.snapshot,
        "A-EXECUTABLE-CANARY",
    );
    let machine_b = Machine::new(&root, "machine-b", &snapshot(None), "B-EXECUTABLE-CANARY");
    install_component_snapshot(&machine_a, &executable);
    plan_and_apply(&machine_a, &remote);
    assert_eq!(
        plan_and_apply(&machine_b, &remote)["disposition"],
        "receive"
    );
    machine_b.initialize_apply_state("machine-b");

    let environment_before = regular_file_map(&machine_b.environment);
    let state_before = regular_file_map(&machine_b.state);
    let home_before = regular_file_map(&machine_b.home);
    let working_before = regular_file_map(&machine_b.working);
    let blocked = machine_b.apply_target("codex");

    assert!(!blocked.status.success());
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("error[apply.executable_blocked]"));
    assert!(!sentinel.exists());
    assert!(!machine_b.home.join(".agents/skills/review").exists());
    assert_eq!(regular_file_map(&machine_b.environment), environment_before);
    assert_eq!(regular_file_map(&machine_b.state), state_before);
    assert_eq!(regular_file_map(&machine_b.home), home_before);
    assert_eq!(regular_file_map(&machine_b.working), working_before);
}
