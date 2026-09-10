#![forbid(unsafe_code)]

#[path = "support/owned_fixture.rs"]
mod owned_fixture;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::process::{Command, Stdio};

use kitrove_core::{
    FilesystemSyncBackend, PortableSnapshotV1, PublicationStatus, SyncBackend, SyncBackendApply,
    derive_lockfile,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, Pack, PortablePath,
    PublicationId, Revision, SchemaVersion, Source, SyncLimits,
};

fn manifest() -> EnvironmentManifest {
    let mut asset = Asset {
        id: AssetId::parse("alpha").unwrap(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"pending-pack-cli-integration-asset"),
        provenance: BTreeMap::new(),
        portable: None,
        native_variants: BTreeMap::new(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    let pack_id = AssetId::parse("tooling").unwrap();
    let pack = Pack {
        id: pack_id.clone(),
        source: Source::Local {
            path: PortablePath::parse("packs/tooling").unwrap(),
        },
        revision: Revision::parse("local:tooling").unwrap(),
        exact_source_hash: ContentHash::digest(b"tooling-source"),
        content_hash: ContentHash::digest(b"pending-pack-cli-integration-pack"),
        members: BTreeMap::from([(asset.id.clone(), asset.content_hash.clone())]),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    };
    let utilities_id = AssetId::parse("utilities").unwrap();
    let utilities = Pack {
        id: utilities_id.clone(),
        source: pack.source.clone(),
        revision: pack.revision.clone(),
        exact_source_hash: pack.exact_source_hash.clone(),
        content_hash: ContentHash::digest(b"pending-pack-cli-integration-utilities"),
        members: pack.members.clone(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    };
    let mut manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(asset.id.clone(), asset)]),
        packs: BTreeMap::from([(pack_id, pack), (utilities_id, utilities)]),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    manifest.refresh_pack_revisions().unwrap();
    manifest
}

#[test]
fn list_and_inspect_are_read_only_and_emit_stable_json() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let environment = root.join("environment");
    fs::create_dir(&environment).unwrap();
    let manifest_bytes = manifest().to_toml().unwrap().into_bytes();
    fs::write(environment.join("kitrove.toml"), &manifest_bytes).unwrap();

    let list = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["pack", "list", "--environment"])
        .arg(&environment)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(list_json["operation"], "pack_list");
    assert_eq!(list_json["packs"][0]["id"], "tooling");

    let inspect = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["pack", "inspect", "--pack", "tooling", "--environment"])
        .arg(&environment)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(inspect_json["operation"], "pack_inspect");
    assert_eq!(inspect_json["pack"]["id"], "tooling");
    assert_eq!(inspect_json["components"][0]["id"], "alpha");
    assert_eq!(inspect_json["components"][0]["parents"][0], "tooling");

    assert_eq!(
        fs::read(environment.join("kitrove.toml")).unwrap(),
        manifest_bytes
    );
    assert_eq!(fs::read_dir(&environment).unwrap().count(), 1);
}

#[test]
fn inspect_missing_pack_is_typed_and_help_documents_the_workflow() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let environment = root.join("environment");
    fs::create_dir(&environment).unwrap();
    fs::write(
        environment.join("kitrove.toml"),
        manifest().to_toml().unwrap(),
    )
    .unwrap();

    let missing = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["pack", "inspect", "--pack", "missing", "--environment"])
        .arg(&environment)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("error[pack.missing]"));

    let help = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("kitrove pack list"));
    assert!(help.contains("kitrove pack inspect --pack <pack-id>"));
    assert!(help.contains("kitrove pack discover"));
    assert!(help.contains("kitrove pack adopt --pack <pack-id>"));
    assert!(help.contains("kitrove pack update --pack <pack-id>"));
    assert!(help.contains("kitrove pack rollback --pack <pack-id>"));
}

#[test]
fn create_confirms_and_atomically_groups_shared_source_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let environment = root.join("environment");
    fs::create_dir(&environment).unwrap();
    let manifest = manifest();
    owned_fixture::create(
        &environment.join("kitrove.toml"),
        manifest.to_toml().unwrap().as_bytes(),
    );
    owned_fixture::create(
        &environment.join("kitrove.lock.json"),
        derive_lockfile(&manifest)
            .unwrap()
            .to_json()
            .unwrap()
            .as_bytes(),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args([
            "pack",
            "create",
            "--pack",
            "suite",
            "--member",
            "tooling",
            "--environment",
        ])
        .arg(&environment)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["operation"], "pack_create");
    assert_eq!(result["outcome"], "committed");
    assert_eq!(result["pack"]["id"], "suite");

    let committed = EnvironmentManifest::from_toml(
        &fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        committed.packs[&AssetId::parse("suite").unwrap()]
            .members
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>(),
        ["tooling"]
    );
    assert_eq!(
        fs::read_to_string(environment.join("kitrove.lock.json")).unwrap(),
        derive_lockfile(&committed).unwrap().to_json().unwrap()
    );
    assert!(!environment.join(".kitrove/adoption-journal.json").exists());

    let suite_id = AssetId::parse("suite").unwrap();
    let prior = committed.packs[&suite_id].content_hash.as_str();
    let manifest_before_update = fs::read(environment.join("kitrove.toml")).unwrap();
    let lock_before_update = fs::read(environment.join("kitrove.lock.json")).unwrap();
    let mut unconfirmed = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args([
            "pack",
            "update",
            "--pack",
            "suite",
            "--expected-prior",
            prior,
            "--member",
            "utilities",
            "--environment",
        ])
        .arg(&environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    unconfirmed
        .stdin
        .take()
        .unwrap()
        .write_all(b"no\n")
        .unwrap();
    let unconfirmed = unconfirmed.wait_with_output().unwrap();
    assert_eq!(unconfirmed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unconfirmed.stderr)
            .contains("error[pack_update.confirmation_required]")
    );
    assert_eq!(
        fs::read(environment.join("kitrove.toml")).unwrap(),
        manifest_before_update
    );
    assert_eq!(
        fs::read(environment.join("kitrove.lock.json")).unwrap(),
        lock_before_update
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args([
            "pack",
            "update",
            "--pack",
            "suite",
            "--expected-prior",
            prior,
            "--member",
            "utilities",
            "--environment",
        ])
        .arg(&environment)
        .arg("--json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let update_prompt = String::from_utf8_lossy(&output.stderr);
    assert!(update_prompt.contains(r#""added_members":["utilities"]"#));
    assert!(update_prompt.contains(r#""removed_members":["tooling"]"#));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["operation"], "pack_update");
    assert_eq!(result["outcome"], "committed");

    let updated = EnvironmentManifest::from_toml(
        &fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        updated.packs[&suite_id]
            .members
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>(),
        ["utilities"]
    );
    assert_ne!(updated.packs[&suite_id].content_hash.as_str(), prior);
    assert_eq!(
        fs::read_to_string(environment.join("kitrove.lock.json")).unwrap(),
        derive_lockfile(&updated).unwrap().to_json().unwrap()
    );

    let stale = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args([
            "pack",
            "update",
            "--pack",
            "suite",
            "--expected-prior",
            prior,
            "--member",
            "tooling",
            "--environment",
        ])
        .arg(&environment)
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&stale.stderr)
            .contains("error[pack_update.expected_prior_mismatch]")
    );
    assert_eq!(
        EnvironmentManifest::from_toml(
            &fs::read_to_string(environment.join("kitrove.toml")).unwrap()
        )
        .unwrap(),
        updated
    );
}

#[test]
fn rollback_restores_verified_filesystem_history_and_preserves_generated_authority() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let environment = root.join("environment");
    let remote = root.join("remote");
    let state = root.join("state");
    let home = root.join("home");
    let working = root.join("working");
    for directory in [&environment, &remote, &state, &home, &working] {
        fs::create_dir(directory).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&working)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("LOCALAPPDATA", home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &state)
            .env_remove("KITROVE_ENV")
            .env_remove("XDG_DATA_HOME");
        command
    };
    let backend = FilesystemSyncBackend::open(&remote).unwrap();
    // Subsequent fixture revisions preserve these files' current-user ownership.
    owned_fixture::create(&environment.join("kitrove.toml"), b"");
    owned_fixture::create(&environment.join("kitrove.lock.json"), b"");
    let publish = |manifest: &EnvironmentManifest, marker: char| {
        fs::write(
            environment.join("kitrove.toml"),
            manifest.to_toml().unwrap(),
        )
        .unwrap();
        fs::write(
            environment.join("kitrove.lock.json"),
            derive_lockfile(manifest).unwrap().to_json().unwrap(),
        )
        .unwrap();
        let limits = SyncLimits::default();
        let snapshot = PortableSnapshotV1::new(manifest.clone(), BTreeSet::new(), limits).unwrap();
        let mut session = backend.begin_apply(limits).unwrap();
        let current = session.inspect(limits).unwrap();
        let publication = PublicationId::parse(format!(
            "publication:blake3:{}",
            marker.to_string().repeat(64)
        ))
        .unwrap();
        let intent = session
            .prepare_publication(current.revision(), &publication, &snapshot, &[], limits)
            .unwrap();
        assert!(matches!(
            session.publish(&intent, &snapshot, &[], limits).unwrap(),
            PublicationStatus::Published(_)
        ));
    };

    let historical = manifest();
    let pack_id = AssetId::parse("tooling").unwrap();
    let historical_revision = historical.packs[&pack_id].content_hash.clone();
    publish(&historical, 'a');
    let mut current = historical.clone();
    current
        .assets
        .get_mut(&AssetId::parse("alpha").unwrap())
        .unwrap()
        .content_class = ContentClass::AgentActive;
    current
        .assets
        .get_mut(&AssetId::parse("alpha").unwrap())
        .unwrap()
        .refresh_content_hash();
    current.refresh_pack_revisions().unwrap();
    let current_revision = current.packs[&pack_id].content_hash.clone();
    publish(&current, 'b');

    let manifest_before = fs::read(environment.join("kitrove.toml")).unwrap();
    let lock_before = fs::read(environment.join("kitrove.lock.json")).unwrap();
    let mut unconfirmed = command()
        .args([
            "pack",
            "rollback",
            "--pack",
            "tooling",
            "--expected-prior",
            current_revision.as_str(),
            "--to",
            historical_revision.as_str(),
            "--filesystem",
        ])
        .arg(&remote)
        .arg("--environment")
        .arg(&environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    unconfirmed
        .stdin
        .take()
        .unwrap()
        .write_all(b"no\n")
        .unwrap();
    let unconfirmed = unconfirmed.wait_with_output().unwrap();
    assert_eq!(unconfirmed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unconfirmed.stderr)
            .contains("error[pack_rollback.confirmation_required]")
    );
    assert_eq!(
        fs::read(environment.join("kitrove.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(environment.join("kitrove.lock.json")).unwrap(),
        lock_before
    );

    let rollback = command()
        .args([
            "pack",
            "rollback",
            "--pack",
            "tooling",
            "--expected-prior",
            current_revision.as_str(),
            "--to",
            historical_revision.as_str(),
            "--filesystem",
        ])
        .arg(&remote)
        .arg("--environment")
        .arg(&environment)
        .args(["--yes", "--json"])
        .output()
        .unwrap();
    assert!(
        rollback.status.success(),
        "{}",
        String::from_utf8_lossy(&rollback.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&rollback.stdout).unwrap();
    assert_eq!(output["operation"], "pack_rollback");
    assert_eq!(output["outcome"], "committed");
    assert_eq!(output["revision"], historical_revision.as_str());
    let committed = EnvironmentManifest::from_toml(
        &fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(committed, historical);
    assert_eq!(
        fs::read_to_string(environment.join("kitrove.lock.json")).unwrap(),
        derive_lockfile(&committed).unwrap().to_json().unwrap()
    );
    assert!(!environment.join(".kitrove/adoption-journal.json").exists());
}

#[test]
fn discover_and_adopt_verified_distribution_head_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let environment = root.join("environment");
    let remote = root.join("remote");
    fs::create_dir(&environment).unwrap();
    fs::create_dir(&remote).unwrap();

    let distributed = manifest();
    let limits = SyncLimits::default();
    let snapshot = PortableSnapshotV1::new(distributed.clone(), BTreeSet::new(), limits).unwrap();
    let backend = FilesystemSyncBackend::open(&remote).unwrap();
    let mut session = backend.begin_apply(limits).unwrap();
    let current = session.inspect(limits).unwrap();
    let publication =
        PublicationId::parse(format!("publication:blake3:{}", "c".repeat(64))).unwrap();
    let intent = session
        .prepare_publication(current.revision(), &publication, &snapshot, &[], limits)
        .unwrap();
    assert!(matches!(
        session.publish(&intent, &snapshot, &[], limits).unwrap(),
        PublicationStatus::Published(_)
    ));
    drop(session);

    let discover = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["pack", "discover", "--filesystem"])
        .arg(&remote)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        discover.status.success(),
        "{}",
        String::from_utf8_lossy(&discover.stderr)
    );
    let discovered: serde_json::Value = serde_json::from_slice(&discover.stdout).unwrap();
    assert_eq!(discovered["operation"], "pack_discover");
    assert_eq!(discovered["packs"][0]["id"], "tooling");

    let empty = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    owned_fixture::create(
        &environment.join("kitrove.toml"),
        empty.to_toml().unwrap().as_bytes(),
    );
    owned_fixture::create(
        &environment.join("kitrove.lock.json"),
        derive_lockfile(&empty)
            .unwrap()
            .to_json()
            .unwrap()
            .as_bytes(),
    );
    let manifest_before = fs::read(environment.join("kitrove.toml")).unwrap();
    let lock_before = fs::read(environment.join("kitrove.lock.json")).unwrap();
    let mut unconfirmed = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["pack", "adopt", "--pack", "tooling", "--filesystem"])
        .arg(&remote)
        .arg("--environment")
        .arg(&environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    unconfirmed
        .stdin
        .take()
        .unwrap()
        .write_all(b"no\n")
        .unwrap();
    let unconfirmed = unconfirmed.wait_with_output().unwrap();
    assert_eq!(unconfirmed.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&unconfirmed.stderr)
            .contains("error[pack_adopt.confirmation_required]")
    );
    assert_eq!(
        fs::read(environment.join("kitrove.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read(environment.join("kitrove.lock.json")).unwrap(),
        lock_before
    );

    let adopted = Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(["pack", "adopt", "--pack", "tooling", "--filesystem"])
        .arg(&remote)
        .arg("--environment")
        .arg(&environment)
        .args(["--yes", "--json"])
        .output()
        .unwrap();
    assert!(
        adopted.status.success(),
        "{}",
        String::from_utf8_lossy(&adopted.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&adopted.stdout).unwrap();
    assert_eq!(result["operation"], "pack_adopt");
    assert_eq!(result["outcome"], "committed");
    assert_eq!(result["pack_id"], "tooling");

    let committed = EnvironmentManifest::from_toml(
        &fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(committed.assets, distributed.assets);
    assert_eq!(committed.packs.len(), 1);
    assert_eq!(
        committed.packs[&AssetId::parse("tooling").unwrap()],
        distributed.packs[&AssetId::parse("tooling").unwrap()]
    );
    assert_eq!(
        fs::read_to_string(environment.join("kitrove.lock.json")).unwrap(),
        derive_lockfile(&committed).unwrap().to_json().unwrap()
    );
}
