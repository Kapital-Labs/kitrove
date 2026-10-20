use super::*;
use std::path::{Path, PathBuf};
use std::process::Output;

struct Fixture {
    _temporary: tempfile::TempDir,
    environment: PathBuf,
    remote: PathBuf,
    prior: ContentHash,
    target: ContentHash,
}

fn publish(remote: &Path, manifest: &EnvironmentManifest, marker: char) {
    let limits = SyncLimits::default();
    let backend = FilesystemSyncBackend::open(remote).unwrap();
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
}

impl Fixture {
    fn new(rollback: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let environment = root.join("environment");
        let remote = root.join("remote");
        fs::create_dir(&environment).unwrap();
        fs::create_dir(&remote).unwrap();
        let historical = manifest();
        let pack = AssetId::parse("tooling").unwrap();
        let target = historical.packs[&pack].content_hash.clone();
        publish(&remote, &historical, 'a');
        let mut current = historical.clone();
        let alpha = current
            .assets
            .get_mut(&AssetId::parse("alpha").unwrap())
            .unwrap();
        alpha.content_class = ContentClass::AgentActive;
        alpha.refresh_content_hash();
        current.refresh_pack_revisions().unwrap();
        let prior = current.packs[&pack].content_hash.clone();
        let local = if rollback {
            publish(&remote, &current, 'b');
            current
        } else {
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: BTreeSet::new(),
            }
        };
        owned_fixture::create(
            &environment.join("kitrove.toml"),
            local.to_toml().unwrap().as_bytes(),
        );
        owned_fixture::create(
            &environment.join("kitrove.lock.json"),
            derive_lockfile(&local)
                .unwrap()
                .to_json()
                .unwrap()
                .as_bytes(),
        );
        Self {
            _temporary: temporary,
            environment,
            remote,
            prior,
            target,
        }
    }

    fn run(&self, rollback: bool, flags: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command.args([
            "pack",
            if rollback { "rollback" } else { "adopt" },
            "--pack",
            "tooling",
        ]);
        if rollback {
            command.args([
                "--expected-prior",
                self.prior.as_str(),
                "--to",
                self.target.as_str(),
            ]);
        }
        command
            .arg("--filesystem")
            .arg(&self.remote)
            .arg("--environment")
            .arg(&self.environment)
            .arg("--json")
            .args(flags)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn authority(&self) -> [Vec<u8>; 2] {
        ["kitrove.toml", "kitrove.lock.json"]
            .map(|path| fs::read(self.environment.join(path)).unwrap())
    }
}

#[test]
fn import_and_rollback_preview_and_exact_approval_use_closed_stdin() {
    for rollback in [false, true] {
        let fixture = Fixture::new(rollback);
        let before = fixture.authority();
        let preview = fixture.run(rollback, &["--plan"]);
        assert!(preview.status.success(), "{preview:?}");
        assert!(preview.stderr.is_empty());
        assert_eq!(fixture.authority(), before);
        let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        let digest = plan["digest"].as_str().unwrap();
        let wrong = fixture.run(
            rollback,
            &["--confirm", ContentHash::digest(b"wrong").as_str()],
        );
        assert_eq!(wrong.status.code(), Some(1), "{wrong:?}");
        assert_eq!(fixture.authority(), before);
        let committed = fixture.run(rollback, &["--confirm", digest]);
        assert!(committed.status.success(), "{committed:?}");
        assert!(committed.stderr.is_empty());
        assert_ne!(fixture.authority(), before);
        assert!(
            !fixture
                .environment
                .join(".kitrove/adoption-journal.json")
                .exists()
        );
    }
}

#[test]
fn import_approval_preserves_pending_journal_and_authority() {
    for rollback in [false, true] {
        let fixture = Fixture::new(rollback);
        let preview = fixture.run(rollback, &["--plan"]);
        assert!(preview.status.success(), "{preview:?}");
        let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        let journal = fixture.environment.join(".kitrove/adoption-journal.json");
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        owned_fixture::create(&journal, b"pending-canary");
        let before = fixture.authority();
        for flags in [
            vec!["--plan"],
            vec!["--confirm", plan["digest"].as_str().unwrap()],
        ] {
            let result = fixture.run(rollback, &flags);
            assert_eq!(result.status.code(), Some(1), "{result:?}");
            assert_eq!(fixture.authority(), before);
            assert_eq!(fs::read(&journal).unwrap(), b"pending-canary");
        }
    }
}

#[test]
fn import_approval_flags_conflict_with_each_other_and_legacy_yes() {
    for rollback in [false, true] {
        let fixture = Fixture::new(rollback);
        let digest = ContentHash::digest(b"approval");
        let before = fixture.authority();
        for flags in [
            vec!["--plan", "--plan"],
            vec!["--plan", "--confirm", digest.as_str()],
            vec!["--confirm", digest.as_str(), "--plan"],
            vec!["--confirm", digest.as_str(), "--confirm", digest.as_str()],
            vec!["--yes", "--plan"],
            vec!["--plan", "--yes"],
            vec!["--yes", "--confirm", digest.as_str()],
            vec!["--confirm", digest.as_str(), "--yes"],
            vec!["--confirm", "invalid"],
        ] {
            let result = fixture.run(rollback, &flags);
            assert_eq!(result.status.code(), Some(2), "{result:?}");
            assert_eq!(fixture.authority(), before);
        }
    }
}

#[test]
fn changed_selected_authority_cannot_consume_old_import_approval() {
    for rollback in [false, true] {
        let fixture = Fixture::new(rollback);
        let preview = fixture.run(rollback, &["--plan"]);
        assert!(preview.status.success(), "{preview:?}");
        let plan: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
        let mut changed = manifest();
        let alpha = changed
            .assets
            .get_mut(&AssetId::parse("alpha").unwrap())
            .unwrap();
        alpha.content_class = ContentClass::AgentActive;
        alpha.refresh_content_hash();
        changed.refresh_pack_revisions().unwrap();
        if rollback {
            // Replace current local authority with the historical revision, making
            // the separately supplied expected-prior stale.
            let local = manifest();
            fs::write(
                fixture.environment.join("kitrove.toml"),
                local.to_toml().unwrap(),
            )
            .unwrap();
            fs::write(
                fixture.environment.join("kitrove.lock.json"),
                derive_lockfile(&local).unwrap().to_json().unwrap(),
            )
            .unwrap();
        } else {
            publish(&fixture.remote, &changed, 'b');
        }
        let before = fixture.authority();
        let refused = fixture.run(rollback, &["--confirm", plan["digest"].as_str().unwrap()]);
        assert_eq!(refused.status.code(), Some(1), "{refused:?}");
        assert_eq!(fixture.authority(), before);
    }
}
