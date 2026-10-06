//! Preservation of typed synthetic state, not remote-content validation or credential use.
use super::*;
use kitrove_model::*;
use std::collections::BTreeSet;

fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn hash(c: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", c.to_string().repeat(64))).unwrap()
}

pub(super) fn populated(path: &Path, harness: &Path) {
    let deployed = harness.join("review.txt");
    file(&deployed, b"synthetic managed content, preserve exactly\n");
    file(&harness.join("unmanaged.txt"), CANARY.as_bytes());
    let local = LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("populated-fixture").unwrap(),
            active_profile: Some(ProfileId::parse("default").unwrap()),
            enabled_targets: BTreeSet::from([HarnessId::Claude]),
            harness_roots: BTreeMap::from([(
                HarnessId::Claude,
                harness.to_str().unwrap().to_owned(),
            )]),
        },
        bindings: BTreeMap::from([(
            BindingName::parse("synthetic_token").unwrap(),
            BindingResolver::Environment {
                variable: EnvironmentVariableName::parse("KITROVE_UNSET_ACCEPTANCE_TOKEN").unwrap(),
            },
        )]),
        receipts: BTreeMap::from([(
            ReceiptId::parse("synthetic-receipt").unwrap(),
            DeploymentReceipt {
                asset_id: AssetId::parse("review").unwrap(),
                harness: HarnessId::Claude,
                scope: HarnessScope::User,
                destination: NormalizedDestination::parse(deployed.to_str().unwrap()).unwrap(),
                target: Default::default(),
                logical_key: None,
                shared_with: BTreeSet::new(),
                shared_adapter_versions: BTreeMap::new(),
                source_hash: hash('a'),
                rendered_hash: hash('b'),
                document_hash: None,
                prior_hash: None,
                adapter_version: "fixture-adapter/1".into(),
                environment_revision: Revision::parse("fixture-revision").unwrap(),
            },
        )]),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::from([(
            hash('a'),
            TrustDecision::Trusted {
                rationale: "synthetic fixture only".into(),
            },
        )]),
        scans: vec![ScanRecord {
            harness: HarnessId::Claude,
            observed_at: "2026-09-27T00:00:00Z".into(),
            discovered_assets: 1,
        }],
    };
    let encoded = local.to_json().unwrap();
    assert_eq!(LocalState::from_json(&encoded).unwrap(), local);
    let _authority = state(path, encoded.as_bytes());
    let remote = RemoteKey::parse(format!("remote:blake3:{}", "1".repeat(64))).unwrap();
    let object = ObjectDescriptor::new(
        SnapshotObjectKind::PortableSkillTree,
        PortablePath::parse("objects/fixture").unwrap(),
        hash('c'),
        CANARY.len() as u64,
    )
    .unwrap();
    // Identifiers are synthetic. The installer validates schema/selection, not these
    // object hashes against a real remote or the content of this test envelope.
    let record = SyncBaseRecord::new(
        remote.clone(),
        SnapshotDigest::parse(format!("snapshot:blake3:{}", "2".repeat(64))).unwrap(),
        Revision::parse("fixture-revision").unwrap(),
        RemoteRevision::parse("fixture-backend").unwrap(),
        BTreeSet::from([object]),
        SyncLimits::default(),
    )
    .unwrap();
    let record_json = record.to_json(SyncLimits::default()).unwrap();
    let generation = SyncBaseRecord::generation_id_for_json(&record_json);
    let remote_path = path.join("sync").join("1".repeat(64));
    let base = remote_path
        .join("bases")
        .join(generation.as_str().strip_prefix("blake3:").unwrap());
    for dir in [
        path.join("sync"),
        remote_path.clone(),
        remote_path.join("bases"),
        base.clone(),
        base.join("objects"),
        base.join("objects/fixture"),
    ] {
        directory(&dir);
    }
    file(&base.join("base.json"), record_json.as_bytes());
    file(&base.join("base-manifest.toml"), b"schema_version = 1\n");
    file(&base.join("objects/fixture/canary.txt"), CANARY.as_bytes());
    file(
        &remote_path.join("base-current.json"),
        SyncBasePointer::new(remote, generation)
            .to_json()
            .unwrap()
            .as_bytes(),
    );
}

#[test]
#[ignore = "operator-only pinned A/B lifecycle acceptance with durable synthetic state"]
fn real_aba_preserves_populated_state_and_sync_controls() {
    let evidence = PathBuf::from(
        std::env::var_os("KITROVE_TEST_RELEASE_EVIDENCE").expect("evidence directory"),
    );
    let root = tempfile::Builder::new()
        .prefix("populated-state-")
        .tempdir_in(&evidence)
        .unwrap()
        .keep();
    println!("preserved populated-state evidence: {}", root.display());
    let destination = root.join("destination");
    let harness = root.join("synthetic-harness");
    directory(&destination);
    directory(&harness);
    file(&destination.join("unmanaged.txt"), CANARY.as_bytes());
    let first = root.join("state-a");
    let second = root.join("state-b");
    populated(&first, &harness);
    let _second = state(&second, VALID);
    let before = [snapshot(&first), snapshot(&second), snapshot(&harness)];
    let unmanaged = snapshot(&destination.join("unmanaged.txt"));
    let roots: Vec<String> = vec![
        "--destination".into(),
        destination.to_str().unwrap().into(),
        "--state-root".into(),
        first.to_str().unwrap().into(),
        "--state-root".into(),
        second.to_str().unwrap().into(),
    ];
    for (phase, candidate_b, prior_b, actions, digest) in [
        (
            "install",
            false,
            None,
            ["preflight-install", "install", "retire-install"],
            pins::EXECUTABLE_DIGESTS[0],
        ),
        (
            "upgrade",
            true,
            Some(false),
            ["preflight-upgrade", "upgrade", "retire-upgrade"],
            pins::EXECUTABLE_DIGESTS[1],
        ),
        (
            "rollback",
            false,
            Some(true),
            ["preflight-rollback", "rollback", "retire-rollback"],
            pins::EXECUTABLE_DIGESTS[0],
        ),
    ] {
        for action in actions {
            let preflight_snapshot = action
                .starts_with("preflight-")
                .then(|| snapshot(&destination));
            let mut args = vec![action.to_owned()];
            args.extend(release(&evidence, false, candidate_b));
            if let Some(b) = prior_b {
                let prior = release(&evidence, true, b);
                for pair in prior.chunks_exact(2) {
                    if action.starts_with("retire-")
                        && matches!(pair[0].as_str(), "--prior-archive" | "--prior-bundle")
                    {
                        continue;
                    }
                    args.extend_from_slice(pair);
                }
            }
            args.extend(roots.clone());
            invoke(&root, action, &args, None);
            assert_eq!(
                before,
                [snapshot(&first), snapshot(&second), snapshot(&harness)]
            );
            assert_eq!(unmanaged, snapshot(&destination.join("unmanaged.txt")));
            if let Some(preflight) = preflight_snapshot {
                assert_eq!(preflight, snapshot(&destination));
            } else {
                use std::fmt::Write as _;
                let mut observed = String::with_capacity(64);
                for byte in Sha256::digest(fs::read(destination.join("kitrove")).unwrap()) {
                    write!(&mut observed, "{byte:02x}").unwrap();
                }
                assert_eq!(observed, digest);
            }
        }
        println!(
            "{phase}: state, sync controls, harness and unmanaged file unchanged; executable {digest}"
        );
    }
}
