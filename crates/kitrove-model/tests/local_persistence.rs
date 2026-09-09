use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    AssetId, BindingName, BindingResolver, ContentHash, DeploymentReceipt, EnvironmentManifest,
    EnvironmentVariableName, HarnessId, HarnessScope, LocalState, MachineConfig, MachineId,
    NormalizedDestination, PackApplicationClaim, ProfileId, ReceiptId, Revision, ScanRecord,
    SchemaVersion, TrustDecision,
};

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).expect("test hash")
}

fn local_state() -> LocalState {
    let machine = MachineConfig {
        id: MachineId::parse("work-laptop").expect("machine id"),
        active_profile: Some(ProfileId::parse("default").expect("profile id")),
        enabled_targets: BTreeSet::from([HarnessId::Claude, HarnessId::Codex]),
        harness_roots: BTreeMap::from([
            (HarnessId::Claude, "/Users/test/.claude".to_owned()),
            (HarnessId::Codex, "/Users/test/.codex".to_owned()),
        ]),
    };
    let binding = BindingName::parse("github_mcp_token").expect("binding name");
    let receipt_id = ReceiptId::parse("review-claude-user").expect("receipt id");

    LocalState {
        schema_version: SchemaVersion::V1,
        machine,
        bindings: BTreeMap::from([(
            binding,
            BindingResolver::Environment {
                variable: EnvironmentVariableName::parse("KITROVE_TEST_SECRET")
                    .expect("environment variable"),
            },
        )]),
        receipts: BTreeMap::from([(
            receipt_id,
            DeploymentReceipt {
                asset_id: AssetId::parse("review").expect("asset id"),
                harness: HarnessId::Claude,
                scope: HarnessScope::User,
                destination: NormalizedDestination::parse("/Users/test/.claude/skills/review")
                    .expect("destination"),
                target: Default::default(),
                logical_key: None,
                shared_with: BTreeSet::new(),
                shared_adapter_versions: BTreeMap::new(),
                source_hash: hash('a'),
                rendered_hash: hash('b'),
                document_hash: None,
                prior_hash: None,
                adapter_version: "claude-adapter/1".to_owned(),
                environment_revision: Revision::parse("env:0001").expect("revision"),
            },
        )]),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::from([(
            hash('a'),
            TrustDecision::Trusted {
                rationale: "reviewed local copy".to_owned(),
            },
        )]),
        scans: vec![ScanRecord {
            harness: HarnessId::Claude,
            observed_at: "2026-08-22T12:00:00Z".to_owned(),
            discovered_assets: 1,
        }],
    }
}

#[test]
fn local_state_round_trips_receipts_and_symbolic_resolvers() {
    let state = local_state();
    let encoded = state.to_json().expect("serialize local state");
    let decoded = LocalState::from_json(&encoded).expect("deserialize local state");

    assert!(encoded.contains("\"scope\": \"user\""));
    assert_eq!(decoded, state);
    assert_eq!(decoded.to_json().expect("serialize again"), encoded);
}

#[test]
fn pack_application_identity_binds_context_but_not_mutable_revision_or_receipts() {
    let claim = PackApplicationClaim {
        pack_id: AssetId::parse("tooling").unwrap(),
        pack_revision: hash('c'),
        scope: HarnessScope::User,
        target_anchor: NormalizedDestination::parse("/Users/test").unwrap(),
        targets: BTreeSet::from([HarnessId::Codex]),
        receipts: BTreeSet::from([ReceiptId::parse("receipt-a").unwrap()]),
    };
    let identity = claim.application_id().unwrap();
    let mut mutable_evidence = claim.clone();
    mutable_evidence.pack_revision = hash('d');
    mutable_evidence.receipts = BTreeSet::from([ReceiptId::parse("receipt-b").unwrap()]);
    assert_eq!(mutable_evidence.application_id().unwrap(), identity);

    let mut changed_context = claim;
    changed_context.targets.insert(HarnessId::Claude);
    assert_ne!(changed_context.application_id().unwrap(), identity);
    let debug = format!("{changed_context:?}");
    assert!(!debug.contains("tooling"));
    assert!(!debug.contains("/Users/test"));
    assert!(!debug.contains(changed_context.pack_revision.as_str()));
}

#[test]
fn portable_output_excludes_machine_local_state() {
    let portable = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::from([
            BindingName::parse("github_mcp_token").expect("binding name")
        ]),
    }
    .to_toml()
    .expect("serialize portable manifest");
    let local = local_state().to_json().expect("serialize local state");

    assert!(portable.contains("github_mcp_token"));
    assert!(!portable.contains("KITROVE_TEST_SECRET"));
    assert!(!portable.contains("work-laptop"));
    assert!(!portable.contains("/Users/test/.claude"));
    assert!(local.contains("KITROVE_TEST_SECRET"));
    assert!(local.contains("work-laptop"));
}

#[test]
fn local_binding_schema_cannot_represent_a_resolved_value() {
    let input = r#"
{
  "schema_version": 1,
  "machine": {
    "id": "laptop",
    "active_profile": null,
    "enabled_targets": [],
    "harness_roots": {}
  },
  "bindings": {
    "github_mcp_token": {
      "type": "value",
      "value": "canary-secret"
    }
  },
  "receipts": {},
  "trust": {},
  "scans": []
}
"#;
    assert!(LocalState::from_json(input).is_err());
}

#[test]
fn local_schema_rejects_unknown_fields() {
    let encoded = local_state().to_json().expect("serialize local state");
    let with_unknown = encoded.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"oauth_token\": \"canary\",",
        1,
    );
    assert!(LocalState::from_json(&with_unknown).is_err());
}
