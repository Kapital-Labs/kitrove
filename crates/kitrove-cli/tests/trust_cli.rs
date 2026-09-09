#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use kitrove_adapter_api::{RootId, RootTier};
use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, hash_tree};
use kitrove_core::{
    CapturedNativeExtension, NativeExtensionLayout, NativeExtensionObservation,
    VerifiedObjectEnvelope, commit_native_extension_plan, derive_lockfile,
    plan_native_extension_adoption,
};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, HarnessId, HarnessScope, LocalState, MachineConfig,
    MachineId, PortablePath, SchemaVersion, SyncLimits, TrustDecision,
};
use kitrove_testkit::initialize_empty_authority_fixture;
use serde_json::Value;
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    environment: PathBuf,
    state: PathBuf,
    home: PathBuf,
    working: PathBuf,
    object_hash: kitrove_model::ContentHash,
}

impl Fixture {
    fn new() -> Self {
        let temporary = kitrove_testkit::trusted_tempdir(".kitrove-trust-cli-");
        let root = fs::canonicalize(temporary.path()).unwrap();
        let environment = root.join("environment");
        let state = root.join("state");
        let home = root.join("home");
        let working = root.join("working");
        for directory in [&home, &working] {
            fs::create_dir_all(directory).unwrap();
        }
        let manifest =
            kitrove_model::EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let local_state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("trust-cli-machine").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::from([HarnessId::Pi]),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: vec![],
        };
        let mut initial_state = local_state.clone();
        initial_state.machine.enabled_targets.clear();
        initialize_empty_authority_fixture(&environment, &state, &manifest, &initial_state)
            .unwrap();
        fs::write(state.join("state.json"), local_state.to_json().unwrap()).unwrap();

        let extension_bytes =
            b"require('node:fs').writeFileSync('KITROVE_GATE_G_EXECUTION_SENTINEL', 'ran');\n";
        let files = BTreeMap::from([(
            PortablePath::parse("review.ts").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: extension_bytes.to_vec(),
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
        let plan = plan_native_extension_adoption(
            &observation,
            Some(AssetId::parse("native-review").unwrap()),
            &manifest,
        )
        .unwrap();
        let object = plan.native_object();
        let destination = plan.proposed_manifest().assets
            [&AssetId::parse("native-review").unwrap()]
            .native_variants[&HarnessId::Pi]
            .root
            .clone();
        let envelope =
            VerifiedObjectEnvelope::native_extension(destination, object.clone()).unwrap();
        commit_native_extension_plan(
            &environment,
            &plan,
            &observation,
            &[],
            std::slice::from_ref(&envelope),
            SyncLimits::default(),
        )
        .unwrap();

        let mut mixed_manifest = plan.proposed_manifest().clone();
        let mut unrelated_pi_skill =
            mixed_manifest.assets[&AssetId::parse("native-review").unwrap()].clone();
        unrelated_pi_skill.id = AssetId::parse("ordinary-pi-skill").unwrap();
        unrelated_pi_skill.kind = AssetKind::Skill;
        unrelated_pi_skill.content_class = ContentClass::AgentActive;
        unrelated_pi_skill.refresh_content_hash();
        mixed_manifest
            .assets
            .insert(unrelated_pi_skill.id.clone(), unrelated_pi_skill);
        fs::write(
            environment.join("kitrove.toml"),
            mixed_manifest.to_toml().unwrap(),
        )
        .unwrap();
        fs::write(
            environment.join("kitrove.lock.json"),
            derive_lockfile(&mixed_manifest).unwrap().to_json().unwrap(),
        )
        .unwrap();
        Self {
            _temporary: temporary,
            environment,
            state,
            home,
            working,
            object_hash: object.hash().clone(),
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
}

#[test]
fn trust_plan_and_audit_are_exact_read_only_and_redacted() {
    let fixture = Fixture::new();
    let before = fs::read(fixture.state.join("state.json")).unwrap();
    let planned = fixture
        .command()
        .args([
            "trust",
            "plan",
            "--asset",
            "native-review",
            "--decision",
            "trusted",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(planned.status.code(), Some(0), "{}", stderr(&planned));
    let planned_json = json(&planned);
    assert_eq!(planned_json["object_hash"], fixture.object_hash.as_str());
    assert_eq!(planned_json["disposition"], "first");
    assert_eq!(planned_json["harness"], "pi");
    assert_eq!(
        object_keys(&planned_json),
        BTreeSet::from([
            "asset_id",
            "decision",
            "disposition",
            "harness",
            "object_hash",
            "operation",
            "phase",
            "plan_digest",
            "schema_version",
        ])
    );
    assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);
    let digest = planned_json["plan_digest"].as_str().unwrap().to_owned();

    let wrong = fixture
        .command()
        .args([
            "trust",
            "apply",
            "--asset",
            "native-review",
            "--decision",
            "trusted",
            "--confirm",
            &format!("blake3:{}", "0".repeat(64)),
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(wrong.status.code(), Some(1));
    assert!(stderr(&wrong).contains("trust.confirmation_mismatch"));
    assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), before);

    let audit = fixture
        .command()
        .args([
            "trust",
            "audit",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(audit.status.code(), Some(3), "{}", stderr(&audit));
    let audit_json = json(&audit);
    assert_eq!(audit_json["objects"][0]["status"], "unreviewed");
    assert_eq!(audit_json["objects"][0]["harness"], "pi");
    assert_eq!(
        object_keys(&audit_json),
        BTreeSet::from(["objects", "operation", "phase", "schema_version"])
    );
    assert_eq!(
        object_keys(&audit_json["objects"][0]),
        BTreeSet::from(["asset_id", "harness", "object_hash", "status"])
    );

    let applied = fixture
        .command()
        .args([
            "trust",
            "apply",
            "--asset",
            "native-review",
            "--decision",
            "trusted",
            "--confirm",
            &digest,
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let applied_json = json(&applied);
    assert_eq!(applied_json["disposition"], "first");
    assert_eq!(
        object_keys(&applied_json),
        BTreeSet::from([
            "asset_id",
            "decision",
            "disposition",
            "harness",
            "object_hash",
            "operation",
            "phase",
            "plan_digest",
            "schema_version",
        ])
    );
    let applied_state =
        LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(
        applied_state.machine.enabled_targets,
        BTreeSet::from([HarnessId::Pi])
    );
    let trusted_audit = fixture
        .command()
        .args([
            "trust",
            "audit",
            "--environment",
            fixture.environment.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        trusted_audit.status.code(),
        Some(0),
        "{}",
        stderr(&trusted_audit)
    );
    assert_eq!(json(&trusted_audit)["objects"][0]["status"], "trusted");

    let manifest_text = fs::read_to_string(fixture.environment.join("kitrove.toml")).unwrap();
    let mut manifest = kitrove_model::EnvironmentManifest::from_toml(&manifest_text).unwrap();
    manifest
        .assets
        .remove(&AssetId::parse("ordinary-pi-skill").unwrap());
    fs::write(
        fixture.environment.join("kitrove.toml"),
        manifest.to_toml().unwrap(),
    )
    .unwrap();

    let state_before_refusal = fs::read(fixture.state.join("state.json")).unwrap();
    let extension_plan = fixture
        .command()
        .args([
            "plan",
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
    assert_eq!(extension_plan.status.code(), Some(1));
    assert!(stderr(&extension_plan).contains("error[apply.harness_version_unverified]"));
    assert!(extension_plan.stdout.is_empty());

    let extension_text_plan = fixture
        .command()
        .args([
            "plan",
            "--target",
            "pi",
            "--scope",
            "user",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(extension_text_plan.status.code(), Some(1));
    assert!(stderr(&extension_text_plan).contains("error[apply.harness_version_unverified]"));
    assert!(extension_text_plan.stdout.is_empty());

    let mut apply = fixture.command();
    apply
        .args([
            "apply",
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
    let mut child = apply.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let extension_apply = child.wait_with_output().unwrap();
    assert_eq!(extension_apply.status.code(), Some(1));
    assert!(stderr(&extension_apply).contains("error[apply.harness_version_unverified]"));
    assert!(extension_apply.stdout.is_empty());
    assert!(!fixture.home.join(".pi/agent/extensions/review.ts").exists());
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        state_before_refusal
    );
    assert!(
        !fixture
            .working
            .join("KITROVE_GATE_G_EXECUTION_SENTINEL")
            .exists()
    );

    let mut state =
        LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
            .unwrap();
    state.trust.insert(
        fixture.object_hash.clone(),
        TrustDecision::Denied {
            rationale: "TRUST-CLI-PRIVATE-CANARY".to_owned(),
        },
    );
    fs::write(fixture.state.join("state.json"), state.to_json().unwrap()).unwrap();
    let denied = fixture
        .command()
        .args([
            "trust",
            "audit",
            "--asset",
            "native-review",
            "--environment",
            fixture.environment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(3), "{}", stderr(&denied));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        stderr(&denied)
    );
    assert!(combined.contains("denied"));
    assert!(!combined.contains("TRUST-CLI-PRIVATE-CANARY"));
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn object_keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
