#![cfg(windows)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, Command, Output, Stdio};

use kitrove_adapter_api::{RootId, RootTier};
use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, hash_tree};
use kitrove_core::{
    CapturedNativeExtension, NativeExtensionLayout, NativeExtensionObservation,
    VerifiedObjectEnvelope, commit_native_extension_plan, plan_native_extension_adoption,
};
use kitrove_model::{
    AssetId, BindingName, BindingResolver, ContentClass, ContentHash, EnvironmentManifest,
    HarnessId, HarnessScope, LocalState, MachineConfig, MachineId, PortablePath, SchemaVersion,
    SyncLimits,
};
use kitrove_windows_security::{
    IntegrityFileRead, canonical_directory_path_for_tests, read_bounded_integrity_file,
};

use support::read_until_prompt;

const EMPTY_MANIFEST: &str = "schema_version = 1\n";
struct WindowsCliFixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    working: PathBuf,
    environment: PathBuf,
    state_home: PathBuf,
    executable: PathBuf,
}

impl WindowsCliFixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("kitrove-windows-cli-probe-")
            .tempdir()
            .expect("fixture directory");
        let canonical_root =
            canonical_directory_path_for_tests(root.path()).expect("canonical fixture path");
        let home = canonical_root.join("home");
        let working = canonical_root.join("working");
        let environment = canonical_root.join("environment");
        let state_home = canonical_root.join("state");
        let executable_root = canonical_root.join("supported");
        kitrove_windows_security::ensure_private_directory_for_tests(&home)
            .expect("private fixture home");
        for directory in [&working, &executable_root] {
            std::fs::create_dir(directory).expect("fixture directory");
        }
        let executable = executable_root.join("pi.exe");
        std::fs::copy(
            env!("CARGO_BIN_EXE_kitrove-windows-version-probe-fixture"),
            &executable,
        )
        .expect("copy fixture executable");
        Self {
            _root: root,
            home,
            working,
            environment,
            state_home,
            executable,
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

    fn prepare_trusted_extension(&self) {
        let empty = EnvironmentManifest::from_toml(EMPTY_MANIFEST).unwrap();
        let state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("windows-cli-fixture").unwrap(),
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
        kitrove_testkit::initialize_empty_authority_fixture(
            &self.environment,
            &self.state_home,
            &empty,
            &state,
        )
        .unwrap();
        let files = BTreeMap::from([(
            PortablePath::parse("review.ts").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"export const review = true;\n".to_vec(),
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
        let asset_id = AssetId::parse("review-extension").unwrap();
        let adoption =
            plan_native_extension_adoption(&observation, Some(asset_id.clone()), &empty).unwrap();
        let object = adoption.native_object();
        let destination = adoption.proposed_manifest().assets[&asset_id].native_variants
            [&HarnessId::Pi]
            .root
            .clone();
        let envelope =
            VerifiedObjectEnvelope::native_extension(destination, object.clone()).unwrap();
        commit_native_extension_plan(
            &self.environment,
            &adoption,
            &observation,
            &[],
            std::slice::from_ref(&envelope),
            SyncLimits::default(),
        )
        .unwrap();
        self.trust_extension();
    }

    fn trust_extension(&self) {
        let plan = self
            .command()
            .args([
                "trust",
                "plan",
                "--asset",
                "review-extension",
                "--decision",
                "trusted",
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(plan.status.code(), Some(0), "{}", stderr(&plan));
        let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
        let digest = plan["plan_digest"].as_str().unwrap();
        let applied = self
            .command()
            .args([
                "trust",
                "apply",
                "--asset",
                "review-extension",
                "--decision",
                "trusted",
                "--confirm",
                digest,
                "--environment",
                self.environment.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    }

    fn materialization_command(&self, operation: &str, scope: &str) -> Command {
        let mut command = self.command();
        command.args([
            operation,
            "--asset",
            "review-extension",
            "--target",
            "pi",
            "--scope",
            scope,
            "--version-binary",
            self.executable.to_str().unwrap(),
            "--environment",
            self.environment.to_str().unwrap(),
            "--json",
        ]);
        if scope == "project" {
            command.args(["--project-root", self.working.to_str().unwrap()]);
        }
        command
    }

    fn confirmed_apply(&self) -> Output {
        let mut command = self.materialization_command("apply", "user");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
        child.wait_with_output().unwrap()
    }

    fn save_project_trust(&self, decision: bool) -> PathBuf {
        let pi_directory = self.home.join(".pi");
        kitrove_windows_security::ensure_private_directory_for_tests(&pi_directory).unwrap();
        let directory = pi_directory.join("agent");
        kitrove_windows_security::ensure_private_directory_for_tests(&directory).unwrap();
        let store = directory.join("trust.json");
        let bytes = serde_json::to_vec(&BTreeMap::from([(
            self.working.to_str().unwrap(),
            decision,
        )]))
        .unwrap();
        kitrove_windows_security::write_current_user_owned_file_for_tests(&store, &bytes).unwrap();
        assert_eq!(
            read_bounded_integrity_file(&store, bytes.len()),
            IntegrityFileRead::Bytes(bytes),
            "saved Pi project trust fixture must satisfy the production integrity boundary",
        );
        store
    }

    fn pending_project_apply(&self) -> (Child, ChildStderr, Vec<u8>) {
        let mut command = self.materialization_command("apply", "project");
        command
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
        (child, error_stream, error_bytes)
    }
}

#[test]
fn cli_reports_exact_windows_pi_probe_evidence_without_ambient_state() {
    let fixture = WindowsCliFixture::new();
    let expected_hash = ContentHash::digest(&std::fs::read(&fixture.executable).unwrap());

    let output = fixture
        .command()
        .args([
            "versions",
            "probe",
            "--harness",
            "pi",
            "--binary",
            fixture.executable.to_str().unwrap(),
            "--json",
        ])
        .env("KITROVE_AMBIENT_SECRET_CANARY", "must-not-reach-probe")
        .output()
        .expect("run Kitrove CLI");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-reach-probe"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-reach-probe"));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let evidence = format!(
        "local.version_probe.pi.blake3.{}",
        expected_hash.as_str().strip_prefix("blake3:").unwrap()
    );
    assert_eq!(
        result,
        serde_json::json!({
            "schema_version": 1,
            "harness": "pi",
            "observed": "0.83.0",
            "policy_line": "pi_latest",
            "evidence": evidence,
            "executable_hash": expected_hash.as_str(),
        })
    );
}

#[test]
fn verified_windows_pi_evidence_drives_user_plan_and_apply() {
    let fixture = WindowsCliFixture::new();
    fixture.prepare_trusted_extension();

    let plan = fixture
        .materialization_command("plan", "user")
        .output()
        .unwrap();
    assert_eq!(plan.status.code(), Some(0), "{}", stderr(&plan));
    let plan_json: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan_json["disposition"], "install");

    let applied = fixture.confirmed_apply();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let result: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(result["outcome"], "committed");
    assert_eq!(
        std::fs::read_to_string(fixture.home.join(".pi/agent/extensions/review.ts")).unwrap(),
        "export const review = true;\n"
    );
    assert_single_receipt_scope(&fixture, HarnessScope::User);
}

#[test]
fn verified_windows_saved_project_trust_drives_plan_and_apply() {
    let fixture = WindowsCliFixture::new();
    fixture.prepare_trusted_extension();
    fixture.save_project_trust(true);

    let plan = fixture
        .materialization_command("plan", "project")
        .output()
        .unwrap();
    assert_eq!(plan.status.code(), Some(0), "{}", stderr(&plan));
    let plan_json: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan_json["disposition"], "install");

    let mut command = fixture.materialization_command("apply", "project");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let applied = child.wait_with_output().unwrap();
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let result: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(result["outcome"], "committed");
    assert_eq!(
        std::fs::read_to_string(fixture.working.join(".pi/extensions/review.ts")).unwrap(),
        "export const review = true;\n"
    );
    assert_single_receipt_scope(&fixture, HarnessScope::Project);
}

#[test]
fn windows_project_apply_revalidates_saved_trust_after_confirmation() {
    let fixture = WindowsCliFixture::new();
    fixture.prepare_trusted_extension();
    fixture.save_project_trust(true);
    let (child, error_stream, error_bytes) = fixture.pending_project_apply();
    fixture.save_project_trust(false);
    let (output, error_bytes) = confirm_pending(child, error_stream, error_bytes);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&error_bytes).contains("error[apply.project_trust_declined]"),
        "{}",
        String::from_utf8_lossy(&error_bytes)
    );
    assert!(!fixture.working.join(".pi/extensions/review.ts").exists());
}

#[test]
fn windows_project_apply_revalidates_acl_authority_after_confirmation() {
    let fixture = WindowsCliFixture::new();
    fixture.prepare_trusted_extension();
    let trust_store = fixture.save_project_trust(true);
    let state_before = std::fs::read(fixture.state_home.join("state.json")).unwrap();
    let manifest_before = std::fs::read(fixture.environment.join("kitrove.toml")).unwrap();
    let lock_before = std::fs::read(fixture.environment.join("kitrove.lock.json")).unwrap();
    let (child, error_stream, error_bytes) = fixture.pending_project_apply();
    kitrove_windows_security::grant_world_file_mutation_for_tests(&trust_store).unwrap();
    let (output, error_bytes) = confirm_pending(child, error_stream, error_bytes);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&error_bytes).contains("error[pi.project_trust_store_unsafe]"),
        "{}",
        String::from_utf8_lossy(&error_bytes)
    );
    assert!(!fixture.working.join(".pi/extensions/review.ts").exists());
    assert_eq!(
        std::fs::read(fixture.state_home.join("state.json")).unwrap(),
        state_before
    );
    assert_eq!(
        std::fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        std::fs::read(fixture.environment.join("kitrove.lock.json")).unwrap(),
        lock_before
    );
}

#[test]
fn windows_apply_reprobes_exact_executable_before_confirmation() {
    let fixture = WindowsCliFixture::new();
    fixture.prepare_trusted_extension();
    let mut command = fixture.materialization_command("apply", "user");
    command
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

    std::fs::OpenOptions::new()
        .append(true)
        .open(&fixture.executable)
        .unwrap()
        .write_all(&[0])
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    error_stream.read_to_end(&mut error_bytes).unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&error_bytes).contains("error[apply.plan_stale]"),
        "{}",
        String::from_utf8_lossy(&error_bytes)
    );
    assert!(!fixture.home.join(".pi/agent/extensions/review.ts").exists());
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_single_receipt_scope(fixture: &WindowsCliFixture, expected: HarnessScope) {
    let state = LocalState::from_json(
        &std::fs::read_to_string(fixture.state_home.join("state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.receipts.values().next().unwrap().scope, expected);
}

fn confirm_pending(
    mut child: Child,
    mut error_stream: ChildStderr,
    mut error_bytes: Vec<u8>,
) -> (Output, Vec<u8>) {
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    error_stream.read_to_end(&mut error_bytes).unwrap();
    (child.wait_with_output().unwrap(), error_bytes)
}
