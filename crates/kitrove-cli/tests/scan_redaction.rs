#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kitrove_adapter_api::{
    EnvironmentInput, FindingSubject, LocalStateInput, ProjectBoundary, ScanLimits, ScanRequest,
    ScopeSelection,
};
use kitrove_cli::tier_one_registry;
use kitrove_core::{ScanEngine, ScanReport};
use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, HarnessId, HarnessScope, NormalizedDestination,
    Revision,
};
use serde_json::{Map, Value, json};
use tempfile::TempDir;

const REJECTED_CONTENT_CANARY: &str = "KITROVE_REJECTED_CONTENT_CANARY_7f9c75dfe1c44b48a05e";
const MALFORMED_YAML_CANARY: &str = "KITROVE_MALFORMED_YAML_CANARY_8a13e09072aa4b918df4";
const RECEIPT_FIELD_CANARY: &str = "KITROVE_RECEIPT_FIELD_CANARY_b401ed4f26bc45ac82a7";
const SYMLINK_TARGET_CANARY: &str = "KITROVE_SYMLINK_TARGET_CANARY_c6b1e437bde44c129f21";
const NATIVE_ID_CANARY: &str = "sk-ant-api03-KITROVE_SECRET_CANARY_42";
const PADDED_NATIVE_ID_CANARY: &str = "\u{200b}sk-ant-api03-KITROVE_SECRET_CANARY_42";
const BENIGN_NATIVE_ID: &str = "\u{200b}sk-analysis";
const CANARIES: [(&str, &str); 5] = [
    ("rejected content", REJECTED_CONTENT_CANARY),
    ("malformed YAML", MALFORMED_YAML_CANARY),
    ("receipt unknown field", RECEIPT_FIELD_CANARY),
    ("symlink target", SYMLINK_TARGET_CANARY),
    ("Pi native ID", NATIVE_ID_CANARY),
];
const HASH: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

struct RedactionFixture {
    _tempdir: TempDir,
    root: PathBuf,
    home: PathBuf,
    working: PathBuf,
    environment: PathBuf,
    state_home: PathBuf,
    fake_bin: PathBuf,
    sentinel: PathBuf,
    symlink_target: PathBuf,
    local_state_json: String,
}

impl RedactionFixture {
    fn create() -> Self {
        let tempdir = tempfile::tempdir().expect("temporary fixture root");
        let root = fs::canonicalize(tempdir.path()).expect("canonical fixture root");
        let home = root.join("home");
        let working = root.join("project");
        let environment = root.join("environment");
        let state_home = root.join("state-home");
        let fake_bin = root.join("fake-bin");
        let sentinel = root.join("process-sentinel");
        let symlink_target = root.join("outside-symlink-target.txt");
        let skills = home.join(".claude/skills");
        let pi_skills = home.join(".pi/agent/skills");

        for directory in [
            &home,
            &working,
            &environment,
            &state_home,
            &fake_bin,
            &sentinel,
            &skills,
            &pi_skills,
        ] {
            fs::create_dir_all(directory).expect("fixture directory");
        }
        fs::create_dir_all(working.join(".git")).expect("repository marker");
        fs::write(environment.join("kitrove.toml"), "schema_version = 1\n")
            .expect("manifest input");

        let rejected = skills.join("rejected-content");
        fs::create_dir_all(&rejected).expect("rejected source");
        fs::write(
            rejected.join("SKILL.md"),
            format!(
                "---\nname: rejected-content\ndescription: Rejected content fixture.\nmetadata:\n  api_key: {REJECTED_CONTENT_CANARY}\n---\n# Rejected\n"
            ),
        )
        .expect("rejected content canary");

        let malformed = skills.join("malformed-yaml");
        fs::create_dir_all(&malformed).expect("malformed source");
        fs::write(
            malformed.join("SKILL.md"),
            format!(
                "---\nname: [{MALFORMED_YAML_CANARY}\ndescription: Malformed YAML fixture.\n---\n# Broken\n"
            ),
        )
        .expect("malformed YAML canary");

        let symlinked = skills.join("symlinked-source");
        fs::create_dir_all(&symlinked).expect("symlink source");
        fs::write(
            symlinked.join("SKILL.md"),
            "---\nname: symlinked-source\ndescription: Symlink fixture.\n---\n# Safe principal\n",
        )
        .expect("symlink source principal");
        fs::write(&symlink_target, SYMLINK_TARGET_CANARY).expect("symlink target canary");
        create_file_symlink(&symlink_target, &symlinked.join("support.txt"));

        for (container, native_id) in [
            ("credential-shaped", PADDED_NATIVE_ID_CANARY),
            ("benign", BENIGN_NATIVE_ID),
        ] {
            let skill = pi_skills.join(container);
            fs::create_dir_all(&skill).expect("Pi skill directory");
            fs::write(
                skill.join("SKILL.md"),
                format!(
                    "---\nname: \"{native_id}\"\ndescription: Pi native ID redaction fixture.\n---\n# Safe body\n"
                ),
            )
            .expect("Pi skill fixture");
        }

        let receipt = DeploymentReceipt {
            asset_id: AssetId::parse("rejected-content").expect("asset ID"),
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            destination: normalized_destination(&rejected),
            target: Default::default(),
            logical_key: None,
            shared_with: Default::default(),
            shared_adapter_versions: Default::default(),
            source_hash: ContentHash::parse(HASH).expect("source hash"),
            rendered_hash: ContentHash::digest(b"rejected receipt fixture"),
            document_hash: None,
            prior_hash: None,
            adapter_version: "acceptance/1".to_owned(),
            environment_revision: Revision::parse(format!(
                "manifest:blake3:{}",
                &HASH["blake3:".len()..]
            ))
            .expect("environment revision"),
        };
        let receipt_id = receipt.receipt_id().expect("receipt identity");
        let mut receipt_value = serde_json::to_value(receipt)
            .expect("receipt JSON")
            .as_object()
            .expect("receipt object")
            .clone();
        receipt_value.insert(
            "unknown_secret_field".to_owned(),
            Value::String(RECEIPT_FIELD_CANARY.to_owned()),
        );
        let local_state_json = serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "machine": {
                "id": "redaction-machine",
                "active_profile": null,
                "enabled_targets": [],
                "harness_roots": {}
            },
            "bindings": {},
            "receipts": Map::from_iter([(receipt_id.as_str().to_owned(), Value::Object(receipt_value))]),
            "trust": {},
            "scans": []
        }))
        .expect("local state JSON");
        fs::write(state_home.join("state.json"), &local_state_json).expect("local state input");

        install_fake_executables(&fake_bin);

        Self {
            _tempdir: tempdir,
            root,
            home,
            working,
            environment,
            state_home,
            fake_bin,
            sentinel,
            symlink_target,
            local_state_json,
        }
    }

    fn command(&self, json: bool) -> Command {
        let inherited_path = env::var_os("PATH").unwrap_or_default();
        let path = env::join_paths(
            std::iter::once(self.fake_bin.as_os_str().to_owned())
                .chain(env::split_paths(&inherited_path).map(|path| path.into_os_string())),
        )
        .expect("fake executable PATH");
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.working)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.root.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state_home)
            .env("KITROVE_ACCEPTANCE_SENTINEL", &self.sentinel)
            .env("PATH", path)
            .env("PATHEXT", ".CMD;.EXE;.BAT")
            .env_remove("KITROVE_ENV")
            .args([
                "scan",
                "--scope",
                "all",
                "--environment",
                self.environment.to_str().unwrap(),
            ]);
        if json {
            command.arg("--json");
        }
        command
    }

    fn run(&self, json: bool) -> Output {
        self.command(json).output().expect("run kitrove scan")
    }

    fn report(&self) -> ScanReport {
        let manifest = fs::read(self.environment.join("kitrove.toml")).expect("manifest bytes");
        let request = ScanRequest {
            home: Some(self.home.clone()),
            working_directory: self.working.clone(),
            project_boundary: ProjectBoundary::Repository {
                root: self.working.clone(),
            },
            harnesses: BTreeSet::from([
                HarnessId::Claude,
                HarnessId::Codex,
                HarnessId::Pi,
                HarnessId::OpenCode,
            ]),
            scopes: ScopeSelection::All,
            explicit_roots: vec![],
            supplied_native_roots: vec![],
            versions: BTreeMap::new(),
            project_trust: BTreeMap::new(),
            environment: Some(EnvironmentInput {
                source_path: self.environment.join("kitrove.toml"),
                toml_bytes: &manifest,
            }),
            local_state: Some(LocalStateInput::Bytes {
                source_path: self.state_home.join("state.json"),
                json_bytes: self.local_state_json.as_bytes(),
            }),
            limits: ScanLimits::default(),
        };
        let registry = tier_one_registry();
        ScanEngine::from_registry(&registry)
            .scan(&request)
            .expect("redacted report")
    }

    fn assert_canaries_are_seeded(&self) {
        let rejected =
            fs::read_to_string(self.home.join(".claude/skills/rejected-content/SKILL.md"))
                .expect("rejected source");
        let malformed =
            fs::read_to_string(self.home.join(".claude/skills/malformed-yaml/SKILL.md"))
                .expect("malformed source");
        let symlink_target = fs::read_to_string(&self.symlink_target).expect("symlink target");
        let pi_secret = fs::read_to_string(
            self.home
                .join(".pi/agent/skills/credential-shaped/SKILL.md"),
        )
        .expect("Pi secret native ID source");
        for ((label, canary), value) in CANARIES.into_iter().zip([
            rejected,
            malformed,
            self.local_state_json.clone(),
            symlink_target,
            pi_secret,
        ]) {
            assert!(
                value.contains(canary),
                "{label} does not contain its distinct canary"
            );
            assert!(
                CANARIES
                    .iter()
                    .filter(|(_, other)| *other != canary)
                    .all(|(_, other)| !value.contains(other)),
                "{label} contains another source's canary"
            );
        }
    }

    fn assert_sentinel_untouched(&self) {
        let touched = fs::read_dir(&self.sentinel)
            .expect("sentinel directory")
            .map(|entry| entry.expect("sentinel entry").file_name())
            .collect::<Vec<_>>();
        assert!(
            touched.is_empty(),
            "scan launched fake commands: {touched:?}"
        );
    }
}

fn normalized_destination(path: &Path) -> NormalizedDestination {
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
    NormalizedDestination::parse(encoded).expect("normalized destination")
}

fn assert_entry_rejection(report: &ScanReport, source: &str, code: &str) {
    let entry = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some(source))
        .unwrap_or_else(|| panic!("missing rejected source {source}"));
    let expected_subject = FindingSubject::Observation(
        entry
            .observation_id
            .clone()
            .unwrap_or_else(|| panic!("rejected source {source} has no observation ID")),
    );
    assert!(
        entry
            .findings
            .iter()
            .any(|finding| finding.code == code && finding.subject == expected_subject),
        "rejected source {source} did not reach {code} with its observation subject: {:?}",
        entry.findings
    );
}

fn assert_rejected_paths_reached(fixture: &RedactionFixture, report: &ScanReport) {
    assert_entry_rejection(report, "rejected-content", "skill.credential_metadata");
    assert_entry_rejection(report, "malformed-yaml", "skill.frontmatter_invalid");
    assert_entry_rejection(report, "symlinked-source", "capture.symlink");

    let expected_subject = FindingSubject::Destination {
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        normalized_destination: normalized_destination(
            &fixture.home.join(".claude/skills/rejected-content"),
        ),
    };
    assert!(
        report.findings.iter().any(|finding| {
            finding.code == "scan.receipt_invalid" && finding.subject == expected_subject
        }),
        "receipt unknown field did not reach scan.receipt_invalid with its destination subject: {:?}",
        report.findings
    );
}

fn assert_pi_native_id_boundaries(report: &ScanReport) {
    assert!(report.entries.iter().any(|entry| {
        entry.harness == HarnessId::Pi && entry.native_id.as_deref() == Some(BENIGN_NATIVE_ID)
    }));
    assert!(!report.entries.iter().any(|entry| {
        entry.native_id.as_deref() == Some(PADDED_NATIVE_ID_CANARY)
            || entry.native_id.as_deref() == Some(NATIVE_ID_CANARY)
    }));
    assert!(report.entries.iter().any(|entry| {
        entry.harness == HarnessId::Pi
            && entry
                .findings
                .iter()
                .any(|finding| finding.code == "skill.credential_artifact")
    }));
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("symlink fixture");
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_file(target, link).expect("symlink fixture");
}

fn install_fake_executables(directory: &Path) {
    for name in ["claude", "codex", "pi", "opencode", "git", "curl", "ssh"] {
        install_fake_executable(directory, name);
    }
}

#[cfg(unix)]
fn install_fake_executable(directory: &Path, name: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join(name);
    fs::write(
        &path,
        format!("#!/bin/sh\n: > \"$KITROVE_ACCEPTANCE_SENTINEL/{name}\"\nexit 99\n"),
    )
    .expect("fake executable");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("fake executable mode");
}

#[cfg(windows)]
fn install_fake_executable(directory: &Path, name: &str) {
    fs::write(
        directory.join(format!("{name}.cmd")),
        format!(
            "@echo off\r\ntype nul > \"%KITROVE_ACCEPTANCE_SENTINEL%\\{name}\"\r\nexit /b 99\r\n"
        ),
    )
    .expect("fake executable");
}

fn assert_output_redacted(label: &str, output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(3),
        "{label} status: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let rendered = String::from_utf8_lossy(bytes);
        for (source, canary) in CANARIES {
            assert!(
                !rendered.contains(canary),
                "{label} {stream} disclosed the {source} canary"
            );
        }
    }
}

fn assert_source_redacted(
    source: &str,
    canary: &str,
    text_output: &Output,
    json_output: &Output,
    debug: &str,
) {
    for (surface, rendered) in [
        ("text", String::from_utf8_lossy(&text_output.stdout)),
        ("text stderr", String::from_utf8_lossy(&text_output.stderr)),
        ("JSON", String::from_utf8_lossy(&json_output.stdout)),
        ("JSON stderr", String::from_utf8_lossy(&json_output.stderr)),
        ("Debug", debug.into()),
    ] {
        assert!(
            !rendered.contains(canary),
            "{surface} disclosed the distinct {source} canary"
        );
    }
}

#[test]
fn rejected_sources_and_receipts_are_redacted_from_text_json_stderr_and_debug() {
    let fixture = RedactionFixture::create();
    fixture.assert_canaries_are_seeded();

    let text = fixture.run(false);
    let json_output = fixture.run(true);
    let report = fixture.report();
    assert_rejected_paths_reached(&fixture, &report);
    assert_pi_native_id_boundaries(&report);
    let debug = format!("{report:?}\n{:?}", report.observations());

    assert_output_redacted("text scan", &text);
    assert_output_redacted("JSON scan", &json_output);
    serde_json::from_slice::<Value>(&json_output.stdout).expect("JSON scan output");
    for (source, canary) in CANARIES {
        assert_source_redacted(source, canary, &text, &json_output, &debug);
    }
    for output in [&text, &json_output] {
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(BENIGN_NATIVE_ID),
            "scan output removed the benign Pi native ID"
        );
    }
    fixture.assert_sentinel_untouched();
}

#[test]
fn scan_never_launches_harness_process_git_or_network_command_sentinels() {
    let fixture = RedactionFixture::create();

    let output = fixture.run(true);

    assert_output_redacted("sentinel scan", &output);
    fixture.assert_sentinel_untouched();
}
