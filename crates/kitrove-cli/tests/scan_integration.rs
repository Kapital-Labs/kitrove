#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kitrove_adapter_api::{
    EnvironmentInput, EvidenceRef, HarnessVersion, LocalStateInput, NativeRootKey, PolicyLine,
    ProjectBoundary, ProjectTrustKey, ProjectTrustObservation, RootContext, RootTier, ScanLimits,
    ScanRequest, ScopeSelection, SuppliedNativeRoot, VerifiedVersionEvidence, VersionObservation,
    VersionObservationOwned,
};
use kitrove_cli::tier_one_registry;
use kitrove_core::{
    ScanClassification, ScanEngine, ScanReport, render_scan_json, render_scan_text,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, ComponentProvenance, ContentClass, ContentHash, DeploymentReceipt,
    EnvironmentManifest, HarnessId, HarnessScope, LocalState, MachineConfig, MachineId,
    NormalizedDestination, PortableContent, PortablePath, Revision, SchemaVersion, Source,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const DESCRIPTION: &str = "A complete Gate C2 acceptance fixture.";

struct AcceptanceFixture {
    _tempdir: TempDir,
    home: PathBuf,
    project: PathBuf,
    environment: PathBuf,
    state_home: PathBuf,
    codex_system: PathBuf,
    opencode_built_in: PathBuf,
    manifest_toml: String,
    local_state_json: String,
}

impl AcceptanceFixture {
    fn create() -> Self {
        let tempdir = tempfile::tempdir().expect("temporary acceptance root");
        let root = fs::canonicalize(tempdir.path()).expect("canonical acceptance root");
        let home = root.join("home");
        let project = root.join("project");
        let environment = root.join("environment");
        let state_home = root.join("state-home");
        let codex_system = root.join("codex-system");
        let opencode_built_in = root.join("opencode-built-in");
        for directory in [
            &home,
            &project,
            &environment,
            &state_home,
            &codex_system,
            &opencode_built_in,
        ] {
            fs::create_dir_all(directory).expect("acceptance fixture directory");
        }
        fs::create_dir_all(project.join(".git")).expect("repository marker");

        let (managed_directory, managed_directory_bytes) =
            directory_skill(&home.join(".claude/skills"), "managed-dir", "managed-dir");
        directory_skill(
            &home.join(".claude/skills"),
            "shared-shadow",
            "shared-shadow",
        );
        directory_skill(
            &project.join(".claude/skills"),
            "shared-shadow",
            "shared-shadow",
        );
        directory_skill(
            &project.join(".claude/skills"),
            "claude-project",
            "claude-project",
        );
        fs::create_dir_all(project.join(".claude/commands")).expect("Claude command directory");
        fs::write(
            project.join(".claude/commands/review.md"),
            "# Related Claude command\n",
        )
        .expect("related Claude command");
        fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://user-mcp.example.com/mcp"},"secret":{"type":"http","url":"https://secret-mcp.example.com/mcp","headers":{"Authorization":"Bearer sk-live-12345678901234567890"}}}}"#,
        )
        .expect("Claude user MCP document");
        fs::write(
            project.join(".mcp.json"),
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://project-mcp.example.com/mcp"}}}"#,
        )
        .expect("Claude project MCP document");

        let (modified_directory, _) =
            directory_skill(&home.join(".agents/skills"), "modified-dir", "modified-dir");
        directory_skill(
            &project.join(".agents/skills"),
            "codex-project",
            "codex-project",
        );
        fs::create_dir_all(project.join(".codex")).expect("Codex project configuration root");
        fs::write(
            project.join(".codex/config.toml"),
            "[mcp_servers.local]\ncommand = \"SECRET-COMMAND\"\nargs = [\"SECRET-ARG\"]\n",
        )
        .expect("Codex project MCP document");
        directory_skill(&codex_system, "system-skill", "system-skill");

        directory_skill(&home.join(".pi/agent/skills"), "pi-user-dir", "pi-user-dir");
        directory_skill(
            &home.join(".pi/agent/skills"),
            "pi-conflict-user",
            "pi-conflict",
        );
        let (managed_standalone, managed_standalone_bytes) = standalone_skill(
            &home.join(".pi/agent/skills"),
            "managed-flat.md",
            "managed-flat",
        );
        directory_skill(
            &project.join(".pi/skills"),
            "pi-project-dir",
            "pi-project-dir",
        );
        directory_skill(
            &project.join(".pi/skills"),
            "pi-conflict-project",
            "pi-conflict",
        );
        standalone_skill(
            &project.join(".pi/skills"),
            "pi-project-flat.md",
            "pi-project-flat",
        );
        fs::create_dir_all(home.join(".pi/agent/extensions")).expect("Pi user extension directory");
        fs::write(
            home.join(".pi/agent/extensions/review.ts"),
            b"throw new Error('must never execute during scan');\n",
        )
        .expect("Pi standalone extension");
        fs::create_dir_all(project.join(".pi/extensions/team.ts"))
            .expect("Pi project extension directory");
        fs::write(
            project.join(".pi/extensions/team.ts/index.ts"),
            b"export default {};\n",
        )
        .expect("Pi directory extension entrypoint");
        fs::write(
            project.join(".pi/extensions/team.ts/helper.ts"),
            b"export const helper = true;\n",
        )
        .expect("Pi directory extension payload");

        directory_skill(
            &home.join(".config/opencode/skills"),
            "opencode-user",
            "opencode-user",
        );
        directory_skill(
            &home.join(".config/opencode/skills"),
            "v2-shadow",
            "v2-shadow",
        );
        directory_skill(
            &project.join(".opencode/skills"),
            "opencode-project",
            "opencode-project",
        );
        directory_skill(&project.join(".opencode/skills"), "v2-shadow", "v2-shadow");
        standalone_skill(
            &project.join(".opencode/skills"),
            "opencode-flat.md",
            "opencode-flat",
        );
        malformed_directory_skill(&project.join(".opencode/skills"), "malformed-sibling");
        directory_skill(&opencode_built_in, "v2-built-in", "v2-built-in");

        let missing_destination = project.join(".opencode/skills/missing-managed");
        let assets: BTreeMap<_, _> = [
            "managed-dir",
            "modified-dir",
            "managed-flat",
            "missing-managed",
        ]
        .into_iter()
        .map(|id| {
            let asset = acceptance_asset(id);
            (asset.id.clone(), asset)
        })
        .collect();
        let asset_hashes = assets
            .values()
            .map(|asset| (asset.id.as_str().to_owned(), asset.content_hash.clone()))
            .collect();
        let manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets,
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };
        let manifest_toml = manifest.to_toml().expect("acceptance manifest");
        let environment_revision = Revision::parse(format!(
            "manifest:{}",
            ContentHash::digest(manifest_toml.as_bytes()).as_str()
        ))
        .expect("manifest revision");

        let receipts = [
            receipt(
                "managed-dir",
                HarnessId::Claude,
                HarnessScope::User,
                &managed_directory,
                exact_single_file_hash(0, "SKILL.md", &managed_directory_bytes),
                &asset_hashes,
                &environment_revision,
            ),
            receipt(
                "modified-dir",
                HarnessId::Codex,
                HarnessScope::User,
                &modified_directory,
                ContentHash::digest(b"previous rendered directory bytes"),
                &asset_hashes,
                &environment_revision,
            ),
            receipt(
                "managed-flat",
                HarnessId::Pi,
                HarnessScope::User,
                &managed_standalone,
                exact_single_file_hash(1, "managed-flat.md", &managed_standalone_bytes),
                &asset_hashes,
                &environment_revision,
            ),
            receipt(
                "missing-managed",
                HarnessId::OpenCode,
                HarnessScope::Project,
                &missing_destination,
                ContentHash::digest(b"missing expected render"),
                &asset_hashes,
                &environment_revision,
            ),
        ];
        let receipt_map = receipts
            .into_iter()
            .map(|receipt| (receipt.receipt_id().expect("receipt identity"), receipt))
            .collect();
        let local_state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("acceptance-machine").expect("machine ID"),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: receipt_map,
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: vec![],
        };
        let local_state_json = local_state.to_json().expect("acceptance local state");
        fs::write(environment.join("kitrove.toml"), &manifest_toml).expect("manifest fixture");
        fs::write(state_home.join("state.json"), &local_state_json).expect("local-state fixture");

        Self {
            _tempdir: tempdir,
            home,
            project,
            environment,
            state_home,
            codex_system,
            opencode_built_in,
            manifest_toml,
            local_state_json,
        }
    }

    fn request(&self) -> ScanRequest<'_> {
        ScanRequest {
            home: Some(self.home.clone()),
            working_directory: self.project.clone(),
            project_boundary: ProjectBoundary::Repository {
                root: self.project.clone(),
            },
            harnesses: BTreeSet::from([
                HarnessId::Claude,
                HarnessId::Codex,
                HarnessId::Pi,
                HarnessId::OpenCode,
            ]),
            scopes: ScopeSelection::All,
            explicit_roots: vec![],
            supplied_native_roots: vec![
                SuppliedNativeRoot::new(
                    HarnessId::Codex,
                    HarnessScope::User,
                    NativeRootKey::parse("codex.bundled").expect("Codex system key"),
                    self.codex_system.clone(),
                ),
                SuppliedNativeRoot::new(
                    HarnessId::OpenCode,
                    HarnessScope::User,
                    NativeRootKey::parse("opencode-v2.built-in").expect("OpenCode built-in key"),
                    self.opencode_built_in.clone(),
                ),
            ],
            versions: BTreeMap::from([(
                HarnessId::OpenCode,
                VerifiedVersionEvidence::new(
                    HarnessId::OpenCode,
                    HarnessVersion::parse("2.0.0-acceptance").expect("OpenCode version"),
                    PolicyLine::OpenCodeV2,
                    EvidenceRef::parse("acceptance.fixture.opencode-v2").expect("version evidence"),
                )
                .expect("OpenCode V2 evidence"),
            )]),
            project_trust: BTreeMap::from([(
                ProjectTrustKey {
                    harness: HarnessId::Pi,
                    project_anchor: self.project.clone(),
                },
                ProjectTrustObservation::Declined {
                    evidence: EvidenceRef::parse("acceptance.fixture.pi-trust-declined")
                        .expect("Pi trust evidence"),
                },
            )]),
            environment: Some(EnvironmentInput {
                source_path: self.environment.join("kitrove.toml"),
                toml_bytes: self.manifest_toml.as_bytes(),
            }),
            local_state: Some(LocalStateInput::Bytes {
                source_path: self.state_home.join("state.json"),
                json_bytes: self.local_state_json.as_bytes(),
            }),
            limits: ScanLimits::default(),
        }
    }

    fn command(&self, json: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kitrove"));
        command
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("LOCALAPPDATA", self.home.join("local-app-data"))
            .env("KITROVE_STATE_HOME", &self.state_home)
            .env_remove("KITROVE_ENV")
            .args([
                "scan",
                "--scope",
                "all",
                "--environment",
                self.environment.to_str().expect("environment path text"),
            ]);
        if json {
            command.arg("--json");
        }
        command
    }

    fn run_cli(&self, json: bool) -> Output {
        self.command(json).output().expect("run kitrove scan")
    }
}

fn skill_document(name: &str) -> Vec<u8> {
    format!("---\nname: {name}\ndescription: {DESCRIPTION}\n---\n# {name}\n").into_bytes()
}

fn directory_skill(parent: &Path, directory: &str, declared_name: &str) -> (PathBuf, Vec<u8>) {
    let package = parent.join(directory);
    fs::create_dir_all(&package).expect("directory skill package");
    let bytes = skill_document(declared_name);
    fs::write(package.join("SKILL.md"), &bytes).expect("directory skill document");
    (package, bytes)
}

fn standalone_skill(parent: &Path, file_name: &str, declared_name: &str) -> (PathBuf, Vec<u8>) {
    fs::create_dir_all(parent).expect("standalone skill root");
    let path = parent.join(file_name);
    let bytes = skill_document(declared_name);
    fs::write(&path, &bytes).expect("standalone skill document");
    (path, bytes)
}

fn malformed_directory_skill(parent: &Path, directory: &str) {
    let package = parent.join(directory);
    fs::create_dir_all(&package).expect("malformed sibling package");
    fs::write(
        package.join("SKILL.md"),
        "---\nname: [unterminated\ndescription: malformed sibling\n---\n",
    )
    .expect("malformed sibling document");
}

fn acceptance_asset(id: &str) -> Asset {
    let id = AssetId::parse(id).expect("acceptance asset ID");
    let provenance = ComponentProvenance::new(
        Source::Local {
            path: PortablePath::parse(format!("sources/{}", id.as_str()))
                .expect("portable source path"),
        },
        Revision::parse(format!("source-{}-v1", id.as_str())).expect("source revision"),
        ContentHash::digest(format!("exact-{}", id.as_str()).as_bytes()),
        None,
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: id.clone(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"computed below"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: "agent-skill-v1".to_owned(),
            root: PortablePath::parse(format!("objects/{}", id.as_str()))
                .expect("portable object root"),
            object_hash: ContentHash::digest(format!("portable-{}", id.as_str()).as_bytes()),
            provenance: provenance_id,
        }),
        native_variants: BTreeMap::new(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    asset
}

fn receipt(
    asset_id: &str,
    harness: HarnessId,
    scope: HarnessScope,
    destination: &Path,
    rendered_hash: ContentHash,
    asset_hashes: &BTreeMap<String, ContentHash>,
    environment_revision: &Revision,
) -> DeploymentReceipt {
    DeploymentReceipt {
        asset_id: AssetId::parse(asset_id).expect("receipt asset ID"),
        harness,
        scope,
        destination: normalized_destination(destination),
        target: Default::default(),
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: asset_hashes
            .get(asset_id)
            .expect("asset hash for receipt")
            .clone(),
        rendered_hash,
        document_hash: None,
        prior_hash: None,
        adapter_version: "acceptance/1".to_owned(),
        environment_revision: environment_revision.clone(),
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
    NormalizedDestination::parse(encoded).expect("receipt destination")
}

fn exact_single_file_hash(layout_tag: u8, document_name: &str, bytes: &[u8]) -> ContentHash {
    let mut frame = b"kitrove-skill-source-v1\0".to_vec();
    frame.push(layout_tag);
    append_text_record(&mut frame, document_name);
    append_text_record(&mut frame, document_name);
    frame.push(0);
    frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    frame.extend_from_slice(bytes);
    ContentHash::digest(&frame)
}

fn append_text_record(frame: &mut Vec<u8>, value: &str) {
    frame.extend_from_slice(&(value.len() as u64).to_be_bytes());
    frame.extend_from_slice(value.as_bytes());
}

fn scan_twice(fixture: &AcceptanceFixture) -> (ScanReport, ScanReport) {
    let registry = tier_one_registry();
    let first = ScanEngine::from_registry(&registry)
        .scan(&fixture.request())
        .expect("first acceptance scan");
    let second = ScanEngine::from_registry(&registry)
        .scan(&fixture.request())
        .expect("second acceptance scan");
    (first, second)
}

fn entry_for_asset<'a>(report: &'a ScanReport, asset_id: &str) -> &'a kitrove_core::ScanEntry {
    report
        .entries
        .iter()
        .find(|entry| entry.asset_id.as_ref().map(AssetId::as_str) == Some(asset_id))
        .unwrap_or_else(|| panic!("missing scan entry for asset {asset_id}"))
}

fn cli_entry_for_asset<'a>(report: &'a Value, asset_id: &str) -> &'a Value {
    report["entries"]
        .as_array()
        .expect("CLI entries")
        .iter()
        .find(|entry| entry["asset_id"] == asset_id)
        .unwrap_or_else(|| panic!("missing CLI entry for asset {asset_id}"))
}

fn assert_shadow_relationship(
    report: &ScanReport,
    harness: HarnessId,
    native_id: &str,
    winner_scope: HarnessScope,
    winner_tier: RootTier,
    shadow_scope: HarnessScope,
    shadow_tier: RootTier,
) {
    let candidates = report
        .entries
        .iter()
        .filter(|entry| entry.harness == harness && entry.native_id.as_deref() == Some(native_id))
        .collect::<Vec<_>>();
    assert_eq!(
        candidates.len(),
        2,
        "expected one winner and one shadow for {harness}/{native_id}: {candidates:?}"
    );
    let winner = candidates
        .iter()
        .copied()
        .find(|entry| entry.scope == winner_scope && entry.root_tier == Some(winner_tier))
        .unwrap_or_else(|| panic!("missing expected {harness}/{native_id} winner"));
    let shadow = candidates
        .iter()
        .copied()
        .find(|entry| entry.scope == shadow_scope && entry.root_tier == Some(shadow_tier))
        .unwrap_or_else(|| panic!("missing expected {harness}/{native_id} shadow"));
    assert_eq!(winner.shadowed_by, None);
    assert_eq!(
        shadow.shadowed_by.as_ref(),
        winner.observation_id.as_ref(),
        "{harness}/{native_id} shadow does not name the expected winner"
    );
    assert!(
        shadow
            .findings
            .iter()
            .any(|finding| finding.code == "scan.candidate_shadowed"),
        "{harness}/{native_id} shadow lacks its stable finding"
    );
}

#[test]
fn cli_four_harness_current_unknown_scan_covers_inputs_classification_render_and_exit() {
    let fixture = AcceptanceFixture::create();

    let first_text = fixture.run_cli(false);
    let second_text = fixture.run_cli(false);
    let first_json = fixture.run_cli(true);
    let second_json = fixture.run_cli(true);

    for (label, output) in [
        ("first text", &first_text),
        ("second text", &second_text),
        ("first JSON", &first_json),
        ("second JSON", &second_json),
    ] {
        assert_eq!(
            output.status.code(),
            Some(3),
            "{label} exit/stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{label} emitted stderr");
    }
    assert_eq!(first_text.stdout, second_text.stdout);
    assert_eq!(first_json.stdout, second_json.stdout);

    let rendered_text = std::str::from_utf8(&first_text.stdout).expect("CLI text output");
    let rendered_json = std::str::from_utf8(&first_json.stdout).expect("CLI JSON output");
    let report: Value = serde_json::from_str(rendered_json).expect("CLI JSON report");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["mode"], "classified");
    assert_eq!(
        report["versions"],
        json!({
            "claude": {"status": "unknown"},
            "codex": {"status": "unknown"},
            "opencode": {"status": "unknown"},
            "pi": {"status": "unknown"}
        }),
        "the CLI must use Current/Unknown policy inputs rather than typed evidence"
    );

    let entries = report["entries"].as_array().expect("CLI entries");
    let harnesses = entries
        .iter()
        .filter_map(|entry| entry["harness"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        harnesses,
        BTreeSet::from([
            "claude".to_owned(),
            "codex".to_owned(),
            "opencode".to_owned(),
            "pi".to_owned(),
        ]),
        "default CLI parsing did not select the four tier-one registry policies"
    );
    for harness in ["claude", "codex", "opencode", "pi"] {
        for scope in ["user", "project"] {
            assert!(
                entries
                    .iter()
                    .any(|entry| { entry["harness"] == harness && entry["scope"] == scope }),
                "CLI report omitted {harness}/{scope} discovery"
            );
        }
    }

    let classifications = entries
        .iter()
        .filter_map(|entry| entry["classification"].as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classifications,
        BTreeSet::from([
            "conflicting_duplicate".to_owned(),
            "managed_modified".to_owned(),
            "managed_unchanged".to_owned(),
            "missing_managed".to_owned(),
            "unknown".to_owned(),
            "unmanaged".to_owned(),
        ])
    );
    assert_eq!(
        cli_entry_for_asset(&report, "managed-dir")["classification"],
        "managed_unchanged"
    );
    assert_eq!(
        cli_entry_for_asset(&report, "modified-dir")["classification"],
        "managed_modified"
    );
    assert_eq!(
        cli_entry_for_asset(&report, "managed-flat")["classification"],
        "managed_unchanged"
    );
    assert_eq!(
        cli_entry_for_asset(&report, "missing-managed")["classification"],
        "missing_managed"
    );

    assert!(entries.iter().any(|entry| {
        entry["harness"] == "pi"
            && entry["scope"] == "project"
            && entry["findings"].as_array().is_some_and(|findings| {
                findings
                    .iter()
                    .any(|finding| finding["code"] == "pi.project_trust_unknown")
            })
    }));
    assert!(entries.iter().all(|entry| {
        entry["native_id"] != "system-skill" && entry["native_id"] != "v2-built-in"
    }));
    assert!(rendered_text.starts_with("kitrove scan v1\nmode classified\n"));
    let mcp_servers = report["mcp_servers"].as_array().expect("CLI MCP servers");
    assert_eq!(mcp_servers.len(), 4);
    assert!(
        mcp_servers.iter().any(|server| {
            server["harness"] == "claude"
                && server["scope"] == "user"
                && server["portable_name"] == "docs"
                && server["precedence"] == "shadowed"
                && server["shadowed_by"].is_string()
        }),
        "MCP precedence report: {mcp_servers:#?}"
    );
    assert!(mcp_servers.iter().any(|server| {
        server["harness"] == "claude"
            && server["scope"] == "project"
            && server["portable_name"] == "docs"
            && server["precedence"] == "effective"
    }));
    assert!(mcp_servers.iter().any(|server| {
        server["harness"] == "codex"
            && server["content_class"] == "executable"
            && server["block_reasons"]
                .as_array()
                .is_some_and(|reasons| reasons.iter().any(|reason| reason == "local_stdio"))
    }));
    assert!(!rendered_json.contains("SECRET-COMMAND"));
    assert!(!rendered_json.contains("SECRET-ARG"));
    assert!(!rendered_json.contains("sk-live"));
    assert!(!rendered_json.contains("user-mcp.example.com"));
    for harness in ["claude", "codex", "opencode", "pi"] {
        assert!(
            rendered_text.contains(&format!("version harness=\"{harness}\" status=\"unknown\""))
        );
    }
    let related_count = report["related"].as_array().expect("CLI related").len();
    let native_extension_count = report["native_extensions"]
        .as_array()
        .expect("CLI native extensions")
        .len();
    let prompt_command_count = report["prompt_commands"]
        .as_array()
        .expect("CLI prompt commands")
        .len();
    let agent_count = report["agents"].as_array().expect("CLI agents").len();
    let instruction_count = report["instructions"]
        .as_array()
        .expect("CLI instructions")
        .len();
    let mcp_server_count = report["mcp_servers"]
        .as_array()
        .expect("CLI MCP servers")
        .len();
    let finding_count = report["findings"].as_array().expect("CLI findings").len()
        + entries
            .iter()
            .map(|entry| entry["findings"].as_array().expect("entry findings").len())
            .sum::<usize>()
        + report["related"]
            .as_array()
            .expect("CLI related")
            .iter()
            .map(|related| {
                related["findings"]
                    .as_array()
                    .expect("related findings")
                    .len()
            })
            .sum::<usize>()
        + report["native_extensions"]
            .as_array()
            .expect("CLI native extensions")
            .iter()
            .map(|extension| {
                extension["findings"]
                    .as_array()
                    .expect("native extension findings")
                    .len()
            })
            .sum::<usize>()
        + report["instructions"]
            .as_array()
            .expect("CLI instructions")
            .iter()
            .map(|instruction| {
                instruction["findings"]
                    .as_array()
                    .expect("instruction findings")
                    .len()
            })
            .sum::<usize>()
        + report["prompt_commands"]
            .as_array()
            .expect("CLI prompt commands")
            .iter()
            .map(|command| {
                command["findings"]
                    .as_array()
                    .expect("prompt-command findings")
                    .len()
            })
            .sum::<usize>()
        + report["agents"]
            .as_array()
            .expect("CLI agents")
            .iter()
            .map(|agent| agent["findings"].as_array().expect("agent findings").len())
            .sum::<usize>()
        + report["mcp_servers"]
            .as_array()
            .expect("CLI MCP servers")
            .iter()
            .map(|server| server["findings"].as_array().expect("MCP findings").len())
            .sum::<usize>();
    assert!(rendered_text.contains(&format!(
        "summary entries={} related={related_count} prompt_commands={prompt_command_count} agents={agent_count} native_extensions={native_extension_count} instructions={instruction_count} mcp_servers={mcp_server_count} findings={finding_count}\n",
        entries.len(),
    )));
}

#[test]
fn typed_policy_library_acceptance_covers_v2_trust_system_and_complete_report() {
    let fixture = AcceptanceFixture::create();
    let registry = tier_one_registry();
    let request = fixture.request();
    let context = RootContext {
        home: request.home.as_deref(),
        working_directory: &request.working_directory,
        project_boundary: &request.project_boundary,
        scopes: request.scopes,
        explicit_roots: &request.explicit_roots,
        supplied_native_roots: &request.supplied_native_roots,
        project_trust: &request.project_trust,
        limits: &request.limits,
    };
    let codex = registry
        .policies()
        .into_iter()
        .find(|policy| policy.harness() == HarnessId::Codex)
        .expect("compiled Codex policy");
    let codex_profile = codex.profile(VersionObservation::Unknown).unwrap();
    #[cfg(unix)]
    let codex_static_roots = codex.roots(&context, &codex_profile).expect("Codex roots");
    let codex_unusual = codex
        .discover_unusual_roots(&context, &codex_profile)
        .expect("Codex unusual roots");
    #[cfg(unix)]
    assert!(
        codex_static_roots
            .iter()
            .any(|root| root.tier == RootTier::Admin),
        "compiled Codex admin root evidence is missing"
    );
    assert!(
        codex_unusual
            .roots
            .iter()
            .any(|root| root.tier == RootTier::System),
        "supplied Codex system root evidence is missing"
    );

    let (first, second) = scan_twice(&fixture);
    assert_eq!(first, second, "repeated scans differ structurally");
    assert_eq!(
        render_scan_text(&first),
        render_scan_text(&second),
        "repeated text output differs"
    );
    let first_json = render_scan_json(&first).expect("first JSON output");
    let second_json = render_scan_json(&second).expect("second JSON output");
    assert_eq!(first_json.as_bytes(), second_json.as_bytes());
    serde_json::from_str::<Value>(&first_json).expect("canonical JSON output");
    assert_eq!(first.native_extensions.len(), 2);
    assert_eq!(first.native_extension_observations().len(), 2);
    assert!(first.native_extensions.iter().all(|entry| {
        entry.harness == HarnessId::Pi
            && entry.classification == ScanClassification::Unmanaged
            && entry
                .findings
                .iter()
                .any(|finding| finding.code == "scan.native_extension_captured")
    }));
    let dotted_directory = first
        .native_extensions
        .iter()
        .find(|entry| entry.native_id == "team.ts")
        .expect("directory extension whose name ends in .ts");
    assert_eq!(
        dotted_directory.layout,
        kitrove_core::NativeExtensionLayout::Directory
    );
    assert!(dotted_directory.findings.iter().any(|finding| {
        finding.code == "scan.native_extension_captured"
            && finding.action
                == "review and explicitly adopt the native extension, then trust its exact object locally before materialization"
    }));
    assert!(first_json.contains("native_extensions"));
    assert!(!first_json.contains("must never execute"));

    let harnesses = first
        .entries
        .iter()
        .map(|entry| entry.harness.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        harnesses,
        BTreeSet::from([
            HarnessId::Claude,
            HarnessId::Codex,
            HarnessId::Pi,
            HarnessId::OpenCode,
        ])
    );
    let harness_scopes = first
        .entries
        .iter()
        .map(|entry| (entry.harness.clone(), entry.scope))
        .collect::<BTreeSet<_>>();
    for harness in [
        HarnessId::Claude,
        HarnessId::Codex,
        HarnessId::Pi,
        HarnessId::OpenCode,
    ] {
        for scope in [HarnessScope::User, HarnessScope::Project] {
            assert!(
                harness_scopes.contains(&(harness.clone(), scope)),
                "missing {harness}/{scope:?} layout"
            );
        }
    }

    let classifications = first
        .entries
        .iter()
        .map(|entry| entry.classification)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classifications,
        BTreeSet::from([
            ScanClassification::ManagedUnchanged,
            ScanClassification::ManagedModified,
            ScanClassification::Unmanaged,
            ScanClassification::MissingManaged,
            ScanClassification::ConflictingDuplicate,
            ScanClassification::Unknown,
        ])
    );

    assert_eq!(
        entry_for_asset(&first, "managed-dir").classification,
        ScanClassification::ManagedUnchanged
    );
    assert_eq!(
        entry_for_asset(&first, "managed-flat").classification,
        ScanClassification::ManagedUnchanged
    );
    assert_eq!(
        entry_for_asset(&first, "modified-dir").classification,
        ScanClassification::ManagedModified
    );
    let missing = entry_for_asset(&first, "missing-managed");
    assert_eq!(missing.classification, ScanClassification::MissingManaged);
    assert!(missing.observation_id.is_none());

    assert!(
        first.entries.iter().any(|entry| {
            entry.harness == HarnessId::Codex
                && entry.root_tier == Some(RootTier::System)
                && entry.native_id.as_deref() == Some("system-skill")
        }),
        "Codex system candidate was not retained"
    );
    assert!(
        first.entries.iter().any(|entry| {
            entry.harness == HarnessId::Pi
                && entry.scope == HarnessScope::Project
                && entry
                    .findings
                    .iter()
                    .any(|finding| finding.code == "pi.project_trust_declined")
        }),
        "typed Pi project trust evidence was not applied"
    );
    assert!(
        first.entries.iter().any(|entry| {
            entry.harness == HarnessId::Pi
                && entry.source_relative_path.as_deref() == Some("managed-flat.md")
                && format!("{:?}", entry.layout) == "Some(Standalone)"
        }),
        "Pi standalone source was not retained"
    );
    assert!(matches!(
        first.versions.get(&HarnessId::OpenCode),
        Some(VersionObservationOwned::Verified {
            policy_line: PolicyLine::OpenCodeV2,
            ..
        })
    ));
    assert!(
        first.entries.iter().any(|entry| {
            entry.harness == HarnessId::OpenCode
                && entry.native_id.as_deref() == Some("opencode-flat")
                && format!("{:?}", entry.layout) == "Some(Standalone)"
        }),
        "typed OpenCode V2 standalone source was not accepted"
    );

    assert!(
        first.entries.iter().any(|entry| {
            entry.harness == HarnessId::Pi
                && entry.native_id.as_deref() == Some("pi-conflict")
                && entry.classification == ScanClassification::ConflictingDuplicate
        }),
        "ambiguous Pi duplicate was not classified"
    );
    assert_shadow_relationship(
        &first,
        HarnessId::Claude,
        "shared-shadow",
        HarnessScope::User,
        RootTier::User,
        HarnessScope::Project,
        RootTier::Project,
    );
    assert_shadow_relationship(
        &first,
        HarnessId::OpenCode,
        "v2-shadow",
        HarnessScope::Project,
        RootTier::Project,
        HarnessScope::User,
        RootTier::User,
    );
    assert!(
        first.entries.iter().any(|entry| {
            entry.source_relative_path.as_deref() == Some("malformed-sibling")
                && entry.classification == ScanClassification::Unknown
        }),
        "malformed sibling was not localized as unknown"
    );
    assert!(
        first.entries.iter().any(|entry| {
            entry.harness == HarnessId::OpenCode
                && entry.native_id.as_deref() == Some("opencode-project")
        }),
        "valid sibling disappeared beside malformed content"
    );

    assert!(
        first.prompt_commands.iter().any(|command| {
            command.harness == HarnessId::Claude && command.source_relative_path == "review.md"
        }),
        "Claude command was not retained as a typed prompt command"
    );
    assert!(
        first
            .entries
            .iter()
            .all(|entry| entry.source_relative_path.as_deref() != Some("review.md")),
        "Claude command was misclassified as an Agent Skill"
    );
}
