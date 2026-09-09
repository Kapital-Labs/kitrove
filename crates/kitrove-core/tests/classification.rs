#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EnvironmentInput, EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy,
    LocalStateInput, LocatorDecision, NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile,
    PolicyRuntimeAuthority, PortablePolicyDecision, ProjectBoundary, ReceiptAnchor,
    RelatedDocumentPattern, RelatedRoot, RootContext, RootId, RootTier, ScanFinding, ScanLimits,
    ScanRequest, ScopeSelection, VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{
    CaptureLimits, CaptureUsage, CapturedSkillSource, SkillSource, SkillSourceLayout,
    capture_skill_source, capture_skill_source_metered,
};
use kitrove_core::{ScanClassification, ScanEngine, ScanMode};
use kitrove_model::{
    Asset, AssetId, AssetKind, ComponentProvenance, ContentClass, ContentHash, DeploymentReceipt,
    EnvironmentManifest, HarnessId, HarnessScope, LocalState, MachineConfig, MachineId,
    NormalizedDestination, PortableContent, PortablePath, Revision, SchemaVersion, Source,
};
use serde_json::{Map, Value, json};

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

fn test_engine(policy: &dyn HarnessObservationPolicy) -> ScanEngine<'_> {
    ScanEngine::from_authorities(vec![(policy, policy.runtime_authority())])
        .expect("test authority catalog")
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kitrove-core-classification-{}-{label}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn directory_skill(&self, relative: &str, name: &str) -> PathBuf {
        let directory = self.path().join(relative);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("SKILL.md"), valid_document(name)).unwrap();
        directory
    }

    fn malformed_skill(&self, relative: &str) -> PathBuf {
        let directory = self.path().join(relative);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("SKILL.md"), b"---\nname: [\n---\n").unwrap();
        directory
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestPolicy {
    harness: HarnessId,
    line: PolicyLine,
    root: PathBuf,
    anchor: PathBuf,
    scope: HarnessScope,
    root_tier: RootTier,
    ambiguous: bool,
    duplicate_root_views: bool,
    remove_before_receipt_recapture: Option<PathBuf>,
    standalone_unsupported: bool,
    agent_root: Option<PathBuf>,
    anchor_calls: AtomicUsize,
}

impl TestPolicy {
    fn user(root: &Path) -> Self {
        Self {
            harness: HarnessId::Claude,
            line: PolicyLine::ClaudeCurrent,
            root: root.to_path_buf(),
            anchor: root.to_path_buf(),
            scope: HarnessScope::User,
            root_tier: RootTier::User,
            ambiguous: false,
            duplicate_root_views: false,
            remove_before_receipt_recapture: None,
            standalone_unsupported: false,
            agent_root: None,
            anchor_calls: AtomicUsize::new(0),
        }
    }

    fn opencode_unknown(root: &Path) -> Self {
        Self {
            harness: HarnessId::OpenCode,
            line: PolicyLine::OpenCodeCurrent,
            ..Self::user(root)
        }
    }

    fn with_anchor(mut self, anchor: &Path) -> Self {
        self.anchor = anchor.to_path_buf();
        self
    }

    fn with_scope(mut self, scope: HarnessScope) -> Self {
        self.scope = scope;
        self.root_tier = match scope {
            HarnessScope::User => RootTier::User,
            HarnessScope::Project => RootTier::Project,
        };
        self
    }

    fn ambiguous(mut self) -> Self {
        self.ambiguous = true;
        self
    }

    fn with_duplicate_root_views(mut self) -> Self {
        self.duplicate_root_views = true;
        self
    }

    fn remove_before_receipt_recapture(mut self, destination: &Path) -> Self {
        self.remove_before_receipt_recapture = Some(destination.to_path_buf());
        self
    }

    fn standalone_unsupported(mut self) -> Self {
        self.standalone_unsupported = true;
        self
    }

    fn with_agent_root(mut self, root: &Path) -> Self {
        self.agent_root = Some(root.to_path_buf());
        self
    }

    fn agent_roots(&self) -> Vec<RelatedRoot> {
        self.agent_root
            .iter()
            .map(|path| RelatedRoot {
                logical_id: RootId::parse("test.agents").unwrap(),
                path: path.clone(),
                scope: self.scope,
                tier: self.root_tier,
                policy_rank: 20,
                kind: AssetKind::Agent,
                pattern: RelatedDocumentPattern::MarkdownDirectChildren,
                evidence: EvidenceRef::parse("test.agent-root").unwrap(),
            })
            .collect()
    }

    fn anchor_calls(&self) -> usize {
        self.anchor_calls.load(Ordering::Relaxed)
    }
}

impl HarnessObservationPolicy for TestPolicy {
    fn harness(&self) -> HarnessId {
        self.harness.clone()
    }

    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        let layouts = if self.standalone_unsupported {
            BTreeSet::from([SkillSourceLayout::Directory, SkillSourceLayout::Standalone])
        } else {
            BTreeSet::from([SkillSourceLayout::Directory])
        };
        let mut roots = vec![ObservedRoot {
            logical_id: RootId::parse("test.skills").unwrap(),
            path: self.root.clone(),
            scope: self.scope,
            tier: self.root_tier,
            policy_rank: 10,
            enabled_layouts: layouts.clone(),
            evidence: EvidenceRef::parse("test.root").unwrap(),
        }];
        if self.duplicate_root_views {
            roots.push(ObservedRoot {
                logical_id: RootId::parse("test.skills.secondary").unwrap(),
                path: self.root.clone(),
                scope: self.scope,
                tier: self.root_tier,
                policy_rank: 11,
                enabled_layouts: layouts,
                evidence: EvidenceRef::parse("test.root.secondary").unwrap(),
            });
        }
        let anchors = [ReceiptAnchor {
            scope: self.scope,
            path: self.anchor.clone(),
            evidence: EvidenceRef::parse("test.receipt-anchor").unwrap(),
        }];
        PolicyRuntimeAuthority::exact(self.line, &roots, &self.agent_roots(), &anchors)
    }

    fn profile(&self, _version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            self.harness.clone(),
            self.line,
            VersionObservationOwned::Unknown,
            EvidenceRef::parse("test.profile").unwrap(),
        )
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        let layouts = if self.standalone_unsupported {
            BTreeSet::from([SkillSourceLayout::Directory, SkillSourceLayout::Standalone])
        } else {
            BTreeSet::from([SkillSourceLayout::Directory])
        };
        let mut roots = vec![ObservedRoot {
            logical_id: RootId::parse("test.skills").unwrap(),
            path: self.root.clone(),
            scope: self.scope,
            tier: self.root_tier,
            policy_rank: 10,
            enabled_layouts: layouts.clone(),
            evidence: EvidenceRef::parse("test.root").unwrap(),
        }];
        if self.duplicate_root_views {
            roots.push(ObservedRoot {
                logical_id: RootId::parse("test.skills.secondary").unwrap(),
                path: self.root.clone(),
                scope: self.scope,
                tier: self.root_tier,
                policy_rank: 11,
                enabled_layouts: layouts,
                evidence: EvidenceRef::parse("test.root.secondary").unwrap(),
            });
        }
        Ok(roots)
    }

    fn related_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        if let Some(destination) = &self.remove_before_receipt_recapture {
            match fs::symlink_metadata(destination) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    fs::remove_dir_all(destination).unwrap();
                }
                Ok(_) => {
                    fs::remove_file(destination).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("failed to stage disappeared destination: {error}"),
            }
        }
        Ok(self.agent_roots())
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory => LocatorDecision::Capture,
            SkillSourceLayout::Standalone if self.standalone_unsupported => {
                LocatorDecision::Unsupported {
                    finding: ScanFinding::new(
                        "scan.layout_unsupported",
                        FindingSeverity::Attention,
                        FindingSubject::Harness(self.harness.clone()),
                        vec![EvidenceRef::parse("test.profile").unwrap()],
                        "retain the existing receipt but verify policy before a later apply",
                    ),
                }
            }
            SkillSourceLayout::Standalone => LocatorDecision::Ignore,
        }
    }

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        let name = candidate
            .document
            .declared_name
            .as_deref()
            .unwrap_or("fallback");
        CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(name.to_owned()),
            PortablePolicyDecision::Project {
                name: AssetId::parse(name).unwrap(),
                description: "A valid test skill.".to_owned(),
                reasons: vec![],
            },
            vec![],
        )
    }

    fn resolve_duplicates(
        &self,
        _group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        Ok(if self.ambiguous {
            DuplicateDecision::Ambiguous {
                reason: ScanFinding::new(
                    "scan.duplicate_ambiguous",
                    FindingSeverity::Attention,
                    FindingSubject::Harness(self.harness.clone()),
                    vec![EvidenceRef::parse("test.duplicate").unwrap()],
                    "choose one effective candidate",
                ),
            }
        } else {
            DuplicateDecision::Coexist
        })
    }

    fn receipt_anchors(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        self.anchor_calls.fetch_add(1, Ordering::Relaxed);
        Ok(vec![ReceiptAnchor {
            scope: self.scope,
            path: self.anchor.clone(),
            evidence: EvidenceRef::parse("test.receipt-anchor").unwrap(),
        }])
    }
}

fn valid_document(name: &str) -> Vec<u8> {
    format!("---\nname: {name}\ndescription: A valid skill.\n---\n# Skill\n").into_bytes()
}

fn valid_agent_document(name: &str) -> Vec<u8> {
    format!(
        "---\nname: {name}\ndescription: Reviews code safely.\n---\nReview the requested code.\n"
    )
    .into_bytes()
}

fn hash(label: &str) -> ContentHash {
    ContentHash::digest(label.as_bytes())
}

struct ManifestFixture {
    toml: String,
    asset_content_hash: ContentHash,
    portable_object_hash: ContentHash,
    revision: Revision,
}

fn manifest_fixture() -> ManifestFixture {
    manifest_fixture_for(AssetKind::Skill)
}

fn agent_manifest_fixture() -> ManifestFixture {
    manifest_fixture_for(AssetKind::Agent)
}

fn manifest_fixture_for(kind: AssetKind) -> ManifestFixture {
    let asset_id = AssetId::parse("managed").unwrap();
    let portable_object_hash = hash("portable-object-only");
    let provenance = ComponentProvenance::new(
        Source::Local {
            path: PortablePath::parse("sources/managed").unwrap(),
        },
        Revision::parse("source-revision-1").unwrap(),
        hash("exact-source"),
        None,
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: asset_id.clone(),
        kind,
        content_hash: hash("computed below"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: match kind {
                AssetKind::Agent => "kitrove-agent/v1",
                _ => "agent-skill-v1",
            }
            .to_owned(),
            root: PortablePath::parse("objects/portable").unwrap(),
            object_hash: portable_object_hash.clone(),
            provenance: provenance_id,
        }),
        native_variants: BTreeMap::new(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    let asset_content_hash = asset.content_hash.clone();
    let manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(asset_id, asset)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let toml = manifest.to_toml().unwrap();
    let revision = Revision::parse(format!(
        "manifest:blake3:{}",
        blake3::hash(toml.as_bytes()).to_hex()
    ))
    .unwrap();
    ManifestFixture {
        toml,
        asset_content_hash,
        portable_object_hash,
        revision,
    }
}

fn deployment_receipt(
    destination: &Path,
    rendered_hash: ContentHash,
    manifest: &ManifestFixture,
) -> DeploymentReceipt {
    DeploymentReceipt {
        asset_id: AssetId::parse("managed").unwrap(),
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        destination: normalized(destination),
        target: Default::default(),
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: manifest.asset_content_hash.clone(),
        rendered_hash,
        document_hash: None,
        prior_hash: None,
        adapter_version: "test-adapter/1".to_owned(),
        environment_revision: manifest.revision.clone(),
    }
}

fn normalized(path: &Path) -> NormalizedDestination {
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
    NormalizedDestination::parse(encoded).unwrap()
}

fn exact_hash(path: &Path, layout: SkillSourceLayout) -> ContentHash {
    let source = match layout {
        SkillSourceLayout::Directory => SkillSource::Directory {
            path: path.to_path_buf(),
        },
        SkillSourceLayout::Standalone => SkillSource::Standalone {
            path: path.to_path_buf(),
        },
    };
    capture_skill_source(&source, CaptureLimits::default())
        .unwrap()
        .exact_source_hash
}

fn local_state(receipts: Vec<DeploymentReceipt>) -> String {
    let receipts = receipts
        .into_iter()
        .map(|receipt| (receipt.receipt_id().unwrap(), receipt))
        .collect();
    LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("machine").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::new(),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::new(),
        receipts,
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: vec![],
    }
    .to_json()
    .unwrap()
}

fn local_state_values(receipts: Vec<(String, Value)>) -> String {
    let receipts = receipts.into_iter().collect::<Map<String, Value>>();
    serde_json::to_string(&json!({
        "schema_version": 1,
        "machine": {
            "id": "machine",
            "active_profile": null,
            "enabled_targets": [],
            "harness_roots": {}
        },
        "bindings": {},
        "receipts": receipts,
        "trust": {},
        "scans": []
    }))
    .unwrap()
}

fn request<'a>(
    home: &Path,
    working_directory: &Path,
    boundary: ProjectBoundary,
    manifest: &'a str,
    local_state: Option<&'a str>,
) -> ScanRequest<'a> {
    ScanRequest {
        home: Some(home.to_path_buf()),
        working_directory: working_directory.to_path_buf(),
        project_boundary: boundary,
        harnesses: BTreeSet::from([HarnessId::Claude]),
        scopes: ScopeSelection::All,
        explicit_roots: vec![],
        supplied_native_roots: vec![],
        versions: BTreeMap::new(),
        project_trust: BTreeMap::new(),
        environment: Some(EnvironmentInput {
            source_path: PathBuf::from("/authored/manifest-path-must-not-leak"),
            toml_bytes: manifest.as_bytes(),
        }),
        local_state: local_state.map(|json| LocalStateInput::Bytes {
            source_path: PathBuf::from("/authored/local-state-path-must-not-leak"),
            json_bytes: json.as_bytes(),
        }),
        limits: ScanLimits::default(),
    }
}

fn request_for_harness<'a>(
    harness: HarnessId,
    home: &Path,
    working_directory: &Path,
    boundary: ProjectBoundary,
    manifest: &'a str,
    local_state: Option<&'a str>,
) -> ScanRequest<'a> {
    let mut request = request(home, working_directory, boundary, manifest, local_state);
    request.harnesses = BTreeSet::from([harness]);
    request
}

fn observed_agent_target_hash(
    policy: &TestPolicy,
    fixture: &TestRoot,
    destination: &Path,
    manifest: &ManifestFixture,
) -> ContentHash {
    let probe_state = local_state(vec![deployment_receipt(
        destination,
        hash("probe-agent-render"),
        manifest,
    )]);
    let report = test_engine(policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&probe_state),
        ))
        .unwrap();
    report
        .agents
        .iter()
        .find(|entry| entry.normalized_destination.as_ref() == Some(&normalized(destination)))
        .and_then(|entry| entry.observed_target_hash.clone())
        .expect("captured agent target hash")
}

#[derive(Clone, Copy)]
enum SixStateCase {
    Exact,
    Modified,
    Unmanaged,
    Missing,
    Conflicting,
    Failed,
}

#[test]
fn classified_scan_emits_all_six_states_in_the_specified_order() {
    let cases = [
        (SixStateCase::Exact, ScanClassification::ManagedUnchanged),
        (SixStateCase::Modified, ScanClassification::ManagedModified),
        (SixStateCase::Unmanaged, ScanClassification::Unmanaged),
        (SixStateCase::Missing, ScanClassification::MissingManaged),
        (
            SixStateCase::Conflicting,
            ScanClassification::ConflictingDuplicate,
        ),
        (SixStateCase::Failed, ScanClassification::Unknown),
    ];

    for (index, (case, expected)) in cases.into_iter().enumerate() {
        let fixture = TestRoot::new(&format!("six-state-{index}"));
        let manifest = manifest_fixture();
        let mut policy = TestPolicy::user(fixture.path());
        let receipts = match case {
            SixStateCase::Exact => {
                let destination = fixture.directory_skill("exact", "exact");
                vec![deployment_receipt(
                    &destination,
                    exact_hash(&destination, SkillSourceLayout::Directory),
                    &manifest,
                )]
            }
            SixStateCase::Modified => {
                let destination = fixture.directory_skill("modified", "modified");
                vec![deployment_receipt(
                    &destination,
                    hash("different-rendered-output"),
                    &manifest,
                )]
            }
            SixStateCase::Unmanaged => {
                fixture.directory_skill("unmanaged", "unmanaged");
                vec![]
            }
            SixStateCase::Missing => vec![deployment_receipt(
                &fixture.path().join("missing"),
                hash("expected-missing-render"),
                &manifest,
            )],
            SixStateCase::Conflicting => {
                fixture.directory_skill("first", "duplicate");
                fixture.directory_skill("second", "duplicate");
                policy = policy.ambiguous();
                vec![]
            }
            SixStateCase::Failed => {
                fixture.malformed_skill("failed");
                vec![]
            }
        };
        let state = local_state(receipts);
        let report = test_engine(&policy)
            .scan(&request(
                fixture.path(),
                fixture.path(),
                ProjectBoundary::NoRepository,
                &manifest.toml,
                Some(&state),
            ))
            .unwrap();

        assert_eq!(report.mode, ScanMode::Classified, "case {index}");
        assert!(!report.entries.is_empty(), "case {index}");
        assert!(
            report
                .entries
                .iter()
                .all(|entry| entry.classification == expected),
            "case {index}: {:?}",
            report.entries
        );
        assert_eq!(policy.anchor_calls(), 1, "case {index}");
    }
}

#[test]
fn agent_receipts_emit_all_six_states_without_inventing_observation_identity() {
    let cases = [
        (SixStateCase::Exact, ScanClassification::ManagedUnchanged),
        (SixStateCase::Modified, ScanClassification::ManagedModified),
        (SixStateCase::Unmanaged, ScanClassification::Unmanaged),
        (SixStateCase::Missing, ScanClassification::MissingManaged),
        (
            SixStateCase::Conflicting,
            ScanClassification::ConflictingDuplicate,
        ),
        (SixStateCase::Failed, ScanClassification::Unknown),
    ];

    for (index, (case, expected)) in cases.into_iter().enumerate() {
        let fixture = TestRoot::new(&format!("agent-six-state-{index}"));
        let agent_root = fixture.path().join("agents");
        fs::create_dir_all(&agent_root).unwrap();
        let destination = agent_root.join("review.md");
        let manifest = agent_manifest_fixture();
        let policy = TestPolicy::user(fixture.path()).with_agent_root(&agent_root);

        match case {
            SixStateCase::Exact | SixStateCase::Modified | SixStateCase::Unmanaged => {
                fs::write(&destination, valid_agent_document("review")).unwrap();
            }
            SixStateCase::Conflicting => {
                fs::write(&destination, valid_agent_document("review")).unwrap();
                fs::write(agent_root.join("other.md"), valid_agent_document("review")).unwrap();
            }
            SixStateCase::Failed => fs::create_dir_all(&destination).unwrap(),
            SixStateCase::Missing => {}
        }

        let observed_hash = if matches!(case, SixStateCase::Exact | SixStateCase::Conflicting) {
            observed_agent_target_hash(&policy, &fixture, &destination, &manifest)
        } else {
            hash("unused-agent-render")
        };
        let receipts = match case {
            SixStateCase::Unmanaged => vec![],
            SixStateCase::Exact | SixStateCase::Conflicting => {
                vec![deployment_receipt(&destination, observed_hash, &manifest)]
            }
            SixStateCase::Modified | SixStateCase::Missing | SixStateCase::Failed => {
                vec![deployment_receipt(
                    &destination,
                    hash("different-agent-render"),
                    &manifest,
                )]
            }
        };
        let state = local_state(receipts);
        let report = test_engine(&policy)
            .scan(&request(
                fixture.path(),
                fixture.path(),
                ProjectBoundary::NoRepository,
                &manifest.toml,
                Some(&state),
            ))
            .unwrap();

        assert_eq!(report.mode, ScanMode::Classified, "case {index}");
        assert!(!report.agents.is_empty(), "case {index}");
        assert!(
            report
                .agents
                .iter()
                .all(|entry| entry.classification == expected),
            "case {index}: {:?}",
            report.agents
        );
        if matches!(case, SixStateCase::Missing | SixStateCase::Failed) {
            assert!(report.agents[0].observation_id.is_none(), "case {index}");
            assert!(report.agents[0].receipt_id.is_some(), "case {index}");
        }
        assert_eq!(
            report.agent_observations().len(),
            usize::from(matches!(case, SixStateCase::Unmanaged)),
            "only unmanaged, unambiguous agents remain eligible for adoption in case {index}",
        );
    }
}

#[test]
fn stale_agent_receipt_preserves_exact_content_classification() {
    let fixture = TestRoot::new("agent-stale");
    let agent_root = fixture.path().join("agents");
    fs::create_dir_all(&agent_root).unwrap();
    let destination = agent_root.join("review.md");
    fs::write(&destination, valid_agent_document("review")).unwrap();
    let manifest = agent_manifest_fixture();
    let policy = TestPolicy::user(fixture.path()).with_agent_root(&agent_root);
    let target_hash = observed_agent_target_hash(&policy, &fixture, &destination, &manifest);
    let mut receipt = deployment_receipt(&destination, target_hash, &manifest);
    receipt.source_hash = manifest.portable_object_hash.clone();
    receipt.environment_revision = Revision::parse(format!(
        "manifest:blake3:{}",
        blake3::hash(b"stale-agent-manifest").to_hex()
    ))
    .unwrap();
    let state = local_state(vec![receipt]);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(
        report.agents[0].classification,
        ScanClassification::ManagedUnchanged
    );
    assert!(
        report.agents[0]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_stale_desired_state")
    );
}

#[test]
fn agent_receipt_recapture_exhaustion_fails_closed_and_withholds_adoption_authority() {
    let fixture = TestRoot::new("agent-recapture-budget");
    let agent_root = fixture.path().join("agents");
    fs::create_dir_all(&agent_root).unwrap();
    let destination = agent_root.join("review.md");
    fs::write(&destination, valid_agent_document("review")).unwrap();
    let manifest = agent_manifest_fixture();
    let policy = TestPolicy::user(fixture.path()).with_agent_root(&agent_root);
    let state = local_state(vec![deployment_receipt(
        &destination,
        hash("expected-agent-render"),
        &manifest,
    )]);
    let mut limited = request(
        fixture.path(),
        fixture.path(),
        ProjectBoundary::NoRepository,
        &manifest.toml,
        Some(&state),
    );
    limited.limits.max_capture_files = 1;

    let report = test_engine(&policy).scan(&limited).unwrap();

    assert_eq!(report.agents[0].classification, ScanClassification::Unknown);
    assert!(
        report.agents[0]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.capture_budget_exhausted")
    );
    assert!(report.agent_observations().is_empty());
}

#[test]
fn invalid_ownership_inputs_withhold_agent_adoption_authority() {
    let fixture = TestRoot::new("agent-invalid-ownership");
    let agent_root = fixture.path().join("agents");
    fs::create_dir_all(&agent_root).unwrap();
    fs::write(agent_root.join("review.md"), valid_agent_document("review")).unwrap();
    let manifest = agent_manifest_fixture();
    let policy = TestPolicy::user(fixture.path()).with_agent_root(&agent_root);

    for (manifest_text, state) in [
        ("not valid manifest", None),
        (manifest.toml.as_str(), Some("not valid local state")),
    ] {
        let report = test_engine(&policy)
            .scan(&request(
                fixture.path(),
                fixture.path(),
                ProjectBoundary::NoRepository,
                manifest_text,
                state,
            ))
            .unwrap();

        assert_eq!(report.mode, ScanMode::Degraded);
        assert_eq!(report.agents[0].classification, ScanClassification::Unknown);
        assert!(report.agent_observations().is_empty());
    }
}

#[test]
fn stale_desired_state_does_not_change_content_classification() {
    let fixture = TestRoot::new("stale");
    let destination = fixture.directory_skill("managed", "managed");
    let manifest = manifest_fixture();
    let mut receipt = deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    );
    receipt.source_hash = manifest.portable_object_hash.clone();
    receipt.environment_revision = Revision::parse(format!(
        "manifest:blake3:{}",
        blake3::hash(b"stale-manifest").to_hex()
    ))
    .unwrap();
    let state = local_state(vec![receipt]);
    let policy = TestPolicy::user(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(
        report.entries[0].classification,
        ScanClassification::ManagedUnchanged
    );
    assert!(
        report.entries[0]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_stale_desired_state")
    );
}

#[test]
fn source_identity_uses_complete_asset_hash_not_portable_object_hash() {
    let fixture = TestRoot::new("asset-hash");
    let destination = fixture.directory_skill("managed", "managed");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(
        report.entries[0].classification,
        ScanClassification::ManagedUnchanged
    );
    assert!(
        report.entries[0]
            .findings
            .iter()
            .all(|finding| finding.code != "scan.receipt_stale_desired_state")
    );
    assert_ne!(manifest.asset_content_hash, manifest.portable_object_hash);
}

#[test]
fn portable_hash_equality_cannot_substitute_for_exact_rendered_identity() {
    let fixture = TestRoot::new("exact-not-portable");
    let destination = fixture.directory_skill("managed", "managed");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        manifest.portable_object_hash.clone(),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(
        report.entries[0].classification,
        ScanClassification::ManagedModified
    );
}

#[test]
fn invalid_receipt_localizes_unknown_without_erasing_a_valid_sibling() {
    let fixture = TestRoot::new("localized-invalid");
    let valid_path = fixture.directory_skill("valid", "valid");
    let invalid_path = fixture.directory_skill("invalid", "invalid");
    let manifest = manifest_fixture();
    let valid = deployment_receipt(
        &valid_path,
        exact_hash(&valid_path, SkillSourceLayout::Directory),
        &manifest,
    );
    let invalid = deployment_receipt(
        &invalid_path,
        exact_hash(&invalid_path, SkillSourceLayout::Directory),
        &manifest,
    );
    let mut invalid_value = serde_json::to_value(&invalid).unwrap();
    invalid_value
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), json!("sentinel-invalid-receipt"));
    let state = local_state_values(vec![
        (
            valid.receipt_id().unwrap().as_str().to_owned(),
            serde_json::to_value(valid).unwrap(),
        ),
        (
            invalid.receipt_id().unwrap().as_str().to_owned(),
            invalid_value,
        ),
    ]);
    let policy = TestPolicy::user(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Degraded);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| entry.classification)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ScanClassification::ManagedUnchanged,
            ScanClassification::Unknown,
        ])
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_invalid")
    );
    assert!(!format!("{report:?}").contains("sentinel-invalid-receipt"));
}

#[test]
fn invalid_receipt_for_a_destination_outranks_valid_receipt_and_preserves_a_sibling() {
    let fixture = TestRoot::new("invalid-valid-destination-collision");
    let collision = fixture.directory_skill("collision", "managed");
    let sibling = fixture.directory_skill("sibling", "managed");
    let manifest = manifest_fixture();
    let valid_collision = deployment_receipt(
        &collision,
        exact_hash(&collision, SkillSourceLayout::Directory),
        &manifest,
    );
    let valid_sibling = deployment_receipt(
        &sibling,
        exact_hash(&sibling, SkillSourceLayout::Directory),
        &manifest,
    );
    let mut malformed_collision = deployment_receipt(
        &collision,
        exact_hash(&collision, SkillSourceLayout::Directory),
        &manifest,
    );
    malformed_collision.asset_id = AssetId::parse("malformed").unwrap();
    let malformed_key = malformed_collision
        .receipt_id()
        .unwrap()
        .as_str()
        .to_owned();
    let mut malformed_value = serde_json::to_value(malformed_collision).unwrap();
    malformed_value
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), json!("sentinel-collision-value"));
    let state = local_state_values(vec![
        (
            valid_collision.receipt_id().unwrap().as_str().to_owned(),
            serde_json::to_value(valid_collision).unwrap(),
        ),
        (malformed_key, malformed_value),
        (
            valid_sibling.receipt_id().unwrap().as_str().to_owned(),
            serde_json::to_value(valid_sibling).unwrap(),
        ),
    ]);
    let policy = TestPolicy::user(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Degraded);
    assert_eq!(report.entries.len(), 2);
    let collision_entry = report
        .entries
        .iter()
        .find(|entry| entry.source_relative_path.as_deref() == Some("collision"))
        .unwrap();
    assert_eq!(collision_entry.classification, ScanClassification::Unknown);
    let sibling_entry = report
        .entries
        .iter()
        .find(|entry| {
            entry.normalized_destination.as_deref() == Some(normalized(&sibling).as_str())
        })
        .unwrap();
    assert_eq!(
        sibling_entry.classification,
        ScanClassification::ManagedUnchanged
    );
    assert!(!format!("{report:?}").contains("sentinel-collision-value"));
}

#[test]
fn broad_invalidity_never_suppresses_an_exact_valid_destination_receipt() {
    for (case, field, value) in [
        (
            "harness-scope",
            "destination",
            json!("relative/not-absolute"),
        ),
        ("harness", "scope", json!("invalid-scope")),
        ("report", "harness", json!("/invalid-harness")),
    ] {
        let fixture = TestRoot::new(case);
        let destination = fixture.directory_skill("managed", "managed");
        let manifest = manifest_fixture();
        let valid = deployment_receipt(
            &destination,
            exact_hash(&destination, SkillSourceLayout::Directory),
            &manifest,
        );
        let mut malformed = serde_json::to_value(&valid).unwrap();
        malformed
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        malformed
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), json!("redacted-invalidity-canary"));
        let state = local_state_values(vec![
            (
                valid.receipt_id().unwrap().as_str().to_owned(),
                serde_json::to_value(valid).unwrap(),
            ),
            (format!("invalid-{case}"), malformed),
        ]);
        let policy = TestPolicy::user(fixture.path());

        let report = test_engine(&policy)
            .scan(&request(
                fixture.path(),
                fixture.path(),
                ProjectBoundary::NoRepository,
                &manifest.toml,
                Some(&state),
            ))
            .unwrap();

        assert_eq!(report.mode, ScanMode::Degraded, "case {case}");
        let managed = report
            .entries
            .iter()
            .find(|entry| entry.source_relative_path.as_deref() == Some("managed"))
            .unwrap();
        assert_eq!(
            managed.classification,
            ScanClassification::ManagedUnchanged,
            "case {case}"
        );
        assert!(!format!("{report:?}").contains("redacted-invalidity-canary"));
    }
}

#[test]
fn disappeared_receipt_destination_preserves_failed_candidate_as_unknown() {
    let fixture = TestRoot::new("missing-overlap-failed");
    let destination = fixture.malformed_skill("managed");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        hash("unread-rendered-identity"),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path()).remove_before_receipt_recapture(&destination);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::Unknown
    );
    assert!(report.entries[0].observation_id.is_some());
    assert!(
        report.entries[0]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_destination_missing")
    );
    assert!(
        report
            .entries
            .iter()
            .all(|entry| entry.classification != ScanClassification::MissingManaged)
    );
}

#[test]
fn disappeared_receipt_destination_preserves_ambiguous_effective_duplicates() {
    let fixture = TestRoot::new("missing-overlap-ambiguous");
    let destination = fixture.directory_skill("managed", "managed");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path())
        .with_duplicate_root_views()
        .ambiguous()
        .remove_before_receipt_recapture(&destination);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.entries.len(), 2);
    assert!(report.entries.iter().all(|entry| {
        entry.classification == ScanClassification::ConflictingDuplicate
            && entry.observation_id.is_some()
            && entry
                .findings
                .iter()
                .any(|finding| finding.code == "scan.receipt_destination_missing")
    }));
    assert!(
        report
            .entries
            .iter()
            .all(|entry| entry.classification != ScanClassification::MissingManaged)
    );
}

#[test]
fn disappeared_receipt_destination_collapses_multiple_observations_to_one_missing_entry() {
    let fixture = TestRoot::new("missing-overlap-multiple");
    let destination = fixture.directory_skill("managed", "managed");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path())
        .with_duplicate_root_views()
        .remove_before_receipt_recapture(&destination);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.entries.len(), 1);
    let entry = &report.entries[0];
    assert_eq!(entry.classification, ScanClassification::MissingManaged);
    assert_eq!(
        entry.normalized_destination.as_deref(),
        Some(normalized(&destination).as_str())
    );
    assert!(entry.observation_id.is_none());
    assert!(entry.root_tier.is_none());
    assert!(entry.logical_root.is_none());
    assert!(entry.source_relative_path.is_none());
    assert!(entry.exact_source_hash.is_none());
    assert_eq!(
        entry
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.receipt_destination_missing")
            .count(),
        1
    );
}

#[test]
fn invalid_manifest_and_invalid_local_state_select_degraded_mode() {
    let fixture = TestRoot::new("invalid-inputs");
    fixture.directory_skill("candidate", "candidate");
    let manifest = manifest_fixture();
    let policy = TestPolicy::user(fixture.path());
    let valid_state = local_state(vec![]);
    let invalid_state = valid_state.replace("\"id\": \"machine\"", "\"id\": \"INVALID\"");

    let bad_manifest = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            "not valid manifest = [",
            Some(&valid_state),
        ))
        .unwrap();
    assert_eq!(bad_manifest.mode, ScanMode::Degraded);
    assert_eq!(
        bad_manifest.entries[0].classification,
        ScanClassification::Unknown
    );
    assert!(
        bad_manifest
            .findings
            .iter()
            .any(|finding| finding.code == "scan.environment_invalid")
    );

    let bad_state = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&invalid_state),
        ))
        .unwrap();
    assert_eq!(bad_state.mode, ScanMode::Degraded);
    assert_eq!(
        bad_state.entries[0].classification,
        ScanClassification::Unknown
    );
    assert!(
        bad_state
            .findings
            .iter()
            .any(|finding| finding.code == "scan.local_state_invalid")
    );
    assert!(!format!("{bad_state:?}").contains("authored/local-state"));
}

#[test]
fn receipt_containment_rejects_user_project_and_manifest_mismatches() {
    let fixture = TestRoot::new("containment");
    let trusted_anchor = fixture.path().join("trusted");
    let observed_root = fixture.path().join("observed");
    let repository = fixture.path().join("repository");
    fs::create_dir_all(&trusted_anchor).unwrap();
    fs::create_dir_all(&observed_root).unwrap();
    fs::create_dir_all(&repository).unwrap();
    let destination = observed_root.join("managed");
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("SKILL.md"), valid_document("managed")).unwrap();
    let manifest = manifest_fixture();
    let outside_user = deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    );
    let state = local_state(vec![outside_user]);
    let policy = TestPolicy::user(&observed_root).with_anchor(&trusted_anchor);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            &repository,
            ProjectBoundary::Repository {
                root: repository.clone(),
            },
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Degraded);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::Unknown
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_invalid")
    );

    let project_policy = TestPolicy::user(&observed_root)
        .with_scope(HarnessScope::Project)
        .with_anchor(&observed_root);
    let mut project_receipt = deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    );
    project_receipt.scope = HarnessScope::Project;
    let project_state = local_state(vec![project_receipt]);
    let project_report = test_engine(&project_policy)
        .scan(&request(
            fixture.path(),
            &repository,
            ProjectBoundary::Repository {
                root: repository.clone(),
            },
            &manifest.toml,
            Some(&project_state),
        ))
        .unwrap();
    assert_eq!(project_report.mode, ScanMode::Degraded);
    assert_eq!(
        project_report.entries[0].classification,
        ScanClassification::Unknown
    );

    let mut absent_asset = deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    );
    absent_asset.asset_id = AssetId::parse("absent").unwrap();
    let absent_state = local_state(vec![absent_asset]);
    let absent_report = test_engine(&TestPolicy::user(&observed_root))
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&absent_state),
        ))
        .unwrap();
    assert_eq!(absent_report.mode, ScanMode::Degraded);
    assert_eq!(
        absent_report.entries[0].classification,
        ScanClassification::Unknown
    );
}

#[test]
fn receipt_scope_must_match_the_compiled_anchor_scope() {
    let fixture = TestRoot::new("scope-mismatch");
    let repository = fixture.path().join("repository");
    let destination = repository.join("managed");
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("SKILL.md"), valid_document("managed")).unwrap();
    let manifest = manifest_fixture();
    let mut receipt = deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Directory),
        &manifest,
    );
    receipt.scope = HarnessScope::Project;
    let state = local_state(vec![receipt]);
    let policy = TestPolicy::user(&repository).with_anchor(&repository);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            &repository,
            ProjectBoundary::Repository {
                root: repository.clone(),
            },
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Degraded);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| (entry.scope, entry.classification))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (HarnessScope::User, ScanClassification::Unmanaged),
            (HarnessScope::Project, ScanClassification::Unknown),
        ])
    );
}

#[cfg(unix)]
#[test]
fn symlinked_receipt_anchor_cannot_authorize_an_outside_destination() {
    use std::os::unix::fs::symlink;

    let fixture = TestRoot::new("unsafe-anchor");
    let outside = TestRoot::new("unsafe-anchor-target");
    let observed_root = fixture.path().join("observed");
    fs::create_dir_all(&observed_root).unwrap();
    let outside_destination = outside.directory_skill("managed", "managed");
    fs::write(
        outside_destination.join("secret.txt"),
        b"sentinel-anchor-target-must-not-be-read",
    )
    .unwrap();
    let anchor = fixture.path().join("receipt-anchor");
    symlink(outside.path(), &anchor).unwrap();
    let destination = anchor.join("managed");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        hash("unread-rendered-identity"),
        &manifest,
    )]);
    let policy = TestPolicy::user(&observed_root).with_anchor(&anchor);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Degraded);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::Unknown
    );
    assert_eq!(report.capture_usage().file_attempts, 0);
    assert_eq!(report.capture_usage().bytes_read, 0);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_anchor_invalid")
    );
    assert!(!format!("{report:?}").contains("sentinel-anchor-target"));
}

#[cfg(unix)]
#[test]
fn unsafe_receipt_destination_is_unknown_and_never_followed() {
    use std::os::unix::fs::symlink;

    let fixture = TestRoot::new("unsafe-receipt");
    let outside = TestRoot::new("unsafe-target");
    let target = outside.directory_skill("target", "managed");
    fs::write(
        target.join("secret.txt"),
        b"sentinel-symlink-target-must-not-be-read",
    )
    .unwrap();
    let destination = fixture.path().join("managed");
    symlink(&target, &destination).unwrap();
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &destination,
        hash("unread-expected-render"),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Classified);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::Unknown
    );
    assert_eq!(report.capture_usage().bytes_read, 0);
    assert!(!format!("{report:?}").contains("sentinel-symlink-target"));
}

#[test]
fn receipt_recapture_charges_the_request_budget_on_success_and_failure() {
    let fixture = TestRoot::new("receipt-capture-budget");
    let good = fixture.directory_skill("good", "managed");
    let malformed = fixture.malformed_skill("malformed");
    let manifest = manifest_fixture();
    let policy = TestPolicy::user(fixture.path());
    let mut successful_usage = CaptureUsage::default();
    capture_skill_source_metered(
        &SkillSource::Directory { path: good.clone() },
        CaptureLimits::default(),
        &mut successful_usage,
    )
    .unwrap();
    let mut failed_usage = CaptureUsage::default();
    capture_skill_source_metered(
        &SkillSource::Directory {
            path: malformed.clone(),
        },
        CaptureLimits::default(),
        &mut failed_usage,
    )
    .unwrap_err();
    let empty_state = local_state(vec![]);
    let baseline = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&empty_state),
        ))
        .unwrap();
    let state = local_state(vec![
        deployment_receipt(
            &good,
            exact_hash(&good, SkillSourceLayout::Directory),
            &manifest,
        ),
        deployment_receipt(&malformed, hash("unread-rendered-identity"), &manifest),
    ]);

    let report = test_engine(&policy)
        .scan(&request(
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(
        report.capture_usage().file_attempts,
        baseline.capture_usage().file_attempts
            + successful_usage.file_attempts
            + failed_usage.file_attempts
    );
    assert_eq!(
        report.capture_usage().bytes_read,
        baseline.capture_usage().bytes_read + successful_usage.bytes_read + failed_usage.bytes_read
    );
    assert!(report.entries.iter().any(|entry| {
        entry.classification == ScanClassification::ManagedUnchanged
            && entry.normalized_destination.as_deref() == Some(normalized(&good).as_str())
    }));
    assert!(report.entries.iter().any(|entry| {
        entry.classification == ScanClassification::Unknown
            && entry
                .findings
                .iter()
                .any(|finding| finding.code == "scan.receipt_capture_failed")
    }));
}

#[test]
fn synthetic_receipt_evidence_obeys_global_entry_and_finding_budgets() {
    let fixture = TestRoot::new("receipt-report-budget");
    let manifest = manifest_fixture();
    let state = local_state(vec![deployment_receipt(
        &fixture.path().join("missing"),
        hash("missing-rendered-identity"),
        &manifest,
    )]);
    let policy = TestPolicy::user(fixture.path());

    let mut entry_limited = request(
        fixture.path(),
        fixture.path(),
        ProjectBoundary::NoRepository,
        &manifest.toml,
        Some(&state),
    );
    entry_limited.limits.max_report_entries = 0;
    let error = test_engine(&policy).scan(&entry_limited).unwrap_err();
    assert_eq!(error.code, "scan.report_budget_exhausted");

    let mut finding_limited = request(
        fixture.path(),
        fixture.path(),
        ProjectBoundary::NoRepository,
        &manifest.toml,
        Some(&state),
    );
    finding_limited.limits.max_findings = 0;
    let error = test_engine(&policy).scan(&finding_limited).unwrap_err();
    assert_eq!(error.code, "scan.report_budget_exhausted");
}

#[test]
fn unknown_opencode_current_policy_still_verifies_a_v2_standalone_receipt() {
    let fixture = TestRoot::new("standalone-receipt");
    let destination = fixture.path().join("legacy.md");
    fs::write(&destination, valid_document("legacy")).unwrap();
    let manifest = manifest_fixture();
    let mut receipt = deployment_receipt(
        &destination,
        exact_hash(&destination, SkillSourceLayout::Standalone),
        &manifest,
    );
    receipt.harness = HarnessId::OpenCode;
    receipt.adapter_version = "opencode/v2".to_owned();
    let state = local_state(vec![receipt]);
    let policy = TestPolicy::opencode_unknown(fixture.path()).standalone_unsupported();

    let report = test_engine(&policy)
        .scan(&request_for_harness(
            HarnessId::OpenCode,
            fixture.path(),
            fixture.path(),
            ProjectBoundary::NoRepository,
            &manifest.toml,
            Some(&state),
        ))
        .unwrap();

    assert_eq!(report.mode, ScanMode::Classified);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::ManagedUnchanged
    );
    assert_eq!(
        report.entries[0].layout,
        Some(SkillSourceLayout::Standalone)
    );
    assert!(
        report.entries[0]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.layout_unsupported")
    );
    assert_eq!(policy.anchor_calls(), 1);
}
