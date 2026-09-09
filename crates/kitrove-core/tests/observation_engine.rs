#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kitrove_adapter_api::{
    AdapterError, AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary,
    DuplicateDecision, EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy,
    HarnessVersion, LocatorDecision, NativeAcceptance, ObservationId, ObservationIdentity,
    ObservedRoot, PolicyLine, PolicyProfile, PolicyRuntimeAuthority, PortablePolicyDecision,
    ReceiptAnchor, RelatedRoot, RootContext, RootHookReport, RootId, RootPathAuthority, RootTier,
    ScanFinding, ScanLimits, ScanRequest, ScopeSelection, SourceRelativePath,
    VerifiedVersionEvidence, VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{CapturedSkillSource, SkillSourceLayout};
use kitrove_core::{ObservedCandidate, ScanClassification, ScanEngine};
use kitrove_model::{AssetId, HarnessId, HarnessScope};

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

fn test_engine(policy: &dyn HarnessObservationPolicy) -> ScanEngine<'_> {
    ScanEngine::from_authorities(vec![(policy, policy.runtime_authority())])
        .expect("test authority catalog")
}

fn test_engines(policies: Vec<&dyn HarnessObservationPolicy>) -> ScanEngine<'_> {
    let policies = policies
        .into_iter()
        .map(|policy| (policy, policy.runtime_authority()))
        .collect();
    ScanEngine::from_authorities(policies).expect("test authority catalogs")
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kitrove-core-observation-engine-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn skill(&self, name: &str, bytes: &[u8]) {
        let directory = self.path().join(name);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("SKILL.md"), bytes).unwrap();
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakePolicy {
    roots: Vec<(PathBuf, RootTier, RootId)>,
    decisions: AtomicUsize,
    description: String,
    top_findings: usize,
    top_finding_actions: Vec<&'static str>,
    candidate_findings: bool,
    reverse_candidate_findings: bool,
    capture_standalone: bool,
}

impl FakePolicy {
    fn new(root: &Path) -> Self {
        Self {
            roots: vec![(
                root.to_path_buf(),
                RootTier::User,
                RootId::parse("test.skills.0000").unwrap(),
            )],
            decisions: AtomicUsize::new(0),
            description: "test skill".to_owned(),
            top_findings: 0,
            top_finding_actions: vec![],
            candidate_findings: false,
            reverse_candidate_findings: false,
            capture_standalone: false,
        }
    }

    fn from_roots(roots: Vec<PathBuf>) -> Self {
        let mut canonical_order = roots.clone();
        canonical_order.sort();
        Self {
            roots: roots
                .into_iter()
                .map(|path| {
                    let index = canonical_order
                        .binary_search(&path)
                        .expect("the path came from the canonical root set");
                    (
                        path,
                        RootTier::User,
                        RootId::parse(format!("test.skills.{index:04}")).unwrap(),
                    )
                })
                .collect(),
            decisions: AtomicUsize::new(0),
            description: "test skill".to_owned(),
            top_findings: 0,
            top_finding_actions: vec![],
            candidate_findings: false,
            reverse_candidate_findings: false,
            capture_standalone: false,
        }
    }

    fn from_tiered_roots(roots: Vec<(PathBuf, RootTier)>) -> Self {
        Self {
            roots: roots
                .into_iter()
                .map(|(path, tier)| {
                    let ordinal = match tier {
                        RootTier::User => 0,
                        RootTier::Project => 1,
                        RootTier::Admin => 2,
                        RootTier::System => 3,
                        RootTier::Compatibility => 4,
                        RootTier::Explicit => 5,
                    };
                    (
                        path,
                        tier,
                        RootId::parse(format!("test.skills.{ordinal:04}")).unwrap(),
                    )
                })
                .collect(),
            decisions: AtomicUsize::new(0),
            description: "test skill".to_owned(),
            top_findings: 0,
            top_finding_actions: vec![],
            candidate_findings: false,
            reverse_candidate_findings: false,
            capture_standalone: false,
        }
    }

    fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_owned();
        self
    }

    fn with_top_findings(mut self, count: usize) -> Self {
        self.top_findings = count;
        self
    }

    fn with_top_finding_actions(mut self, actions: &[&'static str]) -> Self {
        self.top_finding_actions = actions.to_vec();
        self
    }

    fn with_reversed_candidate_findings(mut self) -> Self {
        self.candidate_findings = true;
        self.reverse_candidate_findings = true;
        self
    }

    fn with_candidate_findings(mut self) -> Self {
        self.candidate_findings = true;
        self
    }

    fn with_standalone_capture(mut self) -> Self {
        self.capture_standalone = true;
        self
    }

    fn decision_count(&self) -> usize {
        self.decisions.load(Ordering::Relaxed)
    }
}

impl HarnessObservationPolicy for FakePolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        let roots = self
            .roots
            .iter()
            .map(|(path, tier, logical_id)| ObservedRoot {
                logical_id: logical_id.clone(),
                path: path.clone(),
                scope: HarnessScope::User,
                tier: *tier,
                policy_rank: 7,
                enabled_layouts: if self.capture_standalone {
                    BTreeSet::from([SkillSourceLayout::Directory, SkillSourceLayout::Standalone])
                } else {
                    BTreeSet::from([SkillSourceLayout::Directory])
                },
                evidence: EvidenceRef::parse("test.root").unwrap(),
            })
            .collect::<Vec<_>>();
        PolicyRuntimeAuthority::exact(PolicyLine::ClaudeCurrent, &roots, &[], &[])
    }

    fn profile(&self, _version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            VersionObservationOwned::Unknown,
            EvidenceRef::parse("test.profile").unwrap(),
        )
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        Ok(self
            .roots
            .iter()
            .map(|(path, tier, logical_id)| ObservedRoot {
                logical_id: logical_id.clone(),
                path: path.clone(),
                scope: HarnessScope::User,
                tier: *tier,
                policy_rank: 7,
                enabled_layouts: if self.capture_standalone {
                    BTreeSet::from([SkillSourceLayout::Directory, SkillSourceLayout::Standalone])
                } else {
                    BTreeSet::from([SkillSourceLayout::Directory])
                },
                evidence: EvidenceRef::parse("test.root").unwrap(),
            })
            .collect())
    }

    fn discover_unusual_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        Ok(RootHookReport {
            roots: vec![],
            findings: (0..self.top_findings)
                .map(|_index| {
                    ScanFinding::new(
                        "test.top",
                        FindingSeverity::Attention,
                        FindingSubject::Root(RootId::parse("test.skills").unwrap()),
                        vec![EvidenceRef::parse("test.root").unwrap()],
                        "inspect the test root",
                    )
                })
                .chain(self.top_finding_actions.iter().map(|action| {
                    ScanFinding::new(
                        "test.top.action",
                        FindingSeverity::Attention,
                        FindingSubject::Root(RootId::parse("test.skills").unwrap()),
                        vec![EvidenceRef::parse("test.root").unwrap()],
                        action,
                    )
                }))
                .collect(),
        })
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory => LocatorDecision::Capture,
            SkillSourceLayout::Standalone if self.capture_standalone => LocatorDecision::Capture,
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
        self.decisions.fetch_add(1, Ordering::Relaxed);
        let name = candidate
            .document
            .declared_name
            .as_deref()
            .unwrap_or("fallback");
        let mut findings = if self.candidate_findings {
            ["test.candidate.a", "test.candidate.z"]
                .into_iter()
                .map(|code| {
                    ScanFinding::new(
                        code,
                        FindingSeverity::Informational,
                        FindingSubject::Root(RootId::parse("test.skills").unwrap()),
                        vec![EvidenceRef::parse("test.root").unwrap()],
                        "inspect the candidate",
                    )
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        if self.reverse_candidate_findings {
            findings.reverse();
        }
        CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(name.to_owned()),
            PortablePolicyDecision::Project {
                name: AssetId::parse(name).unwrap(),
                description: self.description.clone(),
                reasons: vec![],
            },
            findings,
        )
    }

    fn resolve_duplicates(
        &self,
        _group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        Ok(DuplicateDecision::Coexist)
    }

    fn receipt_anchors(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        Ok(vec![])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailingStage {
    Profile,
    Roots,
    UnusualRoots,
    RelatedRoots,
    ReceiptAnchors,
    CandidateDecision,
    DuplicateDecision,
    FabricatedDuplicateWinner,
}

struct StageFailingPolicy {
    root: PathBuf,
    stage: FailingStage,
}

struct AuthorityProbePolicy {
    roots: Vec<ObservedRoot>,
    related_roots: Vec<RelatedRoot>,
    anchors: Vec<ReceiptAnchor>,
    authority: PolicyRuntimeAuthority,
    decisions: AtomicUsize,
}

impl HarnessObservationPolicy for AuthorityProbePolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        self.authority.clone()
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            version.into(),
            EvidenceRef::parse("test.authority.profile").unwrap(),
        )
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        Ok(self.roots.clone())
    }

    fn related_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        Ok(self.related_roots.clone())
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory => LocatorDecision::Capture,
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
        self.decisions.fetch_add(1, Ordering::Relaxed);
        let name = candidate.document.declared_name.as_deref().unwrap();
        CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(name.to_owned()),
            PortablePolicyDecision::Project {
                name: AssetId::parse(name).unwrap(),
                description: "authority probe".to_owned(),
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
        Ok(DuplicateDecision::Coexist)
    }

    fn receipt_anchors(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        Ok(self.anchors.clone())
    }
}

impl StageFailingPolicy {
    fn new(root: &Path, stage: FailingStage) -> Self {
        Self {
            root: root.to_path_buf(),
            stage,
        }
    }

    fn failure<T>(&self) -> AdapterResult<T> {
        Err(AdapterError::new(
            "test.policy_failure",
            "the compiled test policy failed",
        ))
    }
}

impl HarnessObservationPolicy for StageFailingPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Pi
    }

    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        let roots = [ObservedRoot {
            logical_id: RootId::parse("test.pi.skills").unwrap(),
            path: self.root.clone(),
            scope: HarnessScope::User,
            tier: RootTier::User,
            policy_rank: 4,
            enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
            evidence: EvidenceRef::parse("test.pi.root").unwrap(),
        }];
        PolicyRuntimeAuthority::exact(PolicyLine::PiLatest, &roots, &[], &[])
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        if self.stage == FailingStage::Profile {
            return self.failure();
        }
        PolicyProfile::new(
            HarnessId::Pi,
            PolicyLine::PiLatest,
            version.into(),
            EvidenceRef::parse("test.pi.profile").unwrap(),
        )
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        if self.stage == FailingStage::Roots {
            return self.failure();
        }
        Ok(vec![ObservedRoot {
            logical_id: RootId::parse("test.pi.skills").unwrap(),
            path: self.root.clone(),
            scope: HarnessScope::User,
            tier: RootTier::User,
            policy_rank: 4,
            enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
            evidence: EvidenceRef::parse("test.pi.root").unwrap(),
        }])
    }

    fn discover_unusual_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        if self.stage == FailingStage::UnusualRoots {
            return self.failure();
        }
        Ok(RootHookReport::default())
    }

    fn related_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        if self.stage == FailingStage::RelatedRoots {
            return self.failure();
        }
        Ok(vec![])
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory => LocatorDecision::Capture,
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
        if self.stage == FailingStage::CandidateDecision {
            return self.failure();
        }
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
                description: "test skill".to_owned(),
                reasons: vec![],
            },
            vec![],
        )
    }

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        if self.stage == FailingStage::DuplicateDecision {
            return self.failure();
        }
        if self.stage == FailingStage::FabricatedDuplicateWinner {
            let harness = HarnessId::Pi;
            let root = RootId::parse("test.fabricated").unwrap();
            let relative = SourceRelativePath::parse("fabricated").unwrap();
            let fabricated = ObservationId::from_identity(&ObservationIdentity {
                harness: &harness,
                scope: HarnessScope::User,
                root_tier: RootTier::User,
                policy_rank: 999,
                logical_root: &root,
                source_relative_path: &relative,
                layout: SkillSourceLayout::Directory,
                original_document_name: "SKILL.md",
                native_id: Some("shared"),
                exact_source_hash: Some(&group[0].exact_source_hash),
            });
            return Ok(DuplicateDecision::Winner {
                observation_id: fabricated,
                reason: EvidenceRef::parse("test.pi.duplicate").unwrap(),
            });
        }
        Ok(DuplicateDecision::Coexist)
    }

    fn receipt_anchors(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        if self.stage == FailingStage::ReceiptAnchors {
            return self.failure();
        }
        Ok(vec![])
    }
}

fn request(limits: ScanLimits) -> ScanRequest<'static> {
    ScanRequest {
        home: Some(PathBuf::from("/unused-home")),
        working_directory: PathBuf::from("/unused-workspace"),
        project_boundary: kitrove_adapter_api::ProjectBoundary::NoRepository,
        harnesses: BTreeSet::from([HarnessId::Claude]),
        scopes: ScopeSelection::All,
        explicit_roots: vec![],
        supplied_native_roots: vec![],
        versions: BTreeMap::new(),
        project_trust: BTreeMap::new(),
        environment: None,
        local_state: None,
        limits,
    }
}

fn request_for_both(limits: ScanLimits) -> ScanRequest<'static> {
    let mut request = request(limits);
    request.harnesses.insert(HarnessId::Pi);
    request
}

fn valid_document(name: &str) -> Vec<u8> {
    format!("---\nname: {name}\ndescription: A valid skill.\n---\n# Skill\n").into_bytes()
}

fn probe_root(path: &Path, logical_id: &str, rank: u32) -> ObservedRoot {
    ObservedRoot {
        logical_id: RootId::parse(logical_id).unwrap(),
        path: path.to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank: rank,
        enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
        evidence: EvidenceRef::parse("test.authority.root").unwrap(),
    }
}

#[test]
fn engine_constructor_rejects_an_invalid_explicit_authority_catalog() {
    let root = TestRoot::new();
    let policy = FakePolicy::new(root.path());
    let mut authority = policy.runtime_authority();
    authority.roots[0].scopes.clear();

    let error = ScanEngine::from_authorities(vec![(&policy, authority)])
        .err()
        .expect("an empty authority scope set must fail before scanning");

    assert_eq!(error.code, "scan.runtime_authority_invalid");
}

#[test]
fn engine_constructor_rejects_an_unkeyed_explicit_file_authority() {
    let root = TestRoot::new();
    let policy = FakePolicy::new(root.path());
    let mut authority = policy.runtime_authority();
    authority.roots[0].path = RootPathAuthority::ExplicitFileRequest;

    let error = ScanEngine::from_authorities(vec![(&policy, authority)])
        .err()
        .expect("an explicit file authority must carry its closed request-item identity");

    assert_eq!(error.code, "scan.runtime_authority_invalid");
}

#[test]
fn engine_constructor_rejects_explicit_file_authority_for_related_roots() {
    let root = TestRoot::new();
    let policy = FakePolicy::new(root.path());
    let mut authority = policy.runtime_authority();
    let mut related_claim = authority.roots.remove(0);
    related_claim.logical_id = kitrove_adapter_api::RootIdAuthority::IndexedPrefixWithEncodedFile(
        "test.explicit.file.".to_owned(),
    );
    related_claim.path = RootPathAuthority::ExplicitFileRequest;
    related_claim.layouts.clear();
    authority
        .related_roots
        .push(kitrove_adapter_api::RelatedRootAuthority {
            root: related_claim,
            kind: kitrove_model::AssetKind::Command,
            pattern: kitrove_adapter_api::RelatedDocumentPattern::MarkdownAtAnyDepth,
        });

    let error = ScanEngine::from_authorities(vec![(&policy, authority)])
        .err()
        .expect("explicit file request authority must not grant recursive related-root access");

    assert_eq!(error.code, "scan.runtime_authority_invalid");
}

#[test]
fn central_authority_rejects_conflicting_and_out_of_catalog_claims_before_walking() {
    let authorized = TestRoot::new();
    authorized.skill("authorized", &valid_document("authorized"));
    let duplicate = TestRoot::new();
    duplicate.skill("duplicate", &valid_document("duplicate"));
    let rogue = TestRoot::new();
    rogue.skill("rogue", &valid_document("rogue"));
    let related = TestRoot::new();
    fs::write(related.path().join("command.md"), b"secret command body").unwrap();
    let first = probe_root(authorized.path(), "test.authorized", 1);
    let conflicting = probe_root(duplicate.path(), "test.authorized", 1);
    let out_of_catalog = probe_root(rogue.path(), "test.rogue", 2);
    let authority = PolicyRuntimeAuthority::exact(
        PolicyLine::ClaudeCurrent,
        &[first.clone(), conflicting.clone()],
        &[],
        &[],
    );
    let policy = AuthorityProbePolicy {
        roots: vec![first, conflicting, out_of_catalog],
        related_roots: vec![RelatedRoot {
            logical_id: RootId::parse("test.rogue.related").unwrap(),
            path: related.path().to_path_buf(),
            scope: HarnessScope::User,
            tier: RootTier::Compatibility,
            policy_rank: 3,
            kind: kitrove_model::AssetKind::Command,
            pattern: kitrove_adapter_api::RelatedDocumentPattern::MarkdownAtAnyDepth,
            evidence: EvidenceRef::parse("test.authority.related").unwrap(),
        }],
        anchors: vec![ReceiptAnchor {
            scope: HarnessScope::User,
            path: rogue.path().to_path_buf(),
            evidence: EvidenceRef::parse("test.authority.receipt").unwrap(),
        }],
        authority,
        decisions: AtomicUsize::new(0),
    };

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(policy.decisions.load(Ordering::Relaxed), 1);
    assert_eq!(report.entries.len(), 1);
    assert!(report.related.is_empty());
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|finding| finding.code == "scan.policy_root_conflict")
            .count(),
        3
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.receipt_policy_failed")
    );
}

#[test]
fn policy_stage_failures_are_localized_without_hiding_a_valid_sibling() {
    let stages = [
        (FailingStage::Profile, "scan.policy_profile_failed"),
        (FailingStage::Roots, "scan.policy_roots_failed"),
        (
            FailingStage::UnusualRoots,
            "scan.policy_unusual_roots_failed",
        ),
        (
            FailingStage::RelatedRoots,
            "scan.policy_related_roots_failed",
        ),
        (FailingStage::ReceiptAnchors, "scan.receipt_policy_failed"),
    ];

    for (stage, expected_code) in stages {
        let valid = TestRoot::new();
        valid.skill("valid", &valid_document("valid"));
        let failing = TestRoot::new();
        failing.skill("pi", &valid_document("pi"));
        let valid_policy = FakePolicy::new(valid.path());
        let failing_policy = StageFailingPolicy::new(failing.path(), stage);

        let report = test_engines(vec![&valid_policy, &failing_policy])
            .scan(&request_for_both(ScanLimits::default()))
            .unwrap();

        assert!(report.entries.iter().any(|entry| {
            entry.harness == HarnessId::Claude
                && entry.classification == ScanClassification::Unmanaged
        }));
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == expected_code),
            "missing localized finding for {stage:?}"
        );
    }
}

#[test]
fn candidate_policy_failure_becomes_nested_unknown_and_keeps_sibling() {
    let valid = TestRoot::new();
    valid.skill("valid", &valid_document("valid"));
    let failing = TestRoot::new();
    failing.skill("pi", &valid_document("pi"));
    let valid_policy = FakePolicy::new(valid.path());
    let failing_policy = StageFailingPolicy::new(failing.path(), FailingStage::CandidateDecision);

    let report = test_engines(vec![&valid_policy, &failing_policy])
        .scan(&request_for_both(ScanLimits::default()))
        .unwrap();

    assert!(report.entries.iter().any(|entry| {
        entry.harness == HarnessId::Claude && entry.classification == ScanClassification::Unmanaged
    }));
    let failed = report
        .entries
        .iter()
        .find(|entry| entry.harness == HarnessId::Pi)
        .unwrap();
    assert_eq!(failed.classification, ScanClassification::Unknown);
    assert_eq!(failed.findings.len(), 1);
    assert_eq!(failed.findings[0].code, "scan.candidate_policy_failed");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| { finding.code != "scan.candidate_policy_failed" })
    );
}

#[test]
fn duplicate_policy_failures_and_fabricated_winners_never_escape_the_group() {
    for (stage, expected_code) in [
        (
            FailingStage::DuplicateDecision,
            "scan.duplicate_policy_failed",
        ),
        (
            FailingStage::FabricatedDuplicateWinner,
            "scan.duplicate_winner_invalid",
        ),
    ] {
        let valid = TestRoot::new();
        valid.skill("valid", &valid_document("valid"));
        let failing = TestRoot::new();
        failing.skill("first", &valid_document("shared"));
        failing.skill("second", &valid_document("shared"));
        let valid_policy = FakePolicy::new(valid.path());
        let failing_policy = StageFailingPolicy::new(failing.path(), stage);

        let report = test_engines(vec![&valid_policy, &failing_policy])
            .scan(&request_for_both(ScanLimits::default()))
            .unwrap();

        assert!(report.entries.iter().any(|entry| {
            entry.harness == HarnessId::Claude
                && entry.classification == ScanClassification::Unmanaged
        }));
        let pi_entries = report
            .entries
            .iter()
            .filter(|entry| entry.harness == HarnessId::Pi)
            .collect::<Vec<_>>();
        assert_eq!(
            pi_entries.len(),
            2,
            "unexpected Pi entries: {:?}",
            pi_entries
                .iter()
                .map(|entry| entry.source_relative_path.as_deref())
                .collect::<Vec<_>>()
        );
        assert!(pi_entries.iter().all(|entry| {
            entry.shadowed_by.is_none()
                && entry
                    .findings
                    .iter()
                    .any(|finding| finding.code == expected_code)
        }));
    }
}

#[test]
fn mismatched_version_map_key_is_redacted_and_conservatively_unknown() {
    let fixture = TestRoot::new();
    fixture.skill("valid", &valid_document("valid"));
    let policy = FakePolicy::new(fixture.path());
    let mut scan_request = request(ScanLimits::default());
    scan_request.versions.insert(
        HarnessId::Claude,
        VerifiedVersionEvidence::new(
            HarnessId::Codex,
            HarnessVersion::parse("1.0.0").unwrap(),
            PolicyLine::CodexCurrent,
            EvidenceRef::parse("test.version").unwrap(),
        )
        .unwrap(),
    );

    let report = test_engine(&policy).scan(&scan_request).unwrap();

    assert_eq!(
        report.versions.get(&HarnessId::Claude),
        Some(&VersionObservationOwned::Unknown)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "scan.version_evidence_mismatch")
    );
}

#[test]
fn one_bad_candidate_does_not_hide_a_valid_sibling_or_escape_the_budget() {
    let fixture = TestRoot::new();
    fixture.skill("malformed", b"---\nname: [\n---\n");
    fixture.skill("valid", &valid_document("valid"));
    let policy = FakePolicy::new(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(report.entries.len(), 2);
    assert_eq!(
        report
            .entries
            .iter()
            .map(|entry| (
                entry.source_relative_path.as_deref().unwrap(),
                entry.classification
            ))
            .collect::<Vec<_>>(),
        [
            ("malformed", ScanClassification::Unknown),
            ("valid", ScanClassification::Unmanaged),
        ]
    );
    assert_eq!(policy.decision_count(), 1);
    assert_eq!(report.capture_usage().file_attempts, 4);
    assert!(report.capture_usage().bytes_read > 0);
    assert!(matches!(
        report.observations()[0],
        ObservedCandidate::Failed(_)
    ));
    assert!(matches!(
        report.observations()[1],
        ObservedCandidate::Accepted(_)
    ));
}

#[test]
fn exhausted_capture_keeps_remaining_safe_locators_unknown_without_opening_them() {
    let fixture = TestRoot::new();
    fixture.skill("a", &valid_document("a"));
    fixture.skill("b", &valid_document("b"));
    let policy = FakePolicy::new(fixture.path());
    let limits = ScanLimits {
        max_capture_files: 2,
        ..ScanLimits::default()
    };

    let report = test_engine(&policy).scan(&request(limits)).unwrap();

    assert_eq!(policy.decision_count(), 1);
    assert_eq!(report.capture_usage().file_attempts, 2);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::Unmanaged
    );
    assert_eq!(
        report.entries[1].classification,
        ScanClassification::Unknown
    );
    assert_eq!(report.entries[1].exact_source_hash, None);
    assert!(
        report.entries[1]
            .findings
            .iter()
            .any(|finding| finding.code == "scan.capture_budget_exhausted")
    );
}

#[test]
fn accepted_observation_identity_changes_with_exact_source_but_failed_identity_does_not() {
    let fixture = TestRoot::new();
    fixture.skill("candidate", &valid_document("candidate"));
    let policy = FakePolicy::new(fixture.path());
    let first = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let accepted_first = first.entries[0].observation_id.clone().unwrap();

    fs::write(
        fixture.path().join("candidate/SKILL.md"),
        b"---\nname: candidate\ndescription: Changed.\n---\n",
    )
    .unwrap();
    let second = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let accepted_second = second.entries[0].observation_id.clone().unwrap();
    assert_ne!(accepted_first, accepted_second);

    fs::write(
        fixture.path().join("candidate/SKILL.md"),
        b"---\nname: [\n---\nfirst invalid body\n",
    )
    .unwrap();
    let failed_first = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    fs::write(
        fixture.path().join("candidate/SKILL.md"),
        b"---\nname: [\n---\nsecond invalid body\n",
    )
    .unwrap();
    let failed_second = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(
        failed_first.entries[0].observation_id,
        failed_second.entries[0].observation_id
    );
}

#[cfg(unix)]
#[test]
fn a_nonportable_relative_locator_is_unknown_without_hiding_its_sibling() {
    let fixture = TestRoot::new();
    fixture.skill("bad\\name", &valid_document("bad-name"));
    fixture.skill("valid", &valid_document("valid"));
    let policy = FakePolicy::new(fixture.path());

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(report.entries.len(), 2);
    let invalid = report
        .entries
        .iter()
        .find(|entry| entry.observation_id.is_none())
        .unwrap();
    assert_eq!(invalid.classification, ScanClassification::Unknown);
    assert_eq!(invalid.source_relative_path, None);
    assert!(!format!("{report:?}").contains("bad\\name"));
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.classification == ScanClassification::Unmanaged)
    );
    assert_eq!(policy.decision_count(), 1);
}

#[test]
fn finding_budget_counts_zero_limit_and_candidate_local_findings() {
    let fixture = TestRoot::new();
    fixture.skill("malformed", b"---\nname: [\n---\n");
    let policy = FakePolicy::new(fixture.path());
    let error = test_engine(&policy)
        .scan(&request(ScanLimits {
            max_findings: 0,
            ..ScanLimits::default()
        }))
        .unwrap_err();

    assert_eq!(error.code, "scan.report_budget_exhausted");

    let valid_fixture = TestRoot::new();
    valid_fixture.skill("valid", &valid_document("valid"));
    let valid_policy = FakePolicy::new(valid_fixture.path());
    let report = test_engine(&valid_policy)
        .scan(&request(ScanLimits {
            max_findings: 0,
            ..ScanLimits::default()
        }))
        .unwrap();
    assert!(report.findings.is_empty());
    assert!(report.entries[0].findings.is_empty());
}

#[test]
fn report_entry_meter_refuses_before_capturing_an_unretainable_candidate() {
    let fixture = TestRoot::new();
    for name in ["one", "three", "two"] {
        fixture.skill(name, &valid_document(name));
    }
    let policy = FakePolicy::new(fixture.path());

    let error = test_engine(&policy)
        .scan(&request(ScanLimits {
            max_report_entries: 1,
            ..ScanLimits::default()
        }))
        .unwrap_err();

    assert_eq!(error.code, "scan.report_budget_exhausted");
    assert_eq!(policy.decision_count(), 1);
}

#[cfg(unix)]
#[test]
fn unreadable_root_becomes_one_root_level_unknown_entry() {
    use std::os::unix::fs::symlink;

    let fixture = TestRoot::new();
    let external = TestRoot::new();
    let linked_root = fixture.path().join("linked-root");
    symlink(external.path(), &linked_root).unwrap();
    let policy = FakePolicy::new(&linked_root);

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert!(report.findings.is_empty());
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].classification,
        ScanClassification::Unknown
    );
    assert_eq!(report.entries[0].source_relative_path, None);
    assert_eq!(report.entries[0].observation_id, None);
    assert_eq!(report.entries[0].findings.len(), 1);
    assert_eq!(report.entries[0].findings[0].code, "scan.root_unreadable");
}

#[test]
fn finding_budget_uses_one_global_count_for_top_level_and_nested_findings() {
    let fixture = TestRoot::new();
    fixture.skill("malformed", b"---\nname: [\n---\n");
    let policy = FakePolicy::new(fixture.path()).with_top_findings(1);

    let error = test_engine(&policy)
        .scan(&request(ScanLimits {
            max_findings: 2,
            ..ScanLimits::default()
        }))
        .unwrap_err();
    assert_eq!(error.code, "scan.report_budget_exhausted");

    let report = test_engine(&policy)
        .scan(&request(ScanLimits {
            max_findings: 3,
            ..ScanLimits::default()
        }))
        .unwrap();
    assert_eq!(
        report.findings.len()
            + report
                .entries
                .iter()
                .map(|entry| entry.findings.len())
                .sum::<usize>(),
        3
    );
}

#[test]
fn duplicate_harness_policies_are_rejected_independent_of_caller_order() {
    let fixture = TestRoot::new();
    fixture.skill("valid", &valid_document("valid"));
    let first = FakePolicy::new(fixture.path());
    let second = FakePolicy::new(fixture.path());

    let forward = ScanEngine::from_authorities(vec![
        (&first, first.runtime_authority()),
        (&second, second.runtime_authority()),
    ])
    .err()
    .expect("duplicate harness authorities must fail construction");
    let reverse = ScanEngine::from_authorities(vec![
        (&second, second.runtime_authority()),
        (&first, first.runtime_authority()),
    ])
    .err()
    .expect("duplicate harness authorities must fail construction");

    assert_eq!(forward, reverse);
    assert_eq!(forward.code, "scan.duplicate_harness_policy");
    assert_eq!(first.decision_count(), 0);
    assert_eq!(second.decision_count(), 0);
}

#[test]
fn unique_root_keys_and_reversed_findings_produce_equal_canonical_reports() {
    let first = TestRoot::new();
    let second = TestRoot::new();
    first.skill("same", &valid_document("beta"));
    second.skill("same", &valid_document("alpha"));
    let forward = FakePolicy::from_roots(vec![
        first.path().to_path_buf(),
        second.path().to_path_buf(),
    ])
    .with_candidate_findings();
    let reverse = FakePolicy::from_roots(vec![
        second.path().to_path_buf(),
        first.path().to_path_buf(),
    ])
    .with_reversed_candidate_findings();

    let forward = test_engine(&forward)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let reverse = test_engine(&reverse)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .entries
            .iter()
            .map(|entry| entry.native_id.as_deref().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["alpha", "beta"])
    );
    assert!(forward.entries.iter().all(|entry| {
        entry
            .findings
            .windows(2)
            .all(|pair| pair[0].code <= pair[1].code)
    }));
    assert!(
        forward
            .findings
            .iter()
            .all(|finding| { !matches!(finding.code, "test.candidate.a" | "test.candidate.z") })
    );
    assert!(forward.entries.iter().all(|entry| {
        entry.findings.iter().all(|finding| {
            matches!(
                &finding.subject,
                FindingSubject::Observation(id) if Some(id) == entry.observation_id.as_ref()
            )
        })
    }));
}

#[test]
fn finding_order_is_caller_independent_when_only_action_differs() {
    let fixture = TestRoot::new();
    let forward = FakePolicy::new(fixture.path())
        .with_top_finding_actions(&["inspect second", "inspect first"]);
    let reverse = FakePolicy::new(fixture.path())
        .with_top_finding_actions(&["inspect first", "inspect second"]);

    let forward = test_engine(&forward)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let reverse = test_engine(&reverse)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .findings
            .iter()
            .map(|finding| finding.action)
            .collect::<Vec<_>>(),
        ["inspect first", "inspect second"]
    );
}

#[test]
fn observation_order_is_caller_independent_when_only_root_tier_differs() {
    let tiers = [
        RootTier::User,
        RootTier::Project,
        RootTier::Admin,
        RootTier::System,
        RootTier::Compatibility,
        RootTier::Explicit,
    ];
    let fixtures = tiers
        .iter()
        .map(|_| {
            let fixture = TestRoot::new();
            fixture.skill("same", &valid_document("same"));
            fixture
        })
        .collect::<Vec<_>>();
    let roots = fixtures
        .iter()
        .zip(tiers)
        .map(|(fixture, tier)| (fixture.path().to_path_buf(), tier))
        .collect::<Vec<_>>();
    let forward = FakePolicy::from_tiered_roots(roots.clone());
    let reverse = FakePolicy::from_tiered_roots(roots.into_iter().rev().collect());

    let forward = test_engine(&forward)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let reverse = test_engine(&reverse)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .observations()
            .iter()
            .map(|observation| observation.location().root_tier)
            .collect::<Vec<_>>(),
        tiers
    );
}

#[test]
fn debug_output_never_exposes_captured_or_projection_text() {
    let secret = "sentinel-secret-never-debug";
    let fixture = TestRoot::new();
    fixture.skill("accepted", &valid_document("accepted"));
    fixture.skill(
        "failed",
        format!("---\nname: [\n---\n{secret}\n").as_bytes(),
    );
    let policy = FakePolicy::new(fixture.path()).with_description(secret);

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    for observation in report.observations() {
        assert!(!format!("{observation:?}").contains(secret));
    }
    for entry in &report.entries {
        assert!(!format!("{entry:?}").contains(secret));
    }
    assert!(!format!("{report:?}").contains(secret));
}

#[test]
fn debug_output_never_exposes_a_standalone_filename() {
    let sentinel = "sentinel-filename-never-debug";
    let fixture = TestRoot::new();
    fs::write(
        fixture.path().join(format!("{sentinel}-accepted.md")),
        valid_document("accepted"),
    )
    .unwrap();
    fs::write(
        fixture.path().join(format!("{sentinel}-failed.md")),
        b"---\nname: [\n---\n",
    )
    .unwrap();
    let policy = FakePolicy::new(fixture.path()).with_standalone_capture();

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    let accepted = report
        .observations()
        .iter()
        .find(|candidate| matches!(candidate, ObservedCandidate::Accepted(_)))
        .unwrap();
    let failed = report
        .observations()
        .iter()
        .find(|candidate| matches!(candidate, ObservedCandidate::Failed(_)))
        .unwrap();
    assert!(!format!("{accepted:?}").contains(sentinel));
    assert!(!format!("{failed:?}").contains(sentinel));
    assert!(!format!("{report:?}").contains(sentinel));
}
