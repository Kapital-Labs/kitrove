#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocatorDecision,
    NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile, PortablePolicyDecision,
    ReceiptAnchor, RootContext, RootId, RootTier, ScanFinding, ScanLimits, ScanRequest,
    ScopeSelection, VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{CapturedSkillSource, SkillSourceLayout};
use kitrove_core::{
    RelatedCapabilityObservation, ScanClassification, ScanEngine, ScanEntry, ScanMode,
    render_scan_json, render_scan_text,
};
use kitrove_model::{
    AssetId, AssetKind, ContentHash, HarnessId, HarnessScope, NormalizedDestination, ReceiptId,
};

fn test_engine(policy: &dyn HarnessObservationPolicy) -> ScanEngine<'_> {
    ScanEngine::from_authorities(vec![(policy, policy.runtime_authority())])
        .expect("test authority catalog")
}

#[derive(Clone)]
struct CatalogPolicy {
    harness: HarnessId,
    line: PolicyLine,
}

impl HarnessObservationPolicy for CatalogPolicy {
    fn harness(&self) -> HarnessId {
        self.harness.clone()
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            self.harness.clone(),
            self.line,
            VersionObservationOwned::from(version),
            evidence("golden.profile"),
        )
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        Ok(vec![])
    }

    fn classify_locator(
        &self,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        LocatorDecision::Ignore
    }

    fn decide_candidate(
        &self,
        _candidate: &CapturedSkillSource,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        CandidateDecision::new(
            NativeAcceptance::Rejected,
            None,
            PortablePolicyDecision::Unavailable {
                reasons: vec![kitrove_model::FidelityReason::new(
                    "golden.unused",
                    "the golden policy captures no candidates",
                )],
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
        Ok(vec![])
    }
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).unwrap()
}

fn request() -> ScanRequest<'static> {
    ScanRequest {
        home: Some(PathBuf::from("/unused-home")),
        working_directory: PathBuf::from("/unused-working-directory"),
        project_boundary: kitrove_adapter_api::ProjectBoundary::NoRepository,
        harnesses: BTreeSet::new(),
        scopes: ScopeSelection::All,
        explicit_roots: vec![],
        supplied_native_roots: vec![],
        versions: BTreeMap::new(),
        project_trust: BTreeMap::new(),
        environment: None,
        local_state: None,
        limits: ScanLimits::default(),
    }
}

fn hash(digit: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", digit.to_string().repeat(64))).unwrap()
}

fn golden_report() -> kitrove_core::ScanReport {
    let empty_policy = CatalogPolicy {
        harness: HarnessId::Claude,
        line: PolicyLine::ClaudeCurrent,
    };
    let mut report = test_engine(&empty_policy).scan(&request()).unwrap();
    report.mode = ScanMode::Classified;
    report.versions = BTreeMap::from([
        (HarnessId::Claude, VersionObservationOwned::Unknown),
        (
            HarnessId::OpenCode,
            VersionObservationOwned::Verified {
                observed: kitrove_adapter_api::HarnessVersion::parse("2.0 fixture").unwrap(),
                policy_line: PolicyLine::OpenCodeV2,
                evidence: evidence("fixture.opencode.v2"),
            },
        ),
    ]);
    report.entries = vec![
        ScanEntry {
            observation_id: None,
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            root_tier: Some(RootTier::User),
            logical_root: Some(RootId::parse("golden.claude.user").unwrap()),
            policy_rank: Some(7),
            source_relative_path: Some("review".to_owned()),
            layout: Some(SkillSourceLayout::Directory),
            native_id: Some("review \"quoted\"".to_owned()),
            asset_id: Some(AssetId::parse("review").unwrap()),
            receipt_id: Some(ReceiptId::parse("receipt-review").unwrap()),
            normalized_destination: Some("/Users/dev/Skill \"Review\"".to_owned()),
            receipt_rendered_hash: Some(hash('1')),
            classification: ScanClassification::ManagedModified,
            exact_source_hash: Some(hash('2')),
            portable_hash: Some(hash('3')),
            shadowed_by: None,
            findings: vec![ScanFinding::new(
                "scan.receipt_stale_desired_state",
                FindingSeverity::Attention,
                FindingSubject::Destination {
                    harness: HarnessId::Claude,
                    scope: HarnessScope::User,
                    normalized_destination: NormalizedDestination::parse(
                        "/Users/dev/Skill \"Review\"",
                    )
                    .unwrap(),
                },
                vec![evidence("fixture.receipt")],
                "plan the desired-state transition",
            )],
        },
        ScanEntry {
            observation_id: None,
            harness: HarnessId::Pi,
            scope: HarnessScope::Project,
            root_tier: None,
            logical_root: None,
            policy_rank: None,
            source_relative_path: None,
            layout: None,
            native_id: None,
            asset_id: Some(AssetId::parse("missing").unwrap()),
            receipt_id: Some(ReceiptId::parse("receipt-missing").unwrap()),
            normalized_destination: Some("/workspace/.pi/skills/missing".to_owned()),
            receipt_rendered_hash: Some(hash('4')),
            classification: ScanClassification::MissingManaged,
            exact_source_hash: None,
            portable_hash: None,
            shadowed_by: None,
            findings: vec![],
        },
    ];
    report.related = vec![RelatedCapabilityObservation {
        harness: HarnessId::Codex,
        scope: HarnessScope::Project,
        root_tier: RootTier::Compatibility,
        logical_root: RootId::parse("golden.codex.related").unwrap(),
        policy_rank: 11,
        source_relative_path: "commands/review.md".to_owned(),
        kind: AssetKind::Command,
        findings: vec![ScanFinding::new(
            "scan.related_capability",
            FindingSeverity::Informational,
            FindingSubject::Related {
                logical_root: RootId::parse("golden.codex.related").unwrap(),
                source_relative_path: kitrove_adapter_api::SourceRelativePath::parse(
                    "commands/review.md",
                )
                .unwrap(),
            },
            vec![evidence("fixture.related")],
            "inspect the related capability separately",
        )],
    }];
    report.findings = vec![ScanFinding::new(
        "scan.version_unknown",
        FindingSeverity::Informational,
        FindingSubject::Harness(HarnessId::Claude),
        vec![evidence("fixture.version")],
        "supply typed evidence only from a trusted caller",
    )];
    report.sort_canonical();
    report
}

#[test]
fn text_and_json_render_the_same_report_counts() {
    let report = golden_report();
    assert_eq!(render_scan_text(&report), include_str!("golden/scan.txt"));
    assert_eq!(
        render_scan_json(&report).unwrap(),
        include_str!("golden/scan.json")
    );
}

#[test]
fn renderers_preserve_report_order_instead_of_sorting() {
    let mut report = golden_report();
    report.entries.reverse();

    let text = render_scan_text(&report);
    assert!(
        text.find("entry observation_id=null harness=\"pi\"")
            .unwrap()
            < text
                .find("entry observation_id=null harness=\"claude\"")
                .unwrap()
    );

    let json: serde_json::Value =
        serde_json::from_str(&render_scan_json(&report).unwrap()).unwrap();
    assert_eq!(json["entries"][0]["harness"], "pi");
    assert_eq!(json["entries"][1]["harness"], "claude");
}
