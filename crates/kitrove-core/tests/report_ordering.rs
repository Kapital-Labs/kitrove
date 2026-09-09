#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocatorDecision,
    NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile, PolicyRuntimeAuthority,
    PortablePolicyDecision, ReceiptAnchor, RelatedDocumentPattern, RelatedRoot, RootContext,
    RootId, RootTier, ScanFinding, ScanLimits, ScanRequest, ScopeSelection, VersionObservation,
    VersionObservationOwned,
};
use kitrove_agent_skills::{CapturedSkillSource, SkillSourceLayout};
use kitrove_core::{
    RelatedCapabilityObservation, ScanClassification, ScanEngine, ScanEntry, ScanMode,
};
use kitrove_model::{AssetId, AssetKind, ContentHash, HarnessId, HarnessScope, ReceiptId};

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
            "kitrove-core-report-ordering-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn skill(&self, directory: &str, native_name: &str) {
        let path = self.path().join(directory);
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join("SKILL.md"),
            format!(
                "---\nname: {native_name}\ndescription: A canonical test skill.\n---\n# Skill\n"
            ),
        )
        .unwrap();
    }

    fn markdown(&self, relative: &str, body: &[u8]) {
        fs::write(self.path().join(relative), body).unwrap();
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum DuplicateBehavior {
    Coexist,
    Winner,
    Ambiguous,
}

struct FakePolicy {
    roots: Vec<ObservedRoot>,
    related_roots: Vec<RelatedRoot>,
    duplicate_behavior: DuplicateBehavior,
}

impl HarnessObservationPolicy for FakePolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        PolicyRuntimeAuthority::exact(
            PolicyLine::ClaudeCurrent,
            &self.roots,
            &self.related_roots,
            &[],
        )
    }

    fn profile(&self, _version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            VersionObservationOwned::Unknown,
            evidence("test.profile"),
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
        let native_name = candidate.document.declared_name.as_deref().unwrap();
        CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(native_name.to_owned()),
            PortablePolicyDecision::Project {
                name: AssetId::parse(native_name).unwrap(),
                description: "A canonical test skill.".to_owned(),
                reasons: vec![],
            },
            vec![ScanFinding::new(
                "test.candidate",
                FindingSeverity::Informational,
                FindingSubject::Harness(HarnessId::Claude),
                vec![evidence("test.z"), evidence("test.a"), evidence("test.z")],
                "inspect the candidate",
            )],
        )
    }

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        Ok(match self.duplicate_behavior {
            DuplicateBehavior::Coexist => DuplicateDecision::Coexist,
            DuplicateBehavior::Winner => {
                let winner = group
                    .iter()
                    .find(|candidate| candidate.logical_root.as_str() == "test.skills.a")
                    .expect("the winner root is present");
                DuplicateDecision::Winner {
                    observation_id: winner.observation_id.clone(),
                    reason: evidence("test.duplicate.winner"),
                }
            }
            DuplicateBehavior::Ambiguous => DuplicateDecision::Ambiguous {
                reason: ScanFinding::new(
                    "scan.duplicate_ambiguous",
                    FindingSeverity::Attention,
                    FindingSubject::Harness(HarnessId::Claude),
                    vec![
                        evidence("test.duplicate.z"),
                        evidence("test.duplicate.a"),
                        evidence("test.duplicate.z"),
                    ],
                    "choose a unique native identity",
                ),
            },
        })
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

fn observed_root(path: &Path, logical_id: &str, policy_rank: u32) -> ObservedRoot {
    ObservedRoot {
        logical_id: RootId::parse(logical_id).unwrap(),
        path: path.to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::User,
        policy_rank,
        enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
        evidence: evidence("test.skills"),
    }
}

fn related_root(path: &Path, logical_id: &str, policy_rank: u32) -> RelatedRoot {
    RelatedRoot {
        logical_id: RootId::parse(logical_id).unwrap(),
        path: path.to_path_buf(),
        scope: HarnessScope::User,
        tier: RootTier::Compatibility,
        policy_rank,
        kind: AssetKind::Command,
        pattern: RelatedDocumentPattern::MarkdownAtAnyDepth,
        evidence: evidence("test.commands"),
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

fn policy_for(
    skill_roots: [&TestRoot; 2],
    command_roots: [&TestRoot; 2],
    reverse_policy_order: bool,
    duplicate_behavior: DuplicateBehavior,
) -> FakePolicy {
    let mut roots = vec![
        observed_root(skill_roots[0].path(), "test.skills.a", 7),
        observed_root(skill_roots[1].path(), "test.skills.b", 3),
    ];
    let mut related_roots = vec![
        related_root(command_roots[0].path(), "test.commands.a", 8),
        related_root(command_roots[1].path(), "test.commands.b", 4),
    ];
    if reverse_policy_order {
        roots.reverse();
        related_roots.reverse();
    }
    FakePolicy {
        roots,
        related_roots,
        duplicate_behavior,
    }
}

#[test]
fn reversed_policy_and_filesystem_order_produce_equal_reports() {
    let first_skill_a = TestRoot::new("first-skill-a");
    let first_skill_b = TestRoot::new("first-skill-b");
    first_skill_a.skill("candidate", "shared");
    first_skill_b.skill("candidate", "shared");
    let first_commands_a = TestRoot::new("first-commands-a");
    let first_commands_b = TestRoot::new("first-commands-b");
    first_commands_a.markdown("z.md", b"canonical z body\n");
    first_commands_b.markdown("a.md", b"canonical a body\n");

    let second_skill_b = TestRoot::new("second-skill-b");
    let second_skill_a = TestRoot::new("second-skill-a");
    second_skill_b.skill("candidate", "shared");
    second_skill_a.skill("candidate", "shared");
    let second_commands_b = TestRoot::new("second-commands-b");
    let second_commands_a = TestRoot::new("second-commands-a");
    second_commands_b.markdown("a.md", b"canonical a body\n");
    second_commands_a.markdown("z.md", b"canonical z body\n");

    let forward_policy = policy_for(
        [&first_skill_a, &first_skill_b],
        [&first_commands_a, &first_commands_b],
        false,
        DuplicateBehavior::Winner,
    );
    let reverse_policy = policy_for(
        [&second_skill_a, &second_skill_b],
        [&second_commands_a, &second_commands_b],
        true,
        DuplicateBehavior::Winner,
    );

    let forward = test_engine(&forward_policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let reverse = test_engine(&reverse_policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(forward.schema_version, 1);
    assert_eq!(forward.mode, ScanMode::Inventory);
    assert_eq!(forward.entries.len(), 2);
    assert!(forward.related.is_empty());
    assert_eq!(forward.prompt_commands.len(), 2);
    assert!(forward.findings.is_empty());
    assert_eq!(
        forward
            .entries
            .iter()
            .filter(|entry| entry.shadowed_by.is_some())
            .count(),
        1
    );
    assert!(forward.entries.iter().all(|entry| {
        entry.classification == ScanClassification::Unmanaged
            && entry.asset_id.is_none()
            && entry.receipt_id.is_none()
            && entry.normalized_destination.is_none()
            && entry.receipt_rendered_hash.is_none()
            && entry.exact_source_hash.is_some()
            && entry.portable_hash.is_some()
    }));
    assert!(forward.prompt_commands.iter().all(|entry| {
        entry.classification == ScanClassification::Unmanaged
            && entry.exact_source_hash.as_str().starts_with("blake3:")
            && entry.portable_hash.is_some()
            && entry.blocked_reason.is_none()
    }));
    assert!(forward.entries.iter().all(|entry| {
        entry
            .findings
            .iter()
            .all(|finding| finding.evidence.windows(2).all(|pair| pair[0] < pair[1]))
    }));
}

#[test]
fn ambiguous_duplicates_remain_unmanaged_and_retain_every_candidate() {
    let skill_a = TestRoot::new("ambiguous-skill-a");
    let skill_b = TestRoot::new("ambiguous-skill-b");
    skill_a.skill("candidate", "shared");
    skill_b.skill("candidate", "shared");
    let commands_a = TestRoot::new("ambiguous-commands-a");
    let commands_b = TestRoot::new("ambiguous-commands-b");
    let policy = policy_for(
        [&skill_a, &skill_b],
        [&commands_a, &commands_b],
        false,
        DuplicateBehavior::Ambiguous,
    );

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(report.entries.len(), 2);
    assert!(report.entries.iter().all(|entry| {
        entry.classification == ScanClassification::Unmanaged
            && entry.shadowed_by.is_none()
            && entry
                .findings
                .iter()
                .any(|finding| finding.code == "scan.duplicate_ambiguous")
    }));
}

#[test]
fn coexistence_keeps_independent_entries_without_shadow_findings() {
    let skill_a = TestRoot::new("coexist-skill-a");
    let skill_b = TestRoot::new("coexist-skill-b");
    skill_a.skill("candidate", "shared");
    skill_b.skill("candidate", "shared");
    let commands_a = TestRoot::new("coexist-commands-a");
    let commands_b = TestRoot::new("coexist-commands-b");
    let policy = policy_for(
        [&skill_a, &skill_b],
        [&commands_a, &commands_b],
        false,
        DuplicateBehavior::Coexist,
    );

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();

    assert_eq!(report.entries.len(), 2);
    assert!(report.entries.iter().all(|entry| {
        entry.shadowed_by.is_none()
            && !entry
                .findings
                .iter()
                .any(|finding| finding.code == "scan.candidate_shadowed")
    }));
}

#[cfg(unix)]
#[test]
fn unreadable_prompt_command_is_refused_after_a_bounded_capture_attempt() {
    use std::os::unix::fs::PermissionsExt as _;

    let skill_a = TestRoot::new("unread-skill-a");
    let skill_b = TestRoot::new("unread-skill-b");
    let commands_a = TestRoot::new("unread-commands-a");
    let commands_b = TestRoot::new("unread-commands-b");
    commands_a.markdown("unreadable.md", b"sentinel body must not be opened\n");
    let path = commands_a.path().join("unreadable.md");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
    let policy = policy_for(
        [&skill_a, &skill_b],
        [&commands_a, &commands_b],
        false,
        DuplicateBehavior::Coexist,
    );

    let report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(report.related.len(), 1);
    assert_eq!(report.related[0].source_relative_path, "unreadable.md");
    assert_eq!(report.related[0].findings.len(), 1);
    assert_eq!(
        report.related[0].findings[0].code,
        "scan.prompt_command_unsafe"
    );
    assert_eq!(report.capture_usage().file_attempts, 1);
    assert_eq!(report.capture_usage().bytes_read, 0);
}

#[test]
fn duplicate_findings_participate_in_the_global_finding_budget() {
    let skill_a = TestRoot::new("budget-skill-a");
    let skill_b = TestRoot::new("budget-skill-b");
    skill_a.skill("candidate", "shared");
    skill_b.skill("candidate", "shared");
    let commands_a = TestRoot::new("budget-commands-a");
    let commands_b = TestRoot::new("budget-commands-b");
    let policy = policy_for(
        [&skill_a, &skill_b],
        [&commands_a, &commands_b],
        false,
        DuplicateBehavior::Winner,
    );

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
                .sum::<usize>()
            + report
                .related
                .iter()
                .map(|observation| observation.findings.len())
                .sum::<usize>(),
        3
    );
}

#[test]
fn canonical_sort_uses_the_spec_keys_and_deterministic_tie_breakers() {
    let skill_a = TestRoot::new("sort-skill-a");
    let skill_b = TestRoot::new("sort-skill-b");
    skill_a.skill("candidate", "shared");
    skill_b.skill("candidate", "shared");
    let commands_a = TestRoot::new("sort-commands-a");
    let commands_b = TestRoot::new("sort-commands-b");
    commands_a.markdown("command.md", b"ignored\n");
    let policy = policy_for(
        [&skill_a, &skill_b],
        [&commands_a, &commands_b],
        false,
        DuplicateBehavior::Coexist,
    );
    let mut report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let first_id = report.entries[0].observation_id.clone();
    let second_id = report.entries[1].observation_id.clone();

    let present = ScanEntry {
        observation_id: first_id,
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        root_tier: Some(RootTier::Project),
        logical_root: Some(RootId::parse("test.root.z").unwrap()),
        policy_rank: Some(1),
        source_relative_path: Some("z".to_owned()),
        layout: Some(SkillSourceLayout::Standalone),
        native_id: Some("z".to_owned()),
        asset_id: Some(AssetId::parse("z").unwrap()),
        receipt_id: Some(ReceiptId::parse("receipt-z").unwrap()),
        normalized_destination: Some("/z".to_owned()),
        receipt_rendered_hash: Some(ContentHash::digest(b"receipt-z")),
        classification: ScanClassification::Unknown,
        exact_source_hash: Some(ContentHash::digest(b"exact-z")),
        portable_hash: Some(ContentHash::digest(b"portable-z")),
        shadowed_by: second_id,
        findings: vec![ScanFinding::new(
            "test.z",
            FindingSeverity::Attention,
            FindingSubject::Report,
            vec![evidence("test.z"), evidence("test.a"), evidence("test.z")],
            "z action",
        )],
    };
    let mut missing = present.clone();
    missing.policy_rank = None;
    missing.logical_root = None;
    missing.source_relative_path = None;
    missing.layout = None;
    missing.native_id = None;
    missing.asset_id = None;
    missing.receipt_id = None;
    missing.normalized_destination = None;
    missing.receipt_rendered_hash = None;
    missing.exact_source_hash = None;
    missing.portable_hash = None;
    missing.shadowed_by = None;
    missing.findings[0].action = "a action";
    report.entries = vec![missing, present];

    let related_z = RelatedCapabilityObservation {
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        root_tier: RootTier::Compatibility,
        logical_root: RootId::parse("test.related.z").unwrap(),
        policy_rank: 9,
        source_relative_path: "z.md".to_owned(),
        kind: AssetKind::Command,
        findings: vec![],
    };
    let mut related_a = related_z.clone();
    related_a.policy_rank = 1;
    related_a.logical_root = RootId::parse("test.related.a").unwrap();
    related_a.source_relative_path = "a.md".to_owned();
    report.related = vec![related_z, related_a];
    report.findings = vec![
        ScanFinding::new(
            "test.same",
            FindingSeverity::Attention,
            FindingSubject::Report,
            vec![evidence("test.z"), evidence("test.a"), evidence("test.z")],
            "z action",
        ),
        ScanFinding::new(
            "test.same",
            FindingSeverity::Attention,
            FindingSubject::Report,
            vec![evidence("test.a"), evidence("test.z")],
            "a action",
        ),
    ];

    report.sort_canonical();

    assert_eq!(report.entries[0].policy_rank, Some(1));
    assert_eq!(report.entries[1].policy_rank, None);
    assert_eq!(report.related[0].policy_rank, 1);
    assert_eq!(report.findings[0].action, "a action");
    assert_eq!(
        report.entries[0].findings[0].evidence,
        [evidence("test.a"), evidence("test.z")]
    );
    assert_eq!(
        report.findings[0].evidence,
        [evidence("test.a"), evidence("test.z")]
    );
}

#[test]
fn observation_id_precedes_supplemental_entry_tie_breakers() {
    let skill_a = TestRoot::new("observation-key-skill-a");
    let skill_b = TestRoot::new("observation-key-skill-b");
    skill_a.skill("candidate", "shared");
    skill_b.skill("candidate", "shared");
    let commands_a = TestRoot::new("observation-key-commands-a");
    let commands_b = TestRoot::new("observation-key-commands-b");
    let policy = policy_for(
        [&skill_a, &skill_b],
        [&commands_a, &commands_b],
        false,
        DuplicateBehavior::Coexist,
    );
    let mut report = test_engine(&policy)
        .scan(&request(ScanLimits::default()))
        .unwrap();
    let mut ids = report
        .entries
        .iter()
        .map(|entry| entry.observation_id.clone().unwrap())
        .collect::<Vec<_>>();
    ids.sort();
    let lower_id = ids[0].clone();
    let higher_id = ids[1].clone();

    let mut lower_id_entry = report.entries[0].clone();
    let mut higher_id_entry = lower_id_entry.clone();
    lower_id_entry.observation_id = Some(lower_id.clone());
    higher_id_entry.observation_id = Some(higher_id);
    lower_id_entry.root_tier = Some(RootTier::Project);
    higher_id_entry.root_tier = Some(RootTier::User);
    lower_id_entry.portable_hash = Some(ContentHash::digest(b"supplemental-z"));
    higher_id_entry.portable_hash = Some(ContentHash::digest(b"supplemental-a"));
    report.entries = vec![lower_id_entry, higher_id_entry];

    report.sort_canonical();

    assert_eq!(report.entries[0].observation_id.as_ref(), Some(&lower_id));
}
