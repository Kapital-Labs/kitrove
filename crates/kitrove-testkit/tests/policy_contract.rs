use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, HarnessObservationPolicy, LocatorDecision, NativeAcceptance, NativeRootKey,
    ObservedRoot, PolicyLine, PolicyProfile, PolicyRuntimeAuthority, PortablePolicyDecision,
    ReceiptAnchor, RootContext, RootHookReport, RootId, RootTier, ScopeSelection,
    SuppliedNativeRoot, VersionObservation,
};
use kitrove_agent_skills::{CapturedSkillSource, SkillSourceLayout};
use kitrove_model::{FidelityReason, HarnessId, HarnessScope};
use kitrove_testkit::{
    FixtureBuilder, LocatorExpectation, LocatorProbe, NativeRootExpectation, PolicyContractCase,
    ProcessSentinel, ReceiptAnchorExpectation, SentinelEvent, assert_policy_contract,
};

static ENGINE_DISCOVERY_CALLS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn shared_contract_rejects_root_escape_and_process_spawn() {
    let case = PolicyContractCase::new(FakePolicy::root_escape_and_spawn());

    let failures = assert_policy_contract(case).expect_err("the fake policy violates the contract");

    assert!(failures.codes().contains(&"contract.root_escape"));
    assert!(failures.codes().contains(&"contract.process_spawned"));
}

#[test]
fn shared_contract_accepts_a_contained_deterministic_policy() {
    let case = compliant_case(
        false,
        HarnessScope::User,
        HarnessScope::User,
        ScopeSelection::All,
    );

    assert_policy_contract(case).expect("the compliant policy meets the shared contract");
}

#[test]
fn shared_contract_exercises_engine_discovery() {
    ENGINE_DISCOVERY_CALLS.store(0, Ordering::Relaxed);
    let case = compliant_case(
        false,
        HarnessScope::User,
        HarnessScope::User,
        ScopeSelection::All,
    );
    let source = case.fixture().root().join("home/.fake/skills/engine-only");
    fs::create_dir_all(&source).expect("engine-only source directory");
    fs::write(
        source.join("SKILL.md"),
        b"---\nname: engine-only\ndescription: Engine discovery probe.\n---\n# Probe\n",
    )
    .expect("engine-only source");

    assert_policy_contract(case).expect("the engine-discovered source remains compliant");

    assert_eq!(ENGINE_DISCOVERY_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn shared_contract_rejects_side_effect_in_candidate_decision() {
    let case = compliant_case(
        true,
        HarnessScope::User,
        HarnessScope::User,
        ScopeSelection::All,
    );

    let failures = assert_policy_contract(case)
        .expect_err("the direct candidate decision records a forbidden process attempt");

    assert!(failures.codes().contains(&"contract.process_spawned"));
    assert!(failures.codes().contains(&"contract.network_accessed"));
    assert!(failures.codes().contains(&"contract.filesystem_write"));
}

#[test]
fn shared_contract_rejects_roots_and_anchors_outside_the_requested_scope() {
    let case = compliant_case(
        false,
        HarnessScope::Project,
        HarnessScope::Project,
        ScopeSelection::User,
    );

    let failures = assert_policy_contract(case)
        .expect_err("a user-only request must not certify project policy output");

    assert!(failures.codes().contains(&"contract.root_scope_unselected"));
    assert!(
        failures
            .codes()
            .contains(&"contract.receipt_anchor_scope_unselected")
    );
}

#[test]
fn shared_contract_rejects_an_accept_all_scope_native_policy() {
    let case = unsupported_native_scope_case(false);

    let failures = assert_policy_contract(case)
        .expect_err("a policy must not accept a caller scope outside its descriptor");

    assert!(failures.codes().contains(&"contract.native_root_scope"));
}

#[test]
fn shared_contract_accepts_a_diagnosed_unsupported_native_scope() {
    let case = unsupported_native_scope_case(true);

    assert_policy_contract(case)
        .expect("the policy rejects the unsupported scope with a retained hook finding");
}

fn compliant_case(
    decide_spawns: bool,
    root_scope: HarnessScope,
    receipt_scope: HarnessScope,
    scopes: ScopeSelection,
) -> PolicyContractCase<CompliantPolicy> {
    let fixture = FixtureBuilder::new()
        .repository()
        .build()
        .expect("fixture creation");
    let approved_anchor = fixture
        .root()
        .canonicalize()
        .expect("canonical fixture root");
    let root = approved_anchor.join("home/.fake/skills");
    let native_root = approved_anchor.join("native/skills");
    let receipt_root = approved_anchor.join("home/.fake/skills");
    let root_id = RootId::parse("fake.user").expect("valid root ID");
    let native_evidence = EvidenceRef::parse("fixture.fake.native").expect("valid evidence");
    let native = SuppliedNativeRoot::new(
        HarnessId::Claude,
        HarnessScope::User,
        NativeRootKey::parse("fake.native").expect("valid native key"),
        native_root.clone(),
    );
    let policy = CompliantPolicy {
        root: root.clone(),
        root_id: root_id.clone(),
        native_root: native_root.clone(),
        receipt_root: receipt_root.clone(),
        native_evidence: native_evidence.clone(),
        decide_spawns,
        root_scope,
        receipt_scope,
        reject_project_native: false,
    };

    PolicyContractCase::new(policy)
        .with_fixture(fixture)
        .allow_anchor(approved_anchor)
        .with_scope_selection(scopes)
        .expect_native_root(NativeRootExpectation {
            supplied: native,
            allowed_scopes: BTreeSet::from([HarnessScope::User]),
            unsupported_scope_finding: "scan.native_root_scope_unsupported".to_owned(),
            tier: RootTier::Explicit,
            policy_rank: 1,
            enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
            evidence: native_evidence,
        })
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::User,
            receipt_root,
            EvidenceRef::parse("fixture.fake").expect("valid evidence"),
        ))
        .expect_locator(
            LocatorProbe::new(
                "review/SKILL.md",
                SkillSourceLayout::Directory,
                "SKILL.md",
                LocatorExpectation::Supported,
            )
            .for_root(root_id),
        )
        .expect_locator(LocatorProbe::new(
            "review.md",
            SkillSourceLayout::Standalone,
            "review.md",
            LocatorExpectation::Unsupported,
        ))
}

fn unsupported_native_scope_case(
    reject_project_native: bool,
) -> PolicyContractCase<CompliantPolicy> {
    let fixture = FixtureBuilder::new().build().expect("fixture creation");
    let approved_anchor = fixture
        .root()
        .canonicalize()
        .expect("canonical fixture root");
    let root = approved_anchor.join("home/.fake/skills");
    let native_root = approved_anchor.join("native/skills");
    let receipt_root = root.clone();
    let policy = CompliantPolicy {
        root: root.clone(),
        root_id: RootId::parse("fake.user").expect("valid root ID"),
        native_root: native_root.clone(),
        receipt_root: receipt_root.clone(),
        native_evidence: EvidenceRef::parse("fixture.fake.native").expect("valid evidence"),
        decide_spawns: false,
        root_scope: HarnessScope::User,
        receipt_scope: HarnessScope::User,
        reject_project_native,
    };
    let native = SuppliedNativeRoot::new(
        HarnessId::Claude,
        HarnessScope::Project,
        NativeRootKey::parse("fake.native").expect("valid native key"),
        native_root,
    );

    PolicyContractCase::new(policy)
        .with_fixture(fixture)
        .allow_anchor(approved_anchor)
        .expect_native_root(NativeRootExpectation {
            supplied: native,
            allowed_scopes: BTreeSet::from([HarnessScope::User]),
            unsupported_scope_finding: "scan.native_root_scope_unsupported".to_owned(),
            tier: RootTier::Explicit,
            policy_rank: 1,
            enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
            evidence: EvidenceRef::parse("fixture.fake.native").expect("valid evidence"),
        })
        .expect_receipt_anchor(ReceiptAnchorExpectation::new(
            HarnessScope::User,
            receipt_root,
            EvidenceRef::parse("fixture.fake").expect("valid evidence"),
        ))
        .expect_locator(LocatorProbe::new(
            "review/SKILL.md",
            SkillSourceLayout::Directory,
            "SKILL.md",
            LocatorExpectation::Supported,
        ))
        .expect_locator(LocatorProbe::new(
            "review.md",
            SkillSourceLayout::Standalone,
            "review.md",
            LocatorExpectation::Unsupported,
        ))
}

#[test]
fn sentinel_records_network_and_write_violations_without_performing_them() {
    let sentinel = ProcessSentinel::install();

    ProcessSentinel::record_network_access();
    ProcessSentinel::record_filesystem_write();

    assert_eq!(
        sentinel.events(),
        vec![
            SentinelEvent::NetworkAccessed,
            SentinelEvent::FilesystemWrite
        ]
    );
}

#[derive(Clone, Copy)]
struct FakePolicy;

impl FakePolicy {
    fn root_escape_and_spawn() -> Self {
        Self
    }
}

impl HarnessObservationPolicy for FakePolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        Ok(PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            version.into(),
            EvidenceRef::parse("fixture.fake").expect("valid fixture evidence"),
        )
        .expect("a matching fake profile"))
    }

    fn roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        ProcessSentinel::record_process_spawn();
        Ok(vec![ObservedRoot {
            logical_id: RootId::parse("fake.escape").expect("valid fake root ID"),
            path: PathBuf::from("/outside-the-fixture"),
            scope: HarnessScope::User,
            tier: RootTier::User,
            policy_rank: 0,
            enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
            evidence: EvidenceRef::parse("fixture.fake").expect("valid fixture evidence"),
        }])
    }

    fn classify_locator(
        &self,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        LocatorDecision::Capture
    }

    fn decide_candidate(
        &self,
        _candidate: &CapturedSkillSource,
        _locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        Ok(CandidateDecision::new(
            NativeAcceptance::Rejected,
            None,
            PortablePolicyDecision::Unavailable {
                reasons: vec![FidelityReason::new(
                    "fixture.fake",
                    "not used by this contract",
                )],
            },
            vec![],
        )
        .expect("a rejected fake decision is valid"))
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

    fn discover_unusual_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        Ok(RootHookReport::default())
    }
}

#[derive(Clone)]
struct CompliantPolicy {
    root: PathBuf,
    root_id: RootId,
    native_root: PathBuf,
    receipt_root: PathBuf,
    native_evidence: EvidenceRef,
    decide_spawns: bool,
    root_scope: HarnessScope,
    receipt_scope: HarnessScope,
    reject_project_native: bool,
}

impl HarnessObservationPolicy for CompliantPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        let roots = [
            ObservedRoot {
                logical_id: self.root_id.clone(),
                path: self.root.clone(),
                scope: self.root_scope,
                tier: RootTier::User,
                policy_rank: 0,
                enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
                evidence: EvidenceRef::parse("fixture.fake").expect("valid evidence"),
            },
            ObservedRoot {
                logical_id: RootId::parse("fake.native").expect("valid root ID"),
                path: self.native_root.clone(),
                scope: HarnessScope::User,
                tier: RootTier::Explicit,
                policy_rank: 1,
                enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
                evidence: self.native_evidence.clone(),
            },
        ];
        let anchors = [ReceiptAnchor {
            scope: self.receipt_scope,
            path: self.receipt_root.clone(),
            evidence: EvidenceRef::parse("fixture.fake").expect("valid evidence"),
        }];
        PolicyRuntimeAuthority::exact(PolicyLine::ClaudeCurrent, &roots, &[], &anchors)
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        Ok(PolicyProfile::new(
            HarnessId::Claude,
            PolicyLine::ClaudeCurrent,
            version.into(),
            EvidenceRef::parse("fixture.fake").expect("valid evidence"),
        )
        .expect("matching profile"))
    }

    fn roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        let mut roots = Vec::new();
        if self.root_scope != HarnessScope::User || context.home.is_some() {
            roots.push(ObservedRoot {
                logical_id: self.root_id.clone(),
                path: self.root.clone(),
                scope: self.root_scope,
                tier: RootTier::User,
                policy_rank: 0,
                enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
                evidence: EvidenceRef::parse("fixture.fake").expect("valid evidence"),
            });
        }
        let rejects_supplied_root = self.reject_project_native
            && context
                .supplied_native_roots
                .iter()
                .any(|root| root.scope() == HarnessScope::Project);
        if !context.supplied_native_roots.is_empty() && !rejects_supplied_root {
            roots.push(ObservedRoot {
                logical_id: RootId::parse("fake.native").expect("valid root ID"),
                path: self.native_root.clone(),
                scope: HarnessScope::User,
                tier: RootTier::Explicit,
                policy_rank: 1,
                enabled_layouts: BTreeSet::from([SkillSourceLayout::Directory]),
                evidence: self.native_evidence.clone(),
            });
        }
        Ok(roots)
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        _root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        if locator.source_relative_path.contains("engine-only")
            && locator.layout == SkillSourceLayout::Directory
        {
            ENGINE_DISCOVERY_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        match locator.layout {
            SkillSourceLayout::Directory => LocatorDecision::Capture,
            SkillSourceLayout::Standalone => LocatorDecision::Unsupported {
                finding: kitrove_adapter_api::ScanFinding::new(
                    "scan.layout_unsupported",
                    kitrove_adapter_api::FindingSeverity::Informational,
                    kitrove_adapter_api::FindingSubject::Report,
                    vec![],
                    "use a directory skill",
                ),
            },
        }
    }

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        if self.decide_spawns {
            ProcessSentinel::record_process_spawn();
            ProcessSentinel::record_network_access();
            ProcessSentinel::record_filesystem_write();
        }
        FakePolicy.decide_candidate(candidate, locator, root, profile)
    }

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        FakePolicy.resolve_duplicates(group, profile)
    }

    fn receipt_anchors(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        if self.receipt_scope == HarnessScope::User && context.home.is_none() {
            return Ok(vec![]);
        }
        Ok(vec![ReceiptAnchor {
            scope: self.receipt_scope,
            path: self.receipt_root.clone(),
            evidence: EvidenceRef::parse("fixture.fake").expect("valid evidence"),
        }])
    }

    fn discover_unusual_roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        if self.reject_project_native
            && context
                .supplied_native_roots
                .iter()
                .any(|root| root.scope() == HarnessScope::Project)
        {
            return Ok(RootHookReport {
                roots: vec![],
                findings: vec![kitrove_adapter_api::ScanFinding::new(
                    "scan.native_root_scope_unsupported",
                    kitrove_adapter_api::FindingSeverity::Attention,
                    kitrove_adapter_api::FindingSubject::Harness(HarnessId::Claude),
                    vec![EvidenceRef::parse("fixture.fake.native").expect("valid evidence")],
                    "supply a user-scoped native root",
                )],
            });
        }
        Ok(RootHookReport::default())
    }
}
