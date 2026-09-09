use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use kitrove_adapter_api::{
    AdapterResult, CandidateLocator, EvidenceRef, ExplicitRoot, HarnessObservationPolicy,
    LocatorDecision, ObservedRoot, PolicyProfile, ReceiptAnchor, RootContext, RootId, RootTier,
    ScanRequest, ScopeSelection, SuppliedNativeRoot, VersionObservation,
};
use kitrove_agent_skills::{CaptureLimits, SkillSource, SkillSourceLayout, capture_skill_source};
use kitrove_core::ScanEngine;
use kitrove_model::HarnessScope;

use crate::{
    AgentSkillFixture, FilesystemSnapshot, FixtureBuilder, HarnessFixture, ProcessSentinel,
    SentinelEvent,
};

/// Expected locator outcome for the shared policy boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LocatorExpectation {
    Supported,
    Unsupported,
}

/// One synthetic candidate position passed directly to `classify_locator`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocatorProbe {
    logical_root: Option<RootId>,
    source_relative_path: String,
    layout: SkillSourceLayout,
    original_document_name: String,
    expectation: LocatorExpectation,
}

impl LocatorProbe {
    #[must_use]
    pub fn new(
        source_relative_path: impl Into<String>,
        layout: SkillSourceLayout,
        original_document_name: impl Into<String>,
        expectation: LocatorExpectation,
    ) -> Self {
        Self {
            logical_root: None,
            source_relative_path: source_relative_path.into(),
            layout,
            original_document_name: original_document_name.into(),
            expectation,
        }
    }

    #[must_use]
    pub fn for_root(mut self, logical_root: RootId) -> Self {
        self.logical_root = Some(logical_root);
        self
    }
}

/// Expected policy-owned shape for one caller-supplied native root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRootExpectation {
    pub supplied: SuppliedNativeRoot,
    /// Scopes declared by the compiled native-root descriptor.
    pub allowed_scopes: BTreeSet<HarnessScope>,
    /// Stable hook finding required when the caller selected an unsupported scope.
    pub unsupported_scope_finding: String,
    pub tier: RootTier,
    pub policy_rank: u32,
    pub enabled_layouts: BTreeSet<SkillSourceLayout>,
    pub evidence: EvidenceRef,
}

/// Expected compiled materialization anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAnchorExpectation {
    pub scope: HarnessScope,
    pub path: PathBuf,
    pub evidence: EvidenceRef,
}

impl ReceiptAnchorExpectation {
    #[must_use]
    pub fn new(scope: HarnessScope, path: PathBuf, evidence: EvidenceRef) -> Self {
        Self {
            scope,
            path,
            evidence,
        }
    }
}

/// Input to the direct shared policy contract.
pub struct PolicyContractCase<P> {
    policy: P,
    fixture: HarnessFixture,
    approved_anchors: Vec<PathBuf>,
    explicit_roots: Vec<ExplicitRoot>,
    native_roots: Vec<NativeRootExpectation>,
    receipt_anchors: Vec<ReceiptAnchorExpectation>,
    locator_probes: Vec<LocatorProbe>,
    scopes: ScopeSelection,
}

impl<P> PolicyContractCase<P>
where
    P: HarnessObservationPolicy,
{
    /// Creates a no-repository fixture with its temporary root as the only approved anchor.
    #[must_use]
    pub fn new(policy: P) -> Self {
        let fixture = FixtureBuilder::new()
            .no_repository()
            .build()
            .expect("the default shared policy fixture must be creatable");
        let approved_anchors = vec![fixture.root().to_path_buf()];
        Self {
            policy,
            fixture,
            approved_anchors,
            explicit_roots: vec![],
            native_roots: vec![],
            receipt_anchors: vec![],
            locator_probes: vec![],
            scopes: ScopeSelection::All,
        }
    }

    #[must_use]
    pub fn with_fixture(mut self, fixture: HarnessFixture) -> Self {
        self.approved_anchors = vec![fixture.root().to_path_buf()];
        self.fixture = fixture;
        self
    }

    #[must_use]
    pub fn allow_anchor(mut self, path: impl Into<PathBuf>) -> Self {
        self.approved_anchors.push(path.into());
        self
    }

    #[must_use]
    pub fn with_scope_selection(mut self, scopes: ScopeSelection) -> Self {
        self.scopes = scopes;
        self
    }

    #[must_use]
    pub fn with_explicit_root(mut self, root: ExplicitRoot) -> Self {
        self.explicit_roots.push(root);
        self
    }

    #[must_use]
    pub fn expect_native_root(mut self, expectation: NativeRootExpectation) -> Self {
        self.native_roots.push(expectation);
        self
    }

    #[must_use]
    pub fn expect_receipt_anchor(mut self, expectation: ReceiptAnchorExpectation) -> Self {
        self.receipt_anchors.push(expectation);
        self
    }

    #[must_use]
    pub fn expect_locator(mut self, probe: LocatorProbe) -> Self {
        self.locator_probes.push(probe);
        self
    }

    #[must_use]
    pub fn fixture(&self) -> &HarnessFixture {
        &self.fixture
    }
}

/// Stable direct-contract failures, collected so one bad policy can expose every violation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyContractFailures {
    failures: Vec<ContractFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ContractFailure {
    code: &'static str,
    detail: String,
}

impl PolicyContractFailures {
    #[must_use]
    pub fn codes(&self) -> BTreeSet<&'static str> {
        self.failures.iter().map(|failure| failure.code).collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}

impl std::fmt::Display for PolicyContractFailures {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, failure) in self.failures.iter().enumerate() {
            if index != 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{}: {}", failure.code, failure.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyContractFailures {}

/// Calls the direct policy boundary twice and checks read-only, containment, and catalog rules.
pub fn assert_policy_contract<P>(case: PolicyContractCase<P>) -> Result<(), PolicyContractFailures>
where
    P: HarnessObservationPolicy,
{
    let mut failures = PolicyContractFailures::default();
    let before = snapshot_or_failure(case.fixture.root(), &mut failures, "before");
    let sentinel = ProcessSentinel::install();
    let harness = case.policy.harness();
    let project_boundary = case.fixture.repository_root().map_or(
        kitrove_adapter_api::ProjectBoundary::NoRepository,
        |root| kitrove_adapter_api::ProjectBoundary::Repository {
            root: root.to_path_buf(),
        },
    );
    let supplied_native_roots = case
        .native_roots
        .iter()
        .map(|expectation| expectation.supplied.clone())
        .collect::<Vec<_>>();
    let project_trust = BTreeMap::new();
    let limits = kitrove_adapter_api::ScanLimits::default();
    let context = RootContext {
        home: Some(case.fixture.home().root()),
        working_directory: case.fixture.working_directory(),
        project_boundary: &project_boundary,
        scopes: case.scopes,
        explicit_roots: &case.explicit_roots,
        supplied_native_roots: &supplied_native_roots,
        project_trust: &project_trust,
        limits: &limits,
    };

    let profile = case.policy.profile(VersionObservation::Unknown);
    let repeated_profile = case.policy.profile(VersionObservation::Unknown);
    if profile != repeated_profile {
        failures.push(
            "contract.nondeterministic_profile",
            "unknown-version profiles differed",
        );
    }
    let profile = match profile {
        Ok(profile) => profile,
        Err(_) => {
            failures.push(
                "contract.profile_failed",
                "unknown-version profile selection failed",
            );
            return Err(failures);
        }
    };
    if profile.harness() != &harness {
        failures.push(
            "contract.profile_harness_mismatch",
            "profile harness differed from policy harness",
        );
    }
    if !matches!(
        profile.version(),
        kitrove_adapter_api::VersionObservationOwned::Unknown
    ) {
        failures.push(
            "contract.production_version_known",
            "production contract call selected verified version evidence",
        );
    }

    let roots = repeat_adapter_call(
        || case.policy.roots(&context, &profile),
        "roots",
        &mut failures,
    );
    let unusual = repeat_adapter_call(
        || case.policy.discover_unusual_roots(&context, &profile),
        "unusual roots",
        &mut failures,
    )
    .unwrap_or_default();
    let related = repeat_adapter_call(
        || case.policy.related_roots(&context, &profile),
        "related roots",
        &mut failures,
    )
    .unwrap_or_default();
    let anchors = repeat_adapter_call(
        || case.policy.receipt_anchors(&context, &profile),
        "receipt anchors",
        &mut failures,
    )
    .unwrap_or_default();
    validate_missing_home(
        &case.policy,
        &profile,
        case.fixture.working_directory(),
        &project_boundary,
        &project_trust,
        &limits,
        &mut failures,
    );
    let duplicate_decision = case.policy.resolve_duplicates(&[], &profile);
    if duplicate_decision != case.policy.resolve_duplicates(&[], &profile) {
        failures.push(
            "contract.nondeterministic_policy_call",
            "repeated empty duplicate decisions differed",
        );
    }
    if duplicate_decision.is_err() {
        failures.push(
            "contract.duplicate_policy_failed",
            "empty duplicate-policy probe failed",
        );
    }

    validate_unusual_findings(&unusual.findings, &mut failures);
    let mut all_roots = roots.unwrap_or_default();
    let static_count = all_roots.len();
    all_roots.extend(unusual.roots);
    let root_validation = RootValidationContext {
        anchors: &case.approved_anchors,
        native_expectations: &case.native_roots,
        unusual_findings: &unusual.findings,
        harness: &harness,
        scopes: case.scopes,
    };
    validate_roots(&all_roots, static_count, &root_validation, &mut failures);
    validate_related_roots(&related, &case.approved_anchors, case.scopes, &mut failures);
    validate_receipt_anchors(
        &anchors,
        &case.receipt_anchors,
        &case.approved_anchors,
        case.scopes,
        &mut failures,
    );
    validate_locator_probes(&case, &profile, &all_roots, &mut failures);
    validate_candidate_decision(&case, &profile, &all_roots, &mut failures);
    validate_engine_scan(
        &case,
        harness,
        project_boundary.clone(),
        supplied_native_roots,
        project_trust.clone(),
        limits,
        &mut failures,
    );

    for event in sentinel.events() {
        match event {
            SentinelEvent::ProcessSpawned => failures.push(
                "contract.process_spawned",
                "policy recorded a process spawn",
            ),
            SentinelEvent::NetworkAccessed => failures.push(
                "contract.network_accessed",
                "policy recorded network access",
            ),
            SentinelEvent::FilesystemWrite => failures.push(
                "contract.filesystem_write",
                "policy recorded a filesystem write",
            ),
        }
    }
    if let Some(before) = before {
        match FilesystemSnapshot::capture(case.fixture.root()) {
            Ok(after) if before != after => failures.push(
                "contract.fixture_mutated",
                "direct policy calls changed the synthetic input tree",
            ),
            Ok(_) => {}
            Err(error) => failures.push(
                "contract.snapshot_failed",
                format!("could not capture fixture after policy calls: {error}"),
            ),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Constructs the shared engine for contract tests through its validated authority boundary.
#[must_use]
pub fn test_engine(policy: &dyn HarnessObservationPolicy) -> ScanEngine<'_> {
    ScanEngine::from_authorities(vec![(policy, policy.runtime_authority())])
        .expect("a contract policy must expose a structurally valid runtime authority catalog")
}

fn validate_engine_scan<P: HarnessObservationPolicy>(
    case: &PolicyContractCase<P>,
    harness: kitrove_model::HarnessId,
    project_boundary: kitrove_adapter_api::ProjectBoundary,
    supplied_native_roots: Vec<SuppliedNativeRoot>,
    project_trust: BTreeMap<
        kitrove_adapter_api::ProjectTrustKey,
        kitrove_adapter_api::ProjectTrustObservation,
    >,
    limits: kitrove_adapter_api::ScanLimits,
    failures: &mut PolicyContractFailures,
) {
    let request = ScanRequest {
        home: Some(case.fixture.home().root().to_path_buf()),
        working_directory: case.fixture.working_directory().to_path_buf(),
        project_boundary,
        harnesses: BTreeSet::from([harness]),
        scopes: case.scopes,
        explicit_roots: case.explicit_roots.clone(),
        supplied_native_roots,
        versions: BTreeMap::new(),
        project_trust,
        environment: None,
        local_state: None,
        limits,
    };
    if let Err(error) = test_engine(&case.policy).scan(&request) {
        failures.push(
            "contract.engine_scan_failed",
            format!("shared engine scan returned {}", error.code),
        );
    }
}

fn validate_missing_home<P: HarnessObservationPolicy>(
    policy: &P,
    profile: &PolicyProfile,
    working_directory: &Path,
    project_boundary: &kitrove_adapter_api::ProjectBoundary,
    project_trust: &BTreeMap<
        kitrove_adapter_api::ProjectTrustKey,
        kitrove_adapter_api::ProjectTrustObservation,
    >,
    limits: &kitrove_adapter_api::ScanLimits,
    failures: &mut PolicyContractFailures,
) {
    let context = RootContext {
        home: None,
        working_directory,
        project_boundary,
        scopes: ScopeSelection::All,
        explicit_roots: &[],
        supplied_native_roots: &[],
        project_trust,
        limits,
    };
    let roots = repeat_adapter_call(
        || policy.roots(&context, profile),
        "roots without home",
        failures,
    )
    .unwrap_or_default();
    let unusual = repeat_adapter_call(
        || policy.discover_unusual_roots(&context, profile),
        "unusual roots without home",
        failures,
    )
    .unwrap_or_default();
    let related = repeat_adapter_call(
        || policy.related_roots(&context, profile),
        "related roots without home",
        failures,
    )
    .unwrap_or_default();
    let anchors = repeat_adapter_call(
        || policy.receipt_anchors(&context, profile),
        "receipt anchors without home",
        failures,
    )
    .unwrap_or_default();

    if roots.iter().chain(&unusual.roots).any(|root| {
        root.scope == HarnessScope::User && !matches!(root.tier, RootTier::Admin | RootTier::System)
    }) || related.iter().any(|root| root.scope == HarnessScope::User)
        || anchors
            .iter()
            .any(|anchor| anchor.scope == HarnessScope::User)
    {
        failures.push(
            "contract.missing_home_implicit_root",
            "policy returned a home-derived user root or receipt anchor when home was unavailable",
        );
    }
}

fn snapshot_or_failure(
    root: &Path,
    failures: &mut PolicyContractFailures,
    phase: &str,
) -> Option<FilesystemSnapshot> {
    match FilesystemSnapshot::capture(root) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            failures.push(
                "contract.snapshot_failed",
                format!("could not capture fixture {phase} policy calls: {error}"),
            );
            None
        }
    }
}

fn repeat_adapter_call<T: Clone + Eq>(
    call: impl Fn() -> AdapterResult<T>,
    name: &str,
    failures: &mut PolicyContractFailures,
) -> Option<T> {
    let first = call();
    let second = call();
    if first != second {
        failures.push(
            "contract.nondeterministic_policy_call",
            format!("repeated {name} calls differed"),
        );
    }
    match first {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(
                "contract.policy_call_failed",
                format!("{name} returned {}", error.code),
            );
            None
        }
    }
}

struct RootValidationContext<'a> {
    anchors: &'a [PathBuf],
    native_expectations: &'a [NativeRootExpectation],
    unusual_findings: &'a [kitrove_adapter_api::ScanFinding],
    harness: &'a kitrove_model::HarnessId,
    scopes: ScopeSelection,
}

fn validate_roots(
    roots: &[ObservedRoot],
    static_count: usize,
    validation: &RootValidationContext<'_>,
    failures: &mut PolicyContractFailures,
) {
    let mut keys = BTreeSet::new();
    for (index, root) in roots.iter().enumerate() {
        if !scope_selected(validation.scopes, root.scope) {
            failures.push(
                "contract.root_scope_unselected",
                format!(
                    "root {} was returned outside the requested scope",
                    root.logical_id
                ),
            );
        }
        if !is_contained_by_any(&root.path, validation.anchors) {
            failures.push(
                "contract.root_escape",
                format!(
                    "{} root {} escaped approved anchors",
                    root_kind(index, static_count),
                    root.logical_id
                ),
            );
        }
        if root.logical_id.as_str().is_empty()
            || root.evidence.as_str().is_empty()
            || root.enabled_layouts.is_empty()
        {
            failures.push(
                "contract.root_metadata_incomplete",
                format!("root {} omitted required metadata", root.logical_id),
            );
        }
        if !keys.insert((root.scope, root.policy_rank, root.logical_id.clone())) {
            failures.push(
                "contract.root_metadata_incomplete",
                format!(
                    "root {} duplicated a scope/rank/logical-ID key",
                    root.logical_id
                ),
            );
        }
    }

    for expectation in validation.native_expectations {
        if expectation.allowed_scopes.is_empty()
            || expectation.unsupported_scope_finding.trim().is_empty()
        {
            failures.push(
                "contract.native_root_descriptor_invalid",
                format!(
                    "native root {} omitted compiled scope metadata",
                    expectation.supplied.source_key()
                ),
            );
            continue;
        }
        if expectation.supplied.harness() != validation.harness {
            failures.push(
                "contract.native_root_scope",
                format!(
                    "supplied native root {} belongs to a different harness",
                    expectation.supplied.source_key()
                ),
            );
        }
        let matching = roots
            .iter()
            .find(|root| root.path == expectation.supplied.path());
        if !expectation
            .allowed_scopes
            .contains(&expectation.supplied.scope())
        {
            if matching.is_some() {
                failures.push(
                    "contract.native_root_scope",
                    format!(
                        "native root {} was accepted outside its compiled scope",
                        expectation.supplied.source_key()
                    ),
                );
            }
            if !validation
                .unusual_findings
                .iter()
                .any(|finding| finding.code == expectation.unsupported_scope_finding)
            {
                failures.push(
                    "contract.native_root_scope_diagnosis_missing",
                    format!(
                        "native root {} lacked its unsupported-scope finding",
                        expectation.supplied.source_key()
                    ),
                );
            }
            continue;
        }
        match matching {
            Some(root)
                if root.scope == expectation.supplied.scope()
                    && root.tier == expectation.tier
                    && root.policy_rank == expectation.policy_rank
                    && root.enabled_layouts == expectation.enabled_layouts
                    && root.evidence == expectation.evidence => {}
            Some(root) => failures.push(
                "contract.native_root_scope",
                format!(
                    "native root {} had policy metadata outside its descriptor",
                    root.logical_id
                ),
            ),
            None => failures.push(
                "contract.native_root_missing",
                format!(
                    "supplied native root {} was not represented",
                    expectation.supplied.source_key()
                ),
            ),
        }
    }
}

fn validate_unusual_findings(
    findings: &[kitrove_adapter_api::ScanFinding],
    failures: &mut PolicyContractFailures,
) {
    for finding in findings {
        if finding.code.trim().is_empty() || finding.action.trim().is_empty() {
            failures.push(
                "contract.unusual_root_finding_invalid",
                "unusual-root hook returned an incomplete finding",
            );
        }
    }
}

fn root_kind(index: usize, static_count: usize) -> &'static str {
    if index < static_count {
        "static"
    } else {
        "unusual"
    }
}

fn validate_related_roots(
    roots: &[kitrove_adapter_api::RelatedRoot],
    anchors: &[PathBuf],
    scopes: ScopeSelection,
    failures: &mut PolicyContractFailures,
) {
    for root in roots {
        if !scope_selected(scopes, root.scope) {
            failures.push(
                "contract.related_root_scope_unselected",
                format!(
                    "related root {} was returned outside the requested scope",
                    root.logical_id
                ),
            );
        }
        if !is_contained_by_any(&root.path, anchors) {
            failures.push(
                "contract.root_escape",
                format!("related root {} escaped approved anchors", root.logical_id),
            );
        }
        if root.logical_id.as_str().is_empty() || root.evidence.as_str().is_empty() {
            failures.push(
                "contract.root_metadata_incomplete",
                format!("related root {} omitted required metadata", root.logical_id),
            );
        }
    }
}

fn validate_receipt_anchors(
    anchors: &[ReceiptAnchor],
    expected: &[ReceiptAnchorExpectation],
    approved: &[PathBuf],
    scopes: ScopeSelection,
    failures: &mut PolicyContractFailures,
) {
    for anchor in anchors {
        if !scope_selected(scopes, anchor.scope) {
            failures.push(
                "contract.receipt_anchor_scope_unselected",
                "receipt anchor was returned outside the requested scope",
            );
        }
        if !is_contained_by_any(&anchor.path, approved) {
            failures.push(
                "contract.receipt_anchor_escape",
                "receipt anchor escaped approved anchors",
            );
        }
        if !expected.iter().any(|item| {
            item.scope == anchor.scope
                && item.path == anchor.path
                && item.evidence == anchor.evidence
        }) {
            failures.push(
                "contract.receipt_anchor_uncompiled",
                "receipt anchor was not declared by the contract case",
            );
        }
    }
    for expectation in expected {
        if !anchors.iter().any(|anchor| {
            anchor.scope == expectation.scope
                && anchor.path == expectation.path
                && anchor.evidence == expectation.evidence
        }) {
            failures.push(
                "contract.receipt_anchor_missing",
                "compiled receipt anchor was not returned",
            );
        }
    }
}

fn validate_candidate_decision<P>(
    case: &PolicyContractCase<P>,
    profile: &PolicyProfile,
    roots: &[ObservedRoot],
    failures: &mut PolicyContractFailures,
) where
    P: HarnessObservationPolicy,
{
    let Some(root) = roots.first() else {
        failures.push(
            "contract.candidate_root_missing",
            "policy returned no root for the direct candidate-decision probe",
        );
        return;
    };
    let source = SkillSource::Directory {
        path: AgentSkillFixture::StandardBasic.directory(),
    };
    let candidate = match capture_skill_source(&source, CaptureLimits::default()) {
        Ok(candidate) => candidate,
        Err(error) => {
            failures.push(
                "contract.candidate_capture_failed",
                format!(
                    "could not capture the direct candidate probe: {}",
                    error.code()
                ),
            );
            return;
        }
    };
    let locator = CandidateLocator {
        absolute_path: root.path.join("contract-source/SKILL.md"),
        source_relative_path: "contract-source/SKILL.md".to_owned(),
        layout: candidate.layout,
        original_document_name: candidate.original_document_name.clone(),
    };
    let first = case
        .policy
        .decide_candidate(&candidate, &locator, root, profile);
    let second = case
        .policy
        .decide_candidate(&candidate, &locator, root, profile);
    if first != second {
        failures.push(
            "contract.nondeterministic_policy_call",
            "repeated candidate decisions differed",
        );
    }
    if first.is_err() {
        failures.push(
            "contract.candidate_policy_failed",
            "direct candidate-decision probe failed",
        );
    }
}

fn validate_locator_probes<P>(
    case: &PolicyContractCase<P>,
    profile: &PolicyProfile,
    roots: &[ObservedRoot],
    failures: &mut PolicyContractFailures,
) where
    P: HarnessObservationPolicy,
{
    let mut expected_coverage = BTreeSet::new();
    for probe in &case.locator_probes {
        expected_coverage.insert(probe.expectation);
        let matching_roots = roots.iter().filter(|root| {
            probe
                .logical_root
                .as_ref()
                .is_none_or(|logical_root| logical_root == &root.logical_id)
        });
        let mut matched_root = false;
        for root in matching_roots {
            matched_root = true;
            let locator = CandidateLocator {
                absolute_path: root.path.join(&probe.source_relative_path),
                source_relative_path: probe.source_relative_path.clone(),
                layout: probe.layout,
                original_document_name: probe.original_document_name.clone(),
            };
            let first = case.policy.classify_locator(&locator, root, profile);
            let second = case.policy.classify_locator(&locator, root, profile);
            if first != second {
                failures.push(
                    "contract.nondeterministic_policy_call",
                    format!(
                        "repeated locator decisions differed for {}",
                        root.logical_id
                    ),
                );
            }
            let actual = match first {
                LocatorDecision::Capture | LocatorDecision::CaptureIfFrontmatterPrefix => {
                    LocatorExpectation::Supported
                }
                LocatorDecision::Unsupported { .. } => LocatorExpectation::Unsupported,
                LocatorDecision::Ignore => {
                    failures.push(
                        "contract.locator_coverage",
                        format!(
                            "probe {} was ignored instead of classified",
                            probe.source_relative_path
                        ),
                    );
                    continue;
                }
            };
            if actual != probe.expectation {
                failures.push(
                    "contract.locator_coverage",
                    format!(
                        "probe {} had the wrong locator decision",
                        probe.source_relative_path
                    ),
                );
            }
        }
        if !matched_root {
            failures.push(
                "contract.locator_coverage",
                format!(
                    "probe {} did not match any observed root",
                    probe.source_relative_path
                ),
            );
        }
    }
    if !expected_coverage.contains(&LocatorExpectation::Supported)
        || !expected_coverage.contains(&LocatorExpectation::Unsupported)
    {
        failures.push(
            "contract.locator_coverage",
            "contract case must probe supported and unsupported positions",
        );
    }
}

fn is_contained_by_any(path: &Path, anchors: &[PathBuf]) -> bool {
    is_safe_absolute(path)
        && anchors
            .iter()
            .any(|anchor| is_safe_absolute(anchor) && path.starts_with(anchor))
}

fn is_safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !raw_parent_component(path)
        && !path
            .components()
            .any(|component| {
                matches!(component, Component::ParentDir | Component::CurDir)
                    || matches!(component, Component::Normal(value) if value == OsStr::new(".") || value == OsStr::new(".."))
            })
}

#[cfg(windows)]
fn raw_parent_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| segment == "..")
}

#[cfg(not(windows))]
const fn raw_parent_component(_path: &Path) -> bool {
    false
}

fn scope_selected(selection: ScopeSelection, scope: HarnessScope) -> bool {
    matches!(selection, ScopeSelection::All)
        || matches!(
            (selection, scope),
            (ScopeSelection::User, HarnessScope::User)
                | (ScopeSelection::Project, HarnessScope::Project)
        )
}

impl PolicyContractFailures {
    fn push(&mut self, code: &'static str, detail: impl Into<String>) {
        self.failures.push(ContractFailure {
            code,
            detail: detail.into(),
        });
    }
}
