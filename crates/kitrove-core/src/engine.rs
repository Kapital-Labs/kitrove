use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{
    AdapterError, AdapterResult, CandidateDecision, CandidateSummary, DuplicateDecision,
    FindingSeverity, FindingSubject, HarnessObservationPolicy, NativeAcceptance, ObservationId,
    ObservationIdentity, ObservedRoot, PolicyProfile, PolicyRuntimeAuthority,
    ProjectTrustObservation, ReceiptAnchor, RelatedRoot, RootAuthority, RootContext,
    RootEvidenceAuthority, RootId, RootIdAuthority, RootPathAuthority, RootRankAuthority, RootTier,
    ScanFinding, ScanRequest, ScopeSelection, SourceRelativePath, VersionObservation,
    VersionObservationOwned,
};
use kitrove_agent_skills::{
    CapturedSkillSource, PortableProjection, SkillSource, SkillSourceLayout,
    capture_skill_source_with_meter, project_skill_source,
};
use kitrove_model::{ContentHash, HarnessId, HarnessScope, NormalizedDestination, PortablePath};

use crate::agent_observation::{AgentCaptureOutcome, capture_agent_locator};
use crate::classification::{
    AssetReceiptAnchor, ClassificationReportState, ReceiptPolicyEvidence, classify_scan,
    normalize_path as normalize_destination_path,
};
use crate::prompt_command_observation::{
    PromptCommandCaptureOutcome, capture_prompt_command_locator,
};
use crate::report::{normalize_findings, normalized_findings};
use crate::{
    AgentScanEntry, DiscoveredLocator, FailedLocator, FailedRoot, NativeExtensionLayout,
    NativeExtensionObservation, NativeExtensionScanEntry, NativeExtensionSource,
    RelatedCapabilityObservation, ScanBudget, ScanClassification, ScanEntry, ScanReport,
    capture_pi_extension_metered, discover_locators, discover_related_documents,
};

/// Canonical, path-redacted location evidence shared by accepted and failed observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationLocation {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub logical_root: RootId,
    pub policy_rank: u32,
    pub source_relative_path: Option<SourceRelativePath>,
    pub layout: SkillSourceLayout,
    pub original_document_name: Option<String>,
}

/// A successfully captured candidate accepted by its version-selected native policy.
///
/// Future adoption APIs can require this type, rather than accepting a display-only ID from a
/// failed observation.
#[derive(Clone)]
pub struct AcceptedObservedCandidate {
    observation_id: ObservationId,
    location: ObservationLocation,
    captured: CapturedSkillSource,
    portable_hash: Option<ContentHash>,
    decision: CandidateDecision,
    normalized_destination: Option<NormalizedDestination>,
}

impl PartialEq for AcceptedObservedCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.observation_id == other.observation_id
            && self.location == other.location
            && self.captured == other.captured
            && self.portable_hash == other.portable_hash
            && self.decision == other.decision
    }
}

impl Eq for AcceptedObservedCandidate {}

impl AcceptedObservedCandidate {
    #[must_use]
    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    #[must_use]
    pub const fn location(&self) -> &ObservationLocation {
        &self.location
    }

    #[must_use]
    pub const fn captured(&self) -> &CapturedSkillSource {
        &self.captured
    }

    #[must_use]
    pub const fn portable_hash(&self) -> Option<&ContentHash> {
        self.portable_hash.as_ref()
    }

    #[must_use]
    pub const fn decision(&self) -> &CandidateDecision {
        &self.decision
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        observation_id: ObservationId,
        location: ObservationLocation,
        captured: CapturedSkillSource,
        portable_hash: Option<ContentHash>,
        decision: CandidateDecision,
    ) -> Self {
        Self {
            observation_id,
            location,
            captured,
            portable_hash,
            decision,
            normalized_destination: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_destination(mut self, destination: NormalizedDestination) -> Self {
        self.normalized_destination = Some(destination);
        self
    }
}

impl Debug for AcceptedObservedCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let finding_codes = self
            .decision
            .findings()
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("AcceptedObservedCandidate")
            .field("observation_id", &self.observation_id)
            .field("harness", &self.location.harness)
            .field("scope", &self.location.scope)
            .field("root_tier", &self.location.root_tier)
            .field("logical_root", &self.location.logical_root)
            .field("policy_rank", &self.location.policy_rank)
            .field("layout", &self.location.layout)
            .field("status", &"accepted")
            .field("exact_source_hash", &self.captured.exact_source_hash)
            .field("portable_hash", &self.portable_hash)
            .field("finding_codes", &finding_codes)
            .finish()
    }
}

/// A safe locator that could not become an adoption-eligible observation.
#[derive(Clone)]
pub struct FailedObservedCandidate {
    observation_id: Option<ObservationId>,
    location: ObservationLocation,
    native_id: Option<String>,
    exact_source_hash: Option<ContentHash>,
    failure_code: String,
    findings: Vec<ScanFinding>,
    normalized_destination: Option<NormalizedDestination>,
}

impl PartialEq for FailedObservedCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.observation_id == other.observation_id
            && self.location == other.location
            && self.native_id == other.native_id
            && self.exact_source_hash == other.exact_source_hash
            && self.failure_code == other.failure_code
            && self.findings == other.findings
    }
}

impl Eq for FailedObservedCandidate {}

impl Debug for FailedObservedCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let finding_codes = self
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("FailedObservedCandidate")
            .field("observation_id", &self.observation_id)
            .field("harness", &self.location.harness)
            .field("scope", &self.location.scope)
            .field("root_tier", &self.location.root_tier)
            .field("logical_root", &self.location.logical_root)
            .field("policy_rank", &self.location.policy_rank)
            .field("layout", &self.location.layout)
            .field("status", &"failed")
            .field("exact_source_hash", &self.exact_source_hash)
            .field("failure_code", &self.failure_code)
            .field("finding_codes", &finding_codes)
            .finish()
    }
}

impl FailedObservedCandidate {
    /// Returns the stable display identity. This is deliberately not an accepted-candidate token.
    #[must_use]
    pub fn observation_id(&self) -> Option<&ObservationId> {
        self.observation_id.as_ref()
    }

    #[must_use]
    pub const fn location(&self) -> &ObservationLocation {
        &self.location
    }

    #[must_use]
    pub fn failure_code(&self) -> &str {
        &self.failure_code
    }
}

/// One post-discovery candidate observation, preserving acceptance as a type boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedCandidate {
    Accepted(Box<AcceptedObservedCandidate>),
    Failed(Box<FailedObservedCandidate>),
}

impl ObservedCandidate {
    #[must_use]
    pub fn observation_id(&self) -> Option<&ObservationId> {
        match self {
            Self::Accepted(candidate) => Some(candidate.observation_id()),
            Self::Failed(candidate) => candidate.observation_id(),
        }
    }

    #[must_use]
    pub const fn location(&self) -> &ObservationLocation {
        match self {
            Self::Accepted(candidate) => candidate.location(),
            Self::Failed(candidate) => candidate.location(),
        }
    }

    pub(crate) fn normalized_destination(&self) -> Option<&NormalizedDestination> {
        match self {
            Self::Accepted(candidate) => candidate.normalized_destination.as_ref(),
            Self::Failed(candidate) => candidate.normalized_destination.as_ref(),
        }
    }

    fn finding_count(&self) -> usize {
        match self {
            Self::Accepted(candidate) => candidate.decision().findings().len(),
            Self::Failed(candidate) => candidate.findings.len(),
        }
    }
}

/// Shared, harness-neutral observation orchestrator.
///
/// Policies cannot be installed through an authority-inferred compatibility constructor. A
/// composition root must use [`Self::from_registry`] or supply catalogs to
/// [`Self::from_authorities`], which validates them before returning an engine.
///
/// ```compile_fail
/// use kitrove_core::ScanEngine;
/// let _ = ScanEngine::from_policies;
/// ```
///
/// ```compile_fail
/// use kitrove_core::ScanEngine;
/// let _ = ScanEngine::new;
/// ```
pub struct ScanEngine<'a> {
    policies: Vec<EnginePolicy<'a>>,
}

#[derive(Clone)]
struct EnginePolicy<'a> {
    policy: &'a dyn HarnessObservationPolicy,
    authority: PolicyRuntimeAuthority,
}

impl<'a> ScanEngine<'a> {
    /// Creates an engine only after validating each explicit closed runtime authority catalog.
    pub fn from_authorities(
        policies: Vec<(&'a dyn HarnessObservationPolicy, PolicyRuntimeAuthority)>,
    ) -> AdapterResult<Self> {
        let mut harnesses = BTreeSet::new();
        let mut validated = Vec::with_capacity(policies.len());
        for (policy, authority) in policies {
            let harness = policy.harness();
            if !harnesses.insert(harness.clone()) {
                return Err(AdapterError::new(
                    "scan.duplicate_harness_policy",
                    "the scan engine received more than one policy for a harness",
                ));
            }
            crate::registry::validate_runtime_authority(&harness, &authority)?;
            validated.push(EnginePolicy { policy, authority });
        }
        Ok(Self {
            policies: validated,
        })
    }

    /// Creates an engine from registry-retained runtime authority catalogs.
    #[must_use]
    pub fn from_registry(registry: &'a crate::PolicyRegistry) -> Self {
        Self {
            policies: registry
                .runtime_policies()
                .into_iter()
                .map(|(policy, authority)| EnginePolicy {
                    policy,
                    authority: authority.clone(),
                })
                .collect(),
        }
    }

    /// Discovers and captures every selected policy with one request-global budget.
    pub fn scan(&self, request: &ScanRequest<'_>) -> AdapterResult<ScanReport> {
        let mut budget = ScanBudget::new(request.limits);
        let mut observations = Vec::new();
        let mut duplicate_annotations = BTreeMap::new();
        let mut related = Vec::new();
        let mut native_extension_entries = Vec::new();
        let mut native_extension_observations = Vec::new();
        let mut prompt_command_entries = Vec::new();
        let mut prompt_command_observations = Vec::new();
        let mut agent_entries = Vec::new();
        let mut agent_observations = Vec::new();
        let mut findings = Vec::new();
        let mut versions = BTreeMap::new();
        let mut receipt_policies = Vec::new();
        let mut root_keys = BTreeSet::new();
        let mut policies = self.policies.clone();
        policies.sort_by_key(|entry| entry.policy.harness());
        if policies
            .windows(2)
            .any(|pair| pair[0].policy.harness() == pair[1].policy.harness())
        {
            return Err(AdapterError::new(
                "scan.duplicate_harness_policy",
                "the scan engine received more than one policy for a harness",
            ));
        }

        for engine_policy in policies {
            let policy = engine_policy.policy;
            let harness = policy.harness();
            if !request.harnesses.contains(&harness) {
                continue;
            }
            let version = match request.versions.get(&harness) {
                Some(evidence) if evidence.harness() == &harness => {
                    VersionObservation::Verified(evidence)
                }
                Some(_) => {
                    push_report_finding(
                        &mut findings,
                        &mut budget,
                        policy_stage_finding(
                            &harness,
                            "scan.version_evidence_mismatch",
                            "supply version evidence under its matching harness key",
                        ),
                    )?;
                    VersionObservation::Unknown
                }
                None => VersionObservation::Unknown,
            };
            let profile = match policy.profile(version) {
                Ok(profile) => profile,
                Err(_) => {
                    versions.insert(harness.clone(), VersionObservationOwned::Unknown);
                    push_report_finding(
                        &mut findings,
                        &mut budget,
                        policy_stage_finding(
                            &harness,
                            "scan.policy_profile_failed",
                            "verify the compiled harness profile catalog",
                        ),
                    )?;
                    continue;
                }
            };
            if profile.harness() != &harness {
                versions.insert(harness.clone(), VersionObservationOwned::Unknown);
                push_report_finding(
                    &mut findings,
                    &mut budget,
                    policy_stage_finding(
                        &harness,
                        "scan.profile_harness_mismatch",
                        "verify the compiled harness profile catalog",
                    ),
                )?;
                continue;
            }
            versions.insert(harness.clone(), profile.version().clone());
            let explicit_roots = request
                .explicit_roots
                .iter()
                .filter(|root| root.harness == harness)
                .cloned()
                .collect::<Vec<_>>();
            let supplied_native_roots = request
                .supplied_native_roots
                .iter()
                .filter(|root| root.harness() == &harness)
                .cloned()
                .collect::<Vec<_>>();
            let context = RootContext {
                home: request.home.as_deref(),
                working_directory: &request.working_directory,
                project_boundary: &request.project_boundary,
                scopes: request.scopes,
                explicit_roots: &explicit_roots,
                supplied_native_roots: &supplied_native_roots,
                project_trust: &request.project_trust,
                limits: &request.limits,
            };
            let (anchors, mut failed) = match policy.receipt_anchors(&context, &profile) {
                Ok(anchors) => (anchors, false),
                Err(_) => {
                    push_report_finding(
                        &mut findings,
                        &mut budget,
                        policy_stage_finding(
                            &harness,
                            "scan.receipt_policy_failed",
                            "verify the compiled receipt-anchor policy",
                        ),
                    )?;
                    (vec![], true)
                }
            };
            let mut anchors = anchors;
            anchors.truncate(request.limits.max_roots.saturating_add(1));
            let anchors = retain_authorized_receipt_anchors(
                &harness,
                anchors,
                &engine_policy.authority,
                &context,
                &mut findings,
                &mut failed,
                &mut budget,
            )?;
            receipt_policies.push(ReceiptPolicyEvidence {
                harness: harness.clone(),
                anchors: anchors
                    .into_iter()
                    .map(|anchor| AssetReceiptAnchor {
                        kind: kitrove_model::AssetKind::Skill,
                        anchor,
                    })
                    .collect(),
                failed_kinds: failed
                    .then_some(kitrove_model::AssetKind::Skill)
                    .into_iter()
                    .collect(),
            });
            let mut roots = match policy.roots(&context, &profile) {
                Ok(roots) => roots,
                Err(_) => {
                    push_report_finding(
                        &mut findings,
                        &mut budget,
                        policy_stage_finding(
                            &harness,
                            "scan.policy_roots_failed",
                            "verify the compiled root policy",
                        ),
                    )?;
                    vec![]
                }
            };
            let buffered_root_limit = request.limits.max_roots.saturating_add(1);
            roots.truncate(buffered_root_limit);
            match policy.discover_unusual_roots_bounded(&context, &profile, &mut budget) {
                Ok(unusual) => {
                    let remaining = buffered_root_limit.saturating_sub(roots.len());
                    roots.extend(unusual.roots.into_iter().take(remaining));
                    extend_report_findings(&mut findings, &mut budget, unusual.findings)?;
                }
                Err(_) => push_report_finding(
                    &mut findings,
                    &mut budget,
                    policy_stage_finding(
                        &harness,
                        "scan.policy_unusual_roots_failed",
                        "verify the compiled unusual-root policy",
                    ),
                )?,
            }
            roots = retain_authorized_roots(
                &harness,
                roots,
                &engine_policy.authority,
                &context,
                profile.line(),
                &mut root_keys,
                &mut findings,
                &mut budget,
            )?;
            roots.retain(|root| scope_selected(request.scopes, root.scope));
            roots.sort_by(|left, right| {
                left.policy_rank
                    .cmp(&right.policy_rank)
                    .then_with(|| left.logical_id.cmp(&right.logical_id))
                    .then_with(|| left.scope.cmp(&right.scope))
                    .then_with(|| left.tier.cmp(&right.tier))
            });

            let observation_start = observations.len();
            let discovery = discover_locators(policy, &roots, &profile, &mut budget);
            extend_report_findings(&mut findings, &mut budget, discovery.findings)?;
            for failed in discovery.failed_roots {
                let observation = failed_root_observation(&harness, failed);
                if !budget.reserve_report_entry(observation.finding_count()) {
                    return Err(report_budget_error());
                }
                observations.push(observation);
            }
            for failed in discovery.failed_locators {
                let observation = failed_locator_observation(&harness, failed);
                if !budget.reserve_report_entry(observation.finding_count()) {
                    return Err(report_budget_error());
                }
                observations.push(observation);
            }
            for discovered in discovery.locators {
                if !budget.reserve_report_entry(0) {
                    return Err(report_budget_error());
                }
                let observation =
                    capture_observation(policy, &harness, &profile, discovered, &mut budget);
                if !budget.reserve_report_findings(observation.finding_count()) {
                    return Err(report_budget_error());
                }
                observations.push(observation);
            }
            apply_duplicate_decisions(
                policy,
                &profile,
                &observations[observation_start..],
                &mut duplicate_annotations,
                &mut budget,
            )?;

            let (mut related_roots, related_failed) = match policy.related_roots(&context, &profile)
            {
                Ok(roots) => (roots, false),
                Err(_) => {
                    push_report_finding(
                        &mut findings,
                        &mut budget,
                        policy_stage_finding(
                            &harness,
                            "scan.policy_related_roots_failed",
                            "verify the compiled related-root policy",
                        ),
                    )?;
                    (vec![], true)
                }
            };
            related_roots.truncate(request.limits.max_roots.saturating_add(1));
            related_roots = retain_authorized_related_roots(
                &harness,
                related_roots,
                &engine_policy.authority,
                &context,
                &mut root_keys,
                &mut findings,
                &mut budget,
            )?;
            let agent_anchors = related_roots
                .iter()
                .filter(|root| root.kind == kitrove_model::AssetKind::Agent)
                .map(|root| AssetReceiptAnchor {
                    kind: kitrove_model::AssetKind::Agent,
                    anchor: ReceiptAnchor {
                        scope: root.scope,
                        path: root.path.clone(),
                        evidence: root.evidence.clone(),
                    },
                })
                .collect::<Vec<_>>();
            let receipt_policy = receipt_policies
                .last_mut()
                .expect("the current harness receipt policy was retained");
            receipt_policy.anchors.extend(agent_anchors);
            if related_failed {
                receipt_policy
                    .failed_kinds
                    .insert(kitrove_model::AssetKind::Agent);
            }
            related_roots.retain(|root| scope_selected(request.scopes, root.scope));
            related_roots.sort_by(|left, right| {
                left.policy_rank
                    .cmp(&right.policy_rank)
                    .then_with(|| left.logical_id.cmp(&right.logical_id))
                    .then_with(|| left.scope.cmp(&right.scope))
                    .then_with(|| left.tier.cmp(&right.tier))
                    .then_with(|| left.kind.cmp(&right.kind))
            });
            let related_discovery = discover_related_documents(&related_roots, &mut budget);
            extend_report_findings(&mut findings, &mut budget, related_discovery.findings)?;
            for locator in related_discovery.locators {
                if locator.root.kind == kitrove_model::AssetKind::Agent {
                    let outcome = capture_agent_locator(
                        &harness,
                        locator,
                        request.limits.capture,
                        &mut budget,
                    )?;
                    if !budget.reserve_report_entry(1) {
                        return Err(report_budget_error());
                    }
                    match outcome {
                        AgentCaptureOutcome::Captured { entry, observation } => {
                            agent_entries.push(*entry);
                            agent_observations.push(*observation);
                        }
                        AgentCaptureOutcome::Refused(observation) => related.push(observation),
                    }
                    continue;
                }
                if locator.root.kind == kitrove_model::AssetKind::Command {
                    let outcome = capture_prompt_command_locator(
                        &harness,
                        locator,
                        request.limits.capture,
                        &mut budget,
                    )?;
                    if !budget.reserve_report_entry(1) {
                        return Err(report_budget_error());
                    }
                    match outcome {
                        PromptCommandCaptureOutcome::Captured { entry, observation } => {
                            prompt_command_entries.push(entry);
                            prompt_command_observations.push(*observation);
                        }
                        PromptCommandCaptureOutcome::Refused(observation) => {
                            related.push(observation);
                        }
                    }
                    continue;
                }
                if locator.root.pattern
                    == kitrove_adapter_api::RelatedDocumentPattern::NativeExtensionAtRoot
                {
                    if !budget.reserve_report_entry(1) {
                        return Err(report_budget_error());
                    }
                    let layout = match locator.layout {
                        SkillSourceLayout::Directory => NativeExtensionLayout::Directory,
                        SkillSourceLayout::Standalone => NativeExtensionLayout::Standalone,
                    };
                    let source = match layout {
                        NativeExtensionLayout::Standalone => NativeExtensionSource::Standalone {
                            path: locator.absolute_path.clone(),
                        },
                        NativeExtensionLayout::Directory => NativeExtensionSource::Directory {
                            path: locator.absolute_path.clone(),
                        },
                    };
                    let remaining_capture = budget.remaining_capture_limits();
                    let captured =
                        match capture_pi_extension_metered(&source, remaining_capture, &mut budget)
                        {
                            Ok(captured) => captured,
                            Err(_) => {
                                related.push(RelatedCapabilityObservation {
                                harness: harness.clone(),
                                scope: locator.root.scope,
                                root_tier: locator.root.tier,
                                logical_root: locator.root.logical_id.clone(),
                                policy_rank: locator.root.policy_rank,
                                source_relative_path: locator.source_relative_path,
                                kind: locator.root.kind,
                                findings: vec![ScanFinding::new(
                                    "scan.native_extension_capture_failed",
                                    FindingSeverity::Attention,
                                    FindingSubject::Root(locator.root.logical_id),
                                    vec![locator.root.evidence],
                                    "inspect the extension path, limits, and credential refusal",
                                )],
                            });
                                continue;
                            }
                        };
                    let native_id = match layout {
                        NativeExtensionLayout::Standalone => locator
                            .source_relative_path
                            .strip_suffix(".ts")
                            .unwrap_or(&locator.source_relative_path)
                            .to_owned(),
                        NativeExtensionLayout::Directory => locator.source_relative_path.clone(),
                    };
                    let source_relative = PortablePath::parse(locator.source_relative_path.clone())
                        .map_err(|_| {
                            AdapterError::new(
                                "scan.native_extension_identity_invalid",
                                "native extension identity could not be represented portably",
                            )
                        })?;
                    let observation = NativeExtensionObservation::new(
                        locator.root.scope,
                        locator.root.tier,
                        locator.root.logical_id.clone(),
                        locator.root.policy_rank,
                        source_relative,
                        native_id.clone(),
                        captured,
                    )
                    .map_err(|_| {
                        AdapterError::new(
                            "scan.native_extension_identity_invalid",
                            "native extension identity could not be constructed",
                        )
                    })?;
                    native_extension_entries.push(NativeExtensionScanEntry {
                        harness: harness.clone(),
                        scope: locator.root.scope,
                        root_tier: locator.root.tier,
                        logical_root: locator.root.logical_id,
                        policy_rank: locator.root.policy_rank,
                        source_relative_path: locator.source_relative_path,
                        layout,
                        native_id,
                        observation_identity: observation.identity().clone(),
                        exact_source_hash: observation.captured().exact.hash.clone(),
                        classification: ScanClassification::Unmanaged,
                        findings: vec![ScanFinding::new(
                            "scan.native_extension_captured",
                            FindingSeverity::Attention,
                            FindingSubject::Harness(HarnessId::Pi),
                            vec![locator.root.evidence],
                            "review and explicitly adopt the native extension, then trust its exact object locally before materialization",
                        )],
                    });
                    native_extension_observations.push(observation);
                    continue;
                }
                if !budget.reserve_report_entry(1) {
                    return Err(report_budget_error());
                }
                related.push(RelatedCapabilityObservation {
                    harness: harness.clone(),
                    scope: locator.root.scope,
                    root_tier: locator.root.tier,
                    logical_root: locator.root.logical_id.clone(),
                    policy_rank: locator.root.policy_rank,
                    source_relative_path: locator.source_relative_path.clone(),
                    kind: locator.root.kind,
                    findings: vec![ScanFinding::new(
                        "scan.related_capability",
                        FindingSeverity::Informational,
                        FindingSubject::Related {
                            logical_root: locator.root.logical_id.clone(),
                            source_relative_path: SourceRelativePath::parse(
                                locator.source_relative_path.clone(),
                            )
                            .expect("discovery retains only validated UTF-8 relative paths"),
                        },
                        vec![locator.root.evidence.clone()],
                        "inspect the related capability separately",
                    )],
                });
            }
        }

        let ambiguous_agents = mark_ambiguous_agent_names(&mut agent_entries, &mut budget)?;
        agent_observations.retain(|observation| !ambiguous_agents.contains(observation.identity()));
        observations.sort_by(observation_order);
        let ambiguous_duplicates = duplicate_annotations
            .iter()
            .filter_map(|(id, annotation)| annotation.ambiguous.then_some(id.clone()))
            .collect::<BTreeSet<_>>();
        let mut entries = observations
            .iter()
            .map(|observation| {
                entry_from_observation(
                    observation,
                    observation
                        .observation_id()
                        .and_then(|id| duplicate_annotations.get(id)),
                )
            })
            .collect::<Vec<_>>();
        let mode = classify_scan(
            request,
            &observations,
            &ambiguous_duplicates,
            &receipt_policies,
            ClassificationReportState {
                entries: &mut entries,
                agent_entries: &mut agent_entries,
                budget: &mut budget,
                findings: &mut findings,
            },
        )?;
        let adoptable_agents = agent_entries
            .iter()
            .filter(|entry| entry.classification == ScanClassification::Unmanaged)
            .filter_map(|entry| entry.observation_id.clone())
            .collect::<BTreeSet<_>>();
        agent_observations.retain(|observation| adoptable_agents.contains(observation.identity()));
        let finding_count = entries
            .iter()
            .map(|entry| entry.findings.len())
            .chain(related.iter().map(|observation| observation.findings.len()))
            .chain(
                prompt_command_entries
                    .iter()
                    .map(|observation| observation.findings.len()),
            )
            .chain(
                agent_entries
                    .iter()
                    .map(|observation| observation.findings.len()),
            )
            .chain(
                native_extension_entries
                    .iter()
                    .map(|observation| observation.findings.len()),
            )
            .try_fold(findings.len(), usize::checked_add);
        let report_entry_count = entries
            .len()
            .checked_add(related.len())
            .and_then(|count| count.checked_add(prompt_command_entries.len()))
            .and_then(|count| count.checked_add(agent_entries.len()))
            .and_then(|count| count.checked_add(native_extension_entries.len()));
        if report_entry_count.is_none_or(|count| count > request.limits.max_report_entries)
            || finding_count.is_none_or(|count| count > request.limits.max_findings)
        {
            return Err(report_budget_error());
        }
        let mut report = ScanReport::new(
            mode,
            versions,
            entries,
            related,
            findings,
            observations,
            budget.capture_usage().clone(),
        );
        report.set_native_extensions(native_extension_entries, native_extension_observations);
        report.set_prompt_commands(prompt_command_entries, prompt_command_observations);
        report.set_agents(agent_entries, agent_observations);
        Ok(report)
    }
}

type RuntimeRootKey = (HarnessId, HarnessScope, u32, RootId);

#[allow(clippy::too_many_arguments)]
fn retain_authorized_roots(
    harness: &HarnessId,
    roots: Vec<ObservedRoot>,
    authority: &PolicyRuntimeAuthority,
    context: &RootContext<'_>,
    line: kitrove_adapter_api::PolicyLine,
    keys: &mut BTreeSet<RuntimeRootKey>,
    findings: &mut Vec<ScanFinding>,
    budget: &mut ScanBudget,
) -> AdapterResult<Vec<ObservedRoot>> {
    let mut retained = Vec::new();
    for (index, root) in roots.into_iter().enumerate() {
        if index >= context.limits.max_roots {
            push_report_finding(
                findings,
                budget,
                policy_stage_finding(
                    harness,
                    "scan.root_budget_exhausted",
                    "reduce policy root claims or increase the request root limit",
                ),
            )?;
            break;
        }
        let authorized = authority
            .roots
            .iter()
            .any(|claim| root_matches_claim(harness, &root, claim, context, Some(line)));
        let unique = authorized
            && keys.insert((
                harness.clone(),
                root.scope,
                root.policy_rank,
                root.logical_id.clone(),
            ));
        if unique {
            retained.push(root);
        } else {
            push_report_finding(
                findings,
                budget,
                root_authority_finding(root.logical_id.clone()),
            )?;
        }
    }
    Ok(retained)
}

fn retain_authorized_related_roots(
    harness: &HarnessId,
    roots: Vec<RelatedRoot>,
    authority: &PolicyRuntimeAuthority,
    context: &RootContext<'_>,
    keys: &mut BTreeSet<RuntimeRootKey>,
    findings: &mut Vec<ScanFinding>,
    budget: &mut ScanBudget,
) -> AdapterResult<Vec<RelatedRoot>> {
    let mut retained = Vec::new();
    for (index, root) in roots.into_iter().enumerate() {
        if index >= context.limits.max_roots {
            push_report_finding(
                findings,
                budget,
                policy_stage_finding(
                    harness,
                    "scan.root_budget_exhausted",
                    "reduce related-root claims or increase the request root limit",
                ),
            )?;
            break;
        }
        let authorized = authority.related_roots.iter().any(|claim| {
            claim.kind == root.kind
                && claim.pattern == root.pattern
                && related_root_matches_claim(harness, &root, &claim.root, context)
        });
        let unique = authorized
            && keys.insert((
                harness.clone(),
                root.scope,
                root.policy_rank,
                root.logical_id.clone(),
            ));
        if unique {
            retained.push(root);
        } else {
            push_report_finding(
                findings,
                budget,
                root_authority_finding(root.logical_id.clone()),
            )?;
        }
    }
    Ok(retained)
}

fn retain_authorized_receipt_anchors(
    harness: &HarnessId,
    anchors: Vec<ReceiptAnchor>,
    authority: &PolicyRuntimeAuthority,
    context: &RootContext<'_>,
    findings: &mut Vec<ScanFinding>,
    failed: &mut bool,
    budget: &mut ScanBudget,
) -> AdapterResult<Vec<ReceiptAnchor>> {
    let mut retained = Vec::new();
    for (index, anchor) in anchors.into_iter().enumerate() {
        if index >= context.limits.max_roots {
            *failed = true;
            push_report_finding(
                findings,
                budget,
                policy_stage_finding(
                    harness,
                    "scan.root_budget_exhausted",
                    "reduce receipt-anchor claims or increase the request root limit",
                ),
            )?;
            break;
        }
        let authorized = authority.receipt_anchors.iter().any(|claim| {
            claim.scope == anchor.scope
                && claim.evidence == anchor.evidence
                && authority_path_index(harness, anchor.scope, &anchor.path, &claim.path, context)
                    .is_some()
        });
        if authorized {
            retained.push(anchor);
        } else {
            *failed = true;
            push_report_finding(
                findings,
                budget,
                policy_stage_finding(
                    harness,
                    "scan.receipt_policy_failed",
                    "verify the compiled receipt-anchor policy",
                ),
            )?;
        }
    }
    Ok(retained)
}

fn root_matches_claim(
    harness: &HarnessId,
    root: &ObservedRoot,
    claim: &RootAuthority,
    context: &RootContext<'_>,
    line: Option<kitrove_adapter_api::PolicyLine>,
) -> bool {
    let Some(index) = authority_request_index(
        harness,
        root.scope,
        &root.path,
        &root.logical_id,
        claim,
        context,
    ) else {
        return false;
    };
    claim.scopes.contains(&root.scope)
        && claim.tier == root.tier
        && authority_rank_matches(claim.rank, root.policy_rank, index)
        && authority_evidence_matches(harness, &claim.evidence, &root.evidence, context)
        && line.is_none_or(|line| claim.layouts.get(&line) == Some(&root.enabled_layouts))
}

fn related_root_matches_claim(
    harness: &HarnessId,
    root: &RelatedRoot,
    claim: &RootAuthority,
    context: &RootContext<'_>,
) -> bool {
    let Some(index) = authority_request_index(
        harness,
        root.scope,
        &root.path,
        &root.logical_id,
        claim,
        context,
    ) else {
        return false;
    };
    claim.scopes.contains(&root.scope)
        && claim.tier == root.tier
        && authority_rank_matches(claim.rank, root.policy_rank, index)
        && authority_evidence_matches(harness, &claim.evidence, &root.evidence, context)
}

fn authority_request_index(
    harness: &HarnessId,
    scope: HarnessScope,
    path: &Path,
    logical_id: &RootId,
    claim: &RootAuthority,
    context: &RootContext<'_>,
) -> Option<usize> {
    if matches!(claim.path, RootPathAuthority::ExplicitFileRequest) {
        return context
            .explicit_roots
            .iter()
            .enumerate()
            .find(|(index, explicit)| {
                &explicit.harness == harness
                    && explicit.scope == scope
                    && explicit.path.parent() == Some(path)
                    && authority_logical_id_matches(&claim.logical_id, logical_id, *index, context)
            })
            .map(|(index, _)| index);
    }

    let index = authority_path_index(harness, scope, path, &claim.path, context)?;
    authority_logical_id_matches(&claim.logical_id, logical_id, index, context).then_some(index)
}

fn authority_path_index(
    harness: &HarnessId,
    scope: HarnessScope,
    path: &Path,
    claim: &RootPathAuthority,
    context: &RootContext<'_>,
) -> Option<usize> {
    match claim {
        RootPathAuthority::Exact(expected) => (path == expected).then_some(0),
        RootPathAuthority::HomeRelative(relative) => context
            .home
            .filter(|home| path == home.join(relative))
            .map(|_| 0),
        RootPathAuthority::WorkingRelative(relative) => {
            (path == context.working_directory.join(relative)).then_some(0)
        }
        RootPathAuthority::ProjectAncestorRelative {
            relative,
            root_to_current,
            ascend_without_repository,
        } => project_ancestors(context, *root_to_current, *ascend_without_repository)
            .into_iter()
            .position(|anchor| path == anchor.join(relative)),
        RootPathAuthority::WorkingDescendant {
            suffix,
            include_working_root,
        } => {
            let anchor = context.working_directory.join(suffix);
            (path.starts_with(context.working_directory)
                && path.ends_with(suffix)
                && (*include_working_root || path != anchor))
                .then_some(0)
        }
        RootPathAuthority::SuppliedNative(key) => context
            .supplied_native_roots
            .iter()
            .enumerate()
            .find(|(_, supplied)| {
                supplied.harness() == harness
                    && supplied.scope() == scope
                    && supplied.source_key() == key
                    && supplied.path() == path
            })
            .map(|(index, _)| index),
        RootPathAuthority::ExplicitDirectory => context
            .explicit_roots
            .iter()
            .enumerate()
            .find(|(_, explicit)| {
                &explicit.harness == harness && explicit.scope == scope && explicit.path == path
            })
            .map(|(index, _)| index),
        RootPathAuthority::ExplicitFileRequest => None,
    }
}

fn project_ancestors(
    context: &RootContext<'_>,
    root_to_current: bool,
    ascend_without_repository: bool,
) -> Vec<PathBuf> {
    let mut anchors = match context.project_boundary {
        kitrove_adapter_api::ProjectBoundary::Repository { root }
            if context.working_directory.starts_with(root) =>
        {
            let mut anchors = Vec::new();
            let mut current = context.working_directory;
            loop {
                anchors.push(current.to_path_buf());
                if current == root {
                    break;
                }
                let Some(parent) = current.parent() else {
                    return vec![];
                };
                current = parent;
            }
            anchors
        }
        kitrove_adapter_api::ProjectBoundary::Repository { .. } => vec![],
        kitrove_adapter_api::ProjectBoundary::NoRepository if ascend_without_repository => context
            .working_directory
            .ancestors()
            .map(Path::to_path_buf)
            .collect(),
        kitrove_adapter_api::ProjectBoundary::NoRepository => {
            vec![context.working_directory.to_path_buf()]
        }
        kitrove_adapter_api::ProjectBoundary::UnsafeStop => {
            vec![context.working_directory.to_path_buf()]
        }
    };
    if root_to_current {
        anchors.reverse();
    }
    anchors
}

fn authority_rank_matches(claim: RootRankAuthority, actual: u32, index: usize) -> bool {
    match claim {
        RootRankAuthority::Exact(expected) => actual == expected,
        RootRankAuthority::Indexed { base } => {
            u32::try_from(index)
                .ok()
                .and_then(|index| base.checked_add(index))
                == Some(actual)
        }
    }
}

fn authority_logical_id_matches(
    claim: &RootIdAuthority,
    actual: &RootId,
    index: usize,
    context: &RootContext<'_>,
) -> bool {
    match claim {
        RootIdAuthority::Exact(expected) => actual == expected,
        RootIdAuthority::Prefix(prefix) => actual
            .as_str()
            .strip_prefix(prefix)
            .is_some_and(|tail| !tail.is_empty()),
        RootIdAuthority::IndexedPrefix(prefix) => actual.as_str() == format!("{prefix}{index:04}"),
        RootIdAuthority::IndexedPrefixWithSuffixes { prefix, suffixes } => suffixes
            .iter()
            .any(|suffix| actual.as_str() == format!("{prefix}{index:04}.{suffix}")),
        RootIdAuthority::IndexedPrefixWithEncodedFile(prefix) => context
            .explicit_roots
            .get(index)
            .and_then(|explicit| explicit.path.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                actual.as_str() == format!("{prefix}{index:04}.{}", encode_hex(name.as_bytes()))
            }),
    }
}

fn authority_evidence_matches(
    harness: &HarnessId,
    claim: &RootEvidenceAuthority,
    actual: &kitrove_adapter_api::EvidenceRef,
    context: &RootContext<'_>,
) -> bool {
    match claim {
        RootEvidenceAuthority::Exact(expected) => actual == expected,
        RootEvidenceAuthority::ProjectTrust { fallback } => {
            let anchor = match context.project_boundary {
                kitrove_adapter_api::ProjectBoundary::Repository { root }
                    if context.working_directory.starts_with(root) =>
                {
                    root
                }
                kitrove_adapter_api::ProjectBoundary::Repository { .. } => return false,
                kitrove_adapter_api::ProjectBoundary::NoRepository
                | kitrove_adapter_api::ProjectBoundary::UnsafeStop => context.working_directory,
            };
            context
                .project_trust
                .iter()
                .find(|(key, _)| &key.harness == harness && key.project_anchor == anchor)
                .map_or(actual == fallback, |(_, trust)| match trust {
                    ProjectTrustObservation::Trusted { evidence }
                    | ProjectTrustObservation::Declined { evidence } => actual == evidence,
                    ProjectTrustObservation::Unknown => actual == fallback,
                })
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn root_authority_finding(root: RootId) -> ScanFinding {
    ScanFinding::new(
        "scan.policy_root_conflict",
        FindingSeverity::Attention,
        FindingSubject::Root(root),
        vec![],
        "verify the compiled root catalog before scanning this location",
    )
}

#[derive(Default)]
struct DuplicateAnnotation {
    shadowed_by: Option<ObservationId>,
    findings: Vec<ScanFinding>,
    ambiguous: bool,
}

fn apply_duplicate_decisions(
    policy: &dyn HarnessObservationPolicy,
    profile: &PolicyProfile,
    observations: &[ObservedCandidate],
    annotations: &mut BTreeMap<ObservationId, DuplicateAnnotation>,
    budget: &mut ScanBudget,
) -> AdapterResult<()> {
    let mut groups = BTreeMap::<String, Vec<CandidateSummary>>::new();
    for observation in observations {
        let ObservedCandidate::Accepted(candidate) = observation else {
            continue;
        };
        let location = candidate.location();
        let native_id = candidate
            .decision()
            .native_id()
            .expect("accepted candidate decisions always include native identity");
        let source_relative_path = location
            .source_relative_path
            .as_ref()
            .expect("accepted observations have a safe source-relative path");
        groups
            .entry(native_id.to_owned())
            .or_default()
            .push(CandidateSummary {
                observation_id: candidate.observation_id().clone(),
                scope: location.scope,
                root_tier: location.root_tier,
                logical_root: location.logical_root.clone(),
                policy_rank: location.policy_rank,
                source_relative_path: source_relative_path.as_str().to_owned(),
                layout: location.layout,
                native_id: native_id.to_owned(),
                exact_source_hash: candidate.captured().exact_source_hash.clone(),
            });
    }

    for group in groups.values_mut().filter(|group| group.len() > 1) {
        group.sort_by(candidate_summary_order);
        match policy.resolve_duplicates(group, profile) {
            Ok(DuplicateDecision::Coexist) => {}
            Ok(DuplicateDecision::Winner {
                observation_id,
                reason,
            }) => {
                if !group
                    .iter()
                    .any(|candidate| candidate.observation_id == observation_id)
                {
                    localize_duplicate_failure(
                        group,
                        annotations,
                        profile,
                        "scan.duplicate_winner_invalid",
                        budget,
                    )?;
                    continue;
                }
                for shadow in group
                    .iter()
                    .filter(|candidate| candidate.observation_id != observation_id)
                {
                    let annotation = annotations
                        .entry(shadow.observation_id.clone())
                        .or_default();
                    annotation.shadowed_by = Some(observation_id.clone());
                    if !budget.reserve_report_findings(1) {
                        return Err(report_budget_error());
                    }
                    annotation.findings.push(ScanFinding::new(
                        "scan.candidate_shadowed",
                        FindingSeverity::Informational,
                        FindingSubject::Observation(shadow.observation_id.clone()),
                        vec![reason.clone()],
                        "use the documented effective candidate or choose a unique native identity",
                    ));
                }
            }
            Ok(DuplicateDecision::Ambiguous { reason }) => {
                let mut reasons = vec![reason];
                normalize_findings(&mut reasons);
                let reason = reasons.pop().expect("one duplicate reason is retained");
                for candidate in group.iter() {
                    let annotation = annotations
                        .entry(candidate.observation_id.clone())
                        .or_default();
                    annotation.ambiguous = true;
                    if !budget.reserve_report_findings(1) {
                        return Err(report_budget_error());
                    }
                    let mut candidate_reason = reason.clone();
                    candidate_reason.subject =
                        FindingSubject::Observation(candidate.observation_id.clone());
                    annotation.findings.push(candidate_reason);
                }
            }
            Err(_) => localize_duplicate_failure(
                group,
                annotations,
                profile,
                "scan.duplicate_policy_failed",
                budget,
            )?,
        }
    }
    for annotation in annotations.values_mut() {
        normalize_findings(&mut annotation.findings);
    }
    Ok(())
}

fn mark_ambiguous_agent_names(
    entries: &mut [AgentScanEntry],
    budget: &mut ScanBudget,
) -> AdapterResult<BTreeSet<ContentHash>> {
    let mut groups = BTreeMap::<(HarnessId, HarnessScope, RootId, String), Vec<usize>>::new();
    let mut ambiguous = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let (Some(logical_root), Some(_)) = (&entry.logical_root, &entry.observation_id) else {
            continue;
        };
        groups
            .entry((
                entry.harness.clone(),
                entry.scope,
                logical_root.clone(),
                entry.name.as_str().to_owned(),
            ))
            .or_default()
            .push(index);
    }

    for indexes in groups.values().filter(|indexes| indexes.len() > 1) {
        for &index in indexes {
            if !budget.reserve_report_findings(1) {
                return Err(report_budget_error());
            }
            let entry = &mut entries[index];
            entry.classification = ScanClassification::ConflictingDuplicate;
            ambiguous.insert(
                entry
                    .observation_id
                    .clone()
                    .expect("ambiguity groups contain only observed agents"),
            );
            let subject = FindingSubject::Related {
                logical_root: entry
                    .logical_root
                    .clone()
                    .expect("ambiguity groups contain only observed agents"),
                source_relative_path: SourceRelativePath::parse(
                    entry
                        .source_relative_path
                        .clone()
                        .expect("ambiguity groups contain only observed agents"),
                )
                .expect("agent discovery retains validated UTF-8 relative paths"),
            };
            let evidence = entry
                .findings
                .first()
                .map_or_else(Vec::new, |finding| finding.evidence.clone());
            entry.findings.push(ScanFinding::new(
                "scan.agent_name_ambiguous",
                FindingSeverity::Attention,
                subject,
                evidence,
                "choose one uniquely named agent within this authority root",
            ));
        }
    }
    Ok(ambiguous)
}

fn localize_duplicate_failure(
    group: &[CandidateSummary],
    annotations: &mut BTreeMap<ObservationId, DuplicateAnnotation>,
    profile: &PolicyProfile,
    code: &'static str,
    budget: &mut ScanBudget,
) -> AdapterResult<()> {
    for candidate in group {
        let annotation = annotations
            .entry(candidate.observation_id.clone())
            .or_default();
        annotation.ambiguous = true;
        if !budget.reserve_report_findings(1) {
            return Err(report_budget_error());
        }
        annotation.findings.push(ScanFinding::new(
            code,
            FindingSeverity::Attention,
            FindingSubject::Observation(candidate.observation_id.clone()),
            vec![profile.evidence().clone()],
            "choose a unique candidate after verifying the compiled duplicate policy",
        ));
    }
    Ok(())
}

fn candidate_summary_order(
    left: &CandidateSummary,
    right: &CandidateSummary,
) -> std::cmp::Ordering {
    left.scope
        .cmp(&right.scope)
        .then_with(|| left.policy_rank.cmp(&right.policy_rank))
        .then_with(|| left.logical_root.cmp(&right.logical_root))
        .then_with(|| left.source_relative_path.cmp(&right.source_relative_path))
        .then_with(|| left.layout.cmp(&right.layout))
        .then_with(|| left.native_id.cmp(&right.native_id))
        .then_with(|| left.exact_source_hash.cmp(&right.exact_source_hash))
        .then_with(|| left.observation_id.cmp(&right.observation_id))
        .then_with(|| left.root_tier.cmp(&right.root_tier))
}

fn scope_selected(selection: ScopeSelection, scope: HarnessScope) -> bool {
    matches!(selection, ScopeSelection::All)
        || matches!(
            (selection, scope),
            (ScopeSelection::User, HarnessScope::User)
                | (ScopeSelection::Project, HarnessScope::Project)
        )
}

fn policy_stage_finding(
    harness: &HarnessId,
    code: &'static str,
    action: &'static str,
) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Harness(harness.clone()),
        vec![],
        action,
    )
}

fn report_budget_error() -> AdapterError {
    AdapterError::new(
        "scan.report_budget_exhausted",
        "the request limits cannot retain a complete trustworthy scan report",
    )
}

fn push_report_finding(
    findings: &mut Vec<ScanFinding>,
    budget: &mut ScanBudget,
    finding: ScanFinding,
) -> AdapterResult<()> {
    if !budget.reserve_report_findings(1) {
        return Err(report_budget_error());
    }
    findings.push(finding);
    Ok(())
}

fn extend_report_findings(
    findings: &mut Vec<ScanFinding>,
    budget: &mut ScanBudget,
    additions: impl IntoIterator<Item = ScanFinding>,
) -> AdapterResult<()> {
    for finding in additions {
        push_report_finding(findings, budget, finding)?;
    }
    Ok(())
}

fn capture_observation(
    policy: &dyn HarnessObservationPolicy,
    harness: &HarnessId,
    profile: &PolicyProfile,
    discovered: DiscoveredLocator,
    budget: &mut ScanBudget,
) -> ObservedCandidate {
    let location = observation_location(harness, &discovered);
    let normalized_destination = normalize_destination_path(&discovered.locator.absolute_path);
    if location.source_relative_path.is_none() {
        return invalid_location_failure(location, &discovered.root, normalized_destination);
    }
    let remaining = budget.remaining_capture_limits();
    if remaining.max_files == 0 || remaining.max_total_bytes == 0 {
        return budget_failure(location, &discovered.root, normalized_destination);
    }
    let source = match discovered.locator.layout {
        SkillSourceLayout::Directory => SkillSource::Directory {
            path: discovered.locator.absolute_path.clone(),
        },
        SkillSourceLayout::Standalone => SkillSource::Standalone {
            path: discovered.locator.absolute_path.clone(),
        },
    };
    let result = capture_skill_source_with_meter(&source, remaining, budget);

    let captured = match result {
        Ok(captured) => captured,
        Err(error) => {
            let observation_id = observation_id(&location, None, None)
                .expect("capture starts only after source-relative path validation");
            let subject = FindingSubject::Observation(observation_id.clone());
            let findings = vec![
                ScanFinding::new(
                    "scan.candidate_invalid",
                    FindingSeverity::Attention,
                    subject.clone(),
                    vec![discovered.root.evidence.clone()],
                    "correct the candidate source and scan again",
                ),
                ScanFinding::new(
                    error.code(),
                    FindingSeverity::Attention,
                    subject,
                    vec![discovered.root.evidence.clone()],
                    "correct the candidate source and scan again",
                ),
            ];
            return ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
                observation_id: Some(observation_id),
                location,
                native_id: None,
                exact_source_hash: None,
                failure_code: error.code().to_owned(),
                findings,
                normalized_destination,
            }));
        }
    };

    // Native policy is intentionally unreachable until generic capture has succeeded.
    let decision =
        match policy.decide_candidate(&captured, &discovered.locator, &discovered.root, profile) {
            Ok(decision) => decision,
            Err(_) => {
                let exact_source_hash = captured.exact_source_hash.clone();
                let observation_id = observation_id(&location, None, Some(&exact_source_hash))
                    .expect("capture starts only after source-relative path validation");
                let finding = ScanFinding::new(
                    "scan.candidate_policy_failed",
                    FindingSeverity::Attention,
                    FindingSubject::Observation(observation_id.clone()),
                    vec![discovered.root.evidence.clone()],
                    "verify the compiled candidate policy and scan again",
                );
                return ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
                    observation_id: Some(observation_id),
                    location,
                    native_id: None,
                    exact_source_hash: Some(exact_source_hash),
                    failure_code: "scan.candidate_policy_failed".to_owned(),
                    findings: vec![finding],
                    normalized_destination,
                }));
            }
        };
    if decision.findings().len() > budget.remaining_report_findings() {
        let exact_source_hash = captured.exact_source_hash.clone();
        let observation_id = observation_id(&location, None, Some(&exact_source_hash))
            .expect("capture starts only after source-relative path validation");
        let finding = ScanFinding::new(
            "scan.candidate_policy_output_exhausted",
            FindingSeverity::Attention,
            FindingSubject::Observation(observation_id.clone()),
            vec![discovered.root.evidence.clone()],
            "reduce candidate policy findings or increase the request finding limit",
        );
        return ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
            observation_id: Some(observation_id),
            location,
            native_id: None,
            exact_source_hash: Some(exact_source_hash),
            failure_code: "scan.candidate_policy_output_exhausted".to_owned(),
            findings: vec![finding],
            normalized_destination,
        }));
    }
    let decision = normalize_candidate_decision(decision);
    let native_id = decision.native_id().map(str::to_owned);
    let exact_source_hash = captured.exact_source_hash.clone();
    let id = observation_id(&location, decision.native_id(), Some(&exact_source_hash))
        .expect("capture starts only after source-relative path validation");
    let decision = CandidateDecision::new(
        decision.acceptance(),
        decision.native_id().map(str::to_owned),
        decision.portable().clone(),
        rebind_candidate_findings(decision.findings(), &id),
    )
    .expect("rebinding findings preserves validated candidate decision invariants");
    if decision.acceptance() == NativeAcceptance::Accepted {
        let portable_hash = match candidate_portable_hash(&captured, &decision) {
            Ok(hash) => hash,
            Err(error) => {
                let mut findings = decision.findings().to_vec();
                findings.push(ScanFinding::new(
                    error.code(),
                    FindingSeverity::Attention,
                    FindingSubject::Observation(id.clone()),
                    vec![discovered.root.evidence.clone()],
                    "correct the adapter projection decision and scan again",
                ));
                return ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
                    observation_id: Some(id),
                    location,
                    native_id,
                    exact_source_hash: Some(exact_source_hash),
                    failure_code: error.code().to_owned(),
                    findings,
                    normalized_destination,
                }));
            }
        };
        ObservedCandidate::Accepted(Box::new(AcceptedObservedCandidate {
            observation_id: id,
            location,
            captured,
            portable_hash,
            decision,
            normalized_destination,
        }))
    } else {
        let mut findings = decision.findings().to_vec();
        if findings.is_empty() {
            findings.push(ScanFinding::new(
                "scan.candidate_invalid",
                FindingSeverity::Attention,
                FindingSubject::Observation(id.clone()),
                vec![discovered.root.evidence.clone()],
                "correct the candidate source and scan again",
            ));
        }
        ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
            observation_id: Some(id),
            location,
            native_id,
            exact_source_hash: Some(exact_source_hash),
            failure_code: "scan.candidate_invalid".to_owned(),
            findings,
            normalized_destination,
        }))
    }
}

fn candidate_portable_hash(
    captured: &CapturedSkillSource,
    decision: &CandidateDecision,
) -> Result<Option<ContentHash>, kitrove_agent_skills::SkillError> {
    let kitrove_adapter_api::PortablePolicyDecision::Project {
        name,
        description,
        reasons,
    } = decision.portable()
    else {
        return Ok(None);
    };
    match project_skill_source(captured, name.clone(), description.clone(), reasons.clone())? {
        PortableProjection::Available { tree, .. } => Ok(Some(tree.hash)),
        PortableProjection::Unavailable { .. } => Ok(None),
    }
}

fn failed_locator_observation(harness: &HarnessId, failed: FailedLocator) -> ObservedCandidate {
    let discovered = DiscoveredLocator {
        locator: failed.locator,
        root: failed.root,
    };
    let normalized_destination = normalize_destination_path(&discovered.locator.absolute_path);
    let location = observation_location(harness, &discovered);
    let id = observation_id(&location, None, None);
    let mut finding = failed.finding;
    if let Some(id) = &id {
        finding.subject = FindingSubject::Observation(id.clone());
    }
    ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
        observation_id: id,
        location,
        native_id: None,
        exact_source_hash: None,
        failure_code: finding.code.to_owned(),
        findings: vec![finding],
        normalized_destination,
    }))
}

fn rebind_candidate_findings(
    findings: &[ScanFinding],
    observation_id: &ObservationId,
) -> Vec<ScanFinding> {
    findings
        .iter()
        .cloned()
        .map(|mut finding| {
            finding.subject = FindingSubject::Observation(observation_id.clone());
            finding
        })
        .collect()
}

fn failed_root_observation(harness: &HarnessId, failed: FailedRoot) -> ObservedCandidate {
    let location = ObservationLocation {
        harness: harness.clone(),
        scope: failed.root.scope,
        root_tier: failed.root.tier,
        logical_root: failed.root.logical_id,
        policy_rank: failed.root.policy_rank,
        source_relative_path: None,
        layout: SkillSourceLayout::Directory,
        original_document_name: None,
    };
    ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
        observation_id: None,
        location,
        native_id: None,
        exact_source_hash: None,
        failure_code: failed.finding.code.to_owned(),
        findings: vec![failed.finding],
        normalized_destination: None,
    }))
}

fn budget_failure(
    location: ObservationLocation,
    root: &kitrove_adapter_api::ObservedRoot,
    normalized_destination: Option<NormalizedDestination>,
) -> ObservedCandidate {
    let observation_id = observation_id(&location, None, None);
    let subject = observation_id.as_ref().map_or_else(
        || FindingSubject::Root(root.logical_id.clone()),
        |id| FindingSubject::Observation(id.clone()),
    );
    let finding = ScanFinding::new(
        "scan.capture_budget_exhausted",
        FindingSeverity::Attention,
        subject,
        vec![root.evidence.clone()],
        "reduce capture work or increase request capture capacity",
    );
    ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
        observation_id,
        location,
        native_id: None,
        exact_source_hash: None,
        failure_code: "scan.capture_budget_exhausted".to_owned(),
        findings: vec![finding],
        normalized_destination,
    }))
}

fn invalid_location_failure(
    location: ObservationLocation,
    root: &kitrove_adapter_api::ObservedRoot,
    normalized_destination: Option<NormalizedDestination>,
) -> ObservedCandidate {
    let finding = ScanFinding::new(
        "scan.discovery_unsafe_path",
        FindingSeverity::Attention,
        FindingSubject::Root(root.logical_id.clone()),
        vec![root.evidence.clone()],
        "rename the candidate using a portable source-relative path",
    );
    ObservedCandidate::Failed(Box::new(FailedObservedCandidate {
        observation_id: None,
        location,
        native_id: None,
        exact_source_hash: None,
        failure_code: "scan.discovery_unsafe_path".to_owned(),
        findings: vec![finding],
        normalized_destination,
    }))
}

fn observation_location(
    harness: &HarnessId,
    discovered: &DiscoveredLocator,
) -> ObservationLocation {
    let source_relative_path =
        SourceRelativePath::parse(discovered.locator.source_relative_path.clone()).ok();
    let original_document_name = source_relative_path
        .as_ref()
        .map(|_| discovered.locator.original_document_name.clone());
    ObservationLocation {
        harness: harness.clone(),
        scope: discovered.root.scope,
        root_tier: discovered.root.tier,
        logical_root: discovered.root.logical_id.clone(),
        policy_rank: discovered.root.policy_rank,
        source_relative_path,
        layout: discovered.locator.layout,
        original_document_name,
    }
}

fn observation_id(
    location: &ObservationLocation,
    native_id: Option<&str>,
    exact_source_hash: Option<&ContentHash>,
) -> Option<ObservationId> {
    let source_relative_path = location.source_relative_path.as_ref()?;
    let original_document_name = location.original_document_name.as_deref()?;
    Some(ObservationId::from_identity(&ObservationIdentity {
        harness: &location.harness,
        scope: location.scope,
        root_tier: location.root_tier,
        policy_rank: location.policy_rank,
        logical_root: &location.logical_root,
        source_relative_path,
        layout: location.layout,
        original_document_name,
        native_id,
        exact_source_hash,
    }))
}

fn entry_from_observation(
    observation: &ObservedCandidate,
    duplicate: Option<&DuplicateAnnotation>,
) -> ScanEntry {
    let location = observation.location();
    match observation {
        ObservedCandidate::Accepted(candidate) => ScanEntry {
            observation_id: Some(candidate.observation_id.clone()),
            harness: location.harness.clone(),
            scope: location.scope,
            root_tier: Some(location.root_tier),
            logical_root: Some(location.logical_root.clone()),
            policy_rank: Some(location.policy_rank),
            source_relative_path: location
                .source_relative_path
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            layout: Some(location.layout),
            native_id: candidate.decision.native_id().map(str::to_owned),
            asset_id: None,
            receipt_id: None,
            normalized_destination: None,
            receipt_rendered_hash: None,
            classification: ScanClassification::Unmanaged,
            exact_source_hash: Some(candidate.captured.exact_source_hash.clone()),
            portable_hash: candidate.portable_hash.clone(),
            shadowed_by: duplicate.and_then(|annotation| annotation.shadowed_by.clone()),
            findings: normalized_findings(
                &candidate
                    .decision
                    .findings()
                    .iter()
                    .cloned()
                    .chain(
                        duplicate
                            .into_iter()
                            .flat_map(|annotation| annotation.findings.iter().cloned()),
                    )
                    .collect::<Vec<_>>(),
            ),
        },
        ObservedCandidate::Failed(candidate) => ScanEntry {
            observation_id: candidate.observation_id.clone(),
            harness: location.harness.clone(),
            scope: location.scope,
            root_tier: Some(location.root_tier),
            logical_root: Some(location.logical_root.clone()),
            policy_rank: Some(location.policy_rank),
            source_relative_path: location
                .source_relative_path
                .as_ref()
                .map(|path| path.as_str().to_owned()),
            layout: Some(location.layout),
            native_id: candidate.native_id.clone(),
            asset_id: None,
            receipt_id: None,
            normalized_destination: None,
            receipt_rendered_hash: None,
            classification: ScanClassification::Unknown,
            exact_source_hash: candidate.exact_source_hash.clone(),
            portable_hash: None,
            shadowed_by: None,
            findings: normalized_findings(&candidate.findings),
        },
    }
}

fn observation_order(left: &ObservedCandidate, right: &ObservedCandidate) -> std::cmp::Ordering {
    let left_location = left.location();
    let right_location = right.location();
    left_location
        .harness
        .cmp(&right_location.harness)
        .then_with(|| left_location.scope.cmp(&right_location.scope))
        .then_with(|| left_location.root_tier.cmp(&right_location.root_tier))
        .then_with(|| left_location.logical_root.cmp(&right_location.logical_root))
        .then_with(|| left_location.policy_rank.cmp(&right_location.policy_rank))
        .then_with(|| {
            match (
                &left_location.source_relative_path,
                &right_location.source_relative_path,
            ) {
                (Some(left), Some(right)) => left.cmp(right),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        })
        .then_with(|| left_location.layout.cmp(&right_location.layout))
        .then_with(|| {
            compare_optional(
                left_location.original_document_name.as_deref(),
                right_location.original_document_name.as_deref(),
            )
        })
        .then_with(|| compare_optional(observation_native_id(left), observation_native_id(right)))
        .then_with(|| {
            compare_optional(
                observation_exact_source_hash(left),
                observation_exact_source_hash(right),
            )
        })
        .then_with(|| observation_classification(left).cmp(&observation_classification(right)))
        .then_with(|| compare_findings(observation_findings(left), observation_findings(right)))
        .then_with(|| compare_optional(left.observation_id(), right.observation_id()))
}

fn finding_order(left: &ScanFinding, right: &ScanFinding) -> std::cmp::Ordering {
    left.severity
        .cmp(&right.severity)
        .then_with(|| left.code.cmp(right.code))
        .then_with(|| finding_subject_key(&left.subject).cmp(&finding_subject_key(&right.subject)))
        .then_with(|| left.evidence.cmp(&right.evidence))
        .then_with(|| left.action.cmp(right.action))
}

fn compare_findings(left: &[ScanFinding], right: &[ScanFinding]) -> std::cmp::Ordering {
    left.iter()
        .zip(right)
        .map(|(left, right)| finding_order(left, right))
        .find(|order| !order.is_eq())
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

fn normalize_candidate_decision(decision: CandidateDecision) -> CandidateDecision {
    CandidateDecision::new(
        decision.acceptance(),
        decision.native_id().map(str::to_owned),
        decision.portable().clone(),
        normalized_findings(decision.findings()),
    )
    .expect("normalizing findings preserves a valid candidate decision")
}

fn observation_native_id(observation: &ObservedCandidate) -> Option<&str> {
    match observation {
        ObservedCandidate::Accepted(candidate) => candidate.decision.native_id(),
        ObservedCandidate::Failed(candidate) => candidate.native_id.as_deref(),
    }
}

fn observation_exact_source_hash(observation: &ObservedCandidate) -> Option<&ContentHash> {
    match observation {
        ObservedCandidate::Accepted(candidate) => Some(&candidate.captured.exact_source_hash),
        ObservedCandidate::Failed(candidate) => candidate.exact_source_hash.as_ref(),
    }
}

fn observation_classification(observation: &ObservedCandidate) -> ScanClassification {
    match observation {
        ObservedCandidate::Accepted(_) => ScanClassification::Unmanaged,
        ObservedCandidate::Failed(_) => ScanClassification::Unknown,
    }
}

fn observation_findings(observation: &ObservedCandidate) -> &[ScanFinding] {
    match observation {
        ObservedCandidate::Accepted(candidate) => candidate.decision.findings(),
        ObservedCandidate::Failed(candidate) => &candidate.findings,
    }
}

fn compare_optional<T: Ord + ?Sized>(left: Option<&T>, right: Option<&T>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn finding_subject_key(subject: &FindingSubject) -> (u8, String, String, String) {
    match subject {
        FindingSubject::Report => (0, String::new(), String::new(), String::new()),
        FindingSubject::Harness(harness) => {
            (1, harness.as_str().to_owned(), String::new(), String::new())
        }
        FindingSubject::Root(root) => (2, root.as_str().to_owned(), String::new(), String::new()),
        FindingSubject::Observation(observation) => (
            3,
            observation.as_str().to_owned(),
            String::new(),
            String::new(),
        ),
        FindingSubject::Receipt(receipt) => {
            (4, receipt.as_str().to_owned(), String::new(), String::new())
        }
        FindingSubject::Destination {
            harness,
            scope,
            normalized_destination,
        } => (
            5,
            harness.as_str().to_owned(),
            scope.as_str().to_owned(),
            normalized_destination.as_str().to_owned(),
        ),
        FindingSubject::Related {
            logical_root,
            source_relative_path,
        } => (
            6,
            logical_root.as_str().to_owned(),
            source_relative_path.as_str().to_owned(),
            String::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kitrove_adapter_api::{EvidenceRef, ProjectBoundary, ProjectTrustKey, ScanLimits};

    #[test]
    fn unsafe_stop_never_uses_no_repository_ancestor_authority() {
        let working = PathBuf::from("/workspace/deep/project");
        let limits = ScanLimits::default();
        let trust = BTreeMap::new();
        let explicit = Vec::new();
        let supplied = Vec::new();

        let no_repository = ProjectBoundary::NoRepository;
        let no_repository_context = RootContext {
            home: None,
            working_directory: &working,
            project_boundary: &no_repository,
            scopes: ScopeSelection::Project,
            explicit_roots: &explicit,
            supplied_native_roots: &supplied,
            project_trust: &trust,
            limits: &limits,
        };
        assert_eq!(
            project_ancestors(&no_repository_context, false, true),
            working
                .ancestors()
                .map(Path::to_path_buf)
                .collect::<Vec<_>>()
        );

        let unsafe_stop = ProjectBoundary::UnsafeStop;
        let unsafe_stop_context = RootContext {
            project_boundary: &unsafe_stop,
            ..no_repository_context
        };
        assert_eq!(
            project_ancestors(&unsafe_stop_context, false, true),
            vec![working]
        );
    }

    #[test]
    fn absence_and_unsafe_stop_use_only_working_directory_project_trust() {
        let working = PathBuf::from("/workspace/deep/project");
        let outer = PathBuf::from("/workspace");
        let limits = ScanLimits::default();
        let explicit = Vec::new();
        let supplied = Vec::new();
        let fallback = EvidenceRef::parse("test.project-trust.fallback").unwrap();
        let outer_evidence = EvidenceRef::parse("test.project-trust.outer").unwrap();
        let working_evidence = EvidenceRef::parse("test.project-trust.working").unwrap();
        let claim = RootEvidenceAuthority::ProjectTrust {
            fallback: fallback.clone(),
        };
        let outer_trust = BTreeMap::from([(
            ProjectTrustKey {
                harness: HarnessId::Pi,
                project_anchor: outer,
            },
            ProjectTrustObservation::Trusted {
                evidence: outer_evidence.clone(),
            },
        )]);
        let working_trust = BTreeMap::from([(
            ProjectTrustKey {
                harness: HarnessId::Pi,
                project_anchor: working.clone(),
            },
            ProjectTrustObservation::Trusted {
                evidence: working_evidence.clone(),
            },
        )]);

        for boundary in [ProjectBoundary::NoRepository, ProjectBoundary::UnsafeStop] {
            let outer_context = RootContext {
                home: None,
                working_directory: &working,
                project_boundary: &boundary,
                scopes: ScopeSelection::Project,
                explicit_roots: &explicit,
                supplied_native_roots: &supplied,
                project_trust: &outer_trust,
                limits: &limits,
            };
            assert!(!authority_evidence_matches(
                &HarnessId::Pi,
                &claim,
                &outer_evidence,
                &outer_context
            ));
            assert!(authority_evidence_matches(
                &HarnessId::Pi,
                &claim,
                &fallback,
                &outer_context
            ));

            let working_context = RootContext {
                project_trust: &working_trust,
                ..outer_context
            };
            assert!(authority_evidence_matches(
                &HarnessId::Pi,
                &claim,
                &working_evidence,
                &working_context
            ));
            assert!(!authority_evidence_matches(
                &HarnessId::Pi,
                &claim,
                &fallback,
                &working_context
            ));
        }
    }
}
