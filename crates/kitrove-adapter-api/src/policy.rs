use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;

use kitrove_agent_skills::{CapturedSkillSource, DirectoryWalkMeter, SkillSourceLayout};
use kitrove_model::{AssetId, AssetKind, ContentHash, FidelityReason, HarnessId, HarnessScope};
use serde::{Deserialize, Serialize};

use crate::version::PolicyLine;
use crate::{
    AdapterError, AdapterResult, EvidenceRef, ObservationId, PolicyRuntimeAuthority, RootContext,
    RootId, ScanFinding, ScanLimits, VersionObservation, VersionObservationOwned,
};

/// Transient harness-native source tier for an observed root.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootTier {
    User,
    Project,
    Admin,
    System,
    Compatibility,
    Explicit,
}

impl RootTier {
    /// Returns the stable root-tier tag used by observation identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Admin => "admin",
            Self::System => "system",
            Self::Compatibility => "compatibility",
            Self::Explicit => "explicit",
        }
    }
}

/// One bounded source root selected by compiled adapter policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRoot {
    pub logical_id: RootId,
    pub path: PathBuf,
    pub scope: HarnessScope,
    pub tier: RootTier,
    pub policy_rank: u32,
    pub enabled_layouts: BTreeSet<SkillSourceLayout>,
    pub evidence: EvidenceRef,
}

/// Version-bound compiled policy profile used throughout one harness scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyProfile {
    harness: HarnessId,
    line: PolicyLine,
    version: VersionObservationOwned,
    evidence: EvidenceRef,
}

impl PolicyProfile {
    /// Creates a profile whose harness, selected line, and verified evidence agree.
    pub fn new(
        harness: HarnessId,
        line: PolicyLine,
        version: VersionObservationOwned,
        evidence: EvidenceRef,
    ) -> Result<Self, AdapterError> {
        if line.harness() != harness
            || matches!(
                &version,
                VersionObservationOwned::Verified { policy_line, .. } if *policy_line != line
            )
        {
            return Err(AdapterError::new(
                "adapter.version_policy_mismatch",
                "policy profile harness, line, and verified version evidence must agree",
            ));
        }
        Ok(Self {
            harness,
            line,
            version,
            evidence,
        })
    }

    #[must_use]
    pub fn harness(&self) -> &HarnessId {
        &self.harness
    }

    #[must_use]
    pub const fn line(&self) -> PolicyLine {
        self.line
    }

    #[must_use]
    pub fn version(&self) -> &VersionObservationOwned {
        &self.version
    }

    #[must_use]
    pub fn evidence(&self) -> &EvidenceRef {
        &self.evidence
    }
}

/// Safe location metadata produced before candidate content is opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateLocator {
    pub absolute_path: PathBuf,
    pub source_relative_path: String,
    pub layout: SkillSourceLayout,
    pub original_document_name: String,
}

/// Pre-capture policy decision for one safe candidate locator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocatorDecision {
    Capture,
    CaptureIfFrontmatterPrefix,
    Unsupported { finding: ScanFinding },
    Ignore,
}

/// Whether a captured candidate is valid under native harness policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAcceptance {
    Accepted,
    Rejected,
}

/// Portable projection selected by native candidate policy.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortablePolicyDecision {
    Project {
        name: AssetId,
        description: String,
        reasons: Vec<FidelityReason>,
    },
    Unavailable {
        reasons: Vec<FidelityReason>,
    },
}

impl Debug for PortablePolicyDecision {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let (variant, reason_count) = match self {
            Self::Project { reasons, .. } => ("Project", reasons.len()),
            Self::Unavailable { reasons } => ("Unavailable", reasons.len()),
        };
        formatter
            .debug_struct("PortablePolicyDecision")
            .field("variant", &variant)
            .field("reason_count", &reason_count)
            .finish()
    }
}

/// Post-capture native acceptance and portable projection decision.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CandidateDecision {
    acceptance: NativeAcceptance,
    native_id: Option<String>,
    portable: PortablePolicyDecision,
    findings: Vec<ScanFinding>,
}

impl Debug for CandidateDecision {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let (portable_variant, fidelity_reason_count) = match &self.portable {
            PortablePolicyDecision::Project { reasons, .. } => ("Project", reasons.len()),
            PortablePolicyDecision::Unavailable { reasons } => ("Unavailable", reasons.len()),
        };
        let finding_codes = self
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("CandidateDecision")
            .field("acceptance", &self.acceptance)
            .field("native_id_present", &self.native_id.is_some())
            .field("portable_variant", &portable_variant)
            .field("fidelity_reason_count", &fidelity_reason_count)
            .field("finding_codes", &finding_codes)
            .finish()
    }
}

impl CandidateDecision {
    /// Creates a candidate decision while enforcing native-ID and loss invariants.
    pub fn new(
        acceptance: NativeAcceptance,
        native_id: Option<String>,
        portable: PortablePolicyDecision,
        findings: Vec<ScanFinding>,
    ) -> Result<Self, AdapterError> {
        if acceptance == NativeAcceptance::Accepted && native_id.is_none() {
            return Err(AdapterError::new(
                "adapter.native_id_required",
                "accepted candidates require a native identity",
            ));
        }
        if let Some(value) = native_id.as_deref() {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(AdapterError::new(
                    "adapter.native_id_invalid",
                    "native candidate identity must contain 1 to 256 UTF-8 bytes without control characters",
                ));
            }
        }
        if acceptance == NativeAcceptance::Rejected
            && !matches!(portable, PortablePolicyDecision::Unavailable { .. })
        {
            return Err(AdapterError::new(
                "adapter.rejected_candidate_portable",
                "rejected candidates cannot claim an available portable projection",
            ));
        }

        let reasons = match &portable {
            PortablePolicyDecision::Project { reasons, .. }
            | PortablePolicyDecision::Unavailable { reasons } => reasons,
        };
        if matches!(portable, PortablePolicyDecision::Unavailable { .. }) && reasons.is_empty() {
            return Err(AdapterError::new(
                "adapter.fidelity_reason_required",
                "an unavailable portable projection requires a structured fidelity reason",
            ));
        }
        if reasons.iter().any(|reason| reason.code.trim().is_empty()) {
            return Err(AdapterError::new(
                "adapter.fidelity_reason_invalid",
                "candidate fidelity reason codes must be non-empty",
            ));
        }

        Ok(Self {
            acceptance,
            native_id,
            portable,
            findings,
        })
    }

    #[must_use]
    pub const fn acceptance(&self) -> NativeAcceptance {
        self.acceptance
    }

    #[must_use]
    pub fn native_id(&self) -> Option<&str> {
        self.native_id.as_deref()
    }

    #[must_use]
    pub fn portable(&self) -> &PortablePolicyDecision {
        &self.portable
    }

    #[must_use]
    pub fn findings(&self) -> &[ScanFinding] {
        &self.findings
    }
}

/// Accepted-candidate identity evidence supplied to duplicate policy.
#[derive(Clone, Eq, PartialEq)]
pub struct CandidateSummary {
    pub observation_id: ObservationId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub logical_root: RootId,
    pub policy_rank: u32,
    pub source_relative_path: String,
    pub layout: SkillSourceLayout,
    pub native_id: String,
    pub exact_source_hash: ContentHash,
}

impl Debug for CandidateSummary {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateSummary")
            .field("observation_id", &self.observation_id)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("logical_root", &self.logical_root)
            .field("policy_rank", &self.policy_rank)
            .field("layout", &self.layout)
            .field("native_id_present", &true)
            .field("exact_source_hash", &self.exact_source_hash)
            .finish()
    }
}

/// Version-aware resolution of candidates sharing one harness-native identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateDecision {
    Coexist,
    Winner {
        observation_id: ObservationId,
        reason: EvidenceRef,
    },
    Ambiguous {
        reason: ScanFinding,
    },
}

/// Bounded unusual-root hook output.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RootHookReport {
    pub roots: Vec<ObservedRoot>,
    pub findings: Vec<ScanFinding>,
}

/// Refusing API-owned meter shared by unusual-root input validation and metadata-only walking.
pub trait RootHookMeter: DirectoryWalkMeter {
    fn try_root_input(&mut self) -> bool;
}

/// Standalone bounded meter used when a policy hook is exercised outside the scan engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRootHookMeter {
    max_inputs: usize,
    inputs: usize,
    max_discovery_entries: usize,
    discovery_entries: usize,
}

impl LocalRootHookMeter {
    #[must_use]
    pub const fn new(limits: &ScanLimits) -> Self {
        Self {
            max_inputs: limits.max_roots,
            inputs: 0,
            max_discovery_entries: limits.max_discovery_entries,
            discovery_entries: 0,
        }
    }
}

impl DirectoryWalkMeter for LocalRootHookMeter {
    fn try_discovery_entry(&mut self) -> bool {
        if self.discovery_entries >= self.max_discovery_entries {
            return false;
        }
        self.discovery_entries = self.discovery_entries.saturating_add(1);
        true
    }

    fn remaining_discovery_entries(&self) -> usize {
        self.max_discovery_entries
            .saturating_sub(self.discovery_entries)
    }
}

impl RootHookMeter for LocalRootHookMeter {
    fn try_root_input(&mut self) -> bool {
        if self.inputs >= self.max_inputs {
            return false;
        }
        self.inputs = self.inputs.saturating_add(1);
        true
    }
}

/// A documented native-capability source kept outside Agent Skill capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelatedRoot {
    pub logical_id: RootId,
    pub path: PathBuf,
    pub scope: HarnessScope,
    pub tier: RootTier,
    pub policy_rank: u32,
    pub kind: AssetKind,
    pub pattern: RelatedDocumentPattern,
    pub evidence: EvidenceRef,
}

/// Bounded file pattern for related native capabilities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelatedDocumentPattern {
    MarkdownDirectChildren,
    MarkdownAtAnyDepth,
    TomlDirectChildren,
    NativeExtensionAtRoot,
}

/// Compiled user/project materialization destination eligible for receipt containment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptAnchor {
    pub scope: HarnessScope,
    pub path: PathBuf,
    pub evidence: EvidenceRef,
}

/// Harness-specific policy consumed by the shared, bounded observation engine.
pub trait HarnessObservationPolicy: Send + Sync {
    fn harness(&self) -> HarnessId;
    fn runtime_authority(&self) -> PolicyRuntimeAuthority {
        PolicyRuntimeAuthority::default()
    }
    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile>;
    fn roots(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>>;

    fn discover_unusual_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        Ok(RootHookReport::default())
    }

    /// Engine entrypoint that shares one refusing meter across every selected policy hook.
    fn discover_unusual_roots_bounded(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
        _meter: &mut dyn RootHookMeter,
    ) -> AdapterResult<RootHookReport> {
        self.discover_unusual_roots(context, profile)
    }

    fn related_roots(
        &self,
        _context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        Ok(vec![])
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        profile: &PolicyProfile,
    ) -> LocatorDecision;

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision>;

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision>;

    fn receipt_anchors(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_decision_debug_omits_all_authored_projection_values() {
        const SECRET_NATIVE_ID: &str = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        const SECRET_DESCRIPTION: &str = "KITROVE_DEBUG_DESCRIPTION_CANARY_42";
        let decision = CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(SECRET_NATIVE_ID.to_owned()),
            PortablePolicyDecision::Project {
                name: AssetId::parse(SECRET_NATIVE_ID).unwrap(),
                description: SECRET_DESCRIPTION.to_owned(),
                reasons: vec![],
            },
            vec![],
        )
        .unwrap();

        assert_eq!(decision.native_id(), Some(SECRET_NATIVE_ID));
        let debug = format!("{decision:?}");
        assert!(!debug.contains(SECRET_NATIVE_ID));
        assert!(!debug.contains(SECRET_DESCRIPTION));
        assert!(debug.contains("portable_variant"));
        assert!(debug.contains("Project"));
    }

    #[test]
    fn portable_policy_debug_is_structural_for_both_variants() {
        const SECRET_NAME: &str = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        const SECRET_DESCRIPTION: &str = "KITROVE_PORTABLE_DESCRIPTION_CANARY_42";
        const SECRET_REASON: &str = "KITROVE_FIDELITY_REASON_CANARY_42";
        let reason = FidelityReason::new("test.reason", SECRET_REASON);
        let decisions = [
            PortablePolicyDecision::Project {
                name: AssetId::parse(SECRET_NAME).unwrap(),
                description: SECRET_DESCRIPTION.to_owned(),
                reasons: vec![reason.clone()],
            },
            PortablePolicyDecision::Unavailable {
                reasons: vec![reason],
            },
        ];

        for (decision, variant) in decisions.into_iter().zip(["Project", "Unavailable"]) {
            let debug = format!("{decision:?}");
            for canary in [SECRET_NAME, SECRET_DESCRIPTION, SECRET_REASON] {
                assert!(!debug.contains(canary), "{variant} leaked {canary:?}");
            }
            assert!(debug.contains(variant));
            assert!(debug.contains("reason_count"));
        }
    }

    #[test]
    fn candidate_summary_debug_omits_native_identity() {
        const SECRET_NATIVE_ID: &str = "sk-ant-api03-KITROVE_SECRET_CANARY_42";
        let logical_root = RootId::parse("test.root").unwrap();
        let source_relative_path = crate::SourceRelativePath::parse("fixture/SKILL.md").unwrap();
        let exact_source_hash = ContentHash::digest(b"fixture");
        let observation_id = ObservationId::from_identity(&crate::ObservationIdentity {
            harness: &HarnessId::Pi,
            scope: HarnessScope::User,
            root_tier: RootTier::User,
            policy_rank: 1,
            logical_root: &logical_root,
            source_relative_path: &source_relative_path,
            layout: SkillSourceLayout::Directory,
            original_document_name: "SKILL.md",
            native_id: Some(SECRET_NATIVE_ID),
            exact_source_hash: Some(&exact_source_hash),
        });
        let summary = CandidateSummary {
            observation_id,
            scope: HarnessScope::User,
            root_tier: RootTier::User,
            logical_root,
            policy_rank: 1,
            source_relative_path: source_relative_path.as_str().to_owned(),
            layout: SkillSourceLayout::Directory,
            native_id: SECRET_NATIVE_ID.to_owned(),
            exact_source_hash,
        };

        let debug = format!("{summary:?}");
        assert!(!debug.contains(SECRET_NATIVE_ID));
        assert!(debug.contains("native_id_present"));
    }
}
