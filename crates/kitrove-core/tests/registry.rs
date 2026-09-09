#![forbid(unsafe_code)]

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, HarnessObservationPolicy, LocatorDecision, NativeAcceptance, NativeRootKey,
    ObservedRoot, PolicyLine, PolicyProfile, PortablePolicyDecision, ReceiptAnchor, RootContext,
    VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::CapturedSkillSource;
use kitrove_core::{PolicyCatalog, PolicyRegistration, PolicyRegistry};
use kitrove_model::{FidelityReason, HarnessId};

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
            EvidenceRef::parse("registry.test").unwrap(),
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
                reasons: vec![FidelityReason::new(
                    "registry.unused",
                    "the registry test policy captures no candidates",
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

fn policy(harness: HarnessId, line: PolicyLine) -> Box<dyn HarnessObservationPolicy> {
    Box::new(CatalogPolicy { harness, line })
}

fn catalog(lines: &[PolicyLine], native_keys: &[&str]) -> PolicyCatalog {
    PolicyCatalog::new(
        lines.to_vec(),
        native_keys
            .iter()
            .map(|key| NativeRootKey::parse(*key).unwrap())
            .collect(),
    )
}

#[test]
fn registry_preserves_caller_order_for_distinct_policies() {
    let registry = PolicyRegistry::new(vec![
        policy(HarnessId::Pi, PolicyLine::PiLatest),
        policy(HarnessId::Claude, PolicyLine::ClaudeCurrent),
    ])
    .unwrap();

    assert_eq!(registry.harness_ids(), [HarnessId::Pi, HarnessId::Claude]);
}

#[test]
fn registry_rejects_duplicate_harnesses() {
    let error = PolicyRegistry::new(vec![
        policy(HarnessId::Claude, PolicyLine::ClaudeCurrent),
        policy(HarnessId::Claude, PolicyLine::ClaudeCurrent),
    ])
    .err()
    .unwrap();

    assert_eq!(error.code, "scan.registry_duplicate_harness");
}

#[test]
fn registry_rejects_duplicate_native_root_catalog_keys() {
    let error = PolicyRegistry::new_catalogued(vec![
        PolicyRegistration::new(
            policy(HarnessId::Claude, PolicyLine::ClaudeCurrent),
            catalog(&[PolicyLine::ClaudeCurrent], &["shared.native"]),
        ),
        PolicyRegistration::new(
            policy(HarnessId::Codex, PolicyLine::CodexCurrent),
            catalog(&[PolicyLine::CodexCurrent], &["shared.native"]),
        ),
    ])
    .err()
    .unwrap();

    assert_eq!(error.code, "scan.registry_native_root_catalog_conflict");
}

#[test]
fn registry_rejects_policy_line_catalog_conflicts() {
    let error = PolicyRegistry::new_catalogued(vec![
        PolicyRegistration::new(
            policy(HarnessId::Claude, PolicyLine::ClaudeCurrent),
            catalog(&[PolicyLine::ClaudeCurrent], &[]),
        ),
        PolicyRegistration::new(
            policy(HarnessId::Codex, PolicyLine::CodexCurrent),
            catalog(&[PolicyLine::ClaudeCurrent], &[]),
        ),
    ])
    .err()
    .unwrap();

    assert_eq!(error.code, "scan.registry_policy_line_catalog_conflict");
}

#[test]
fn registry_rejects_catalogs_that_omit_the_unknown_profile_line() {
    let error = PolicyRegistry::new_catalogued(vec![PolicyRegistration::new(
        policy(HarnessId::OpenCode, PolicyLine::OpenCodeCurrent),
        catalog(&[PolicyLine::OpenCodeV2], &[]),
    )])
    .err()
    .unwrap();

    assert_eq!(error.code, "scan.registry_policy_line_catalog_invalid");
}
