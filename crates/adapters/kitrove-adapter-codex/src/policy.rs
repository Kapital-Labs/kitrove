use std::path::Path;

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocalRootHookMeter,
    LocatorDecision, NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile,
    PortablePolicyDecision, ReceiptAnchor, RelatedRoot, RootContext, RootHookMeter, RootHookReport,
    ScanFinding, VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{
    CapturedSkillSource, SkillSourceLayout, is_direct_child_source_path as is_direct_child,
    is_standard_skill_description, is_standard_skill_name as valid_standard_name,
};
use kitrove_model::{AssetId, FidelityReason, HarnessId};

use crate::roots::{
    PROFILE_EVIDENCE, agent_roots, standard_receipt_anchors, standard_roots, unusual_roots,
};

/// Read-only Codex Agent Skills observation policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodexObservationPolicy;

impl CodexObservationPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HarnessObservationPolicy for CodexObservationPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn runtime_authority(&self) -> kitrove_adapter_api::PolicyRuntimeAuthority {
        crate::roots::runtime_authority()
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Codex,
            PolicyLine::CodexCurrent,
            VersionObservationOwned::from(version),
            evidence(PROFILE_EVIDENCE),
        )
    }

    fn roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        standard_roots(context)
    }

    fn discover_unusual_roots(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        let mut meter = LocalRootHookMeter::new(context.limits);
        Ok(unusual_roots(
            context,
            matches!(profile.version(), VersionObservationOwned::Unknown),
            &mut meter,
        ))
    }

    fn discover_unusual_roots_bounded(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
        meter: &mut dyn RootHookMeter,
    ) -> AdapterResult<RootHookReport> {
        Ok(unusual_roots(
            context,
            matches!(profile.version(), VersionObservationOwned::Unknown),
            meter,
        ))
    }

    fn related_roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        Ok(agent_roots(context))
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory if is_direct_child(&locator.source_relative_path) => {
                LocatorDecision::Capture
            }
            SkillSourceLayout::Directory => LocatorDecision::Ignore,
            SkillSourceLayout::Standalone
                if is_direct_child(&locator.source_relative_path)
                    && locator.original_document_name.ends_with(".md") =>
            {
                LocatorDecision::Unsupported {
                    finding: ScanFinding::new(
                        "scan.layout_unsupported",
                        FindingSeverity::Attention,
                        FindingSubject::Root(root.logical_id.clone()),
                        vec![root.evidence.clone()],
                        "place Codex skills in directory packages containing SKILL.md",
                    ),
                }
            }
            SkillSourceLayout::Standalone => LocatorDecision::Ignore,
        }
    }

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        let directory_id = Path::new(&locator.source_relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&locator.source_relative_path);
        let native_id = valid_standard_name(directory_id).then(|| directory_id.to_owned());
        let mut reasons = Vec::new();
        let mut findings = Vec::new();

        match candidate.document.declared_name.as_deref() {
            Some(name) if valid_standard_name(name) => {
                if name != directory_id {
                    reject_field(
                        root,
                        &mut reasons,
                        &mut findings,
                        "skill.directory_name_mismatch",
                        "the standard Agent Skills name must match its Codex package directory",
                        "rename the package directory or its declared name so they match",
                    );
                }
            }
            _ => reject_field(
                root,
                &mut reasons,
                &mut findings,
                "skill.name_invalid",
                "Codex directory skills require a standard-valid name",
                "add a lowercase hyphenated name no longer than 64 bytes",
            ),
        }
        if !candidate
            .document
            .description
            .as_deref()
            .is_some_and(is_standard_skill_description)
        {
            reject_field(
                root,
                &mut reasons,
                &mut findings,
                "skill.description_invalid",
                "Codex directory skills require a standard-valid description",
                "add a description containing between 1 and 1,024 characters",
            );
        }
        if native_id.is_none()
            && !reasons
                .iter()
                .any(|reason: &FidelityReason| reason.code == "skill.name_invalid")
        {
            reject_field(
                root,
                &mut reasons,
                &mut findings,
                "skill.name_invalid",
                "the Codex package directory must be a standard-valid skill name",
                "rename the package directory using a lowercase hyphenated name",
            );
        }

        if !reasons.is_empty() {
            return Ok(CandidateDecision::new(
                NativeAcceptance::Rejected,
                native_id,
                PortablePolicyDecision::Unavailable { reasons },
                findings,
            )
            .expect("rejected Codex candidates retain structured loss evidence"));
        }

        let name = AssetId::parse(directory_id.to_owned())
            .expect("a standard-valid Codex directory name is a valid asset ID");
        let description = candidate
            .document
            .description
            .clone()
            .expect("a valid Codex candidate has an authored description");
        Ok(CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(directory_id.to_owned()),
            PortablePolicyDecision::Project {
                name,
                description,
                reasons: vec![],
            },
            vec![],
        )
        .expect("compiled Codex candidate decisions satisfy adapter invariants"))
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
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        Ok(standard_receipt_anchors(context))
    }
}

fn reject_field(
    root: &ObservedRoot,
    reasons: &mut Vec<FidelityReason>,
    findings: &mut Vec<ScanFinding>,
    code: &'static str,
    detail: &str,
    action: &'static str,
) {
    reasons.push(FidelityReason::new(code, detail));
    findings.push(ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Root(root.logical_id.clone()),
        vec![root.evidence.clone()],
        action,
    ));
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled Codex evidence references are valid")
}
