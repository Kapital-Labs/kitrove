use std::path::Path;

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    EvidenceRef, FindingSeverity, FindingSubject, HarnessObservationPolicy, LocalRootHookMeter,
    LocatorDecision, NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile,
    PortablePolicyDecision, ReceiptAnchor, RootContext, RootHookMeter, RootHookReport, ScanFinding,
    VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{
    CapturedSkillSource, SkillSourceLayout, is_direct_child_source_path as is_direct_child,
    is_standard_skill_description as valid_standard_description,
    is_standard_skill_name as valid_standard_name,
};
use kitrove_model::{AssetId, FidelityReason, HarnessId};

use crate::roots::{
    DUPLICATE_EVIDENCE, PROFILE_EVIDENCE, ProjectTrustState, command_roots, explicit_file_name,
    extension_roots, is_explicit_directory_root, is_explicit_file_root, project_trust_state,
    source_evidence, standard_receipt_anchors, standard_roots, unusual_roots,
};

/// Read-only Pi Latest Agent Skills observation policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct PiObservationPolicy;

impl PiObservationPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HarnessObservationPolicy for PiObservationPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::Pi
    }

    fn runtime_authority(&self) -> kitrove_adapter_api::PolicyRuntimeAuthority {
        crate::roots::runtime_authority()
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        PolicyProfile::new(
            HarnessId::Pi,
            PolicyLine::PiLatest,
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

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> LocatorDecision {
        match locator.layout {
            SkillSourceLayout::Directory => {
                if root.enabled_layouts.contains(&SkillSourceLayout::Directory) {
                    LocatorDecision::Capture
                } else {
                    LocatorDecision::Ignore
                }
            }
            SkillSourceLayout::Standalone => classify_standalone(locator, root),
        }
    }

    fn related_roots(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<kitrove_adapter_api::RelatedRoot>> {
        let mut roots = command_roots(context);
        roots.extend(extension_roots(context));
        Ok(roots)
    }

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        _profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        Ok(decide_pi_candidate(candidate, locator, root))
    }

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        _profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        if group.len() < 2 {
            return Ok(DuplicateDecision::Coexist);
        }
        Ok(DuplicateDecision::Ambiguous {
            reason: ScanFinding::new(
                "scan.duplicate_ambiguous",
                FindingSeverity::Attention,
                FindingSubject::Harness(HarnessId::Pi),
                vec![evidence(DUPLICATE_EVIDENCE)],
                "choose which same-name Pi skill to adopt because the documented first-found rule has no verified total source order",
            ),
        })
    }

    fn receipt_anchors(
        &self,
        context: &RootContext<'_>,
        _profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ReceiptAnchor>> {
        Ok(standard_receipt_anchors(context))
    }
}

fn classify_standalone(locator: &CandidateLocator, root: &ObservedRoot) -> LocatorDecision {
    if !locator.original_document_name.ends_with(".md") {
        return LocatorDecision::Ignore;
    }
    if is_explicit_file_root(root) {
        return if is_direct_child(&locator.source_relative_path)
            && explicit_file_name(root).as_deref() == Some(&locator.original_document_name)
        {
            LocatorDecision::CaptureIfFrontmatterPrefix
        } else {
            LocatorDecision::Ignore
        };
    }
    if locator.original_document_name == "SKILL.md" {
        return LocatorDecision::Ignore;
    }
    if is_explicit_directory_root(root) {
        return unsupported_standalone(
            root,
            "supply this Markdown file as its own explicit Pi source",
        );
    }
    match root.tier {
        kitrove_adapter_api::RootTier::User | kitrove_adapter_api::RootTier::Project
            if is_direct_child(&locator.source_relative_path) =>
        {
            LocatorDecision::CaptureIfFrontmatterPrefix
        }
        kitrove_adapter_api::RootTier::Compatibility
            if !is_direct_child(&locator.source_relative_path) =>
        {
            LocatorDecision::CaptureIfFrontmatterPrefix
        }
        kitrove_adapter_api::RootTier::User
        | kitrove_adapter_api::RootTier::Project
        | kitrove_adapter_api::RootTier::Compatibility => unsupported_standalone(
            root,
            "move the Pi standalone skill to a root position supported by this source family",
        ),
        _ => LocatorDecision::Ignore,
    }
}

fn unsupported_standalone(root: &ObservedRoot, action: &'static str) -> LocatorDecision {
    LocatorDecision::Unsupported {
        finding: ScanFinding::new(
            "scan.layout_unsupported",
            FindingSeverity::Attention,
            FindingSubject::Root(root.logical_id.clone()),
            vec![source_evidence(root)],
            action,
        ),
    }
}

fn decide_pi_candidate(
    candidate: &CapturedSkillSource,
    locator: &CandidateLocator,
    root: &ObservedRoot,
) -> CandidateDecision {
    let declared_name = candidate
        .document
        .declared_name
        .as_deref()
        .filter(|name| valid_native_name(name));
    let description = candidate
        .document
        .description
        .as_deref()
        .filter(|description| !description.is_empty());
    let mut reasons = Vec::new();
    let mut findings = Vec::new();

    if declared_name.is_none() {
        reject_field(
            root,
            &mut reasons,
            &mut findings,
            "skill.name_invalid",
            "Pi skills require a declared non-empty name without control characters",
            "add a declared Pi skill name containing at most 256 UTF-8 bytes",
        );
    }
    if description.is_none() {
        reject_field(
            root,
            &mut reasons,
            &mut findings,
            "skill.description_invalid",
            "Pi skills require a declared non-empty description",
            "add a non-empty declared Pi skill description",
        );
    }

    let native_id = declared_name.map(str::to_owned);
    if declared_name.is_none() || description.is_none() {
        return CandidateDecision::new(
            NativeAcceptance::Rejected,
            native_id,
            PortablePolicyDecision::Unavailable { reasons },
            findings,
        )
        .expect("rejected Pi candidates retain structured field evidence");
    }
    let declared_name = declared_name.expect("checked above");
    let description = description.expect("checked above");

    if container_id(locator).is_some_and(|container| container != declared_name) {
        reasons.push(FidelityReason::new(
            "skill.native_name_differs",
            "Pi uses the declared name even when its containing directory or file name differs",
        ));
        findings.push(candidate_finding(
            root,
            "skill.native_name_differs",
            "retain the Pi container name as native evidence when adopting the declared skill identity",
        ));
    }

    match project_trust_state(root) {
        Some(ProjectTrustState::Declined) => findings.push(candidate_finding(
            root,
            "pi.project_trust_declined",
            "review or change Pi project trust before expecting native activation",
        )),
        Some(ProjectTrustState::Unknown) => findings.push(candidate_finding(
            root,
            "pi.project_trust_unknown",
            "verify Pi project trust before expecting native activation",
        )),
        Some(ProjectTrustState::Trusted) | None => {}
    }

    let portable_name = valid_standard_name(declared_name).then(|| {
        AssetId::parse(declared_name.to_owned()).expect("a standard-valid name is an asset ID")
    });
    let portable_description =
        valid_standard_description(description).then(|| description.to_owned());
    if portable_name.is_none() {
        reasons.push(FidelityReason::new(
            "pi.portable_name_unavailable",
            "the declared Pi name is not a standard Agent Skills name",
        ));
    }
    if portable_description.is_none() {
        reasons.push(FidelityReason::new(
            "pi.portable_description_unavailable",
            "the declared Pi description is longer than the portable Agent Skills limit",
        ));
    }

    let portable = match (portable_name, portable_description) {
        (Some(name), Some(description)) => PortablePolicyDecision::Project {
            name,
            description,
            reasons,
        },
        _ => {
            findings.push(candidate_finding(
                root,
                "pi.portable_projection_unavailable",
                "use a standard-valid declared name and description before portable adoption",
            ));
            PortablePolicyDecision::Unavailable { reasons }
        }
    };

    CandidateDecision::new(NativeAcceptance::Accepted, native_id, portable, findings)
        .expect("compiled Pi candidate decisions satisfy adapter invariants")
}

fn container_id(locator: &CandidateLocator) -> Option<&str> {
    let path = Path::new(&locator.source_relative_path);
    match locator.layout {
        SkillSourceLayout::Directory => path.file_name()?.to_str(),
        SkillSourceLayout::Standalone => path.file_stem()?.to_str(),
    }
}

fn valid_native_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
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
    findings.push(candidate_finding(root, code, action));
}

fn candidate_finding(root: &ObservedRoot, code: &'static str, action: &'static str) -> ScanFinding {
    let mut evidence_refs = vec![source_evidence(root)];
    if root.evidence != evidence_refs[0] {
        evidence_refs.push(root.evidence.clone());
    }
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Root(root.logical_id.clone()),
        evidence_refs,
        action,
    )
}

fn evidence(value: &str) -> EvidenceRef {
    EvidenceRef::parse(value).expect("compiled Pi evidence references are valid")
}
