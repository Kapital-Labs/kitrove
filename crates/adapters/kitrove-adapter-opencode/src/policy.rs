use std::path::Path;

use kitrove_adapter_api::{
    AdapterResult, CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    FindingSeverity, FindingSubject, HarnessObservationPolicy, LocalRootHookMeter, LocatorDecision,
    NativeAcceptance, ObservedRoot, PolicyLine, PolicyProfile, PortablePolicyDecision,
    ReceiptAnchor, RelatedRoot, RootContext, RootHookMeter, RootHookReport, ScanFinding,
    VersionObservation, VersionObservationOwned,
};
use kitrove_agent_skills::{
    CapturedSkillSource, SkillSourceLayout, is_direct_child_source_path as is_direct_child,
    is_standard_skill_description, is_standard_skill_name as valid_standard_name,
};
use kitrove_model::{AssetId, FidelityReason, HarnessId};

use crate::roots::{
    CURRENT_DUPLICATE_EVIDENCE, CURRENT_PROFILE_EVIDENCE, V2_PRECEDENCE_EVIDENCE,
    V2_PROFILE_EVIDENCE, agent_roots, command_roots, evidence, standard_receipt_anchors,
    standard_roots, unusual_roots,
};

/// Version-aware read-only OpenCode Agent Skills observation policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenCodeObservationPolicy;

impl OpenCodeObservationPolicy {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl HarnessObservationPolicy for OpenCodeObservationPolicy {
    fn harness(&self) -> HarnessId {
        HarnessId::OpenCode
    }

    fn runtime_authority(&self) -> kitrove_adapter_api::PolicyRuntimeAuthority {
        crate::roots::runtime_authority()
    }

    fn profile(&self, version: VersionObservation<'_>) -> AdapterResult<PolicyProfile> {
        let line = match version {
            VersionObservation::Unknown => PolicyLine::OpenCodeCurrent,
            VersionObservation::Verified(evidence) => evidence.policy_line(),
        };
        let profile_evidence = match line {
            PolicyLine::OpenCodeCurrent => CURRENT_PROFILE_EVIDENCE,
            PolicyLine::OpenCodeV2 => V2_PROFILE_EVIDENCE,
            _ => CURRENT_PROFILE_EVIDENCE,
        };
        PolicyProfile::new(
            HarnessId::OpenCode,
            line,
            VersionObservationOwned::from(version),
            evidence(profile_evidence),
        )
    }

    fn roots(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<Vec<ObservedRoot>> {
        standard_roots(context, profile.line())
    }

    fn discover_unusual_roots(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<RootHookReport> {
        let mut meter = LocalRootHookMeter::new(context.limits);
        Ok(unusual_roots(
            context,
            profile.line(),
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
            profile.line(),
            matches!(profile.version(), VersionObservationOwned::Unknown),
            meter,
        ))
    }

    fn related_roots(
        &self,
        context: &RootContext<'_>,
        profile: &PolicyProfile,
    ) -> AdapterResult<Vec<RelatedRoot>> {
        let mut roots = agent_roots(context);
        if profile.line() == PolicyLine::OpenCodeV2 {
            roots.extend(command_roots(context));
        }
        Ok(roots)
    }

    fn classify_locator(
        &self,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        profile: &PolicyProfile,
    ) -> LocatorDecision {
        match profile.line() {
            PolicyLine::OpenCodeCurrent => classify_current_locator(locator, root),
            PolicyLine::OpenCodeV2 => classify_v2_locator(locator, root),
            _ => LocatorDecision::Ignore,
        }
    }

    fn decide_candidate(
        &self,
        candidate: &CapturedSkillSource,
        locator: &CandidateLocator,
        root: &ObservedRoot,
        profile: &PolicyProfile,
    ) -> AdapterResult<CandidateDecision> {
        Ok(match profile.line() {
            PolicyLine::OpenCodeCurrent => decide_current_candidate(candidate, locator, root),
            PolicyLine::OpenCodeV2 => decide_v2_candidate(candidate, locator, root),
            _ => unreachable!("OpenCode policy only selects OpenCode lines"),
        })
    }

    fn resolve_duplicates(
        &self,
        group: &[CandidateSummary],
        profile: &PolicyProfile,
    ) -> AdapterResult<DuplicateDecision> {
        if group.len() < 2 {
            return Ok(DuplicateDecision::Coexist);
        }
        if profile.line() != PolicyLine::OpenCodeV2 {
            return Ok(ambiguous_duplicate(CURRENT_DUPLICATE_EVIDENCE));
        }
        let winning_rank = group
            .iter()
            .map(|candidate| candidate.policy_rank)
            .max()
            .expect("a duplicate group is non-empty");
        let mut winners = group
            .iter()
            .filter(|candidate| candidate.policy_rank == winning_rank);
        let winner = winners.next().expect("the maximum rank has a member");
        if winners.next().is_some() {
            return Ok(ambiguous_duplicate(V2_PRECEDENCE_EVIDENCE));
        }
        Ok(DuplicateDecision::Winner {
            observation_id: winner.observation_id.clone(),
            reason: evidence(V2_PRECEDENCE_EVIDENCE),
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

fn classify_current_locator(locator: &CandidateLocator, root: &ObservedRoot) -> LocatorDecision {
    match locator.layout {
        SkillSourceLayout::Directory if is_direct_child(&locator.source_relative_path) => {
            LocatorDecision::Capture
        }
        SkillSourceLayout::Directory => LocatorDecision::Ignore,
        SkillSourceLayout::Standalone
            if is_direct_child(&locator.source_relative_path)
                && locator.original_document_name.ends_with(".md") =>
        {
            unsupported_layout(
                root,
                "place OpenCode current skills in direct directory packages containing SKILL.md",
            )
        }
        SkillSourceLayout::Standalone => LocatorDecision::Ignore,
    }
}

fn classify_v2_locator(locator: &CandidateLocator, root: &ObservedRoot) -> LocatorDecision {
    match locator.layout {
        SkillSourceLayout::Directory
            if root.enabled_layouts.contains(&SkillSourceLayout::Directory) =>
        {
            LocatorDecision::Capture
        }
        SkillSourceLayout::Standalone
            if root
                .enabled_layouts
                .contains(&SkillSourceLayout::Standalone)
                && is_direct_child(&locator.source_relative_path)
                && locator.original_document_name.ends_with(".md") =>
        {
            LocatorDecision::Capture
        }
        SkillSourceLayout::Directory | SkillSourceLayout::Standalone => LocatorDecision::Ignore,
    }
}

fn decide_current_candidate(
    candidate: &CapturedSkillSource,
    locator: &CandidateLocator,
    root: &ObservedRoot,
) -> CandidateDecision {
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
                    "the OpenCode current name must match its package directory",
                    "rename the package directory or declared name so they match exactly",
                );
            }
        }
        _ => reject_field(
            root,
            &mut reasons,
            &mut findings,
            "skill.name_invalid",
            "OpenCode current directory skills require a standard-valid name",
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
            "OpenCode current directory skills require a standard-valid description",
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
            "the OpenCode current package directory must be a standard-valid skill name",
            "rename the package directory using a lowercase hyphenated name",
        );
    }
    if !reasons.is_empty() {
        return CandidateDecision::new(
            NativeAcceptance::Rejected,
            native_id,
            PortablePolicyDecision::Unavailable { reasons },
            findings,
        )
        .expect("rejected OpenCode current candidates retain structured loss evidence");
    }

    CandidateDecision::new(
        NativeAcceptance::Accepted,
        Some(directory_id.to_owned()),
        PortablePolicyDecision::Project {
            name: AssetId::parse(directory_id.to_owned())
                .expect("a standard-valid OpenCode directory is an asset ID"),
            description: candidate
                .document
                .description
                .clone()
                .expect("an accepted current candidate has a description"),
            reasons: vec![],
        },
        vec![],
    )
    .expect("compiled OpenCode current candidate decisions satisfy adapter invariants")
}

fn decide_v2_candidate(
    candidate: &CapturedSkillSource,
    locator: &CandidateLocator,
    root: &ObservedRoot,
) -> CandidateDecision {
    let Some(native_id) = v2_native_id(locator) else {
        return rejected_v2_identity(root);
    };
    if native_id.is_empty() || native_id.len() > 256 || native_id.chars().any(char::is_control) {
        return rejected_v2_identity(root);
    }

    let mut reasons = Vec::new();
    if candidate
        .document
        .declared_name
        .as_deref()
        .is_some_and(|display_name| display_name != native_id)
    {
        reasons.push(FidelityReason::new(
            "opencode.display_name_differs",
            "OpenCode V2 uses the exact path-derived identity while retaining the declared display name",
        ));
    }
    let portable_name = valid_standard_name(native_id).then(|| {
        AssetId::parse(native_id.to_owned()).expect("a standard-valid path ID is an asset ID")
    });
    let portable_description = candidate
        .document
        .description
        .as_deref()
        .filter(|description| is_standard_skill_description(description))
        .map(str::to_owned);
    let portable = match (portable_name, portable_description) {
        (Some(name), Some(description)) => PortablePolicyDecision::Project {
            name,
            description,
            reasons,
        },
        (name, description) => {
            if name.is_none() {
                reasons.push(FidelityReason::new(
                    "opencode.portable_name_unavailable",
                    "the exact OpenCode V2 path identity is not a standard Agent Skills name",
                ));
            }
            if description.is_none() {
                reasons.push(FidelityReason::new(
                    "opencode.portable_description_unavailable",
                    "OpenCode V2 accepts the native source without a standard-valid authored description",
                ));
            }
            PortablePolicyDecision::Unavailable { reasons }
        }
    };
    let findings = matches!(portable, PortablePolicyDecision::Unavailable { .. })
        .then(|| {
            candidate_finding(
                root,
                "opencode.portable_projection_unavailable",
                "retain the native V2 source or add a standard-valid path ID and authored description",
            )
        })
        .into_iter()
        .collect();

    CandidateDecision::new(
        NativeAcceptance::Accepted,
        Some(native_id.to_owned()),
        portable,
        findings,
    )
    .expect("compiled OpenCode V2 candidate decisions satisfy adapter invariants")
}

fn v2_native_id(locator: &CandidateLocator) -> Option<&str> {
    match locator.layout {
        SkillSourceLayout::Directory => Path::new(&locator.source_relative_path)
            .file_name()
            .and_then(|name| name.to_str()),
        SkillSourceLayout::Standalone => Path::new(&locator.original_document_name)
            .file_stem()
            .and_then(|name| name.to_str()),
    }
}

fn rejected_v2_identity(root: &ObservedRoot) -> CandidateDecision {
    CandidateDecision::new(
        NativeAcceptance::Rejected,
        None,
        PortablePolicyDecision::Unavailable {
            reasons: vec![FidelityReason::new(
                "opencode.native_id_unavailable",
                "the exact path-derived OpenCode V2 identity is not bounded UTF-8 text",
            )],
        },
        vec![candidate_finding(
            root,
            "opencode.native_id_unavailable",
            "shorten or rename the OpenCode V2 skill document or parent directory",
        )],
    )
    .expect("a rejected OpenCode V2 identity retains structured evidence")
}

fn ambiguous_duplicate(evidence_ref: &str) -> DuplicateDecision {
    DuplicateDecision::Ambiguous {
        reason: ScanFinding::new(
            "scan.duplicate_ambiguous",
            FindingSeverity::Attention,
            FindingSubject::Harness(HarnessId::OpenCode),
            vec![evidence(evidence_ref)],
            "choose a unique OpenCode skill identity because no documented source winner applies",
        ),
    }
}

fn unsupported_layout(root: &ObservedRoot, action: &'static str) -> LocatorDecision {
    LocatorDecision::Unsupported {
        finding: ScanFinding::new(
            "scan.layout_unsupported",
            FindingSeverity::Attention,
            FindingSubject::Root(root.logical_id.clone()),
            vec![root.evidence.clone()],
            action,
        ),
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
    findings.push(candidate_finding(root, code, action));
}

fn candidate_finding(root: &ObservedRoot, code: &'static str, action: &'static str) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Root(root.logical_id.clone()),
        vec![root.evidence.clone()],
        action,
    )
}
