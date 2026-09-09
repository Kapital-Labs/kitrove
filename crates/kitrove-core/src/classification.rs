use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::DirExt as _;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata};
use kitrove_adapter_api::{
    AdapterError, AdapterResult, EvidenceRef, FindingSeverity, FindingSubject, LocalStateInput,
    ObservationId, ProjectBoundary, ReceiptAnchor, ScanFinding, ScanRequest, ScopeSelection,
};
use kitrove_agent_skills::{
    CaptureMeter, CapturedSkillSource, SkillSource, capture_skill_source_with_meter,
};
use kitrove_agents::{AgentName, NativeAgentDialect};
use kitrove_model::{
    AssetKind, ContentClass, ContentHash, EnvironmentManifest, HarnessId, HarnessScope,
    NormalizedDestination, ReceiptId, ReceiptTarget,
};

use crate::agent_materialization::{agent_document_extension, hash_agent_target};
use crate::agent_observation::agent_dialect;
use crate::materialization::normalized_destination_from_path;
use crate::read_only_fs::{ReadOnlyFileError, read_bounded_regular_file_with_mode, same_file};
use crate::{
    AgentScanEntry, InvalidReceipt, ObservedCandidate, ReceiptIndex, ReceiptInvalidityScope,
    ScanBudget, ScanClassification, ScanEntry, ScanMode,
};

const MAX_RECEIPT_RAW_BYTES: usize = 1024 * 1024;

pub(crate) struct ReceiptPolicyEvidence {
    pub harness: HarnessId,
    pub anchors: Vec<AssetReceiptAnchor>,
    pub failed_kinds: BTreeSet<AssetKind>,
}

pub(crate) struct AssetReceiptAnchor {
    pub kind: AssetKind,
    pub anchor: ReceiptAnchor,
}

struct ValidatedAnchor {
    normalized: NormalizedDestination,
    evidence: EvidenceRef,
}

type ValidatedAnchors = BTreeMap<(HarnessId, HarnessScope, AssetKind), Vec<ValidatedAnchor>>;

struct ValidatedReceipt {
    receipt_id: ReceiptId,
    receipt: kitrove_model::DeploymentReceipt,
    asset_kind: AssetKind,
    asset_content_hash: ContentHash,
    asset_content_class: ContentClass,
    anchor_evidence: EvidenceRef,
}

enum ReceiptCapture {
    Skill(Box<CapturedSkillSource>),
    Agent(ContentHash),
    Missing(ScanFinding),
    Failed(ScanFinding),
}

pub(crate) struct ClassificationReportState<'a> {
    pub entries: &'a mut Vec<ScanEntry>,
    pub agent_entries: &'a mut Vec<AgentScanEntry>,
    pub budget: &'a mut ScanBudget,
    pub findings: &'a mut Vec<ScanFinding>,
}

fn report_budget_error() -> AdapterError {
    AdapterError::new(
        "scan.report_budget_exhausted",
        "the request limits cannot retain a complete trustworthy scan report",
    )
}

fn push_top_finding(
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

fn push_entry_finding(
    entry: &mut ScanEntry,
    budget: &mut ScanBudget,
    finding: ScanFinding,
) -> AdapterResult<()> {
    if !budget.reserve_report_findings(1) {
        return Err(report_budget_error());
    }
    entry.findings.push(finding);
    Ok(())
}

fn push_entry(
    entries: &mut Vec<ScanEntry>,
    budget: &mut ScanBudget,
    entry: ScanEntry,
) -> AdapterResult<()> {
    if !budget.reserve_report_entry(entry.findings.len()) {
        return Err(report_budget_error());
    }
    entries.push(entry);
    Ok(())
}

pub(crate) fn classify_scan(
    request: &ScanRequest<'_>,
    observations: &[ObservedCandidate],
    ambiguous_duplicates: &BTreeSet<ObservationId>,
    policy_evidence: &[ReceiptPolicyEvidence],
    state: ClassificationReportState<'_>,
) -> AdapterResult<ScanMode> {
    let ClassificationReportState {
        entries,
        agent_entries,
        budget,
        findings,
    } = state;
    let (anchors, anchor_invalid) = validate_anchors(request, policy_evidence, findings, budget)?;
    let local_state_unsafe = matches!(request.local_state.as_ref(), Some(LocalStateInput::Unsafe));
    if local_state_unsafe {
        push_top_finding(findings, budget, local_state_invalid_finding())?;
    }
    let Some(environment) = &request.environment else {
        return Ok(ScanMode::Inventory);
    };
    let Some(manifest) = parse_manifest(environment.toml_bytes, request) else {
        push_top_finding(findings, budget, environment_invalid_finding())?;
        mark_all_unknown(entries, agent_entries);
        return Ok(ScanMode::Degraded);
    };
    let manifest_revision = manifest_revision(&manifest);

    let Some(LocalStateInput::Bytes { json_bytes, .. }) = &request.local_state else {
        if local_state_unsafe {
            mark_all_unknown(entries, agent_entries);
            return Ok(ScanMode::Degraded);
        }
        apply_without_receipts(observations, entries, ambiguous_duplicates, &[]);
        return Ok(ScanMode::Classified);
    };
    let max_input_bytes = usize::try_from(request.limits.max_input_bytes).unwrap_or(usize::MAX);
    let inspection = match ReceiptIndex::inspect_json_bounded(
        json_bytes,
        max_input_bytes,
        request.limits.max_receipts,
        MAX_RECEIPT_RAW_BYTES.min(max_input_bytes),
    ) {
        Ok(inspection) => inspection,
        Err(_) => {
            push_top_finding(findings, budget, local_state_invalid_finding())?;
            mark_all_unknown(entries, agent_entries);
            return Ok(ScanMode::Degraded);
        }
    };

    let mut invalid = inspection
        .invalid
        .into_iter()
        .filter(|record| invalidity_selected(&record.scope, request))
        .collect::<Vec<_>>();
    let mut contextual_invalid = Vec::new();
    let mut valid_receipts = Vec::new();
    for record in inspection.valid {
        if record.receipt.target != ReceiptTarget::WholeTarget {
            continue;
        }
        if !request.harnesses.contains(&record.receipt.harness)
            || !scope_selected(request.scopes, record.receipt.scope)
        {
            continue;
        }
        let asset = manifest.assets.get(&record.receipt.asset_id);
        let anchor = asset.and_then(|asset| {
            anchors
                .get(&(
                    record.receipt.harness.clone(),
                    record.receipt.scope,
                    asset.kind,
                ))
                .and_then(|items| {
                    items.iter().find(|anchor| {
                        destination_contained(&record.receipt.destination, &anchor.normalized)
                    })
                })
        });
        let project_contained = record.receipt.scope != HarnessScope::Project
            || project_boundary_destination(request, &record.receipt.destination);
        if anchor.is_none()
            || !project_contained
            || asset.is_none_or(|asset| {
                !matches!(asset.kind, AssetKind::Skill | AssetKind::Agent)
                    || (asset.kind == AssetKind::Agent
                        && receipt_agent_identity(&record.receipt).is_none())
            })
        {
            contextual_invalid.push(contextual_invalid_receipt(
                record.receipt_id,
                &record.receipt,
            ));
            continue;
        }
        let asset = asset.expect("validated manifest asset presence");
        valid_receipts.push(ValidatedReceipt {
            receipt_id: record.receipt_id,
            receipt: record.receipt,
            asset_kind: asset.kind,
            asset_content_hash: asset.content_hash.clone(),
            asset_content_class: asset.content_class,
            anchor_evidence: anchor
                .expect("validated receipt anchor presence")
                .evidence
                .clone(),
        });
    }
    invalid.extend(contextual_invalid);
    invalid.sort_by(|left, right| {
        invalidity_sort_key(&left.scope).cmp(&invalidity_sort_key(&right.scope))
    });
    for finding in invalid.iter().map(|record| record.finding.clone()) {
        push_top_finding(findings, budget, finding)?;
    }

    apply_without_receipts(observations, entries, ambiguous_duplicates, &invalid);
    apply_agents_without_receipts(agent_entries, &invalid);

    let mut valid_destinations = BTreeSet::new();
    let mut suppressed_observations = BTreeSet::new();
    for record in &valid_receipts {
        if record.asset_kind != AssetKind::Skill {
            continue;
        }
        if invalid
            .iter()
            .any(|invalid| invalidity_matches_receipt(&invalid.scope, &record.receipt))
        {
            continue;
        }
        valid_destinations.insert((
            record.receipt.harness.clone(),
            record.receipt.scope,
            record.receipt.destination.clone(),
        ));
        let matching = observations
            .iter()
            .enumerate()
            .filter_map(|(index, observation)| {
                (observation.location().harness == record.receipt.harness
                    && observation.location().scope == record.receipt.scope
                    && observation.normalized_destination() == Some(&record.receipt.destination))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let capture = capture_receipt_destination(record, budget);
        match capture {
            ReceiptCapture::Skill(captured) => {
                let captured = *captured;
                let classification = if captured.exact_source_hash == record.receipt.rendered_hash {
                    ScanClassification::ManagedUnchanged
                } else {
                    ScanClassification::ManagedModified
                };
                if matching.is_empty() {
                    let mut entry = synthetic_receipt_entry(record, classification);
                    entry.layout = Some(captured.layout);
                    entry.exact_source_hash = Some(captured.exact_source_hash);
                    push_entry(entries, budget, entry)?;
                    attach_stale_finding(
                        entries
                            .last_mut()
                            .expect("the synthetic entry was retained"),
                        record,
                        &manifest_revision,
                        budget,
                    )?;
                } else {
                    for index in matching {
                        let observation = &observations[index];
                        let entry = &mut entries[index];
                        apply_receipt_fields(entry, record);
                        entry.layout = Some(captured.layout);
                        entry.exact_source_hash = Some(captured.exact_source_hash.clone());
                        entry.classification = classification_after_success(
                            observation,
                            entry,
                            ambiguous_duplicates,
                            classification,
                        );
                        attach_stale_finding(entry, record, &manifest_revision, budget)?;
                    }
                }
            }
            ReceiptCapture::Agent(_) => unreachable!("skill receipts use skill capture"),
            ReceiptCapture::Missing(finding) => {
                let higher_priority = matching
                    .iter()
                    .filter_map(|index| {
                        classification_before_missing(&observations[*index], ambiguous_duplicates)
                            .map(|classification| (*index, classification))
                    })
                    .collect::<Vec<_>>();
                if higher_priority.is_empty() {
                    suppressed_observations.extend(matching);
                    let mut entry =
                        synthetic_receipt_entry(record, ScanClassification::MissingManaged);
                    entry.findings.push(finding);
                    push_entry(entries, budget, entry)?;
                    attach_stale_finding(
                        entries
                            .last_mut()
                            .expect("the synthetic entry was retained"),
                        record,
                        &manifest_revision,
                        budget,
                    )?;
                } else {
                    let preserved = higher_priority
                        .iter()
                        .map(|(index, _)| *index)
                        .collect::<BTreeSet<_>>();
                    suppressed_observations.extend(
                        matching
                            .into_iter()
                            .filter(|index| !preserved.contains(index)),
                    );
                    for (index, classification) in higher_priority {
                        let entry = &mut entries[index];
                        apply_receipt_fields(entry, record);
                        entry.classification = classification;
                        push_entry_finding(entry, budget, finding.clone())?;
                        attach_stale_finding(entry, record, &manifest_revision, budget)?;
                    }
                }
            }
            ReceiptCapture::Failed(finding) => {
                if matching.is_empty() {
                    let mut entry = synthetic_receipt_entry(record, ScanClassification::Unknown);
                    entry.findings.push(finding);
                    push_entry(entries, budget, entry)?;
                    attach_stale_finding(
                        entries
                            .last_mut()
                            .expect("the synthetic entry was retained"),
                        record,
                        &manifest_revision,
                        budget,
                    )?;
                } else {
                    for index in matching {
                        let entry = &mut entries[index];
                        apply_receipt_fields(entry, record);
                        entry.classification = ScanClassification::Unknown;
                        push_entry_finding(entry, budget, finding.clone())?;
                        attach_stale_finding(entry, record, &manifest_revision, budget)?;
                    }
                }
            }
        }
    }
    classify_agent_receipts(
        agent_entries,
        &valid_receipts,
        &invalid,
        &manifest_revision,
        budget,
    )?;
    if !suppressed_observations.is_empty() {
        let mut index = 0_usize;
        entries.retain(|entry| {
            let keep = !suppressed_observations.contains(&index);
            index += 1;
            if !keep {
                budget.release_report_entry(entry.findings.len());
            }
            keep
        });
    }
    add_invalid_destination_entries(observations, entries, &invalid, &valid_destinations, budget)?;

    if !invalid.is_empty() || anchor_invalid {
        Ok(ScanMode::Degraded)
    } else {
        Ok(ScanMode::Classified)
    }
}

fn parse_manifest(bytes: &[u8], request: &ScanRequest<'_>) -> Option<EnvironmentManifest> {
    let max_input_bytes = usize::try_from(request.limits.max_input_bytes).unwrap_or(usize::MAX);
    if bytes.len() > max_input_bytes {
        return None;
    }
    let input = std::str::from_utf8(bytes).ok()?;
    EnvironmentManifest::from_toml(input).ok()
}

fn manifest_revision(manifest: &EnvironmentManifest) -> String {
    crate::derive_manifest_revision(manifest)
        .expect("a parsed and validated manifest has a canonical revision")
        .as_str()
        .to_owned()
}

fn validate_anchors(
    request: &ScanRequest<'_>,
    policies: &[ReceiptPolicyEvidence],
    findings: &mut Vec<ScanFinding>,
    budget: &mut ScanBudget,
) -> AdapterResult<(ValidatedAnchors, bool)> {
    let mut invalid = false;
    let mut candidates = Vec::new();
    for policy in policies {
        if !policy.failed_kinds.is_empty() {
            invalid = true;
            push_top_finding(findings, budget, anchor_invalid_finding(&policy.harness))?;
        }
        for typed_anchor in &policy.anchors {
            let kind = typed_anchor.kind;
            let anchor = &typed_anchor.anchor;
            if policy.failed_kinds.contains(&kind) {
                continue;
            }
            let Some(normalized) = normalize_path(&anchor.path) else {
                invalid = true;
                push_top_finding(findings, budget, anchor_invalid_finding(&policy.harness))?;
                continue;
            };
            let scope_base = match anchor.scope {
                HarnessScope::User => request.home.as_deref().and_then(normalize_path),
                HarnessScope::Project => match &request.project_boundary {
                    ProjectBoundary::Repository { root } => normalize_path(root),
                    ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => None,
                },
            };
            let safe_kind = no_follow_kind(&normalized);
            if !scope_selected(request.scopes, anchor.scope)
                || scope_base
                    .as_ref()
                    .is_none_or(|base| !destination_contained(&normalized, base))
                || !matches!(
                    safe_kind,
                    Ok(SafePathKind::Directory | SafePathKind::Missing)
                )
            {
                invalid = true;
                push_top_finding(findings, budget, anchor_invalid_finding(&policy.harness))?;
                continue;
            }
            candidates.push((
                policy.harness.clone(),
                anchor.scope,
                kind,
                ValidatedAnchor {
                    normalized,
                    evidence: anchor.evidence.clone(),
                },
            ));
        }
    }
    let mut counts = BTreeMap::new();
    for (harness, scope, kind, anchor) in &candidates {
        *counts
            .entry((harness.clone(), *scope, *kind, anchor.normalized.clone()))
            .or_insert(0_usize) += 1;
    }
    let mut anchors = ValidatedAnchors::new();
    for (harness, scope, kind, anchor) in candidates {
        if counts
            .get(&(harness.clone(), scope, kind, anchor.normalized.clone()))
            .copied()
            .unwrap_or_default()
            != 1
        {
            invalid = true;
            push_top_finding(findings, budget, anchor_invalid_finding(&harness))?;
            continue;
        }
        anchors
            .entry((harness, scope, kind))
            .or_default()
            .push(anchor);
    }
    for values in anchors.values_mut() {
        values.sort_by(|left, right| left.normalized.cmp(&right.normalized));
    }
    Ok((anchors, invalid))
}

fn apply_without_receipts(
    observations: &[ObservedCandidate],
    entries: &mut [ScanEntry],
    ambiguous_duplicates: &BTreeSet<ObservationId>,
    invalid: &[InvalidReceipt],
) {
    for (observation, entry) in observations.iter().zip(entries.iter_mut()) {
        if invalid
            .iter()
            .any(|record| invalidity_matches_observation(&record.scope, observation))
        {
            entry.classification = ScanClassification::Unknown;
            continue;
        }
        entry.classification = match observation {
            ObservedCandidate::Failed(_) => ScanClassification::Unknown,
            ObservedCandidate::Accepted(candidate)
                if ambiguous_duplicates.contains(candidate.observation_id()) =>
            {
                ScanClassification::ConflictingDuplicate
            }
            ObservedCandidate::Accepted(_) => ScanClassification::Unmanaged,
        };
    }
}

fn mark_all_unknown(entries: &mut [ScanEntry], agent_entries: &mut [AgentScanEntry]) {
    for entry in entries {
        entry.classification = ScanClassification::Unknown;
    }
    for entry in agent_entries {
        entry.classification = ScanClassification::Unknown;
    }
}

fn apply_agents_without_receipts(entries: &mut [AgentScanEntry], invalid: &[InvalidReceipt]) {
    for entry in entries {
        if invalid
            .iter()
            .any(|record| invalidity_matches_agent(&record.scope, entry))
        {
            entry.classification = ScanClassification::Unknown;
        } else if entry.classification != ScanClassification::ConflictingDuplicate {
            entry.classification = ScanClassification::Unmanaged;
        }
    }
}

fn classify_agent_receipts(
    entries: &mut Vec<AgentScanEntry>,
    receipts: &[ValidatedReceipt],
    invalid: &[InvalidReceipt],
    manifest_revision: &str,
    budget: &mut ScanBudget,
) -> AdapterResult<()> {
    let mut suppressed = BTreeSet::new();
    for record in receipts
        .iter()
        .filter(|record| record.asset_kind == AssetKind::Agent)
    {
        if invalid
            .iter()
            .any(|invalid| invalidity_matches_receipt(&invalid.scope, &record.receipt))
        {
            continue;
        }
        let matching = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                (entry.harness == record.receipt.harness
                    && entry.scope == record.receipt.scope
                    && entry.normalized_destination.as_ref() == Some(&record.receipt.destination))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        match capture_receipt_destination(record, budget) {
            ReceiptCapture::Agent(exact_hash) => {
                let classification = if exact_hash == record.receipt.rendered_hash {
                    ScanClassification::ManagedUnchanged
                } else {
                    ScanClassification::ManagedModified
                };
                if matching.is_empty() {
                    let mut entry = synthetic_agent_receipt_entry(record, classification);
                    entry.observed_target_hash = Some(exact_hash);
                    push_agent_entry(entries, budget, entry)?;
                    attach_agent_stale_finding(
                        entries.last_mut().expect("synthetic agent entry retained"),
                        record,
                        manifest_revision,
                        budget,
                    )?;
                } else {
                    for index in matching {
                        let entry = &mut entries[index];
                        apply_agent_receipt_fields(entry, record);
                        entry.observed_target_hash = Some(exact_hash.clone());
                        if entry.classification != ScanClassification::ConflictingDuplicate {
                            entry.classification = classification;
                        }
                        attach_agent_stale_finding(entry, record, manifest_revision, budget)?;
                    }
                }
            }
            ReceiptCapture::Missing(finding) => {
                let conflicts = matching
                    .iter()
                    .copied()
                    .filter(|index| {
                        entries[*index].classification == ScanClassification::ConflictingDuplicate
                    })
                    .collect::<BTreeSet<_>>();
                if conflicts.is_empty() {
                    suppressed.extend(matching);
                    let mut entry =
                        synthetic_agent_receipt_entry(record, ScanClassification::MissingManaged);
                    entry.findings.push(finding);
                    push_agent_entry(entries, budget, entry)?;
                    attach_agent_stale_finding(
                        entries.last_mut().expect("synthetic agent entry retained"),
                        record,
                        manifest_revision,
                        budget,
                    )?;
                } else {
                    suppressed.extend(
                        matching
                            .into_iter()
                            .filter(|index| !conflicts.contains(index)),
                    );
                    for index in conflicts {
                        let entry = &mut entries[index];
                        apply_agent_receipt_fields(entry, record);
                        push_agent_finding(entry, budget, finding.clone())?;
                        attach_agent_stale_finding(entry, record, manifest_revision, budget)?;
                    }
                }
            }
            ReceiptCapture::Failed(finding) => {
                if matching.is_empty() {
                    let mut entry =
                        synthetic_agent_receipt_entry(record, ScanClassification::Unknown);
                    entry.findings.push(finding);
                    push_agent_entry(entries, budget, entry)?;
                    attach_agent_stale_finding(
                        entries.last_mut().expect("synthetic agent entry retained"),
                        record,
                        manifest_revision,
                        budget,
                    )?;
                } else {
                    for index in matching {
                        let entry = &mut entries[index];
                        apply_agent_receipt_fields(entry, record);
                        entry.classification = ScanClassification::Unknown;
                        push_agent_finding(entry, budget, finding.clone())?;
                        attach_agent_stale_finding(entry, record, manifest_revision, budget)?;
                    }
                }
            }
            ReceiptCapture::Skill(_) => unreachable!("agent receipts use agent capture"),
        }
    }
    if !suppressed.is_empty() {
        let mut index = 0_usize;
        entries.retain(|entry| {
            let keep = !suppressed.contains(&index);
            index += 1;
            if !keep {
                budget.release_report_entry(entry.findings.len());
            }
            keep
        });
    }
    Ok(())
}

fn push_agent_finding(
    entry: &mut AgentScanEntry,
    budget: &mut ScanBudget,
    finding: ScanFinding,
) -> AdapterResult<()> {
    if !budget.reserve_report_findings(1) {
        return Err(report_budget_error());
    }
    entry.findings.push(finding);
    Ok(())
}

fn push_agent_entry(
    entries: &mut Vec<AgentScanEntry>,
    budget: &mut ScanBudget,
    entry: AgentScanEntry,
) -> AdapterResult<()> {
    if !budget.reserve_report_entry(entry.findings.len()) {
        return Err(report_budget_error());
    }
    entries.push(entry);
    Ok(())
}

fn classification_before_missing(
    observation: &ObservedCandidate,
    ambiguous_duplicates: &BTreeSet<ObservationId>,
) -> Option<ScanClassification> {
    match observation {
        ObservedCandidate::Failed(_) => Some(ScanClassification::Unknown),
        ObservedCandidate::Accepted(candidate)
            if ambiguous_duplicates.contains(candidate.observation_id()) =>
        {
            Some(ScanClassification::ConflictingDuplicate)
        }
        ObservedCandidate::Accepted(_) => None,
    }
}

fn classification_after_success(
    observation: &ObservedCandidate,
    entry: &ScanEntry,
    ambiguous_duplicates: &BTreeSet<ObservationId>,
    managed: ScanClassification,
) -> ScanClassification {
    match observation {
        ObservedCandidate::Accepted(candidate)
            if ambiguous_duplicates.contains(candidate.observation_id()) =>
        {
            ScanClassification::ConflictingDuplicate
        }
        ObservedCandidate::Accepted(_) => managed,
        ObservedCandidate::Failed(_)
            if entry
                .findings
                .iter()
                .all(|finding| finding.code == "scan.layout_unsupported") =>
        {
            managed
        }
        ObservedCandidate::Failed(_) => ScanClassification::Unknown,
    }
}

fn apply_receipt_fields(entry: &mut ScanEntry, record: &ValidatedReceipt) {
    entry.asset_id = Some(record.receipt.asset_id.clone());
    entry.receipt_id = Some(record.receipt_id.clone());
    entry.normalized_destination = Some(record.receipt.destination.as_str().to_owned());
    entry.receipt_rendered_hash = Some(record.receipt.rendered_hash.clone());
}

fn apply_agent_receipt_fields(entry: &mut AgentScanEntry, record: &ValidatedReceipt) {
    entry.asset_id = Some(record.receipt.asset_id.clone());
    entry.receipt_id = Some(record.receipt_id.clone());
    entry.normalized_destination = Some(record.receipt.destination.clone());
    entry.receipt_rendered_hash = Some(record.receipt.rendered_hash.clone());
}

fn synthetic_agent_receipt_entry(
    record: &ValidatedReceipt,
    classification: ScanClassification,
) -> AgentScanEntry {
    let (dialect, name) = receipt_agent_identity(&record.receipt)
        .expect("agent receipt identity was validated before classification");
    AgentScanEntry {
        observation_id: None,
        harness: record.receipt.harness.clone(),
        scope: record.receipt.scope,
        root_tier: None,
        logical_root: None,
        policy_rank: None,
        source_relative_path: None,
        dialect,
        name,
        asset_id: Some(record.receipt.asset_id.clone()),
        receipt_id: Some(record.receipt_id.clone()),
        normalized_destination: Some(record.receipt.destination.clone()),
        receipt_rendered_hash: Some(record.receipt.rendered_hash.clone()),
        exact_source_hash: None,
        observed_target_hash: None,
        portable_hash: None,
        content_class: record.asset_content_class,
        blocked_reason: None,
        classification,
        findings: vec![],
    }
}

fn synthetic_receipt_entry(
    record: &ValidatedReceipt,
    classification: ScanClassification,
) -> ScanEntry {
    ScanEntry {
        observation_id: None,
        harness: record.receipt.harness.clone(),
        scope: record.receipt.scope,
        root_tier: None,
        logical_root: None,
        policy_rank: None,
        source_relative_path: None,
        layout: None,
        native_id: None,
        asset_id: Some(record.receipt.asset_id.clone()),
        receipt_id: Some(record.receipt_id.clone()),
        normalized_destination: Some(record.receipt.destination.as_str().to_owned()),
        receipt_rendered_hash: Some(record.receipt.rendered_hash.clone()),
        classification,
        exact_source_hash: None,
        portable_hash: None,
        shadowed_by: None,
        findings: vec![],
    }
}

fn attach_stale_finding(
    entry: &mut ScanEntry,
    record: &ValidatedReceipt,
    manifest_revision: &str,
    budget: &mut ScanBudget,
) -> AdapterResult<()> {
    if record.receipt.environment_revision.as_str() == manifest_revision
        && record.receipt.source_hash == record.asset_content_hash
    {
        return Ok(());
    }
    push_entry_finding(entry, budget, stale_receipt_finding(record))
}

fn attach_agent_stale_finding(
    entry: &mut AgentScanEntry,
    record: &ValidatedReceipt,
    manifest_revision: &str,
    budget: &mut ScanBudget,
) -> AdapterResult<()> {
    if record.receipt.environment_revision.as_str() == manifest_revision
        && record.receipt.source_hash == record.asset_content_hash
    {
        return Ok(());
    }
    push_agent_finding(entry, budget, stale_receipt_finding(record))
}

fn stale_receipt_finding(record: &ValidatedReceipt) -> ScanFinding {
    ScanFinding::new(
        "scan.receipt_stale_desired_state",
        FindingSeverity::Attention,
        destination_subject(
            &record.receipt.harness,
            record.receipt.scope,
            &record.receipt.destination,
        ),
        vec![record.anchor_evidence.clone()],
        "plan the desired-state transition without changing the observed content classification",
    )
}

fn add_invalid_destination_entries(
    observations: &[ObservedCandidate],
    entries: &mut Vec<ScanEntry>,
    invalid: &[InvalidReceipt],
    valid_destinations: &BTreeSet<(HarnessId, HarnessScope, NormalizedDestination)>,
    budget: &mut ScanBudget,
) -> AdapterResult<()> {
    let mut emitted = BTreeSet::new();
    for record in invalid {
        let ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } = &record.scope
        else {
            continue;
        };
        let key = (harness.clone(), *scope, normalized_destination.clone());
        if valid_destinations.contains(&key)
            || observations.iter().any(|observation| {
                observation.location().harness == *harness
                    && observation.location().scope == *scope
                    && observation.normalized_destination() == Some(normalized_destination)
            })
            || !emitted.insert(key)
        {
            continue;
        }
        push_entry(
            entries,
            budget,
            ScanEntry {
                observation_id: None,
                harness: harness.clone(),
                scope: *scope,
                root_tier: None,
                logical_root: None,
                policy_rank: None,
                source_relative_path: None,
                layout: None,
                native_id: None,
                asset_id: None,
                receipt_id: record.receipt_id.clone(),
                normalized_destination: Some(normalized_destination.as_str().to_owned()),
                receipt_rendered_hash: None,
                classification: ScanClassification::Unknown,
                exact_source_hash: None,
                portable_hash: None,
                shadowed_by: None,
                findings: vec![],
            },
        )?;
    }
    Ok(())
}

fn capture_receipt_destination(
    record: &ValidatedReceipt,
    budget: &mut ScanBudget,
) -> ReceiptCapture {
    let harness = &record.receipt.harness;
    let scope = record.receipt.scope;
    let destination = &record.receipt.destination;
    let subject = destination_subject(harness, scope, destination);
    if record.asset_kind == AssetKind::Agent {
        return capture_agent_receipt_destination(destination, subject, budget);
    }
    let source = match no_follow_kind(destination) {
        Ok(SafePathKind::Directory) => SkillSource::Directory {
            path: PathBuf::from(destination.as_str()),
        },
        Ok(SafePathKind::RegularFile) if has_markdown_extension(destination) => {
            SkillSource::Standalone {
                path: PathBuf::from(destination.as_str()),
            }
        }
        Ok(SafePathKind::Missing) => {
            return ReceiptCapture::Missing(ScanFinding::new(
                "scan.receipt_destination_missing",
                FindingSeverity::Attention,
                subject,
                vec![],
                "restore the managed destination or plan its removal",
            ));
        }
        Ok(SafePathKind::RegularFile | SafePathKind::Other) | Err(()) => {
            return ReceiptCapture::Failed(ScanFinding::new(
                "scan.receipt_destination_unsafe",
                FindingSeverity::Attention,
                subject,
                vec![],
                "replace the unsafe destination with a regular Markdown file or directory before rescanning",
            ));
        }
    };
    let limits = budget.remaining_capture_limits();
    if limits.max_files == 0 || limits.max_total_bytes == 0 {
        return ReceiptCapture::Failed(ScanFinding::new(
            "scan.capture_budget_exhausted",
            FindingSeverity::Attention,
            subject,
            vec![],
            "reduce capture work or increase request capture capacity",
        ));
    }
    let result = capture_skill_source_with_meter(&source, limits, budget);
    match result {
        Ok(captured) => ReceiptCapture::Skill(Box::new(captured)),
        Err(_) => ReceiptCapture::Failed(ScanFinding::new(
            "scan.receipt_capture_failed",
            FindingSeverity::Attention,
            subject,
            vec![],
            "correct the managed destination source and scan again",
        )),
    }
}

fn capture_agent_receipt_destination(
    destination: &NormalizedDestination,
    subject: FindingSubject,
    budget: &mut ScanBudget,
) -> ReceiptCapture {
    match no_follow_kind(destination) {
        Ok(SafePathKind::Missing) => {
            return ReceiptCapture::Missing(ScanFinding::new(
                "scan.receipt_destination_missing",
                FindingSeverity::Attention,
                subject,
                vec![],
                "restore the managed destination or plan its removal",
            ));
        }
        Ok(SafePathKind::RegularFile) => {}
        Ok(SafePathKind::Directory | SafePathKind::Other) | Err(()) => {
            return ReceiptCapture::Failed(ScanFinding::new(
                "scan.receipt_destination_unsafe",
                FindingSeverity::Attention,
                subject,
                vec![],
                "replace the unsafe destination with a regular agent file before rescanning",
            ));
        }
    }
    let limits = budget.remaining_capture_limits();
    let max_bytes = limits
        .max_file_bytes
        .min(limits.max_total_bytes)
        .min(budget.remaining_bytes());
    if max_bytes == 0 || !budget.try_file_attempt() {
        return ReceiptCapture::Failed(ScanFinding::new(
            "scan.capture_budget_exhausted",
            FindingSeverity::Attention,
            subject,
            vec![],
            "reduce capture work or increase request capture capacity",
        ));
    }
    let read_limit = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    match read_bounded_regular_file_with_mode(Path::new(destination.as_str()), read_limit) {
        Ok(file) => {
            let byte_count = u64::try_from(file.bytes.len()).unwrap_or(u64::MAX);
            if !budget.try_charge_bytes(byte_count) {
                return ReceiptCapture::Failed(ScanFinding::new(
                    "scan.capture_budget_exhausted",
                    FindingSeverity::Attention,
                    subject,
                    vec![],
                    "reduce capture work or increase request capture capacity",
                ));
            }
            ReceiptCapture::Agent(hash_agent_target(&file.bytes, file.mode))
        }
        Err(ReadOnlyFileError::Missing) => ReceiptCapture::Missing(ScanFinding::new(
            "scan.receipt_destination_missing",
            FindingSeverity::Attention,
            subject,
            vec![],
            "restore the managed destination or plan its removal",
        )),
        Err(ReadOnlyFileError::Unsafe | ReadOnlyFileError::Limit) => {
            ReceiptCapture::Failed(ScanFinding::new(
                "scan.receipt_capture_failed",
                FindingSeverity::Attention,
                subject,
                vec![],
                "correct the managed agent destination and scan again",
            ))
        }
    }
}

fn receipt_agent_identity(
    receipt: &kitrove_model::DeploymentReceipt,
) -> Option<(NativeAgentDialect, AgentName)> {
    let dialect = agent_dialect(&receipt.harness)?;
    let extension = format!(".{}", agent_document_extension(dialect));
    let name = Path::new(receipt.destination.as_str())
        .file_name()?
        .to_str()?
        .strip_suffix(&extension)?;
    Some((dialect, AgentName::parse(name).ok()?))
}

fn contextual_invalid_receipt(
    receipt_id: ReceiptId,
    receipt: &kitrove_model::DeploymentReceipt,
) -> InvalidReceipt {
    let scope = ReceiptInvalidityScope::Destination {
        harness: receipt.harness.clone(),
        scope: receipt.scope,
        normalized_destination: receipt.destination.clone(),
    };
    InvalidReceipt {
        finding: ScanFinding::new(
            "scan.receipt_invalid",
            FindingSeverity::Attention,
            destination_subject(&receipt.harness, receipt.scope, &receipt.destination),
            vec![],
            "repair or remove the invalid machine-local receipt before trusting ownership absence",
        ),
        receipt_id: Some(receipt_id),
        scope,
    }
}

fn invalidity_matches_observation(
    invalidity: &ReceiptInvalidityScope,
    observation: &ObservedCandidate,
) -> bool {
    let location = observation.location();
    match invalidity {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => {
            location.harness == *harness
                && location.scope == *scope
                && observation.normalized_destination() == Some(normalized_destination)
        }
        ReceiptInvalidityScope::HarnessScope { harness, scope } => {
            location.harness == *harness && location.scope == *scope
        }
        ReceiptInvalidityScope::Harness(harness) => location.harness == *harness,
        ReceiptInvalidityScope::Report => true,
    }
}

fn invalidity_matches_agent(invalidity: &ReceiptInvalidityScope, entry: &AgentScanEntry) -> bool {
    match invalidity {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => {
            entry.harness == *harness
                && entry.scope == *scope
                && entry.normalized_destination.as_ref() == Some(normalized_destination)
        }
        ReceiptInvalidityScope::HarnessScope { harness, scope } => {
            entry.harness == *harness && entry.scope == *scope
        }
        ReceiptInvalidityScope::Harness(harness) => entry.harness == *harness,
        ReceiptInvalidityScope::Report => true,
    }
}

fn invalidity_matches_receipt(
    invalidity: &ReceiptInvalidityScope,
    receipt: &kitrove_model::DeploymentReceipt,
) -> bool {
    match invalidity {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => {
            receipt.harness == *harness
                && receipt.scope == *scope
                && receipt.destination == *normalized_destination
        }
        ReceiptInvalidityScope::HarnessScope { .. }
        | ReceiptInvalidityScope::Harness(_)
        | ReceiptInvalidityScope::Report => false,
    }
}

fn invalidity_selected(invalidity: &ReceiptInvalidityScope, request: &ScanRequest<'_>) -> bool {
    match invalidity {
        ReceiptInvalidityScope::Destination { harness, scope, .. }
        | ReceiptInvalidityScope::HarnessScope { harness, scope } => {
            request.harnesses.contains(harness) && scope_selected(request.scopes, *scope)
        }
        ReceiptInvalidityScope::Harness(harness) => request.harnesses.contains(harness),
        ReceiptInvalidityScope::Report => true,
    }
}

fn invalidity_sort_key(scope: &ReceiptInvalidityScope) -> (u8, String, String, String) {
    match scope {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => (
            0,
            harness.as_str().to_owned(),
            scope.as_str().to_owned(),
            normalized_destination.as_str().to_owned(),
        ),
        ReceiptInvalidityScope::HarnessScope { harness, scope } => (
            1,
            harness.as_str().to_owned(),
            scope.as_str().to_owned(),
            String::new(),
        ),
        ReceiptInvalidityScope::Harness(harness) => {
            (2, harness.as_str().to_owned(), String::new(), String::new())
        }
        ReceiptInvalidityScope::Report => (3, String::new(), String::new(), String::new()),
    }
}

fn project_boundary_destination(
    request: &ScanRequest<'_>,
    destination: &NormalizedDestination,
) -> bool {
    match &request.project_boundary {
        ProjectBoundary::Repository { root } => normalize_path(root)
            .is_some_and(|boundary| destination_contained(destination, &boundary)),
        ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => false,
    }
}

fn destination_contained(
    destination: &NormalizedDestination,
    anchor: &NormalizedDestination,
) -> bool {
    Path::new(destination.as_str()).starts_with(Path::new(anchor.as_str()))
}

pub(crate) fn normalize_path(path: &Path) -> Option<NormalizedDestination> {
    normalized_destination_from_path(path).ok()
}

fn has_markdown_extension(destination: &NormalizedDestination) -> bool {
    Path::new(destination.as_str())
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("md")
}

fn scope_selected(selection: ScopeSelection, scope: HarnessScope) -> bool {
    matches!(selection, ScopeSelection::All)
        || matches!(
            (selection, scope),
            (ScopeSelection::User, HarnessScope::User)
                | (ScopeSelection::Project, HarnessScope::Project)
        )
}

fn destination_subject(
    harness: &HarnessId,
    scope: HarnessScope,
    destination: &NormalizedDestination,
) -> FindingSubject {
    FindingSubject::Destination {
        harness: harness.clone(),
        scope,
        normalized_destination: destination.clone(),
    }
}

fn environment_invalid_finding() -> ScanFinding {
    ScanFinding::new(
        "scan.environment_invalid",
        FindingSeverity::Attention,
        FindingSubject::Report,
        vec![],
        "repair the portable environment before trusting ownership classification",
    )
}

fn local_state_invalid_finding() -> ScanFinding {
    ScanFinding::new(
        "scan.local_state_invalid",
        FindingSeverity::Attention,
        FindingSubject::Report,
        vec![],
        "repair the machine-local state before trusting ownership absence",
    )
}

fn anchor_invalid_finding(harness: &HarnessId) -> ScanFinding {
    ScanFinding::new(
        "scan.receipt_anchor_invalid",
        FindingSeverity::Attention,
        FindingSubject::Harness(harness.clone()),
        vec![],
        "use the compiled no-follow-safe materialization destination policy",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SafePathKind {
    Directory,
    RegularFile,
    Missing,
    Other,
}

fn no_follow_kind(destination: &NormalizedDestination) -> Result<SafePathKind, ()> {
    let path = Path::new(destination.as_str());
    let (anchor, components) = split_absolute_root(path)?;
    let mut directory = Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|_| ())?;
    let metadata = directory.dir_metadata().map_err(|_| ())?;
    if !safe_metadata(&metadata) || !metadata.is_dir() {
        return Ok(SafePathKind::Other);
    }
    if components.is_empty() {
        return Ok(SafePathKind::Directory);
    }
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let metadata = match directory.symlink_metadata(component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(SafePathKind::Missing),
            Err(_) => return Err(()),
        };
        if !safe_metadata(&metadata) {
            return Ok(SafePathKind::Other);
        }
        if last {
            if metadata.is_file() {
                return Ok(SafePathKind::RegularFile);
            }
            if !metadata.is_dir() {
                return Ok(SafePathKind::Other);
            }
            let opened = directory.open_dir_nofollow(component).map_err(|_| ())?;
            let opened_metadata = opened.dir_metadata().map_err(|_| ())?;
            return if safe_metadata(&opened_metadata)
                && opened_metadata.is_dir()
                && same_file(&metadata, &opened_metadata)
            {
                Ok(SafePathKind::Directory)
            } else {
                Ok(SafePathKind::Other)
            };
        }
        if !metadata.is_dir() {
            return Ok(SafePathKind::Other);
        }
        let child = directory.open_dir_nofollow(component).map_err(|_| ())?;
        let opened = child.dir_metadata().map_err(|_| ())?;
        if !safe_metadata(&opened) || !opened.is_dir() || !same_file(&metadata, &opened) {
            return Ok(SafePathKind::Other);
        }
        directory = child;
    }
    Err(())
}

fn split_absolute_root(path: &Path) -> Result<(PathBuf, Vec<OsString>), ()> {
    if raw_parent_component(path) {
        return Err(());
    }
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => return Err(()),
            Component::Normal(component) if component == OsStr::new(".") => {}
            Component::Normal(component) if component == OsStr::new("..") => return Err(()),
            Component::Normal(component) => components.push(component.to_owned()),
        }
    }
    (!anchor.as_os_str().is_empty())
        .then_some((anchor, components))
        .ok_or(())
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

fn safe_metadata(metadata: &Metadata) -> bool {
    !metadata.is_symlink() && !metadata_is_windows_reparse(metadata)
}

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &Metadata) -> bool {
    use cap_fs_ext::OsMetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn metadata_is_windows_reparse(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use kitrove_adapter_api::ScanLimits;

    fn request(boundary: ProjectBoundary) -> ScanRequest<'static> {
        ScanRequest {
            home: None,
            working_directory: PathBuf::from("/workspace/project"),
            project_boundary: boundary,
            harnesses: BTreeSet::new(),
            scopes: ScopeSelection::Project,
            explicit_roots: vec![],
            supplied_native_roots: vec![],
            versions: BTreeMap::new(),
            project_trust: BTreeMap::new(),
            environment: None,
            local_state: None,
            limits: ScanLimits::default(),
        }
    }

    #[test]
    fn absence_and_unsafe_stop_do_not_grant_project_destination_authority() {
        let destination = NormalizedDestination::parse("/workspace/project/.agents/skills")
            .expect("fixture destination is normalized");

        assert!(!project_boundary_destination(
            &request(ProjectBoundary::NoRepository),
            &destination
        ));
        assert!(!project_boundary_destination(
            &request(ProjectBoundary::UnsafeStop),
            &destination
        ));
    }

    #[test]
    fn unsafe_stop_rejects_project_receipt_anchor_authority_during_classification() {
        let request = request(ProjectBoundary::UnsafeStop);
        let policies = [ReceiptPolicyEvidence {
            harness: HarnessId::Pi,
            anchors: vec![AssetReceiptAnchor {
                kind: AssetKind::Skill,
                anchor: ReceiptAnchor {
                    scope: HarnessScope::Project,
                    path: request.working_directory.join(".agents/skills"),
                    evidence: EvidenceRef::parse("test.pi.project-anchor").unwrap(),
                },
            }],
            failed_kinds: BTreeSet::new(),
        }];
        let mut findings = Vec::new();
        let mut budget = ScanBudget::new(request.limits);

        let (anchors, invalid) =
            validate_anchors(&request, &policies, &mut findings, &mut budget).unwrap();

        assert!(invalid);
        assert!(anchors.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "scan.receipt_anchor_invalid");
        assert_eq!(findings[0].subject, FindingSubject::Harness(HarnessId::Pi));
    }
}
