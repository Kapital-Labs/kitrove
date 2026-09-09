use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Read as _};
#[cfg(windows)]
use std::path::Prefix;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{
    DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _,
    OpenOptionsSyncExt as _,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions};
use kitrove_adapter_api::{
    EnvironmentInput, ExplicitRoot, FindingSeverity, FindingSubject, LocalStateInput,
    ProjectBoundary, ScanFinding, ScanLimits, ScanRequest, ScopeSelection, TargetAnchor,
};
use kitrove_core::{
    InstructionDocumentObservation, InstructionScanEntry, McpDocumentObservation, McpPrecedence,
    McpScanEntry, PolicyRegistry, ReceiptIndex, ReceiptInspection, ReceiptInvalidityScope,
    ScanBudget, ScanClassification, ScanEngine, ScanReport, classify_instruction_region,
    derive_manifest_revision, observe_instruction_document_metered, observe_mcp_document_metered,
    render_scan_json, render_scan_text,
};
use kitrove_mcp::{McpParseLimits, McpPortability};
use kitrove_model::{
    AssetKind, EnvironmentManifest, HarnessId, HarnessScope, ReceiptTarget, Revision,
};

use crate::adapters::{instruction_target_policy, mcp_target_policy};
use crate::args::{CliError, ScanArgs};

const MANIFEST_NAME: &str = "kitrove.toml";
const STATE_NAME: &str = "state.json";

pub(crate) struct CompletedScan {
    pub output: String,
    pub status: u8,
}

pub(crate) fn run_scan(
    arguments: ScanArgs,
    registry: &PolicyRegistry,
) -> Result<CompletedScan, CliError> {
    let json = arguments.json;
    let report = scan_report(arguments, registry)?;
    let status = if report_needs_attention(&report) {
        3
    } else {
        0
    };
    let output = if json {
        render_scan_json(&report).map_err(|_| {
            CliError::new(
                "scan.serialization_failed",
                "the scan report could not be serialized",
            )
        })?
    } else {
        render_scan_text(&report)
    };
    Ok(CompletedScan { output, status })
}

pub(crate) fn scan_report(
    arguments: ScanArgs,
    registry: &PolicyRegistry,
) -> Result<ScanReport, CliError> {
    let working_directory = env::current_dir().map_err(|_| context_unavailable())?;
    let working_directory = normalize_absolute(&working_directory, &working_directory)
        .map_err(|_| context_unavailable())?;
    let resolved_home = resolve_home(&working_directory);
    if resolved_home.is_none()
        && arguments.roots.is_empty()
        && matches!(arguments.scope, ScopeSelection::User)
    {
        return Err(context_unavailable());
    }

    let project_boundary =
        resolve_project_boundary(arguments.project_root.as_deref(), &working_directory)?;
    let explicit_roots = normalize_explicit_roots(
        arguments.roots,
        &working_directory,
        &arguments.harnesses,
        arguments.scope,
    )?;
    let limits = ScanLimits::default();

    let environment_source =
        resolve_environment_source(arguments.environment.as_deref(), &working_directory)?;
    let loaded_environment = load_optional_input(environment_source.as_deref(), limits);
    let state_source = resolve_state_source(resolved_home.as_deref(), &working_directory);
    let loaded_state = load_optional_input(state_source.as_deref(), limits);

    let environment = loaded_environment.as_ref().map(|loaded| match loaded {
        LoadedInput::Bytes { path, bytes } => EnvironmentInput {
            source_path: path.clone(),
            toml_bytes: bytes,
        },
        LoadedInput::Unsafe { path } => EnvironmentInput {
            source_path: path.clone(),
            toml_bytes: &[],
        },
    });
    let local_state = loaded_state.as_ref().map(|loaded| match loaded {
        LoadedInput::Bytes { path, bytes } => LocalStateInput::Bytes {
            source_path: path.clone(),
            json_bytes: bytes,
        },
        LoadedInput::Unsafe { .. } => LocalStateInput::Unsafe,
    });
    let composition_context = ScanCompositionContext {
        home: resolved_home.clone(),
        project_boundary: project_boundary.clone(),
        harnesses: arguments.harnesses.clone(),
        scopes: arguments.scope,
    };
    let receipt_authority = inspect_receipts(
        loaded_state.as_ref(),
        inspected_manifest_authority(loaded_environment.as_ref()),
    );
    let request = ScanRequest {
        home: resolved_home,
        working_directory,
        project_boundary,
        harnesses: arguments.harnesses,
        scopes: arguments.scope,
        explicit_roots,
        supplied_native_roots: vec![],
        versions: BTreeMap::new(),
        project_trust: BTreeMap::new(),
        environment,
        local_state,
        limits,
    };

    let mut report = ScanEngine::from_registry(registry)
        .scan(&request)
        .map_err(|_| {
            CliError::new(
                "scan.failed",
                "the read-only scan could not produce a trustworthy report",
            )
        })?;
    let mut budget = ScanBudget::with_usage(
        limits,
        report.capture_usage().clone(),
        report_entry_count(&report),
        report_finding_count(&report),
    )
    .ok_or_else(scan_budget_limit)?;
    let instruction_scan =
        scan_instructions(&composition_context, &receipt_authority, &mut budget)?;
    report.findings.extend(instruction_scan.findings);
    report.set_instructions(
        instruction_scan.entries,
        instruction_scan.observations,
        budget.capture_usage().clone(),
    );
    let mcp_scan = scan_mcp_documents(&composition_context, &receipt_authority, &mut budget)?;
    report.findings.extend(mcp_scan.findings);
    report.set_mcp_servers(
        mcp_scan.entries,
        mcp_scan.observations,
        budget.capture_usage().clone(),
    );
    Ok(report)
}

enum ReceiptAuthority {
    Absent,
    Available {
        inspection: ReceiptInspection,
        manifest: Option<InstructionManifestAuthority>,
    },
    Unavailable,
}

struct ScanCompositionContext {
    home: Option<PathBuf>,
    project_boundary: ProjectBoundary,
    harnesses: BTreeSet<HarnessId>,
    scopes: ScopeSelection,
}

struct InstructionScanResults {
    entries: Vec<InstructionScanEntry>,
    observations: Vec<InstructionDocumentObservation>,
    findings: Vec<ScanFinding>,
}

struct McpScanResults {
    entries: Vec<McpScanEntry>,
    observations: Vec<McpDocumentObservation>,
    findings: Vec<ScanFinding>,
}

struct PendingMcpEntry {
    native_name: String,
    entry: McpScanEntry,
}

struct InstructionManifestAuthority {
    manifest: EnvironmentManifest,
    revision: Revision,
}

fn inspect_receipts(
    state: Option<&LoadedInput>,
    manifest: Option<InstructionManifestAuthority>,
) -> ReceiptAuthority {
    match state {
        None => ReceiptAuthority::Absent,
        Some(LoadedInput::Unsafe { .. }) => ReceiptAuthority::Unavailable,
        Some(LoadedInput::Bytes { bytes, .. }) => ReceiptIndex::inspect_json(bytes)
            .map(|inspection| ReceiptAuthority::Available {
                inspection,
                manifest,
            })
            .unwrap_or(ReceiptAuthority::Unavailable),
    }
}

fn inspected_manifest_authority(
    environment: Option<&LoadedInput>,
) -> Option<InstructionManifestAuthority> {
    let LoadedInput::Bytes { bytes, .. } = environment? else {
        return None;
    };
    let manifest = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| EnvironmentManifest::from_toml(text).ok())?;
    let revision = derive_manifest_revision(&manifest).ok()?;
    Some(InstructionManifestAuthority { manifest, revision })
}

fn scan_instructions(
    context: &ScanCompositionContext,
    receipts: &ReceiptAuthority,
    budget: &mut ScanBudget,
) -> Result<InstructionScanResults, CliError> {
    let mut entries = Vec::new();
    let mut observations = Vec::new();
    let mut unverified = BTreeSet::new();
    let mut findings = Vec::new();
    for harness in &context.harnesses {
        for scope in selected_scopes(context.scopes) {
            let Some(anchor) = scoped_anchor(context, scope) else {
                continue;
            };
            let policy = match instruction_target_policy(harness, scope) {
                Ok(policy) => policy,
                Err(error) if error.code == "apply.harness_version_unverified" => {
                    unverified.insert(harness.clone());
                    continue;
                }
                Err(error) => return Err(error),
            };
            let observation = match observe_instruction_document_metered(
                &anchor,
                &policy,
                Default::default(),
                budget,
            ) {
                Ok(observation) => observation,
                Err(error) if error.code() == "instruction.capture_limit" => {
                    return Err(CliError::new(error.code(), error.message()));
                }
                Err(error) => {
                    findings.push(instruction_observation_finding(harness, &policy, &error));
                    continue;
                }
            };
            entries.extend(instruction_entries(&observation, receipts, budget)?);
            observations.push(observation);
        }
    }
    findings.extend(unverified.into_iter().map(|harness| {
        ScanFinding::new(
            "instruction.policy_unverified",
            FindingSeverity::Attention,
            FindingSubject::Harness(harness),
            Vec::new(),
            "verify the harness version before scanning standing instructions",
        )
    }));
    if !budget.try_report_findings(findings.len()) {
        return Err(scan_budget_limit());
    }
    Ok(InstructionScanResults {
        entries,
        observations,
        findings,
    })
}

fn scan_mcp_documents(
    context: &ScanCompositionContext,
    authority: &ReceiptAuthority,
    budget: &mut ScanBudget,
) -> Result<McpScanResults, CliError> {
    let mut pending = Vec::new();
    let mut observations = Vec::new();
    let mut findings = Vec::new();
    let mut unverified = BTreeSet::new();

    for harness in &context.harnesses {
        for scope in selected_scopes(context.scopes) {
            let policy = match mcp_target_policy(harness, scope) {
                Ok(policy) => policy,
                Err(error) if error.code == "apply.mcp_target_unsupported" => continue,
                Err(error) if error.code == "apply.harness_version_unverified" => {
                    unverified.insert(harness.clone());
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Some(anchor) = mcp_anchor(context, scope, policy.anchor) else {
                findings.push(ScanFinding::new(
                    "mcp.configuration_anchor_unavailable",
                    FindingSeverity::Attention,
                    FindingSubject::Harness(harness.clone()),
                    vec![policy.evidence.clone()],
                    "verify the harness configuration root before scanning this MCP document",
                ));
                continue;
            };
            let observation = match observe_mcp_document_metered(
                &anchor,
                &policy,
                McpParseLimits::default(),
                budget,
            ) {
                Ok(observation) => observation,
                Err(error) if error.code() == "mcp.capture_limit" => {
                    return Err(CliError::new(error.code(), error.message()));
                }
                Err(error) => {
                    findings.push(mcp_observation_finding(harness, &policy, &error));
                    continue;
                }
            };
            let receipts = mcp_receipts(authority, &observation);
            let invalid_findings = invalid_receipt_findings(
                authority,
                observation.harness(),
                observation.scope(),
                observation.destination(),
            );
            let mut observed_names = BTreeSet::new();
            if let Some(document) = observation.parsed() {
                for observed in document.entries() {
                    observed_names.insert(observed.native_name().to_owned());
                    let (portable_name, block_reasons) = match observed.portability() {
                        McpPortability::Portable(projection) => {
                            (Some(projection.name().as_str().to_owned()), Vec::new())
                        }
                        McpPortability::Blocked(reasons) => {
                            (None, reasons.iter().copied().collect())
                        }
                    };
                    let receipt = receipts.iter().find(|record| {
                        record.receipt.logical_key.as_deref() == Some(observed.native_name())
                    });
                    let mut entry_findings = invalid_findings.clone();
                    if let Some(record) = receipt {
                        if !mcp_receipt_matches_manifest(authority, &record.receipt, &policy) {
                            entry_findings.push(instruction_receipt_finding(
                                "mcp.receipt_manifest_stale",
                                &record.receipt_id,
                                "reapply the MCP asset before trusting this receipt",
                            ));
                        }
                    }
                    if !block_reasons.is_empty() {
                        entry_findings.push(ScanFinding::new(
                            "mcp.portable_projection_blocked",
                            FindingSeverity::Attention,
                            FindingSubject::Destination {
                                harness: harness.clone(),
                                scope,
                                normalized_destination: observation.destination().clone(),
                            },
                            vec![policy.evidence.clone()],
                            "review the retained native MCP fields before adopting this declaration",
                        ));
                    }
                    let classification = classify_mcp_entry(
                        authority,
                        &entry_findings,
                        receipt.copied(),
                        Some(observed.exact_entry_hash()),
                    );
                    if !budget.try_report_entry(entry_findings.len()) {
                        return Err(scan_budget_limit());
                    }
                    pending.push(PendingMcpEntry {
                        native_name: observed.native_name().to_owned(),
                        entry: McpScanEntry {
                            harness: harness.clone(),
                            scope,
                            policy_line: policy.policy_line,
                            destination: observation.destination().clone(),
                            dialect: policy.dialect,
                            portable_name,
                            exact_entry_hash: Some(observed.exact_entry_hash().clone()),
                            exact_document_hash: Some(document.exact_document_hash().clone()),
                            content_class: observed.content_class(),
                            block_reasons,
                            precedence: McpPrecedence::Effective,
                            shadowed_by: None,
                            classification,
                            findings: entry_findings,
                        },
                    });
                }
            }
            for record in receipts.iter().filter(|record| {
                record
                    .receipt
                    .logical_key
                    .as_ref()
                    .is_some_and(|name| !observed_names.contains(name))
            }) {
                let Some(native_name) = record.receipt.logical_key.clone() else {
                    continue;
                };
                let mut entry_findings = invalid_findings.clone();
                if !mcp_receipt_matches_manifest(authority, &record.receipt, &policy) {
                    entry_findings.push(instruction_receipt_finding(
                        "mcp.receipt_manifest_stale",
                        &record.receipt_id,
                        "reapply the MCP asset before trusting this receipt",
                    ));
                }
                let classification =
                    classify_mcp_entry(authority, &entry_findings, Some(record), None);
                if !budget.try_report_entry(entry_findings.len()) {
                    return Err(scan_budget_limit());
                }
                pending.push(PendingMcpEntry {
                    native_name: native_name.clone(),
                    entry: McpScanEntry {
                        harness: harness.clone(),
                        scope,
                        policy_line: policy.policy_line,
                        destination: observation.destination().clone(),
                        dialect: policy.dialect,
                        portable_name: Some(native_name),
                        exact_entry_hash: None,
                        exact_document_hash: observation
                            .parsed()
                            .map(|document| document.exact_document_hash().clone()),
                        content_class: kitrove_model::ContentClass::AgentActive,
                        block_reasons: Vec::new(),
                        precedence: McpPrecedence::Effective,
                        shadowed_by: None,
                        classification,
                        findings: entry_findings,
                    },
                });
            }
            observations.push(observation);
        }
    }
    findings.extend(unverified.into_iter().map(|harness| {
        ScanFinding::new(
            "mcp.policy_unverified",
            FindingSeverity::Attention,
            FindingSubject::Harness(harness),
            Vec::new(),
            "verify the harness version before scanning its MCP configuration",
        )
    }));
    apply_mcp_precedence(&mut pending);
    if !budget.try_report_findings(findings.len()) {
        return Err(scan_budget_limit());
    }
    Ok(McpScanResults {
        entries: pending.into_iter().map(|pending| pending.entry).collect(),
        observations,
        findings,
    })
}

fn apply_mcp_precedence(entries: &mut [PendingMcpEntry]) {
    let mut groups = BTreeMap::<(HarnessId, String), Vec<usize>>::new();
    for (index, pending) in entries.iter().enumerate() {
        groups
            .entry((pending.entry.harness.clone(), pending.native_name.clone()))
            .or_default()
            .push(index);
    }
    for indices in groups.values() {
        if indices.len() < 2 {
            continue;
        }
        let effective_scope = if indices
            .iter()
            .any(|index| entries[*index].entry.scope == HarnessScope::Project)
        {
            HarnessScope::Project
        } else {
            HarnessScope::User
        };
        let effective = indices
            .iter()
            .copied()
            .filter(|index| entries[*index].entry.scope == effective_scope)
            .collect::<Vec<_>>();
        if effective.len() != 1 {
            for index in indices {
                entries[*index].entry.precedence = McpPrecedence::Ambiguous;
                entries[*index].entry.classification = ScanClassification::ConflictingDuplicate;
            }
            continue;
        }
        let effective_hash = entries[effective[0]].entry.exact_entry_hash.clone();
        for index in indices {
            if *index != effective[0] {
                entries[*index].entry.precedence = McpPrecedence::Shadowed;
                entries[*index].entry.shadowed_by = effective_hash.clone();
            }
        }
    }
}

fn classify_mcp_entry(
    authority: &ReceiptAuthority,
    findings: &[ScanFinding],
    receipt: Option<&kitrove_core::InspectedReceipt>,
    exact_entry_hash: Option<&kitrove_model::ContentHash>,
) -> ScanClassification {
    if matches!(authority, ReceiptAuthority::Unavailable) || !findings.is_empty() {
        return ScanClassification::Unknown;
    }
    match (receipt, exact_entry_hash) {
        (None, Some(_)) => ScanClassification::Unmanaged,
        (Some(_), None) => ScanClassification::MissingManaged,
        (Some(record), Some(hash)) if hash == &record.receipt.rendered_hash => {
            ScanClassification::ManagedUnchanged
        }
        (Some(_), Some(_)) => ScanClassification::ManagedModified,
        (None, None) => ScanClassification::Unknown,
    }
}

fn mcp_receipts<'a>(
    authority: &'a ReceiptAuthority,
    observation: &McpDocumentObservation,
) -> Vec<&'a kitrove_core::InspectedReceipt> {
    let ReceiptAuthority::Available { inspection, .. } = authority else {
        return Vec::new();
    };
    inspection
        .valid
        .iter()
        .filter(|record| {
            let receipt = &record.receipt;
            receipt.target == ReceiptTarget::ManagedMcpEntry
                && receipt.harness == *observation.harness()
                && receipt.scope == observation.scope()
                && receipt.destination == *observation.destination()
        })
        .collect()
}

fn mcp_receipt_matches_manifest(
    authority: &ReceiptAuthority,
    receipt: &kitrove_model::DeploymentReceipt,
    policy: &kitrove_adapter_api::McpTargetPolicy,
) -> bool {
    let ReceiptAuthority::Available {
        manifest: Some(authority),
        ..
    } = authority
    else {
        return false;
    };
    authority.revision == receipt.environment_revision
        && receipt.adapter_version == policy.adapter_version
        && receipt.logical_key.is_some()
        && authority
            .manifest
            .assets
            .get(&receipt.asset_id)
            .is_some_and(|asset| {
                asset.kind == AssetKind::Mcp
                    && asset.content_hash == receipt.source_hash
                    && asset
                        .compatibility
                        .get(&receipt.harness)
                        .is_some_and(|compatibility| {
                            compatibility.adapter_version() == receipt.adapter_version
                        })
            })
}

fn mcp_anchor(
    context: &ScanCompositionContext,
    scope: HarnessScope,
    anchor: TargetAnchor,
) -> Option<PathBuf> {
    match anchor {
        TargetAnchor::Scope => scoped_anchor(context, scope),
        TargetAnchor::HarnessConfiguration => None,
    }
}

fn mcp_observation_finding(
    harness: &HarnessId,
    policy: &kitrove_adapter_api::McpTargetPolicy,
    error: &kitrove_core::McpObservationError,
) -> ScanFinding {
    let action = match error.code() {
        "mcp.document_unsafe" => "replace the unsafe MCP target with a bounded regular file",
        "mcp.document_limit" => "reduce the MCP document below the configured scan limit",
        _ => "repair the malformed MCP configuration before scanning it again",
    };
    ScanFinding::new(
        error.code(),
        FindingSeverity::Attention,
        FindingSubject::Harness(harness.clone()),
        vec![policy.evidence.clone()],
        action,
    )
}

fn instruction_observation_finding(
    harness: &HarnessId,
    policy: &kitrove_adapter_api::InstructionTargetPolicy,
    error: &kitrove_core::InstructionObservationError,
) -> ScanFinding {
    let action = match error.code() {
        "instruction.document_unsafe" => {
            "replace the unsafe instruction target with a bounded regular file"
        }
        "instruction.document_limit" => {
            "reduce the instruction document below the configured scan limit"
        }
        "instruction.document_invalid" => {
            "repair the malformed Kitrove instruction-region structure"
        }
        _ => "review the compiled instruction policy before scanning this target",
    };
    ScanFinding::new(
        error.code(),
        FindingSeverity::Attention,
        FindingSubject::Harness(harness.clone()),
        vec![policy.evidence.clone()],
        action,
    )
}

fn scan_budget_limit() -> CliError {
    CliError::new(
        "scan.report_budget_exhausted",
        "instruction observation exhausted a request-wide scan limit",
    )
}

fn report_entry_count(report: &ScanReport) -> usize {
    report
        .entries
        .len()
        .saturating_add(report.related.len())
        .saturating_add(report.native_extensions.len())
        .saturating_add(report.prompt_commands.len())
        .saturating_add(report.agents.len())
        .saturating_add(report.instructions.len())
        .saturating_add(report.mcp_servers.len())
}

fn report_finding_count(report: &ScanReport) -> usize {
    report
        .entries
        .iter()
        .map(|entry| entry.findings.len())
        .chain(report.related.iter().map(|entry| entry.findings.len()))
        .chain(
            report
                .native_extensions
                .iter()
                .map(|entry| entry.findings.len()),
        )
        .chain(
            report
                .prompt_commands
                .iter()
                .map(|entry| entry.findings.len()),
        )
        .chain(report.agents.iter().map(|entry| entry.findings.len()))
        .chain(report.instructions.iter().map(|entry| entry.findings.len()))
        .chain(report.mcp_servers.iter().map(|entry| entry.findings.len()))
        .fold(report.findings.len(), usize::saturating_add)
}

fn selected_scopes(selection: ScopeSelection) -> impl Iterator<Item = HarnessScope> {
    [HarnessScope::User, HarnessScope::Project]
        .into_iter()
        .filter(move |scope| scope_selected(selection, *scope))
}

fn scoped_anchor(context: &ScanCompositionContext, scope: HarnessScope) -> Option<PathBuf> {
    match scope {
        HarnessScope::User => context.home.clone(),
        HarnessScope::Project => match &context.project_boundary {
            ProjectBoundary::Repository { root } => Some(root.clone()),
            ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => None,
        },
    }
}

fn instruction_entries(
    observation: &InstructionDocumentObservation,
    authority: &ReceiptAuthority,
    budget: &mut ScanBudget,
) -> Result<Vec<InstructionScanEntry>, CliError> {
    let valid_receipts = match authority {
        ReceiptAuthority::Available { inspection, .. } => inspection
            .valid
            .iter()
            .filter(|record| receipt_matches_observation(&record.receipt, observation))
            .collect::<Vec<_>>(),
        ReceiptAuthority::Absent | ReceiptAuthority::Unavailable => Vec::new(),
    };
    let mut assets = observation
        .regions()
        .map(|region| region.asset_id().clone())
        .collect::<BTreeSet<_>>();
    assets.extend(
        valid_receipts
            .iter()
            .map(|record| record.receipt.asset_id.clone()),
    );
    let invalid_findings = invalid_instruction_findings(authority, observation);
    let mut entries = Vec::with_capacity(assets.len());
    for asset_id in assets {
        let receipt = valid_receipts
            .iter()
            .find(|record| record.receipt.asset_id == asset_id);
        let mut findings = invalid_findings.clone();
        if let Some(record) = receipt {
            if !instruction_receipt_matches_manifest(authority, &record.receipt) {
                findings.push(instruction_receipt_finding(
                    "instruction.receipt_manifest_stale",
                    &record.receipt_id,
                    "reapply the instruction asset before trusting this receipt",
                ));
            }
        }
        let classified = classify_instruction_region(
            observation,
            &asset_id,
            receipt.map(|record| &record.receipt),
        );
        if let (Err(_), Some(record)) = (&classified, receipt) {
            findings.push(instruction_receipt_finding(
                "instruction.receipt_policy_stale",
                &record.receipt_id,
                "reapply the instruction asset with the current adapter policy",
            ));
        }
        let receipt_authority_uncertain =
            matches!(authority, ReceiptAuthority::Unavailable) || !findings.is_empty();
        let classification = if receipt_authority_uncertain {
            ScanClassification::Unknown
        } else {
            classified
                .map_err(|error| CliError::new(error.code(), error.message()))?
                .unwrap_or(ScanClassification::Unknown)
        };
        let region = observation.region(&asset_id);
        if !budget.try_report_entry(findings.len()) {
            return Err(scan_budget_limit());
        }
        entries.push(InstructionScanEntry {
            harness: observation.harness().clone(),
            scope: observation.scope(),
            policy_line: observation.policy().policy_line,
            destination: observation.destination().clone(),
            asset_id,
            observation_revision: region.map(|region| region.observation_revision().clone()),
            exact_region_hash: region.map(|region| region.exact_region_hash().clone()),
            receipt_id: receipt.map(|record| record.receipt_id.clone()),
            classification,
            findings,
        });
    }
    Ok(entries)
}

fn instruction_receipt_matches_manifest(
    authority: &ReceiptAuthority,
    receipt: &kitrove_model::DeploymentReceipt,
) -> bool {
    match authority {
        ReceiptAuthority::Available {
            manifest: Some(authority),
            ..
        } => {
            authority.revision == receipt.environment_revision
                && authority
                    .manifest
                    .assets
                    .get(&receipt.asset_id)
                    .is_some_and(|asset| {
                        asset.kind == AssetKind::Instruction
                            && asset.content_hash == receipt.source_hash
                    })
        }
        ReceiptAuthority::Available { manifest: None, .. }
        | ReceiptAuthority::Absent
        | ReceiptAuthority::Unavailable => false,
    }
}

fn instruction_receipt_finding(
    code: &'static str,
    receipt_id: &kitrove_model::ReceiptId,
    action: &'static str,
) -> ScanFinding {
    ScanFinding::new(
        code,
        FindingSeverity::Attention,
        FindingSubject::Receipt(receipt_id.clone()),
        Vec::new(),
        action,
    )
}

fn receipt_matches_observation(
    receipt: &kitrove_model::DeploymentReceipt,
    observation: &InstructionDocumentObservation,
) -> bool {
    receipt.target == ReceiptTarget::ManagedInstructionRegion
        && receipt.scope == observation.scope()
        && receipt.destination == *observation.destination()
        && receipt
            .consumers()
            .any(|consumer| consumer == observation.harness())
}

fn invalid_instruction_findings(
    authority: &ReceiptAuthority,
    observation: &InstructionDocumentObservation,
) -> Vec<kitrove_adapter_api::ScanFinding> {
    invalid_receipt_findings(
        authority,
        observation.harness(),
        observation.scope(),
        observation.destination(),
    )
}

fn invalid_receipt_findings(
    authority: &ReceiptAuthority,
    harness: &HarnessId,
    selected_scope: HarnessScope,
    destination: &kitrove_model::NormalizedDestination,
) -> Vec<kitrove_adapter_api::ScanFinding> {
    match authority {
        ReceiptAuthority::Unavailable => Vec::new(),
        ReceiptAuthority::Absent => Vec::new(),
        ReceiptAuthority::Available { inspection, .. } => inspection
            .invalid
            .iter()
            .filter(|invalid| {
                invalid_scope_matches(&invalid.scope, harness, selected_scope, destination)
            })
            .map(|invalid| invalid.finding.clone())
            .collect(),
    }
}

fn invalid_scope_matches(
    scope: &ReceiptInvalidityScope,
    selected_harness: &HarnessId,
    selected_scope: HarnessScope,
    selected_destination: &kitrove_model::NormalizedDestination,
) -> bool {
    match scope {
        ReceiptInvalidityScope::Destination {
            harness,
            scope,
            normalized_destination,
        } => {
            harness == selected_harness
                && *scope == selected_scope
                && normalized_destination == selected_destination
        }
        ReceiptInvalidityScope::HarnessScope { harness, scope } => {
            harness == selected_harness && *scope == selected_scope
        }
        ReceiptInvalidityScope::Harness(harness) => harness == selected_harness,
        ReceiptInvalidityScope::Report => true,
    }
}

pub(crate) fn resolve_required_environment_root(
    explicit: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let working_directory = env::current_dir().map_err(|_| context_unavailable())?;
    let working_directory = normalize_absolute(&working_directory, &working_directory)
        .map_err(|_| context_unavailable())?;
    let manifest = resolve_environment_source(explicit, &working_directory)?.ok_or_else(|| {
        CliError::new(
            "cli.environment_missing",
            "no Kitrove environment was found; supply --environment or set KITROVE_ENV",
        )
    })?;
    manifest.parent().map(Path::to_path_buf).ok_or_else(|| {
        CliError::new(
            "cli.environment_invalid",
            "the selected Kitrove environment path is invalid",
        )
    })
}

pub(crate) fn resolve_required_state_root() -> Result<PathBuf, CliError> {
    let working_directory = env::current_dir().map_err(|_| context_unavailable())?;
    let working_directory = normalize_absolute(&working_directory, &working_directory)
        .map_err(|_| context_unavailable())?;
    let home = resolve_home(&working_directory);
    let state = resolve_state_source(home.as_deref(), &working_directory).ok_or_else(|| {
        CliError::new(
            "apply.local_state_missing",
            "no machine-local Kitrove state location is available",
        )
    })?;
    state.parent().map(Path::to_path_buf).ok_or_else(|| {
        CliError::new(
            "apply.local_state_invalid",
            "the machine-local Kitrove state path is invalid",
        )
    })
}

pub(crate) fn resolve_materialization_anchor(
    scope: HarnessScope,
    explicit_project: Option<&Path>,
) -> Result<PathBuf, CliError> {
    let working_directory = env::current_dir().map_err(|_| context_unavailable())?;
    let working_directory = normalize_absolute(&working_directory, &working_directory)
        .map_err(|_| context_unavailable())?;
    let anchor = match scope {
        HarnessScope::User => resolve_home(&working_directory).ok_or_else(|| {
            CliError::new(
                "apply.home_missing",
                "no safe user home is available for user-scope materialization",
            )
        })?,
        HarnessScope::Project => {
            match resolve_project_boundary(explicit_project, &working_directory)? {
                ProjectBoundary::Repository { root } => root,
                ProjectBoundary::NoRepository | ProjectBoundary::UnsafeStop => {
                    return Err(CliError::new(
                        "apply.project_root_missing",
                        "project scope requires a safe selected project root",
                    ));
                }
            }
        }
    };
    open_directory_nofollow(&anchor).map_err(|_| {
        CliError::new(
            "apply.target_anchor_unsafe",
            "the selected materialization anchor is not a safe local directory",
        )
    })?;
    Ok(anchor)
}

pub(crate) fn read_portable_text(
    environment_root: &Path,
    name: &str,
    max_bytes: usize,
) -> Result<Option<String>, CliError> {
    match read_bounded_nofollow(&environment_root.join(name), max_bytes) {
        InputRead::Absent => Ok(None),
        InputRead::Bytes(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| {
            CliError::new(
                "cli.portable_input_invalid",
                "a selected portable control file is not valid UTF-8",
            )
        }),
        InputRead::Unsafe => Err(CliError::new(
            "cli.portable_input_unsafe",
            "a selected portable control file could not be read safely",
        )),
    }
}

fn context_unavailable() -> CliError {
    CliError::new(
        "scan.context_unavailable",
        "no usable local scan context is available without an explicit root",
    )
}

fn report_needs_attention(report: &ScanReport) -> bool {
    report
        .entries
        .iter()
        .any(|entry| entry.classification != ScanClassification::ManagedUnchanged)
        || report
            .instructions
            .iter()
            .any(|entry| entry.classification != ScanClassification::ManagedUnchanged)
        || report
            .mcp_servers
            .iter()
            .any(|entry| entry.classification != ScanClassification::ManagedUnchanged)
        || report
            .findings
            .iter()
            .chain(report.entries.iter().flat_map(|entry| &entry.findings))
            .chain(report.related.iter().flat_map(|related| &related.findings))
            .chain(
                report
                    .instructions
                    .iter()
                    .flat_map(|instruction| &instruction.findings),
            )
            .chain(report.mcp_servers.iter().flat_map(|entry| &entry.findings))
            .any(|finding| finding.severity == FindingSeverity::Attention)
}

fn resolve_home(working_directory: &Path) -> Option<PathBuf> {
    home_variable()
        .filter(|path| path.is_absolute())
        .and_then(|path| normalize_absolute(&path, working_directory).ok())
}

#[cfg(windows)]
fn home_variable() -> Option<PathBuf> {
    nonempty_var("USERPROFILE").map(PathBuf::from)
}

#[cfg(not(windows))]
fn home_variable() -> Option<PathBuf> {
    nonempty_var("HOME").map(PathBuf::from)
}

fn resolve_project_boundary(
    explicit: Option<&Path>,
    working_directory: &Path,
) -> Result<ProjectBoundary, CliError> {
    if let Some(explicit) = explicit {
        let root = normalize_absolute(explicit, working_directory).map_err(|_| {
            CliError::new(
                "scan.project_root_invalid",
                "the project root is not a usable absolute directory",
            )
        })?;
        open_directory_nofollow(&root).map_err(|_| {
            CliError::new(
                "scan.project_root_invalid",
                "the project root is not a usable absolute directory",
            )
        })?;
        return Ok(ProjectBoundary::Repository { root });
    }

    let mut ancestor = Some(working_directory);
    while let Some(directory) = ancestor {
        match git_marker_state(&directory.join(".git")) {
            MarkerState::Present => {
                return Ok(ProjectBoundary::Repository {
                    root: directory.to_path_buf(),
                });
            }
            MarkerState::Unsafe => return Ok(ProjectBoundary::UnsafeStop),
            MarkerState::Absent => {}
        }
        ancestor = directory.parent();
    }
    Ok(ProjectBoundary::NoRepository)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkerState {
    Present,
    Absent,
    Unsafe,
}

fn git_marker_state(path: &Path) -> MarkerState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => classify_marker_kind(
            metadata.is_dir(),
            metadata.is_file(),
            metadata.file_type().is_symlink(),
            std_metadata_is_windows_reparse(&metadata),
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => MarkerState::Absent,
        Err(_) => MarkerState::Unsafe,
    }
}

const fn classify_marker_kind(
    directory: bool,
    regular_file: bool,
    symlink: bool,
    reparse_point: bool,
) -> MarkerState {
    if symlink || reparse_point || (!directory && !regular_file) {
        MarkerState::Unsafe
    } else {
        MarkerState::Present
    }
}

fn normalize_explicit_roots(
    roots: Vec<ExplicitRoot>,
    working_directory: &Path,
    selected_harnesses: &std::collections::BTreeSet<HarnessId>,
    selected_scopes: ScopeSelection,
) -> Result<Vec<ExplicitRoot>, CliError> {
    roots
        .into_iter()
        .map(|root| {
            if !selected_harnesses.contains(&root.harness)
                || !scope_selected(selected_scopes, root.scope)
            {
                return Err(CliError::new(
                    "scan.root_invalid",
                    "an explicit root must match the selected harnesses and scope",
                ));
            }
            let path = normalize_absolute(&root.path, working_directory).map_err(|_| {
                CliError::new(
                    "scan.root_invalid",
                    "an explicit root could not be resolved as an absolute local path",
                )
            })?;
            let directory = open_directory_nofollow(&path).is_ok();
            let standalone = root.harness == HarnessId::Pi
                && path.extension().and_then(|extension| extension.to_str()) == Some("md")
                && regular_file_path_nofollow(&path);
            if !directory && !standalone {
                return Err(CliError::new(
                    "scan.root_invalid",
                    "an explicit root must be a readable regular local directory, or a Pi Markdown file",
                ));
            }
            Ok(ExplicitRoot::new(root.harness, root.scope, path))
        })
        .collect()
}

fn scope_selected(selection: ScopeSelection, scope: HarnessScope) -> bool {
    matches!(selection, ScopeSelection::All)
        || matches!(
            (selection, scope),
            (ScopeSelection::User, HarnessScope::User)
                | (ScopeSelection::Project, HarnessScope::Project)
        )
}

fn resolve_environment_source(
    explicit: Option<&Path>,
    working_directory: &Path,
) -> Result<Option<PathBuf>, CliError> {
    if let Some(root) = explicit {
        return normalize_environment_root(root, working_directory).map(Some);
    }
    if let Some(root) = nonempty_var("KITROVE_ENV") {
        return normalize_environment_root(Path::new(&root), working_directory).map(Some);
    }

    let mut ancestor = Some(working_directory);
    while let Some(directory) = ancestor {
        let candidate = directory.join(MANIFEST_NAME);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => return Ok(Some(candidate)),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Ok(Some(candidate)),
        }
        ancestor = directory.parent();
    }
    Ok(None)
}

fn normalize_environment_root(root: &Path, working_directory: &Path) -> Result<PathBuf, CliError> {
    normalize_absolute(root, working_directory)
        .map(|root| root.join(MANIFEST_NAME))
        .map_err(|_| {
            CliError::new(
                "scan.environment_path_invalid",
                "the environment path could not be resolved as an absolute local path",
            )
        })
}

fn resolve_state_source(home: Option<&Path>, working_directory: &Path) -> Option<PathBuf> {
    let root = match nonempty_var("KITROVE_STATE_HOME").map(PathBuf::from) {
        Some(path) if path.is_absolute() => Some(normalized_or_original(path, working_directory)),
        _ => platform_state_root(home, working_directory),
    };
    root.map(|root| root.join(STATE_NAME))
}

#[cfg(target_os = "macos")]
fn platform_state_root(home: Option<&Path>, _working_directory: &Path) -> Option<PathBuf> {
    home.map(|home| home.join("Library/Application Support/kitrove"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_state_root(home: Option<&Path>, working_directory: &Path) -> Option<PathBuf> {
    match nonempty_var("XDG_DATA_HOME").map(PathBuf::from) {
        Some(path) if path.is_absolute() => {
            Some(normalized_or_original(path, working_directory).join("kitrove"))
        }
        _ => home.map(|home| home.join(".local/share/kitrove")),
    }
}

#[cfg(windows)]
fn platform_state_root(_home: Option<&Path>, working_directory: &Path) -> Option<PathBuf> {
    nonempty_var("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| normalized_or_original(path, working_directory))
        .map(|path| path.join("Kitrove"))
}

#[cfg(not(any(unix, windows)))]
fn platform_state_root(_home: Option<&Path>, _working_directory: &Path) -> Option<PathBuf> {
    None
}

enum LoadedInput {
    Bytes { path: PathBuf, bytes: Vec<u8> },
    Unsafe { path: PathBuf },
}

fn load_optional_input(path: Option<&Path>, limits: ScanLimits) -> Option<LoadedInput> {
    let path = path?;
    let max_bytes = usize::try_from(limits.max_input_bytes).unwrap_or(usize::MAX);
    match read_bounded_nofollow(path, max_bytes) {
        InputRead::Absent => None,
        InputRead::Bytes(bytes) => Some(LoadedInput::Bytes {
            path: path.to_path_buf(),
            bytes,
        }),
        InputRead::Unsafe => Some(LoadedInput::Unsafe {
            path: path.to_path_buf(),
        }),
    }
}

enum InputRead {
    Absent,
    Bytes(Vec<u8>),
    Unsafe,
}

fn read_bounded_nofollow(path: &Path, max_bytes: usize) -> InputRead {
    let absolute = match normalize_absolute(path, path.parent().unwrap_or(path)) {
        Ok(absolute) => absolute,
        Err(()) => return InputRead::Unsafe,
    };
    let (anchor, mut components) = match split_absolute_root(&absolute) {
        Ok(parts) => parts,
        Err(()) => return InputRead::Unsafe,
    };
    let Some(file_name) = components.pop() else {
        return InputRead::Unsafe;
    };
    let mut directory = match Dir::open_ambient_dir(&anchor, ambient_authority()) {
        Ok(directory) => directory,
        Err(error) if error.kind() == ErrorKind::NotFound => return InputRead::Absent,
        Err(_) => return InputRead::Unsafe,
    };
    let root_metadata = match directory.dir_metadata() {
        Ok(metadata) => metadata,
        Err(_) => return InputRead::Unsafe,
    };
    if !safe_metadata(&root_metadata) || !root_metadata.is_dir() {
        return InputRead::Unsafe;
    }

    for component in components {
        let metadata = match directory.symlink_metadata(&component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return InputRead::Absent,
            Err(_) => return InputRead::Unsafe,
        };
        if !safe_metadata(&metadata) || !metadata.is_dir() {
            return InputRead::Unsafe;
        }
        let child = match directory.open_dir_nofollow(&component) {
            Ok(child) => child,
            Err(_) => return InputRead::Unsafe,
        };
        let opened = match child.dir_metadata() {
            Ok(opened) => opened,
            Err(_) => return InputRead::Unsafe,
        };
        if !safe_metadata(&opened) || !opened.is_dir() || !same_file(&metadata, &opened) {
            return InputRead::Unsafe;
        }
        directory = child;
    }

    let expected = match directory.symlink_metadata(&file_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return InputRead::Absent,
        Err(_) => return InputRead::Unsafe,
    };
    if !safe_metadata(&expected) || !expected.is_file() {
        return InputRead::Unsafe;
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let mut file = match directory.open_with(&file_name, &options) {
        Ok(file) => file,
        Err(_) => return InputRead::Unsafe,
    };
    let before = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return InputRead::Unsafe,
    };
    if !safe_metadata(&before) || !before.is_file() || !same_file(&expected, &before) {
        return InputRead::Unsafe;
    }

    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    if file
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > max_bytes
    {
        return InputRead::Unsafe;
    }
    let after = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return InputRead::Unsafe,
    };
    if !safe_metadata(&after)
        || !after.is_file()
        || !same_file(&before, &after)
        || before.len() != after.len()
    {
        return InputRead::Unsafe;
    }
    InputRead::Bytes(bytes)
}

fn open_directory_nofollow(path: &Path) -> Result<Dir, ()> {
    let (anchor, components) = split_absolute_root(path)?;
    let mut directory = Dir::open_ambient_dir(&anchor, ambient_authority()).map_err(|_| ())?;
    let metadata = directory.dir_metadata().map_err(|_| ())?;
    if !safe_metadata(&metadata) || !metadata.is_dir() {
        return Err(());
    }
    for component in components {
        let metadata = directory.symlink_metadata(&component).map_err(|_| ())?;
        if !safe_metadata(&metadata) || !metadata.is_dir() {
            return Err(());
        }
        let child = directory.open_dir_nofollow(&component).map_err(|_| ())?;
        let opened = child.dir_metadata().map_err(|_| ())?;
        if !safe_metadata(&opened) || !opened.is_dir() || !same_file(&metadata, &opened) {
            return Err(());
        }
        directory = child;
    }
    Ok(directory)
}

fn regular_file_path_nofollow(path: &Path) -> bool {
    let Ok((anchor, mut components)) = split_absolute_root(path) else {
        return false;
    };
    let Some(file_name) = components.pop() else {
        return false;
    };
    let Ok(mut directory) = Dir::open_ambient_dir(&anchor, ambient_authority()) else {
        return false;
    };
    let Ok(metadata) = directory.dir_metadata() else {
        return false;
    };
    if !safe_metadata(&metadata) || !metadata.is_dir() {
        return false;
    }
    for component in components {
        let Ok(metadata) = directory.symlink_metadata(&component) else {
            return false;
        };
        if !safe_metadata(&metadata) || !metadata.is_dir() {
            return false;
        }
        let Ok(child) = directory.open_dir_nofollow(&component) else {
            return false;
        };
        let Ok(opened) = child.dir_metadata() else {
            return false;
        };
        if !safe_metadata(&opened) || !opened.is_dir() || !same_file(&metadata, &opened) {
            return false;
        }
        directory = child;
    }
    directory
        .symlink_metadata(file_name)
        .is_ok_and(|metadata| safe_metadata(&metadata) && metadata.is_file())
}

fn normalize_absolute(path: &Path, working_directory: &Path) -> Result<PathBuf, ()> {
    let source = if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_directory.join(path)
    };
    let mut anchor = PathBuf::new();
    let mut normal = Vec::<OsString>::new();
    for component in source.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normal.pop().is_none() {
                    return Err(());
                }
            }
            Component::Normal(component) if component == OsStr::new(".") => {}
            Component::Normal(component) if component == OsStr::new("..") => {
                if normal.pop().is_none() {
                    return Err(());
                }
            }
            Component::Normal(component) => normal.push(component.to_owned()),
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(());
    }
    for component in normal {
        anchor.push(component);
    }
    Ok(ordinary_windows_disk_path(anchor))
}

#[cfg(windows)]
fn ordinary_windows_disk_path(path: PathBuf) -> PathBuf {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path;
    };
    let Prefix::VerbatimDisk(drive) = prefix.kind() else {
        return path;
    };
    let mut normalized = PathBuf::from(format!("{}:", char::from(drive)));
    for component in components {
        normalized.push(component.as_os_str());
    }
    normalized
}

#[cfg(not(windows))]
const fn ordinary_windows_disk_path(path: PathBuf) -> PathBuf {
    path
}

fn normalized_or_original(path: PathBuf, working_directory: &Path) -> PathBuf {
    normalize_absolute(&path, working_directory).unwrap_or(path)
}

fn split_absolute_root(root: &Path) -> Result<(PathBuf, Vec<OsString>), ()> {
    if raw_parent_component(root) {
        return Err(());
    }
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    for component in root.components() {
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

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
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

#[cfg(windows)]
fn std_metadata_is_windows_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn std_metadata_is_windows_reparse(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn nonempty_var(name: &str) -> Option<OsString> {
    env::var_os(name).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use kitrove_adapter_api::PolicyLine;
    use kitrove_core::{
        InspectedReceipt, McpPrecedence, McpScanEntry, ReceiptInspection, ScanClassification,
    };
    use kitrove_mcp::NativeMcpDialect;
    use kitrove_model::{
        AssetId, ContentClass, ContentHash, DeploymentReceipt, HarnessId, HarnessScope,
        NormalizedDestination, ReceiptTarget, Revision,
    };

    use super::{
        MarkerState, PendingMcpEntry, ReceiptAuthority, apply_mcp_precedence, classify_marker_kind,
        classify_mcp_entry, normalize_absolute,
    };

    fn mcp_receipt() -> InspectedReceipt {
        let receipt = DeploymentReceipt {
            asset_id: AssetId::parse("docs").unwrap(),
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            destination: NormalizedDestination::parse("/fixture/.claude.json").unwrap(),
            target: ReceiptTarget::ManagedMcpEntry,
            logical_key: Some("company-docs".to_owned()),
            shared_with: Default::default(),
            shared_adapter_versions: Default::default(),
            source_hash: ContentHash::digest(b"source"),
            rendered_hash: ContentHash::digest(b"rendered"),
            document_hash: Some(ContentHash::digest(b"document")),
            prior_hash: Some(ContentHash::digest(b"prior")),
            adapter_version: "claude-mcp/1".to_owned(),
            environment_revision: Revision::parse("1").unwrap(),
        };
        InspectedReceipt {
            receipt_id: receipt.receipt_id().unwrap(),
            receipt,
        }
    }

    #[test]
    fn lexical_normalization_does_not_access_the_filesystem() {
        assert_eq!(
            normalize_absolute(Path::new("one/../two"), Path::new("/fixture")).unwrap(),
            Path::new("/fixture/two")
        );
    }

    #[test]
    fn git_marker_classifier_rejects_links_reparse_points_and_special_files() {
        assert_eq!(
            classify_marker_kind(false, false, true, false),
            MarkerState::Unsafe
        );
        assert_eq!(
            classify_marker_kind(false, false, false, true),
            MarkerState::Unsafe
        );
        assert_eq!(
            classify_marker_kind(false, false, false, false),
            MarkerState::Unsafe
        );
        assert_eq!(
            classify_marker_kind(true, false, false, false),
            MarkerState::Present
        );
        assert_eq!(
            classify_marker_kind(false, true, false, false),
            MarkerState::Present
        );
    }

    #[test]
    fn mcp_receipt_classification_covers_observed_missing_and_uncertain_states() {
        let receipt = mcp_receipt();
        let authority = ReceiptAuthority::Available {
            inspection: ReceiptInspection {
                valid: vec![receipt.clone()],
                invalid: Vec::new(),
            },
            manifest: None,
        };
        let exact = receipt.receipt.rendered_hash.clone();
        let changed = ContentHash::digest(b"changed");

        assert_eq!(
            classify_mcp_entry(&authority, &[], Some(&receipt), Some(&exact)),
            ScanClassification::ManagedUnchanged
        );
        assert_eq!(
            classify_mcp_entry(&authority, &[], Some(&receipt), Some(&changed)),
            ScanClassification::ManagedModified
        );
        assert_eq!(
            classify_mcp_entry(&authority, &[], Some(&receipt), None),
            ScanClassification::MissingManaged
        );
        assert_eq!(
            classify_mcp_entry(&authority, &[], None, Some(&exact)),
            ScanClassification::Unmanaged
        );
        assert_eq!(
            classify_mcp_entry(&ReceiptAuthority::Unavailable, &[], None, Some(&exact)),
            ScanClassification::Unknown
        );
    }

    #[test]
    fn ambiguous_same_scope_mcp_entries_classify_as_conflicting_duplicates() {
        let entry = McpScanEntry {
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            policy_line: PolicyLine::ClaudeCurrent,
            destination: NormalizedDestination::parse("/fixture/.claude.json").unwrap(),
            dialect: NativeMcpDialect::ClaudeCurrent,
            portable_name: Some("company-docs".to_owned()),
            exact_entry_hash: Some(ContentHash::digest(b"one")),
            exact_document_hash: Some(ContentHash::digest(b"document")),
            content_class: ContentClass::AgentActive,
            block_reasons: Vec::new(),
            precedence: McpPrecedence::Effective,
            shadowed_by: None,
            classification: ScanClassification::Unmanaged,
            findings: Vec::new(),
        };
        let mut entries = vec![
            PendingMcpEntry {
                native_name: "company-docs".to_owned(),
                entry: entry.clone(),
            },
            PendingMcpEntry {
                native_name: "company-docs".to_owned(),
                entry,
            },
        ];

        apply_mcp_precedence(&mut entries);

        assert!(entries.iter().all(|entry| {
            entry.entry.precedence == McpPrecedence::Ambiguous
                && entry.entry.classification == ScanClassification::ConflictingDuplicate
        }));
    }
}
