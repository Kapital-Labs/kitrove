use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

use kitrove_adapter_api::{
    FindingSubject, ObservationId, PolicyLine, RootId, RootTier, ScanFinding,
    VersionObservationOwned,
};
use kitrove_agent_skills::{CaptureUsage, SkillSourceLayout};
use kitrove_agents::{AgentBlockReason, AgentName, NativeAgentDialect};
use kitrove_mcp::{McpBlockReason, NativeMcpDialect};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, HarnessId, HarnessScope, NormalizedDestination,
    ReceiptId,
};
use kitrove_prompt_commands::{NativePromptDialect, PromptCommandBlockReason, PromptCommandName};

use crate::ObservedCandidate;
use crate::{
    AgentObservation, InstructionDocumentObservation, NativeExtensionLayout,
    NativeExtensionObservation, PromptCommandObservation,
};

/// The amount of ownership evidence available to one scan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScanMode {
    Inventory,
    Classified,
    Degraded,
}

/// The ownership and drift result for one observed or expected capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScanClassification {
    ManagedUnchanged,
    ManagedModified,
    Unmanaged,
    MissingManaged,
    ConflictingDuplicate,
    Unknown,
}

/// One canonical observed or expected capability report entry.
#[derive(Clone, Eq, PartialEq)]
pub struct ScanEntry {
    pub observation_id: Option<ObservationId>,
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub root_tier: Option<RootTier>,
    pub logical_root: Option<RootId>,
    pub policy_rank: Option<u32>,
    pub source_relative_path: Option<String>,
    pub layout: Option<SkillSourceLayout>,
    pub native_id: Option<String>,
    pub asset_id: Option<AssetId>,
    pub receipt_id: Option<ReceiptId>,
    pub normalized_destination: Option<String>,
    pub receipt_rendered_hash: Option<ContentHash>,
    pub classification: ScanClassification,
    pub exact_source_hash: Option<ContentHash>,
    pub portable_hash: Option<ContentHash>,
    pub shadowed_by: Option<ObservationId>,
    pub findings: Vec<ScanFinding>,
}

impl Debug for ScanEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let finding_codes = self
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("ScanEntry")
            .field("observation_id", &self.observation_id)
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("logical_root", &self.logical_root)
            .field("policy_rank", &self.policy_rank)
            .field("layout", &self.layout)
            .field("classification", &self.classification)
            .field("exact_source_hash", &self.exact_source_hash)
            .field("portable_hash", &self.portable_hash)
            .field("shadowed_by", &self.shadowed_by)
            .field("finding_codes", &finding_codes)
            .finish()
    }
}

/// One body-unread related native capability observed outside Agent Skill capture.
#[derive(Clone, Eq, PartialEq)]
pub struct RelatedCapabilityObservation {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub logical_root: RootId,
    pub policy_rank: u32,
    pub source_relative_path: String,
    pub kind: AssetKind,
    pub findings: Vec<ScanFinding>,
}

impl Debug for RelatedCapabilityObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let finding_codes = self
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("RelatedCapabilityObservation")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("logical_root", &self.logical_root)
            .field("policy_rank", &self.policy_rank)
            .field("kind", &self.kind)
            .field("finding_codes", &finding_codes)
            .finish()
    }
}

/// One safely captured native extension observation, with authored bytes omitted from reporting.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeExtensionScanEntry {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub logical_root: RootId,
    pub policy_rank: u32,
    pub source_relative_path: String,
    pub layout: NativeExtensionLayout,
    pub native_id: String,
    pub observation_identity: ContentHash,
    pub exact_source_hash: ContentHash,
    pub classification: ScanClassification,
    pub findings: Vec<ScanFinding>,
}

/// One managed standing-instruction region observed through a compiled harness policy.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionScanEntry {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub destination: NormalizedDestination,
    pub asset_id: AssetId,
    pub observation_revision: Option<ContentHash>,
    pub exact_region_hash: Option<ContentHash>,
    pub receipt_id: Option<ReceiptId>,
    pub classification: ScanClassification,
    pub findings: Vec<ScanFinding>,
}

/// Document-layer precedence for one retained native MCP declaration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum McpPrecedence {
    Effective,
    Shadowed,
    Ambiguous,
}

/// One safely parsed MCP declaration with authored values omitted from reporting.
#[derive(Clone, Eq, PartialEq)]
pub struct McpScanEntry {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub destination: NormalizedDestination,
    pub dialect: NativeMcpDialect,
    pub portable_name: Option<String>,
    pub exact_entry_hash: Option<ContentHash>,
    pub exact_document_hash: Option<ContentHash>,
    pub content_class: ContentClass,
    pub block_reasons: Vec<McpBlockReason>,
    pub precedence: McpPrecedence,
    pub shadowed_by: Option<ContentHash>,
    pub classification: ScanClassification,
    pub findings: Vec<ScanFinding>,
}

/// One safely captured native prompt command and its conservative portable-v1 decision.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandScanEntry {
    pub observation_id: ContentHash,
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub root_tier: RootTier,
    pub logical_root: RootId,
    pub policy_rank: u32,
    pub source_relative_path: String,
    pub dialect: NativePromptDialect,
    pub name: PromptCommandName,
    pub exact_source_hash: ContentHash,
    pub portable_hash: Option<ContentHash>,
    pub content_class: ContentClass,
    pub blocked_reason: Option<PromptCommandBlockReason>,
    pub classification: ScanClassification,
    pub findings: Vec<ScanFinding>,
}

/// One observed or receipt-expected native agent and its conservative portable-v1 decision.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentScanEntry {
    pub observation_id: Option<ContentHash>,
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub root_tier: Option<RootTier>,
    pub logical_root: Option<RootId>,
    pub policy_rank: Option<u32>,
    pub source_relative_path: Option<String>,
    pub dialect: NativeAgentDialect,
    pub name: AgentName,
    pub asset_id: Option<AssetId>,
    pub receipt_id: Option<ReceiptId>,
    pub normalized_destination: Option<NormalizedDestination>,
    pub receipt_rendered_hash: Option<ContentHash>,
    pub exact_source_hash: Option<ContentHash>,
    pub observed_target_hash: Option<ContentHash>,
    pub portable_hash: Option<ContentHash>,
    pub content_class: ContentClass,
    pub blocked_reason: Option<AgentBlockReason>,
    pub classification: ScanClassification,
    pub findings: Vec<ScanFinding>,
}

impl Debug for AgentScanEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentScanEntry")
            .field("observation_id", &self.observation_id)
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("logical_root", &self.logical_root)
            .field("policy_rank", &self.policy_rank)
            .field("dialect", &self.dialect)
            .field("name", &self.name)
            .field("receipt_id", &self.receipt_id)
            .field("receipt_rendered_hash", &self.receipt_rendered_hash)
            .field("exact_source_hash", &self.exact_source_hash)
            .field("observed_target_hash", &self.observed_target_hash)
            .field("portable_hash", &self.portable_hash)
            .field("content_class", &self.content_class)
            .field("blocked_reason", &self.blocked_reason)
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

impl Debug for PromptCommandScanEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandScanEntry")
            .field("observation_id", &self.observation_id)
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("logical_root", &self.logical_root)
            .field("policy_rank", &self.policy_rank)
            .field("dialect", &self.dialect)
            .field("name", &self.name)
            .field("exact_source_hash", &self.exact_source_hash)
            .field("portable_hash", &self.portable_hash)
            .field("content_class", &self.content_class)
            .field("blocked_reason", &self.blocked_reason)
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

impl Debug for InstructionScanEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionScanEntry")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("policy_line", &self.policy_line)
            .field("asset_id", &self.asset_id)
            .field("observation_revision", &self.observation_revision)
            .field("exact_region_hash", &self.exact_region_hash)
            .field("receipt_id", &self.receipt_id)
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

impl Debug for McpScanEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpScanEntry")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("policy_line", &self.policy_line)
            .field("dialect", &self.dialect)
            .field("portable_name", &self.portable_name)
            .field("exact_entry_hash", &self.exact_entry_hash)
            .field("exact_document_hash", &self.exact_document_hash)
            .field("content_class", &self.content_class)
            .field("block_reasons", &self.block_reasons)
            .field("precedence", &self.precedence)
            .field("shadowed_by", &self.shadowed_by)
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

impl Debug for NativeExtensionScanEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionScanEntry")
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("root_tier", &self.root_tier)
            .field("logical_root", &self.logical_root)
            .field("policy_rank", &self.policy_rank)
            .field("layout", &self.layout)
            .field("native_id_present", &true)
            .field("observation_identity", &self.observation_identity)
            .field("exact_source_hash", &self.exact_source_hash)
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

/// Canonical deterministic output from read-only observation.
#[derive(Clone, Eq, PartialEq)]
pub struct ScanReport {
    pub schema_version: u32,
    pub mode: ScanMode,
    pub versions: BTreeMap<HarnessId, VersionObservationOwned>,
    pub entries: Vec<ScanEntry>,
    pub related: Vec<RelatedCapabilityObservation>,
    pub prompt_commands: Vec<PromptCommandScanEntry>,
    pub agents: Vec<AgentScanEntry>,
    pub native_extensions: Vec<NativeExtensionScanEntry>,
    pub instructions: Vec<InstructionScanEntry>,
    pub mcp_servers: Vec<McpScanEntry>,
    pub findings: Vec<ScanFinding>,
    observations: Vec<ObservedCandidate>,
    capture_usage: CaptureUsage,
    native_extension_observations: Vec<NativeExtensionObservation>,
    prompt_command_observations: Vec<PromptCommandObservation>,
    agent_observations: Vec<AgentObservation>,
    instruction_observations: Vec<InstructionDocumentObservation>,
    mcp_observations: Vec<crate::McpDocumentObservation>,
}

impl ScanReport {
    pub(crate) fn new(
        mode: ScanMode,
        versions: BTreeMap<HarnessId, VersionObservationOwned>,
        entries: Vec<ScanEntry>,
        related: Vec<RelatedCapabilityObservation>,
        findings: Vec<ScanFinding>,
        observations: Vec<ObservedCandidate>,
        capture_usage: CaptureUsage,
    ) -> Self {
        let mut report = Self {
            schema_version: 1,
            mode,
            versions,
            entries,
            related,
            prompt_commands: Vec::new(),
            agents: Vec::new(),
            native_extensions: Vec::new(),
            instructions: Vec::new(),
            mcp_servers: Vec::new(),
            findings,
            observations,
            capture_usage,
            native_extension_observations: Vec::new(),
            prompt_command_observations: Vec::new(),
            agent_observations: Vec::new(),
            instruction_observations: Vec::new(),
            mcp_observations: Vec::new(),
        };
        report.sort_canonical();
        report
    }

    /// Returns the capture-stage observations retained for a later adoption boundary.
    #[must_use]
    pub fn observations(&self) -> &[ObservedCandidate] {
        &self.observations
    }

    /// Returns request-global content capture usage. Related metadata listing does not contribute.
    #[must_use]
    pub const fn capture_usage(&self) -> &CaptureUsage {
        &self.capture_usage
    }

    /// Returns adoption-eligible exact native extension observations.
    #[must_use]
    pub fn native_extension_observations(&self) -> &[NativeExtensionObservation] {
        &self.native_extension_observations
    }

    /// Returns exact prompt-command observations retained for a later adoption boundary.
    #[must_use]
    pub fn prompt_command_observations(&self) -> &[PromptCommandObservation] {
        &self.prompt_command_observations
    }

    /// Returns exact native agent observations retained for later adoption.
    #[must_use]
    pub fn agent_observations(&self) -> &[AgentObservation] {
        &self.agent_observations
    }

    /// Returns exact instruction documents retained for a later adoption boundary.
    #[must_use]
    pub fn instruction_observations(&self) -> &[InstructionDocumentObservation] {
        &self.instruction_observations
    }

    /// Returns exact MCP documents retained for a later adoption boundary.
    #[must_use]
    pub fn mcp_observations(&self) -> &[crate::McpDocumentObservation] {
        &self.mcp_observations
    }

    pub(crate) fn set_native_extensions(
        &mut self,
        entries: Vec<NativeExtensionScanEntry>,
        observations: Vec<NativeExtensionObservation>,
    ) {
        self.native_extensions = entries;
        self.native_extension_observations = observations;
        self.sort_canonical();
    }

    pub(crate) fn set_prompt_commands(
        &mut self,
        entries: Vec<PromptCommandScanEntry>,
        observations: Vec<PromptCommandObservation>,
    ) {
        self.prompt_commands = entries;
        self.prompt_command_observations = observations;
        self.sort_canonical();
    }

    pub(crate) fn set_agents(
        &mut self,
        entries: Vec<AgentScanEntry>,
        observations: Vec<AgentObservation>,
    ) {
        self.agents = entries;
        self.agent_observations = observations;
        self.sort_canonical();
    }

    /// Adds instruction observations produced by the concrete, policy-aware composition root.
    pub fn set_instructions(
        &mut self,
        entries: Vec<InstructionScanEntry>,
        observations: Vec<InstructionDocumentObservation>,
        capture_usage: CaptureUsage,
    ) {
        self.instructions = entries;
        self.instruction_observations = observations;
        self.capture_usage = capture_usage;
        self.sort_canonical();
    }

    /// Adds MCP observations produced by the concrete, policy-aware composition root.
    pub fn set_mcp_servers(
        &mut self,
        entries: Vec<McpScanEntry>,
        observations: Vec<crate::McpDocumentObservation>,
        capture_usage: CaptureUsage,
    ) {
        self.mcp_servers = entries;
        self.mcp_observations = observations;
        self.capture_usage = capture_usage;
        self.sort_canonical();
    }

    /// Restores the canonical report order without relying on renderer behavior.
    pub fn sort_canonical(&mut self) {
        for entry in &mut self.entries {
            normalize_findings(&mut entry.findings);
        }
        for related in &mut self.related {
            normalize_findings(&mut related.findings);
        }
        for extension in &mut self.native_extensions {
            normalize_findings(&mut extension.findings);
        }
        for command in &mut self.prompt_commands {
            normalize_findings(&mut command.findings);
        }
        for agent in &mut self.agents {
            normalize_findings(&mut agent.findings);
        }
        for instruction in &mut self.instructions {
            normalize_findings(&mut instruction.findings);
        }
        for server in &mut self.mcp_servers {
            normalize_findings(&mut server.findings);
        }
        normalize_findings(&mut self.findings);
        self.entries.sort_by(entry_order);
        self.related.sort_by(related_order);
        self.native_extensions.sort_by(|left, right| {
            left.harness
                .cmp(&right.harness)
                .then_with(|| left.scope.cmp(&right.scope))
                .then_with(|| left.policy_rank.cmp(&right.policy_rank))
                .then_with(|| left.logical_root.cmp(&right.logical_root))
                .then_with(|| left.source_relative_path.cmp(&right.source_relative_path))
                .then_with(|| left.observation_identity.cmp(&right.observation_identity))
        });
        self.prompt_commands.sort_by(|left, right| {
            left.harness
                .cmp(&right.harness)
                .then_with(|| left.scope.cmp(&right.scope))
                .then_with(|| left.policy_rank.cmp(&right.policy_rank))
                .then_with(|| left.logical_root.cmp(&right.logical_root))
                .then_with(|| left.source_relative_path.cmp(&right.source_relative_path))
                .then_with(|| left.exact_source_hash.cmp(&right.exact_source_hash))
        });
        self.prompt_command_observations.sort_by(|left, right| {
            left.harness()
                .cmp(right.harness())
                .then_with(|| left.scope().cmp(&right.scope()))
                .then_with(|| left.policy_rank().cmp(&right.policy_rank()))
                .then_with(|| left.logical_root().cmp(right.logical_root()))
                .then_with(|| left.identity().cmp(right.identity()))
        });
        self.agents.sort_by(|left, right| {
            left.harness
                .cmp(&right.harness)
                .then_with(|| left.scope.cmp(&right.scope))
                .then_with(|| left.policy_rank.cmp(&right.policy_rank))
                .then_with(|| left.logical_root.cmp(&right.logical_root))
                .then_with(|| left.source_relative_path.cmp(&right.source_relative_path))
                .then_with(|| left.exact_source_hash.cmp(&right.exact_source_hash))
        });
        self.agent_observations.sort_by(|left, right| {
            left.harness()
                .cmp(right.harness())
                .then_with(|| left.scope().cmp(&right.scope()))
                .then_with(|| left.policy_rank().cmp(&right.policy_rank()))
                .then_with(|| left.logical_root().cmp(right.logical_root()))
                .then_with(|| left.identity().cmp(right.identity()))
        });
        self.instructions.sort_by(|left, right| {
            left.harness
                .cmp(&right.harness)
                .then_with(|| left.scope.cmp(&right.scope))
                .then_with(|| left.policy_line.cmp(&right.policy_line))
                .then_with(|| left.destination.cmp(&right.destination))
                .then_with(|| left.asset_id.cmp(&right.asset_id))
                .then_with(|| left.classification.cmp(&right.classification))
                .then_with(|| left.observation_revision.cmp(&right.observation_revision))
                .then_with(|| left.exact_region_hash.cmp(&right.exact_region_hash))
                .then_with(|| left.receipt_id.cmp(&right.receipt_id))
                .then_with(|| compare_findings(&left.findings, &right.findings))
        });
        self.mcp_servers.sort_by(|left, right| {
            left.harness
                .cmp(&right.harness)
                .then_with(|| left.scope.cmp(&right.scope))
                .then_with(|| left.policy_line.cmp(&right.policy_line))
                .then_with(|| left.destination.cmp(&right.destination))
                .then_with(|| left.portable_name.cmp(&right.portable_name))
                .then_with(|| left.exact_entry_hash.cmp(&right.exact_entry_hash))
                .then_with(|| left.precedence.cmp(&right.precedence))
                .then_with(|| left.classification.cmp(&right.classification))
                .then_with(|| compare_findings(&left.findings, &right.findings))
        });
    }
}

impl Debug for ScanReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanReport")
            .field("schema_version", &self.schema_version)
            .field("mode", &self.mode)
            .field("versions", &self.versions)
            .field("entries", &self.entries)
            .field("related", &self.related)
            .field("prompt_commands", &self.prompt_commands)
            .field("agents", &self.agents)
            .field("native_extensions", &self.native_extensions)
            .field("instructions", &self.instructions)
            .field("mcp_servers", &self.mcp_servers)
            .field("findings", &self.findings)
            .field("observations", &self.observations)
            .field("capture_usage", &self.capture_usage)
            .finish()
    }
}

pub(crate) fn normalize_findings(findings: &mut Vec<ScanFinding>) {
    for finding in &mut *findings {
        finding.evidence.sort();
        finding.evidence.dedup();
    }
    findings.sort_by(finding_order);
}

pub(crate) fn normalized_findings(findings: &[ScanFinding]) -> Vec<ScanFinding> {
    let mut findings = findings.to_vec();
    normalize_findings(&mut findings);
    findings
}

fn entry_order(left: &ScanEntry, right: &ScanEntry) -> Ordering {
    // The prefix is the exact public scan ordering contract. Remaining public semantic fields
    // are deterministic tie-breakers so comparator equality cannot preserve caller order.
    left.harness
        .cmp(&right.harness)
        .then_with(|| left.scope.cmp(&right.scope))
        .then_with(|| compare_optional(left.policy_rank.as_ref(), right.policy_rank.as_ref()))
        .then_with(|| compare_optional(left.logical_root.as_ref(), right.logical_root.as_ref()))
        .then_with(|| {
            compare_optional(
                left.source_relative_path.as_deref(),
                right.source_relative_path.as_deref(),
            )
        })
        .then_with(|| compare_optional(left.layout.as_ref(), right.layout.as_ref()))
        .then_with(|| compare_optional(left.native_id.as_deref(), right.native_id.as_deref()))
        .then_with(|| compare_optional(left.asset_id.as_ref(), right.asset_id.as_ref()))
        .then_with(|| {
            compare_optional(
                left.normalized_destination.as_deref(),
                right.normalized_destination.as_deref(),
            )
        })
        .then_with(|| compare_optional(left.receipt_id.as_ref(), right.receipt_id.as_ref()))
        .then_with(|| {
            compare_optional(
                left.exact_source_hash.as_ref(),
                right.exact_source_hash.as_ref(),
            )
        })
        .then_with(|| left.classification.cmp(&right.classification))
        .then_with(|| compare_optional(left.observation_id.as_ref(), right.observation_id.as_ref()))
        .then_with(|| compare_optional(left.root_tier.as_ref(), right.root_tier.as_ref()))
        .then_with(|| {
            compare_optional(
                left.receipt_rendered_hash.as_ref(),
                right.receipt_rendered_hash.as_ref(),
            )
        })
        .then_with(|| compare_optional(left.portable_hash.as_ref(), right.portable_hash.as_ref()))
        .then_with(|| compare_optional(left.shadowed_by.as_ref(), right.shadowed_by.as_ref()))
        .then_with(|| compare_findings(&left.findings, &right.findings))
}

fn related_order(
    left: &RelatedCapabilityObservation,
    right: &RelatedCapabilityObservation,
) -> Ordering {
    left.harness
        .cmp(&right.harness)
        .then_with(|| left.scope.cmp(&right.scope))
        .then_with(|| left.policy_rank.cmp(&right.policy_rank))
        .then_with(|| left.logical_root.cmp(&right.logical_root))
        .then_with(|| left.source_relative_path.cmp(&right.source_relative_path))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.root_tier.cmp(&right.root_tier))
        .then_with(|| compare_findings(&left.findings, &right.findings))
}

fn finding_order(left: &ScanFinding, right: &ScanFinding) -> Ordering {
    left.severity
        .cmp(&right.severity)
        .then_with(|| left.code.cmp(right.code))
        .then_with(|| finding_subject_key(&left.subject).cmp(&finding_subject_key(&right.subject)))
        .then_with(|| left.evidence.cmp(&right.evidence))
        .then_with(|| left.action.cmp(right.action))
}

fn compare_findings(left: &[ScanFinding], right: &[ScanFinding]) -> Ordering {
    left.iter()
        .zip(right)
        .map(|(left, right)| finding_order(left, right))
        .find(|order| !order.is_eq())
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

fn compare_optional<T: Ord + ?Sized>(left: Option<&T>, right: Option<&T>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
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
