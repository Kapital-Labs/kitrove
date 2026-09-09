use std::collections::BTreeMap;
use std::fmt::Write as _;

use kitrove_adapter_api::{PolicyLine, ScanFinding, VersionObservationOwned};
use kitrove_agent_skills::SkillSourceLayout;
use kitrove_agents::{AgentBlockReason, NativeAgentDialect};
use kitrove_mcp::{McpBlockReason, NativeMcpDialect};
use kitrove_model::{AssetKind, HarnessId};
use kitrove_prompt_commands::{NativePromptDialect, PromptCommandBlockReason};
use kitrove_risk::is_credential_shaped;
use serde::Serialize;

use crate::{
    AgentScanEntry, InstructionScanEntry, McpPrecedence, McpScanEntry, NativeExtensionLayout,
    NativeExtensionScanEntry, PromptCommandScanEntry, RelatedCapabilityObservation,
    ScanClassification, ScanEntry, ScanMode, ScanReport,
};

#[derive(Serialize)]
struct ScanReportView {
    schema_version: u32,
    mode: String,
    versions: BTreeMap<HarnessId, VersionObservationView>,
    entries: Vec<ScanEntryView>,
    related: Vec<RelatedCapabilityView>,
    prompt_commands: Vec<PromptCommandView>,
    agents: Vec<AgentView>,
    native_extensions: Vec<NativeExtensionView>,
    instructions: Vec<InstructionView>,
    mcp_servers: Vec<McpView>,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum VersionObservationView {
    Verified {
        observed: String,
        policy_line: PolicyLine,
        evidence: String,
    },
    Unknown,
}

#[derive(Serialize)]
struct ScanEntryView {
    observation_id: Option<String>,
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    root_tier: Option<String>,
    logical_root: Option<String>,
    policy_rank: Option<u32>,
    source_relative_path: Option<String>,
    layout: Option<String>,
    native_id: Option<String>,
    asset_id: Option<String>,
    receipt_id: Option<String>,
    normalized_destination: Option<String>,
    receipt_rendered_hash: Option<String>,
    classification: String,
    exact_source_hash: Option<String>,
    portable_hash: Option<String>,
    shadowed_by: Option<String>,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
struct RelatedCapabilityView {
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    root_tier: String,
    logical_root: String,
    policy_rank: u32,
    source_relative_path: String,
    kind: AssetKind,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
struct NativeExtensionView {
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    root_tier: String,
    logical_root: String,
    policy_rank: u32,
    source_relative_path: String,
    layout: String,
    native_id: String,
    observation_identity: String,
    exact_source_hash: String,
    classification: String,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
struct PromptCommandView {
    observation_id: String,
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    root_tier: String,
    logical_root: String,
    policy_rank: u32,
    source_relative_path: String,
    dialect: String,
    name: String,
    exact_source_hash: String,
    portable_hash: Option<String>,
    content_class: kitrove_model::ContentClass,
    blocked_reason: Option<String>,
    classification: String,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
struct AgentView {
    observation_id: Option<String>,
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    root_tier: Option<String>,
    logical_root: Option<String>,
    policy_rank: Option<u32>,
    source_relative_path: Option<String>,
    dialect: String,
    name: String,
    asset_id: Option<String>,
    receipt_id: Option<String>,
    normalized_destination: Option<String>,
    receipt_rendered_hash: Option<String>,
    exact_source_hash: Option<String>,
    observed_target_hash: Option<String>,
    portable_hash: Option<String>,
    content_class: kitrove_model::ContentClass,
    blocked_reason: Option<String>,
    classification: String,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
struct InstructionView {
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    policy_line: PolicyLine,
    destination: String,
    asset_id: String,
    observation_revision: Option<String>,
    exact_region_hash: Option<String>,
    receipt_id: Option<String>,
    classification: String,
    findings: Vec<ScanFinding>,
}

#[derive(Serialize)]
struct McpView {
    harness: HarnessId,
    scope: kitrove_model::HarnessScope,
    policy_line: PolicyLine,
    destination: String,
    dialect: String,
    portable_name: Option<String>,
    exact_entry_hash: Option<String>,
    exact_document_hash: Option<String>,
    content_class: kitrove_model::ContentClass,
    block_reasons: Vec<String>,
    precedence: String,
    shadowed_by: Option<String>,
    classification: String,
    findings: Vec<ScanFinding>,
}

impl From<&ScanReport> for ScanReportView {
    fn from(report: &ScanReport) -> Self {
        Self {
            schema_version: report.schema_version,
            mode: scan_mode(report.mode).to_owned(),
            versions: report
                .versions
                .iter()
                .map(|(harness, version)| (harness.clone(), VersionObservationView::from(version)))
                .collect(),
            entries: report.entries.iter().map(ScanEntryView::from).collect(),
            related: report
                .related
                .iter()
                .map(RelatedCapabilityView::from)
                .collect(),
            prompt_commands: report
                .prompt_commands
                .iter()
                .map(PromptCommandView::from)
                .collect(),
            agents: report.agents.iter().map(AgentView::from).collect(),
            native_extensions: report
                .native_extensions
                .iter()
                .map(NativeExtensionView::from)
                .collect(),
            instructions: report
                .instructions
                .iter()
                .map(InstructionView::from)
                .collect(),
            mcp_servers: report.mcp_servers.iter().map(McpView::from).collect(),
            findings: report.findings.clone(),
        }
    }
}

impl From<&McpScanEntry> for McpView {
    fn from(server: &McpScanEntry) -> Self {
        Self {
            harness: server.harness.clone(),
            scope: server.scope,
            policy_line: server.policy_line,
            destination: server.destination.as_str().to_owned(),
            dialect: mcp_dialect(server.dialect).to_owned(),
            portable_name: server.portable_name.clone(),
            exact_entry_hash: server
                .exact_entry_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            exact_document_hash: server
                .exact_document_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            content_class: server.content_class,
            block_reasons: server
                .block_reasons
                .iter()
                .map(|reason| mcp_block_reason(*reason).to_owned())
                .collect(),
            precedence: mcp_precedence(server.precedence).to_owned(),
            shadowed_by: server
                .shadowed_by
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            classification: scan_classification(server.classification).to_owned(),
            findings: server.findings.clone(),
        }
    }
}

impl From<&AgentScanEntry> for AgentView {
    fn from(agent: &AgentScanEntry) -> Self {
        Self {
            observation_id: agent
                .observation_id
                .as_ref()
                .map(|id| id.as_str().to_owned()),
            harness: agent.harness.clone(),
            scope: agent.scope,
            root_tier: agent.root_tier.map(|tier| tier.as_str().to_owned()),
            logical_root: agent
                .logical_root
                .as_ref()
                .map(|root| root.as_str().to_owned()),
            policy_rank: agent.policy_rank,
            source_relative_path: agent
                .source_relative_path
                .as_deref()
                .map(presented_source_path)
                .map(str::to_owned),
            dialect: agent_dialect(agent.dialect).to_owned(),
            name: agent.name.as_str().to_owned(),
            asset_id: agent.asset_id.as_ref().map(|id| id.as_str().to_owned()),
            receipt_id: agent.receipt_id.as_ref().map(|id| id.as_str().to_owned()),
            normalized_destination: agent
                .normalized_destination
                .as_ref()
                .map(|destination| destination.as_str().to_owned()),
            receipt_rendered_hash: agent
                .receipt_rendered_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            exact_source_hash: agent
                .exact_source_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            observed_target_hash: agent
                .observed_target_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            portable_hash: agent
                .portable_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            content_class: agent.content_class,
            blocked_reason: agent
                .blocked_reason
                .map(agent_block_reason)
                .map(str::to_owned),
            classification: scan_classification(agent.classification).to_owned(),
            findings: agent.findings.clone(),
        }
    }
}

impl From<&PromptCommandScanEntry> for PromptCommandView {
    fn from(command: &PromptCommandScanEntry) -> Self {
        Self {
            observation_id: command.observation_id.as_str().to_owned(),
            harness: command.harness.clone(),
            scope: command.scope,
            root_tier: command.root_tier.as_str().to_owned(),
            logical_root: command.logical_root.as_str().to_owned(),
            policy_rank: command.policy_rank,
            source_relative_path: presented_source_path(&command.source_relative_path).to_owned(),
            dialect: prompt_command_dialect(command.dialect).to_owned(),
            name: command.name.as_str().to_owned(),
            exact_source_hash: command.exact_source_hash.as_str().to_owned(),
            portable_hash: command
                .portable_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            content_class: command.content_class,
            blocked_reason: command
                .blocked_reason
                .map(prompt_command_block_reason)
                .map(str::to_owned),
            classification: scan_classification(command.classification).to_owned(),
            findings: command.findings.clone(),
        }
    }
}

impl From<&InstructionScanEntry> for InstructionView {
    fn from(instruction: &InstructionScanEntry) -> Self {
        Self {
            harness: instruction.harness.clone(),
            scope: instruction.scope,
            policy_line: instruction.policy_line,
            destination: instruction.destination.as_str().to_owned(),
            asset_id: instruction.asset_id.as_str().to_owned(),
            observation_revision: instruction
                .observation_revision
                .as_ref()
                .map(|revision| revision.as_str().to_owned()),
            exact_region_hash: instruction
                .exact_region_hash
                .as_ref()
                .map(|hash| hash.as_str().to_owned()),
            receipt_id: instruction
                .receipt_id
                .as_ref()
                .map(|receipt| receipt.as_str().to_owned()),
            classification: scan_classification(instruction.classification).to_owned(),
            findings: instruction.findings.clone(),
        }
    }
}

impl From<&NativeExtensionScanEntry> for NativeExtensionView {
    fn from(extension: &NativeExtensionScanEntry) -> Self {
        Self {
            harness: extension.harness.clone(),
            scope: extension.scope,
            root_tier: extension.root_tier.as_str().to_owned(),
            logical_root: extension.logical_root.as_str().to_owned(),
            policy_rank: extension.policy_rank,
            source_relative_path: presented_source_path(&extension.source_relative_path).to_owned(),
            layout: native_extension_layout(extension.layout).to_owned(),
            native_id: presented_native_id(Some(&extension.native_id))
                .expect("native extension identity is present")
                .to_owned(),
            observation_identity: extension.observation_identity.as_str().to_owned(),
            exact_source_hash: extension.exact_source_hash.as_str().to_owned(),
            classification: scan_classification(extension.classification).to_owned(),
            findings: extension.findings.clone(),
        }
    }
}

impl From<&VersionObservationOwned> for VersionObservationView {
    fn from(version: &VersionObservationOwned) -> Self {
        match version {
            VersionObservationOwned::Verified {
                observed,
                policy_line,
                evidence,
            } => Self::Verified {
                observed: observed.as_str().to_owned(),
                policy_line: *policy_line,
                evidence: evidence.as_str().to_owned(),
            },
            VersionObservationOwned::Unknown => Self::Unknown,
        }
    }
}

impl From<&ScanEntry> for ScanEntryView {
    fn from(entry: &ScanEntry) -> Self {
        Self {
            observation_id: entry
                .observation_id
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            harness: entry.harness.clone(),
            scope: entry.scope,
            root_tier: entry.root_tier.map(|value| value.as_str().to_owned()),
            logical_root: entry
                .logical_root
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            policy_rank: entry.policy_rank,
            source_relative_path: entry
                .source_relative_path
                .as_deref()
                .map(presented_source_path)
                .map(str::to_owned),
            layout: entry.layout.map(|value| skill_layout(value).to_owned()),
            native_id: presented_native_id(entry.native_id.as_deref()).map(str::to_owned),
            asset_id: entry
                .asset_id
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            receipt_id: entry
                .receipt_id
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            normalized_destination: entry.normalized_destination.clone(),
            receipt_rendered_hash: entry
                .receipt_rendered_hash
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            classification: scan_classification(entry.classification).to_owned(),
            exact_source_hash: entry
                .exact_source_hash
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            portable_hash: entry
                .portable_hash
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            shadowed_by: entry
                .shadowed_by
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            findings: entry.findings.clone(),
        }
    }
}

impl From<&RelatedCapabilityObservation> for RelatedCapabilityView {
    fn from(related: &RelatedCapabilityObservation) -> Self {
        Self {
            harness: related.harness.clone(),
            scope: related.scope,
            root_tier: related.root_tier.as_str().to_owned(),
            logical_root: related.logical_root.as_str().to_owned(),
            policy_rank: related.policy_rank,
            source_relative_path: presented_source_path(&related.source_relative_path).to_owned(),
            kind: related.kind,
            findings: related.findings.clone(),
        }
    }
}

/// Serializes a canonical scan report without changing its established order.
pub fn render_scan_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(&ScanReportView::from(report))?;
    rendered.push('\n');
    Ok(rendered)
}

/// Renders a canonical scan report as stable, line-oriented text.
#[must_use]
pub fn render_scan_text(report: &ScanReport) -> String {
    let mut rendered = String::from("kitrove scan v1\n");
    writeln!(rendered, "mode {}", scan_mode(report.mode)).expect("writing to String cannot fail");

    for (harness, version) in &report.versions {
        write!(rendered, "version harness={} ", json(&harness.as_str()))
            .expect("writing to String cannot fail");
        match version {
            VersionObservationOwned::Unknown => {
                writeln!(rendered, "status=\"unknown\"").expect("writing to String cannot fail");
            }
            VersionObservationOwned::Verified {
                observed,
                policy_line,
                evidence,
            } => {
                writeln!(
                    rendered,
                    "status=\"verified\" observed={} policy_line={} evidence={}",
                    json(&observed.as_str()),
                    json(policy_line),
                    json(&evidence.as_str())
                )
                .expect("writing to String cannot fail");
            }
        }
    }

    for entry in &report.entries {
        render_entry(&mut rendered, entry);
        for finding in &entry.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for related in &report.related {
        render_related(&mut rendered, related);
        for finding in &related.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for command in &report.prompt_commands {
        render_prompt_command(&mut rendered, command);
        for finding in &command.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for agent in &report.agents {
        render_agent(&mut rendered, agent);
        for finding in &agent.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for extension in &report.native_extensions {
        render_native_extension(&mut rendered, extension);
        for finding in &extension.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for instruction in &report.instructions {
        render_instruction(&mut rendered, instruction);
        for finding in &instruction.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for server in &report.mcp_servers {
        render_mcp_server(&mut rendered, server);
        for finding in &server.findings {
            render_finding(&mut rendered, finding);
        }
    }
    for finding in &report.findings {
        render_finding(&mut rendered, finding);
    }

    let finding_count = report.findings.len()
        + report
            .entries
            .iter()
            .map(|entry| entry.findings.len())
            .sum::<usize>()
        + report
            .related
            .iter()
            .map(|related| related.findings.len())
            .sum::<usize>();
    let finding_count = finding_count
        + report
            .prompt_commands
            .iter()
            .map(|command| command.findings.len())
            .sum::<usize>();
    let finding_count = finding_count
        + report
            .mcp_servers
            .iter()
            .map(|server| server.findings.len())
            .sum::<usize>();
    let finding_count = finding_count
        + report
            .agents
            .iter()
            .map(|agent| agent.findings.len())
            .sum::<usize>();
    let finding_count = finding_count
        + report
            .native_extensions
            .iter()
            .map(|extension| extension.findings.len())
            .sum::<usize>();
    let finding_count = finding_count
        + report
            .instructions
            .iter()
            .map(|instruction| instruction.findings.len())
            .sum::<usize>();
    writeln!(
        rendered,
        "summary entries={} related={} prompt_commands={} agents={} native_extensions={} instructions={} mcp_servers={} findings={finding_count}",
        report.entries.len(),
        report.related.len(),
        report.prompt_commands.len(),
        report.agents.len(),
        report.native_extensions.len(),
        report.instructions.len(),
        report.mcp_servers.len()
    )
    .expect("writing to String cannot fail");
    rendered
}

fn render_mcp_server(rendered: &mut String, server: &McpScanEntry) {
    writeln!(
        rendered,
        concat!(
            "mcp_server harness={} scope={} policy_line={} destination={} dialect={} ",
            "portable_name={} exact_entry_hash={} exact_document_hash={} content_class={} ",
            "block_reasons={} precedence={} shadowed_by={} classification={}"
        ),
        json(&server.harness),
        json(&server.scope),
        json(&server.policy_line),
        json(&server.destination),
        json(&mcp_dialect(server.dialect)),
        json(&server.portable_name),
        json(&server.exact_entry_hash),
        json(&server.exact_document_hash),
        json(&server.content_class),
        json(
            &server
                .block_reasons
                .iter()
                .map(|reason| mcp_block_reason(*reason))
                .collect::<Vec<_>>()
        ),
        json(&mcp_precedence(server.precedence)),
        json(&server.shadowed_by),
        json(&scan_classification(server.classification)),
    )
    .expect("writing to String cannot fail");
}

const fn mcp_dialect(dialect: NativeMcpDialect) -> &'static str {
    match dialect {
        NativeMcpDialect::ClaudeCurrent => "claude_current",
        NativeMcpDialect::CodexCurrent => "codex_current",
        NativeMcpDialect::OpenCodeV2 => "open_code_v2",
    }
}

const fn mcp_precedence(precedence: McpPrecedence) -> &'static str {
    match precedence {
        McpPrecedence::Effective => "effective",
        McpPrecedence::Shadowed => "shadowed",
        McpPrecedence::Ambiguous => "ambiguous",
    }
}

const fn mcp_block_reason(reason: McpBlockReason) -> &'static str {
    match reason {
        McpBlockReason::Disabled => "disabled",
        McpBlockReason::InvalidName => "invalid_name",
        McpBlockReason::LocalStdio => "local_stdio",
        McpBlockReason::MalformedEntry => "malformed_entry",
        McpBlockReason::NativeFields => "native_fields",
        McpBlockReason::OAuthConfiguration => "oauth_configuration",
        McpBlockReason::StaticCredential => "static_credential",
        McpBlockReason::UnsupportedTransport => "unsupported_transport",
        McpBlockReason::UnsafeEndpoint => "unsafe_endpoint",
    }
}

fn render_agent(rendered: &mut String, agent: &AgentScanEntry) {
    writeln!(
        rendered,
        concat!(
            "agent observation_id={} harness={} scope={} root_tier={} logical_root={} policy_rank={} ",
            "source_relative_path={} dialect={} name={} asset_id={} receipt_id={} normalized_destination={} ",
            "receipt_rendered_hash={} exact_source_hash={} observed_target_hash={} portable_hash={} ",
            "content_class={} blocked_reason={} classification={}"
        ),
        json(&agent.observation_id),
        json(&agent.harness),
        json(&agent.scope),
        json(&agent.root_tier),
        json(&agent.logical_root),
        json(&agent.policy_rank),
        json(&agent.source_relative_path.as_deref().map(presented_source_path)),
        json(&agent_dialect(agent.dialect)),
        json(&agent.name.as_str()),
        json(&agent.asset_id),
        json(&agent.receipt_id),
        json(&agent.normalized_destination),
        json(&agent.receipt_rendered_hash),
        json(&agent.exact_source_hash),
        json(&agent.observed_target_hash),
        json(&agent.portable_hash),
        json(&agent.content_class),
        json(&agent.blocked_reason.map(agent_block_reason)),
        json(&scan_classification(agent.classification)),
    )
    .expect("writing to String cannot fail");
}

const fn agent_dialect(dialect: NativeAgentDialect) -> &'static str {
    match dialect {
        NativeAgentDialect::ClaudeCurrent => "claude_current",
        NativeAgentDialect::CodexCurrent => "codex_current",
        NativeAgentDialect::OpenCodeCurrent => "open_code_current",
    }
}

const fn agent_block_reason(reason: AgentBlockReason) -> &'static str {
    match reason {
        AgentBlockReason::UnsupportedConfiguration => "unsupported_configuration",
        AgentBlockReason::UnsupportedMode => "unsupported_mode",
    }
}

fn render_prompt_command(rendered: &mut String, command: &PromptCommandScanEntry) {
    writeln!(
        rendered,
        concat!(
            "prompt_command observation_id={} harness={} scope={} root_tier={} logical_root={} policy_rank={} ",
            "source_relative_path={} dialect={} name={} exact_source_hash={} portable_hash={} ",
            "content_class={} blocked_reason={} classification={}"
        ),
        json(&command.observation_id),
        json(&command.harness),
        json(&command.scope),
        json(&command.root_tier),
        json(&command.logical_root),
        json(&command.policy_rank),
        json(&presented_source_path(&command.source_relative_path)),
        json(&prompt_command_dialect(command.dialect)),
        json(&command.name.as_str()),
        json(&command.exact_source_hash),
        json(&command.portable_hash),
        json(&command.content_class),
        json(&command.blocked_reason.map(prompt_command_block_reason)),
        json(&scan_classification(command.classification)),
    )
    .expect("writing to String cannot fail");
}

const fn prompt_command_dialect(dialect: NativePromptDialect) -> &'static str {
    match dialect {
        NativePromptDialect::ClaudeLegacy => "claude_legacy",
        NativePromptDialect::PiLatest => "pi_latest",
        NativePromptDialect::OpenCodeV2 => "open_code_v2",
    }
}

const fn prompt_command_block_reason(reason: PromptCommandBlockReason) -> &'static str {
    match reason {
        PromptCommandBlockReason::NestedDocument => "nested_document",
        PromptCommandBlockReason::ExecutableInterpolation => "executable_interpolation",
        PromptCommandBlockReason::FileInterpolation => "file_interpolation",
        PromptCommandBlockReason::UnsupportedFrontmatter => "unsupported_frontmatter",
        PromptCommandBlockReason::UnsupportedArguments => "unsupported_arguments",
        PromptCommandBlockReason::ImplicitArguments => "implicit_arguments",
        PromptCommandBlockReason::InvalidBody => "invalid_body",
    }
}

fn render_instruction(rendered: &mut String, instruction: &InstructionScanEntry) {
    writeln!(
        rendered,
        concat!(
            "instruction harness={} scope={} policy_line={} destination={} asset_id={} ",
            "observation_revision={} exact_region_hash={} receipt_id={} classification={}"
        ),
        json(&instruction.harness),
        json(&instruction.scope),
        json(&instruction.policy_line),
        json(&instruction.destination),
        json(&instruction.asset_id),
        json(&instruction.observation_revision),
        json(&instruction.exact_region_hash),
        json(&instruction.receipt_id),
        json(&scan_classification(instruction.classification)),
    )
    .expect("writing to String cannot fail");
}

fn render_native_extension(rendered: &mut String, extension: &NativeExtensionScanEntry) {
    writeln!(
        rendered,
        concat!(
            "native_extension harness={} scope={} root_tier={} logical_root={} policy_rank={} ",
            "source_relative_path={} layout={} native_id={} observation_identity={} ",
            "exact_source_hash={} classification={}"
        ),
        json(&extension.harness),
        json(&extension.scope),
        json(&extension.root_tier),
        json(&extension.logical_root),
        json(&extension.policy_rank),
        json(&presented_source_path(&extension.source_relative_path)),
        json(&native_extension_layout(extension.layout)),
        json(&presented_native_id(Some(&extension.native_id))),
        json(&extension.observation_identity),
        json(&extension.exact_source_hash),
        json(&scan_classification(extension.classification)),
    )
    .expect("writing to String cannot fail");
}

const fn native_extension_layout(layout: NativeExtensionLayout) -> &'static str {
    match layout {
        NativeExtensionLayout::Standalone => "standalone",
        NativeExtensionLayout::Directory => "directory",
    }
}

fn render_entry(rendered: &mut String, entry: &ScanEntry) {
    writeln!(
        rendered,
        concat!(
            "entry observation_id={} harness={} scope={} root_tier={} logical_root={} ",
            "policy_rank={} source_relative_path={} layout={} native_id={} asset_id={} ",
            "receipt_id={} normalized_destination={} receipt_rendered_hash={} classification={} ",
            "exact_source_hash={} portable_hash={} shadowed_by={}"
        ),
        json(&entry.observation_id),
        json(&entry.harness),
        json(&entry.scope),
        json(&entry.root_tier),
        json(&entry.logical_root),
        json(&entry.policy_rank),
        json(
            &entry
                .source_relative_path
                .as_deref()
                .map(presented_source_path)
        ),
        json(&entry.layout.map(skill_layout)),
        json(&presented_native_id(entry.native_id.as_deref())),
        json(&entry.asset_id),
        json(&entry.receipt_id),
        json(&entry.normalized_destination),
        json(&entry.receipt_rendered_hash),
        json(&scan_classification(entry.classification)),
        json(&entry.exact_source_hash),
        json(&entry.portable_hash),
        json(&entry.shadowed_by),
    )
    .expect("writing to String cannot fail");
}

fn render_related(rendered: &mut String, related: &RelatedCapabilityObservation) {
    writeln!(
        rendered,
        concat!(
            "related harness={} scope={} root_tier={} logical_root={} policy_rank={} ",
            "source_relative_path={} kind={}"
        ),
        json(&related.harness),
        json(&related.scope),
        json(&related.root_tier),
        json(&related.logical_root),
        json(&related.policy_rank),
        json(&presented_source_path(&related.source_relative_path)),
        json(&related.kind),
    )
    .expect("writing to String cannot fail");
}

fn render_finding(rendered: &mut String, finding: &ScanFinding) {
    writeln!(
        rendered,
        "finding code={} severity={} subject={} evidence={} action={}",
        json(&finding.code),
        json(&finding.severity),
        json(&finding.subject),
        json(&finding.evidence),
        json(&finding.action),
    )
    .expect("writing to String cannot fail");
}

fn json<T: Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string(value).expect("scan report values are always JSON serializable")
}

const REDACTED: &str = "<redacted>";

fn presented_native_id(native_id: Option<&str>) -> Option<&str> {
    native_id.map(|value| {
        let inspected =
            value.trim_start_matches(|character: char| !character.is_ascii_alphanumeric());
        if is_credential_shaped(inspected) {
            REDACTED
        } else {
            value
        }
    })
}

fn presented_source_path(path: &str) -> &str {
    if path.split(['/', '\\']).any(is_credential_shaped) {
        REDACTED
    } else {
        path
    }
}

const fn scan_mode(mode: ScanMode) -> &'static str {
    match mode {
        ScanMode::Inventory => "inventory",
        ScanMode::Classified => "classified",
        ScanMode::Degraded => "degraded",
    }
}

const fn scan_classification(classification: ScanClassification) -> &'static str {
    match classification {
        ScanClassification::ManagedUnchanged => "managed_unchanged",
        ScanClassification::ManagedModified => "managed_modified",
        ScanClassification::Unmanaged => "unmanaged",
        ScanClassification::MissingManaged => "missing_managed",
        ScanClassification::ConflictingDuplicate => "conflicting_duplicate",
        ScanClassification::Unknown => "unknown",
    }
}

const fn skill_layout(layout: SkillSourceLayout) -> &'static str {
    match layout {
        SkillSourceLayout::Directory => "directory",
        SkillSourceLayout::Standalone => "standalone",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kitrove_adapter_api::RootTier;
    use kitrove_model::HarnessScope;

    const SECRET_NATIVE_ID: &str = "sk-ant-api03-KITROVE_SECRET_CANARY_42";
    const PADDED_SECRET_NATIVE_ID: &str = "   sk-ant-api03-KITROVE_SECRET_CANARY_42";
    const INVISIBLE_PADDED_SECRET_NATIVE_ID: &str = "\u{200b}sk-ant-api03-KITROVE_SECRET_CANARY_42";

    fn entry(native_id: &str) -> ScanEntry {
        ScanEntry {
            observation_id: None,
            harness: HarnessId::Pi,
            scope: HarnessScope::User,
            root_tier: Some(RootTier::User),
            logical_root: None,
            policy_rank: Some(1),
            source_relative_path: Some("fixture".to_owned()),
            layout: Some(SkillSourceLayout::Directory),
            native_id: Some(native_id.to_owned()),
            asset_id: None,
            receipt_id: None,
            normalized_destination: None,
            receipt_rendered_hash: None,
            classification: ScanClassification::Unmanaged,
            exact_source_hash: None,
            portable_hash: None,
            shadowed_by: None,
            findings: vec![],
        }
    }

    fn render_entry_text(entry: &ScanEntry) -> String {
        let mut rendered = String::new();
        render_entry(&mut rendered, entry);
        rendered
    }

    #[test]
    fn credential_shaped_native_ids_are_redacted_at_both_render_boundaries() {
        for native_id in [
            SECRET_NATIVE_ID,
            PADDED_SECRET_NATIVE_ID,
            INVISIBLE_PADDED_SECRET_NATIVE_ID,
        ] {
            let entry = entry(native_id);
            assert_eq!(entry.native_id.as_deref(), Some(native_id));

            let json = serde_json::to_string(&ScanEntryView::from(&entry)).unwrap();
            let text = render_entry_text(&entry);

            for rendered in [&json, &text] {
                assert!(!rendered.contains(SECRET_NATIVE_ID));
                assert!(rendered.contains("<redacted>"));
            }
        }
    }

    #[test]
    fn benign_native_ids_and_prefix_near_misses_remain_visible() {
        for native_id in [
            "ordinary-pi-skill",
            "sk-analysis",
            "github-patterns",
            "xoxb-not-a-token",
            "   sk-analysis",
            "\u{200b}sk-analysis",
        ] {
            let entry = entry(native_id);
            let json = serde_json::to_string(&ScanEntryView::from(&entry)).unwrap();
            let text = render_entry_text(&entry);
            assert!(json.contains(native_id), "JSON redacted {native_id:?}");
            assert!(text.contains(native_id), "text redacted {native_id:?}");
        }
    }

    #[test]
    fn credential_shape_detection_is_prefix_bounded_and_conservative() {
        for value in [
            SECRET_NATIVE_ID,
            "github_pat_1234567890abcdef",
            "ghp_1234567890abcdef",
            "npm_1234567890abcdef",
            "xoxb-12345678901234567890",
            "AKIA1234567890ABCDEF",
            "AIza12345678901234567890123456",
            "sk-12345678901234567",
        ] {
            assert!(is_credential_shaped(value), "missed {value:?}");
        }
        for value in [
            "secretary",
            "contains-sk-ant-api03-but-is-benign",
            "sk-analysis",
            "github-patterns",
            "github_pat_short",
            "xoxb-not-a-token",
            "AKIA1234",
        ] {
            assert!(!is_credential_shaped(value), "over-redacted {value:?}");
        }
    }

    #[test]
    fn credential_shaped_source_paths_are_redacted_at_both_render_boundaries() {
        let secret = ["ghp_", "1234567890abcdef"].concat();
        let mut entry = entry("ordinary-pi-skill");
        entry.source_relative_path = Some(format!("nested/{secret}/SKILL.md"));

        let json = serde_json::to_string(&ScanEntryView::from(&entry)).unwrap();
        let text = render_entry_text(&entry);

        for rendered in [&json, &text] {
            assert!(!rendered.contains(&secret));
            assert!(rendered.contains("<redacted>"));
        }
        assert_eq!(
            presented_source_path("nested\\sk-analysis\\SKILL.md"),
            "nested\\sk-analysis\\SKILL.md"
        );
    }
}
