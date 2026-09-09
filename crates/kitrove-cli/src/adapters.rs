use std::collections::BTreeMap;

use kitrove_adapter_api::{
    AgentTargetPolicy, EvidenceRef, ExtensionTargetPolicy, HarnessAdapter, HarnessVersion,
    InstructionTargetPolicy, McpTargetPolicy, PolicyLine, PromptCommandTargetPolicy, TargetPolicy,
    VerifiedVersionEvidence, VersionObservation,
};
use kitrove_adapter_claude::ClaudeAdapter;
use kitrove_adapter_codex::CodexAdapter;
use kitrove_adapter_opencode::OpenCodeAdapter;
use kitrove_adapter_pi::PiAdapter;
use kitrove_core::{
    TierOneAgentCapabilities, TierOneCapabilities, TierOneInstructionCapabilities,
    TierOneMcpCapabilities, TierOnePromptCommandCapabilities,
};
use kitrove_model::{HarnessId, HarnessScope};

use crate::args::CliError;

static CLAUDE_ADAPTER: ClaudeAdapter = ClaudeAdapter;
static CODEX_ADAPTER: CodexAdapter = CodexAdapter;
static OPENCODE_ADAPTER: OpenCodeAdapter = OpenCodeAdapter;
static PI_ADAPTER: PiAdapter = PiAdapter;

pub(crate) fn compiled_adapter(
    harness: &HarnessId,
) -> Result<&'static dyn HarnessAdapter, CliError> {
    tier_one_adapters()
        .into_iter()
        .find_map(|(candidate, adapter)| (candidate == *harness).then_some(adapter))
        .ok_or_else(|| {
            CliError::new(
                "adapter.target_unsupported",
                "the selected target has no compiled adapter policy",
            )
        })
}

pub(crate) fn target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<TargetPolicy, CliError> {
    target_policy_with_version(harness, scope, VersionObservation::Unknown)
}

pub(crate) fn target_policy_with_version(
    harness: &HarnessId,
    scope: HarnessScope,
    version: VersionObservation<'_>,
) -> Result<TargetPolicy, CliError> {
    compiled_adapter(harness)?
        .target_policy(scope, version)
        .map_err(adapter_error)
}

pub(crate) fn instruction_target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<InstructionTargetPolicy, CliError> {
    instruction_target_policy_with_version(harness, scope, VersionObservation::Unknown)
}

pub(crate) fn instruction_target_policy_with_version(
    harness: &HarnessId,
    scope: HarnessScope,
    version: VersionObservation<'_>,
) -> Result<InstructionTargetPolicy, CliError> {
    compiled_adapter(harness)?
        .instruction_target_policy(scope, version)
        .map_err(adapter_error)
}

pub(crate) fn agent_target_policy_with_version(
    harness: &HarnessId,
    scope: HarnessScope,
    version: VersionObservation<'_>,
) -> Result<AgentTargetPolicy, CliError> {
    compiled_adapter(harness)?
        .agent_target_policy(scope, version)
        .map_err(adapter_error)
}

pub(crate) fn prompt_command_target_policy_with_version(
    harness: &HarnessId,
    scope: HarnessScope,
    version: VersionObservation<'_>,
) -> Result<PromptCommandTargetPolicy, CliError> {
    compiled_adapter(harness)?
        .prompt_command_target_policy(scope, version)
        .map_err(adapter_error)
}

pub(crate) fn mcp_target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<McpTargetPolicy, CliError> {
    mcp_target_policy_with_version(harness, scope, VersionObservation::Unknown)
}

pub(crate) fn mcp_target_policy_with_version(
    harness: &HarnessId,
    scope: HarnessScope,
    version: VersionObservation<'_>,
) -> Result<McpTargetPolicy, CliError> {
    compiled_adapter(harness)?
        .mcp_target_policy(scope, version)
        .map_err(adapter_error)
}

pub(crate) fn pi_extension_target_policy(
    scope: HarnessScope,
    version: VersionObservation<'_>,
) -> Result<ExtensionTargetPolicy, CliError> {
    PI_ADAPTER
        .extension_target_policy(scope, version)
        .map_err(adapter_error)
}

pub(crate) fn receipt_instruction_target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<InstructionTargetPolicy, CliError> {
    with_receipt_policy(harness, PolicyLine::OpenCodeCurrent, |version| {
        instruction_target_policy_with_version(harness, scope, version)
    })
}

pub(crate) fn receipt_agent_target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<AgentTargetPolicy, CliError> {
    with_receipt_policy(harness, PolicyLine::OpenCodeCurrent, |version| {
        agent_target_policy_with_version(harness, scope, version)
    })
}

pub(crate) fn receipt_prompt_command_target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<PromptCommandTargetPolicy, CliError> {
    with_receipt_policy(harness, PolicyLine::OpenCodeV2, |version| {
        prompt_command_target_policy_with_version(harness, scope, version)
    })
}

pub(crate) fn receipt_mcp_target_policy(
    harness: &HarnessId,
    scope: HarnessScope,
) -> Result<McpTargetPolicy, CliError> {
    with_receipt_policy(harness, PolicyLine::OpenCodeV2, |version| {
        mcp_target_policy_with_version(harness, scope, version)
    })
}

fn with_receipt_policy<T>(
    harness: &HarnessId,
    opencode_line: PolicyLine,
    select: impl FnOnce(VersionObservation<'_>) -> Result<T, CliError>,
) -> Result<T, CliError> {
    if harness != &HarnessId::OpenCode {
        return select(VersionObservation::Unknown);
    }
    let evidence = VerifiedVersionEvidence::new(
        HarnessId::OpenCode,
        HarnessVersion::parse("receipt-bound").map_err(adapter_error)?,
        opencode_line,
        EvidenceRef::parse("local.receipt.policy").map_err(adapter_error)?,
    )
    .map_err(adapter_error)?;
    select(VersionObservation::Verified(&evidence))
}

pub(crate) fn tier_one_capabilities() -> Result<TierOneCapabilities, CliError> {
    TierOneCapabilities::new(tier_one_matrices()).map_err(adoption_error)
}

pub(crate) fn tier_one_instruction_capabilities() -> Result<TierOneInstructionCapabilities, CliError>
{
    TierOneInstructionCapabilities::new(tier_one_matrices()).map_err(instruction_adoption_error)
}

pub(crate) fn tier_one_agent_capabilities() -> Result<TierOneAgentCapabilities, CliError> {
    TierOneAgentCapabilities::new(tier_one_matrices()).map_err(agent_adoption_error)
}

pub(crate) fn tier_one_prompt_command_capabilities()
-> Result<TierOnePromptCommandCapabilities, CliError> {
    TierOnePromptCommandCapabilities::new(tier_one_matrices())
        .map_err(prompt_command_adoption_error)
}

pub(crate) fn tier_one_mcp_capabilities() -> Result<TierOneMcpCapabilities, CliError> {
    TierOneMcpCapabilities::new(tier_one_matrices()).map_err(mcp_adoption_error)
}

fn tier_one_matrices() -> BTreeMap<HarnessId, kitrove_adapter_api::CapabilityMatrix> {
    tier_one_adapters()
        .into_iter()
        .map(|(harness, adapter)| (harness, adapter.capability_matrix(None)))
        .collect()
}

fn tier_one_adapters() -> [(HarnessId, &'static dyn HarnessAdapter); 4] {
    [
        (HarnessId::Claude, &CLAUDE_ADAPTER),
        (HarnessId::Codex, &CODEX_ADAPTER),
        (HarnessId::Pi, &PI_ADAPTER),
        (HarnessId::OpenCode, &OPENCODE_ADAPTER),
    ]
}

fn adapter_error(error: kitrove_adapter_api::AdapterError) -> CliError {
    CliError::new(error.code, error.message)
}

fn adoption_error(error: kitrove_core::AdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn instruction_adoption_error(error: kitrove_core::InstructionAdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn agent_adoption_error(error: kitrove_core::AgentAdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn prompt_command_adoption_error(error: kitrove_core::PromptCommandAdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn mcp_adoption_error(error: kitrove_core::McpAdoptionError) -> CliError {
    CliError::new(error.code(), error.message())
}
