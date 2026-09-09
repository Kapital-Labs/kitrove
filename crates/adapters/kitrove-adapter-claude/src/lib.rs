#![forbid(unsafe_code)]
//! Compiled Claude Code adapter and read-only observation policy.

mod policy;
mod roots;

use kitrove_adapter_api::{
    AdapterResult, AgentTargetPolicy, CapabilityMatrix, HarnessAdapter, InstructionTargetAnchor,
    InstructionTargetPolicy, McpTargetPolicy, PolicyLine, PromptCommandTargetPolicy, TargetAnchor,
    TargetPolicy, VersionObservation, select_materialization_policy,
};
use kitrove_agents::NativeAgentDialect;
use kitrove_mcp::NativeMcpDialect;
use kitrove_model::{
    AssetKind, Fidelity, FidelityEvidence, FidelityResult, HarnessId, HarnessScope,
};

pub use policy::ClaudeObservationPolicy;

/// Adapter boundary for Claude Code materialization work in later gates.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeAdapter;

fn materialization_line(version: VersionObservation<'_>) -> AdapterResult<PolicyLine> {
    select_materialization_policy(
        HarnessId::Claude,
        version,
        &[PolicyLine::ClaudeCurrent],
        Some(PolicyLine::ClaudeCurrent),
    )
}

impl HarnessAdapter for ClaudeAdapter {
    fn id(&self) -> HarnessId {
        HarnessId::Claude
    }

    fn capability_matrix(&self, _version: Option<&str>) -> CapabilityMatrix {
        let mut matrix = CapabilityMatrix::portable_agent_skills(
            "claude-agent-skills/1",
            "Claude Code accepts canonical Agent Skills directory packages",
        )
        .with_portable_instructions(
            "claude-instructions/1",
            "Claude Code loads authored Markdown from scoped CLAUDE.md files",
        )
        .with_portable_agents(
            "claude-agents/1",
            "Claude Code loads recursive scoped Markdown subagent definitions",
        )
        .with_portable_mcp(
            "claude-mcp/1",
            "Claude Code loads scoped remote Streamable HTTP MCP declarations",
        );
        let command = FidelityResult::exact(
            Fidelity::Adapted,
            vec![FidelityEvidence::new(
                "claude.docs.slash-commands.legacy",
                "Claude Code still loads legacy Markdown custom-command files but recommends skills",
            )],
            "claude-prompt-commands/1",
            None,
        )
        .expect("compiled Claude command fidelity is valid");
        matrix = matrix.with_capability(
            AssetKind::Command,
            command,
            vec![
                "custom commands are a legacy compatibility target; Agent Skills are the recommended successor"
                    .to_owned(),
            ],
        );
        matrix
    }

    fn instruction_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<InstructionTargetPolicy> {
        let line = materialization_line(version)?;
        let document = match scope {
            HarnessScope::User => ".claude/CLAUDE.md",
            HarnessScope::Project => "CLAUDE.md",
        };
        InstructionTargetPolicy::new(
            HarnessId::Claude,
            scope,
            line,
            InstructionTargetAnchor::Scope,
            document,
            "claude-instructions/1",
            "claude.target.instructions",
        )
    }

    fn prompt_command_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<PromptCommandTargetPolicy> {
        PromptCommandTargetPolicy::new(
            HarnessId::Claude,
            scope,
            materialization_line(version)?,
            TargetAnchor::Scope,
            ".claude/commands",
            "claude-prompt-commands/1",
            "claude.target.prompt_commands.legacy",
        )
    }

    fn agent_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<AgentTargetPolicy> {
        AgentTargetPolicy::new(
            scope,
            materialization_line(version)?,
            TargetAnchor::Scope,
            ".claude/agents",
            NativeAgentDialect::ClaudeCurrent,
            "claude-agents/1",
            "claude.target.agents.current",
        )
    }

    fn mcp_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<McpTargetPolicy> {
        let document = match scope {
            HarnessScope::User => ".claude.json",
            HarnessScope::Project => ".mcp.json",
        };
        McpTargetPolicy::new(
            scope,
            materialization_line(version)?,
            TargetAnchor::Scope,
            document,
            NativeMcpDialect::ClaudeCurrent,
            "claude-mcp/1",
            "claude.target.mcp.current",
        )
    }

    fn target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<TargetPolicy> {
        let line = materialization_line(version)?;
        TargetPolicy::agent_skills_directory(
            HarnessId::Claude,
            scope,
            line,
            ".claude/skills",
            "claude-agent-skills/1",
            "claude.target.skills",
        )
    }
}

#[cfg(test)]
mod tests {
    use kitrove_adapter_api::{
        EvidenceRef, HarnessAdapter, HarnessVersion, InstructionTargetAnchor, PolicyLine,
        TargetAnchor, VerifiedVersionEvidence, VersionObservation,
    };
    use kitrove_agent_skills::SkillSourceLayout;
    use kitrove_model::{AssetKind, Fidelity, HarnessId, HarnessScope};

    use super::ClaudeAdapter;

    fn verified() -> VerifiedVersionEvidence {
        VerifiedVersionEvidence::new(
            HarnessId::Claude,
            HarnessVersion::parse("reviewed current").unwrap(),
            PolicyLine::ClaudeCurrent,
            EvidenceRef::parse("fixture.claude.current").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn adapter_has_stable_identity() {
        assert_eq!(ClaudeAdapter.id(), HarnessId::Claude);
    }

    #[test]
    fn adapter_declares_evidence_backed_agent_skills_support() {
        let matrix = ClaudeAdapter.capability_matrix(None);
        assert_eq!(matrix.capabilities.len(), 5);
        let support = &matrix.capabilities[&AssetKind::Skill];
        assert_eq!(support.result.fidelity(), Fidelity::Portable);
        assert!(!support.result.evidence().is_empty());
        assert_eq!(support.result.adapter_version(), "claude-agent-skills/1");
        assert_eq!(
            matrix.capabilities[&AssetKind::Instruction]
                .result
                .adapter_version(),
            "claude-instructions/1"
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Command].result.fidelity(),
            Fidelity::Adapted
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Agent].result.fidelity(),
            Fidelity::Portable
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Mcp].result.fidelity(),
            Fidelity::Portable
        );
    }

    #[test]
    fn instruction_policy_selects_documented_user_and_project_files() {
        let evidence = verified();
        let user = ClaudeAdapter
            .instruction_target_policy(HarnessScope::User, VersionObservation::Verified(&evidence))
            .unwrap();
        let project = ClaudeAdapter
            .instruction_target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&evidence),
            )
            .unwrap();
        assert_eq!(user.relative_document.as_str(), ".claude/CLAUDE.md");
        assert_eq!(project.relative_document.as_str(), "CLAUDE.md");
        assert_eq!(user.anchor, InstructionTargetAnchor::Scope);
    }

    #[test]
    fn target_policy_is_relative_and_scope_preserving() {
        for scope in [HarnessScope::User, HarnessScope::Project] {
            let evidence = verified();
            let policy = ClaudeAdapter
                .target_policy(scope, VersionObservation::Verified(&evidence))
                .unwrap();
            assert_eq!(policy.scope, scope);
            assert_eq!(policy.relative_root.as_str(), ".claude/skills");
            assert_eq!(policy.layout, SkillSourceLayout::Directory);
            assert_eq!(policy.document_name.as_str(), "SKILL.md");
        }
    }

    #[test]
    fn prompt_command_policy_selects_legacy_scoped_root() {
        let policy = ClaudeAdapter
            .prompt_command_target_policy(HarnessScope::Project, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(policy.relative_root.as_str(), ".claude/commands");
        assert_eq!(policy.anchor, TargetAnchor::Scope);
        assert_eq!(policy.policy_line, PolicyLine::ClaudeCurrent);
    }

    #[test]
    fn agent_policy_selects_recursive_scoped_registry() {
        let policy = ClaudeAdapter
            .agent_target_policy(HarnessScope::Project, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(policy.relative_root.as_str(), ".claude/agents");
        assert_eq!(
            policy.discovery,
            kitrove_adapter_api::AgentDiscovery::Recursive
        );
        assert_eq!(
            policy.dialect,
            kitrove_agents::NativeAgentDialect::ClaudeCurrent
        );
    }

    #[test]
    fn mcp_policy_selects_scoped_shared_documents() {
        let user = ClaudeAdapter
            .mcp_target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        let project = ClaudeAdapter
            .mcp_target_policy(HarnessScope::Project, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(user.relative_document.as_str(), ".claude.json");
        assert_eq!(project.relative_document.as_str(), ".mcp.json");
        assert_eq!(user.anchor, TargetAnchor::Scope);
        assert_eq!(user.dialect, kitrove_mcp::NativeMcpDialect::ClaudeCurrent);
    }

    #[test]
    fn unknown_or_future_version_uses_only_the_conservative_target() {
        let policy = ClaudeAdapter
            .target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(policy.policy_line, PolicyLine::ClaudeCurrent);
    }
}
