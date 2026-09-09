#![forbid(unsafe_code)]
//! Compiled Codex adapter and read-only observation policy.

mod policy;
mod roots;

use kitrove_adapter_api::{
    AdapterResult, AgentTargetPolicy, CapabilityMatrix, HarnessAdapter, InstructionTargetAnchor,
    InstructionTargetPolicy, McpTargetPolicy, PolicyLine, TargetPolicy, VersionObservation,
    select_materialization_policy,
};
use kitrove_agents::NativeAgentDialect;
use kitrove_mcp::NativeMcpDialect;
use kitrove_model::{
    AssetKind, Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId, HarnessScope,
};

pub use policy::CodexObservationPolicy;

/// Adapter boundary for Codex materialization work in later gates.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodexAdapter;

fn materialization_line(version: VersionObservation<'_>) -> AdapterResult<PolicyLine> {
    select_materialization_policy(
        HarnessId::Codex,
        version,
        &[PolicyLine::CodexCurrent],
        Some(PolicyLine::CodexCurrent),
    )
}

impl HarnessAdapter for CodexAdapter {
    fn id(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn capability_matrix(&self, _version: Option<&str>) -> CapabilityMatrix {
        let mut matrix = CapabilityMatrix::portable_agent_skills(
            "codex-agent-skills/1",
            "Codex accepts canonical Agent Skills directory packages",
        )
        .with_portable_instructions(
            "codex-instructions/1",
            "Codex loads authored Markdown from scoped AGENTS.md files",
        )
        .with_portable_agents(
            "codex-agents/1",
            "Codex loads scoped TOML custom-agent definitions",
        );
        let command = FidelityResult::new(
            Fidelity::Unsupported,
            vec![FidelityReason::new(
                "command.removed_upstream",
                "current Codex releases no longer load custom prompt command files",
            )],
            vec![FidelityEvidence::new(
                "codex.upstream.custom-prompts.removed",
                "Codex removed custom prompts starting with CLI 0.117.0 and recommends skills",
            )],
            vec![],
            "codex-prompt-commands/1",
            None,
        )
        .expect("compiled Codex command fidelity is valid");
        matrix = matrix.with_capability(
            AssetKind::Command,
            command,
            vec!["Agent Skills are the supported successor".to_owned()],
        );
        let mcp = FidelityResult::new(
            Fidelity::Adapted,
            vec![FidelityReason::new(
                "mcp.auth_fallback_target_local",
                "Codex may retain target-local OAuth fallback after a bearer binding",
            )],
            vec![FidelityEvidence::new(
                "codex.docs.mcp.streamable_http",
                "Codex loads scoped Streamable HTTP MCP declarations and environment-backed bearer tokens",
            )],
            vec![],
            "codex-mcp/1",
            None,
        )
        .expect("compiled Codex MCP fidelity is valid");
        matrix = matrix.with_capability(
            AssetKind::Mcp,
            mcp,
            vec!["OAuth fallback remains machine-local fidelity".to_owned()],
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
            HarnessScope::User => ".codex/AGENTS.md",
            HarnessScope::Project => "AGENTS.md",
        };
        InstructionTargetPolicy::new(
            HarnessId::Codex,
            scope,
            line,
            InstructionTargetAnchor::Scope,
            document,
            "codex-instructions/1",
            "codex.target.instructions",
        )
    }

    fn target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<TargetPolicy> {
        let line = materialization_line(version)?;
        TargetPolicy::agent_skills_directory(
            HarnessId::Codex,
            scope,
            line,
            ".agents/skills",
            "codex-agent-skills/1",
            "codex.target.skills",
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
            kitrove_adapter_api::TargetAnchor::Scope,
            ".codex/agents",
            NativeAgentDialect::CodexCurrent,
            "codex-agents/1",
            "codex.target.agents.current",
        )
    }

    fn mcp_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<McpTargetPolicy> {
        McpTargetPolicy::new(
            scope,
            materialization_line(version)?,
            kitrove_adapter_api::TargetAnchor::Scope,
            ".codex/config.toml",
            NativeMcpDialect::CodexCurrent,
            "codex-mcp/1",
            "codex.target.mcp.current",
        )
    }
}

#[cfg(test)]
mod tests {
    use kitrove_adapter_api::{
        EvidenceRef, HarnessAdapter, HarnessVersion, PolicyLine, VerifiedVersionEvidence,
        VersionObservation,
    };
    use kitrove_agent_skills::SkillSourceLayout;
    use kitrove_model::{AssetKind, Fidelity, HarnessId, HarnessScope};

    use super::CodexAdapter;

    fn verified() -> VerifiedVersionEvidence {
        VerifiedVersionEvidence::new(
            HarnessId::Codex,
            HarnessVersion::parse("reviewed current").unwrap(),
            PolicyLine::CodexCurrent,
            EvidenceRef::parse("fixture.codex.current").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn adapter_has_stable_identity() {
        assert_eq!(CodexAdapter.id(), HarnessId::Codex);
    }

    #[test]
    fn adapter_declares_evidence_backed_agent_skills_support() {
        let matrix = CodexAdapter.capability_matrix(None);
        assert_eq!(matrix.capabilities.len(), 5);
        let support = &matrix.capabilities[&AssetKind::Skill];
        assert_eq!(support.result.fidelity(), Fidelity::Portable);
        assert!(!support.result.evidence().is_empty());
        assert_eq!(support.result.adapter_version(), "codex-agent-skills/1");
        assert_eq!(
            matrix.capabilities[&AssetKind::Instruction]
                .result
                .adapter_version(),
            "codex-instructions/1"
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Command].result.fidelity(),
            Fidelity::Unsupported
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Agent].result.fidelity(),
            Fidelity::Portable
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Mcp].result.fidelity(),
            Fidelity::Adapted
        );
    }

    #[test]
    fn instruction_policy_selects_documented_user_and_project_files() {
        let evidence = verified();
        let user = CodexAdapter
            .instruction_target_policy(HarnessScope::User, VersionObservation::Verified(&evidence))
            .unwrap();
        let project = CodexAdapter
            .instruction_target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&evidence),
            )
            .unwrap();
        assert_eq!(user.relative_document.as_str(), ".codex/AGENTS.md");
        assert_eq!(project.relative_document.as_str(), "AGENTS.md");
    }

    #[test]
    fn target_policy_is_relative_and_scope_preserving() {
        for scope in [HarnessScope::User, HarnessScope::Project] {
            let evidence = verified();
            let policy = CodexAdapter
                .target_policy(scope, VersionObservation::Verified(&evidence))
                .unwrap();
            assert_eq!(policy.scope, scope);
            assert_eq!(policy.relative_root.as_str(), ".agents/skills");
            assert_eq!(policy.layout, SkillSourceLayout::Directory);
            assert_eq!(policy.document_name.as_str(), "SKILL.md");
        }
    }

    #[test]
    fn unknown_or_future_version_uses_only_the_conservative_target() {
        let policy = CodexAdapter
            .target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(policy.policy_line, PolicyLine::CodexCurrent);
    }

    #[test]
    fn prompt_command_target_is_explicitly_unsupported() {
        assert_eq!(
            CodexAdapter
                .prompt_command_target_policy(HarnessScope::User, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.prompt_command_target_unsupported"
        );
    }

    #[test]
    fn agent_policy_selects_direct_scoped_toml_registry() {
        let policy = CodexAdapter
            .agent_target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(policy.relative_root.as_str(), ".codex/agents");
        assert_eq!(
            policy.discovery,
            kitrove_adapter_api::AgentDiscovery::DirectFiles
        );
        assert_eq!(
            policy.dialect,
            kitrove_agents::NativeAgentDialect::CodexCurrent
        );
    }

    #[test]
    fn mcp_policy_selects_scoped_toml_configuration() {
        for scope in [HarnessScope::User, HarnessScope::Project] {
            let policy = CodexAdapter
                .mcp_target_policy(scope, VersionObservation::Unknown)
                .unwrap();
            assert_eq!(policy.relative_document.as_str(), ".codex/config.toml");
            assert_eq!(policy.scope, scope);
            assert_eq!(policy.dialect, kitrove_mcp::NativeMcpDialect::CodexCurrent);
        }
    }
}
