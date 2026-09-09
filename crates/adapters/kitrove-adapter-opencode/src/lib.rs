#![forbid(unsafe_code)]
//! Compiled OpenCode adapter and versioned read-only observation policy.

mod policy;
mod roots;

use kitrove_adapter_api::{
    AdapterResult, AgentTargetPolicy, CapabilityMatrix, HarnessAdapter, InstructionTargetAnchor,
    InstructionTargetPolicy, McpTargetPolicy, PolicyLine, PromptCommandTargetPolicy, TargetAnchor,
    TargetPolicy, VersionObservation, select_materialization_policy,
};
use kitrove_agents::NativeAgentDialect;
use kitrove_mcp::NativeMcpDialect;
use kitrove_model::{HarnessId, HarnessScope};

pub use policy::OpenCodeObservationPolicy;

/// Adapter boundary for OpenCode materialization work in later gates.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenCodeAdapter;

impl HarnessAdapter for OpenCodeAdapter {
    fn id(&self) -> HarnessId {
        HarnessId::OpenCode
    }

    fn capability_matrix(&self, _version: Option<&str>) -> CapabilityMatrix {
        let mut matrix = CapabilityMatrix::portable_agent_skills(
            "opencode-agent-skills/1",
            "OpenCode accepts canonical Agent Skills directory packages",
        )
        .with_portable_instructions(
            "opencode-instructions/1",
            "OpenCode loads authored Markdown from scoped AGENTS.md files on a verified policy line",
        )
        .with_portable_commands(
            "opencode-prompt-commands/1",
            "OpenCode V2 loads scoped Markdown commands with all-arguments substitution",
        )
        .with_portable_agents(
            "opencode-agents/1",
            "OpenCode loads scoped Markdown subagent definitions",
        )
        .with_portable_mcp(
            "opencode-mcp/1",
            "OpenCode V2 loads scoped remote Streamable HTTP MCP declarations",
        );
        matrix
            .capabilities
            .get_mut(&kitrove_model::AssetKind::Instruction)
            .expect("the instruction capability was just inserted")
            .notes
            .push(
                "instruction materialization requires verified current or V2 policy evidence"
                    .to_owned(),
            );
        matrix
            .capabilities
            .get_mut(&kitrove_model::AssetKind::Mcp)
            .expect("the MCP capability was just inserted")
            .notes
            .push("MCP materialization requires verified V2 policy evidence".to_owned());
        matrix
    }

    fn instruction_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<InstructionTargetPolicy> {
        let line = select_materialization_policy(
            HarnessId::OpenCode,
            version,
            &[PolicyLine::OpenCodeCurrent, PolicyLine::OpenCodeV2],
            None,
        )?;
        let (anchor, document) = match scope {
            HarnessScope::User => (InstructionTargetAnchor::HarnessConfiguration, "AGENTS.md"),
            HarnessScope::Project => (InstructionTargetAnchor::Scope, "AGENTS.md"),
        };
        InstructionTargetPolicy::new(
            HarnessId::OpenCode,
            scope,
            line,
            anchor,
            document,
            "opencode-instructions/1",
            "opencode.target.instructions",
        )
    }

    fn prompt_command_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<PromptCommandTargetPolicy> {
        let line = select_materialization_policy(
            HarnessId::OpenCode,
            version,
            &[PolicyLine::OpenCodeV2],
            None,
        )?;
        let (anchor, root) = match scope {
            HarnessScope::User => (TargetAnchor::HarnessConfiguration, "commands"),
            HarnessScope::Project => (TargetAnchor::Scope, ".opencode/commands"),
        };
        PromptCommandTargetPolicy::new(
            HarnessId::OpenCode,
            scope,
            line,
            anchor,
            root,
            "opencode-prompt-commands/1",
            "opencode.target.prompt_commands.v2",
        )
    }

    fn agent_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<AgentTargetPolicy> {
        let line = select_materialization_policy(
            HarnessId::OpenCode,
            version,
            &[PolicyLine::OpenCodeCurrent, PolicyLine::OpenCodeV2],
            None,
        )?;
        let (anchor, root) = match scope {
            HarnessScope::User => (TargetAnchor::HarnessConfiguration, "agents"),
            HarnessScope::Project => (TargetAnchor::Scope, ".opencode/agents"),
        };
        AgentTargetPolicy::new(
            scope,
            line,
            anchor,
            root,
            NativeAgentDialect::OpenCodeCurrent,
            "opencode-agents/1",
            "opencode.target.agents.current",
        )
    }

    fn mcp_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<McpTargetPolicy> {
        let line = select_materialization_policy(
            HarnessId::OpenCode,
            version,
            &[PolicyLine::OpenCodeV2],
            None,
        )?;
        let (anchor, document) = match scope {
            HarnessScope::User => (TargetAnchor::HarnessConfiguration, "opencode.jsonc"),
            HarnessScope::Project => (TargetAnchor::Scope, ".opencode/opencode.jsonc"),
        };
        McpTargetPolicy::new(
            scope,
            line,
            anchor,
            document,
            NativeMcpDialect::OpenCodeV2,
            "opencode-mcp/1",
            "opencode.target.mcp.v2",
        )
    }

    fn target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<TargetPolicy> {
        let line = select_materialization_policy(
            HarnessId::OpenCode,
            version,
            &[PolicyLine::OpenCodeCurrent, PolicyLine::OpenCodeV2],
            Some(PolicyLine::OpenCodeCurrent),
        )?;
        let root = match scope {
            HarnessScope::User => ".config/opencode/skills",
            HarnessScope::Project => ".opencode/skills",
        };
        TargetPolicy::agent_skills_directory(
            HarnessId::OpenCode,
            scope,
            line,
            root,
            "opencode-agent-skills/1",
            "opencode.target.skills",
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

    use super::OpenCodeAdapter;

    fn verified() -> VerifiedVersionEvidence {
        VerifiedVersionEvidence::new(
            HarnessId::OpenCode,
            HarnessVersion::parse("reviewed current").unwrap(),
            PolicyLine::OpenCodeCurrent,
            EvidenceRef::parse("fixture.opencode.current").unwrap(),
        )
        .unwrap()
    }

    fn verified_v2() -> VerifiedVersionEvidence {
        VerifiedVersionEvidence::new(
            HarnessId::OpenCode,
            HarnessVersion::parse("reviewed v2").unwrap(),
            PolicyLine::OpenCodeV2,
            EvidenceRef::parse("fixture.opencode.v2").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn adapter_has_stable_identity() {
        assert_eq!(OpenCodeAdapter.id(), HarnessId::OpenCode);
    }

    #[test]
    fn adapter_declares_evidence_backed_agent_skills_support() {
        let matrix = OpenCodeAdapter.capability_matrix(None);
        assert_eq!(matrix.capabilities.len(), 5);
        let support = &matrix.capabilities[&AssetKind::Skill];
        assert_eq!(support.result.fidelity(), Fidelity::Portable);
        assert!(!support.result.evidence().is_empty());
        assert_eq!(support.result.adapter_version(), "opencode-agent-skills/1");
        let instructions = &matrix.capabilities[&AssetKind::Instruction];
        assert_eq!(
            instructions.result.adapter_version(),
            "opencode-instructions/1"
        );
        assert_eq!(instructions.notes.len(), 1);
        assert_eq!(
            matrix.capabilities[&AssetKind::Command].result.fidelity(),
            Fidelity::Portable
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
    fn instruction_policy_requires_verified_line_and_typed_user_config_anchor() {
        let evidence = verified();
        let user = OpenCodeAdapter
            .instruction_target_policy(HarnessScope::User, VersionObservation::Verified(&evidence))
            .unwrap();
        let project = OpenCodeAdapter
            .instruction_target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&evidence),
            )
            .unwrap();
        assert_eq!(user.relative_document.as_str(), "AGENTS.md");
        assert_eq!(user.anchor, InstructionTargetAnchor::HarnessConfiguration);
        assert_eq!(project.anchor, InstructionTargetAnchor::Scope);
        assert_eq!(
            OpenCodeAdapter
                .instruction_target_policy(HarnessScope::Project, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.harness_version_unverified"
        );
        let v2 = verified_v2();
        assert_eq!(
            OpenCodeAdapter
                .instruction_target_policy(
                    HarnessScope::Project,
                    VersionObservation::Verified(&v2),
                )
                .unwrap()
                .policy_line,
            PolicyLine::OpenCodeV2
        );
    }

    #[test]
    fn target_policy_selects_documented_scope_roots() {
        let evidence = verified();
        let user = OpenCodeAdapter
            .target_policy(HarnessScope::User, VersionObservation::Verified(&evidence))
            .unwrap();
        let project = OpenCodeAdapter
            .target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&evidence),
            )
            .unwrap();
        assert_eq!(user.relative_root.as_str(), ".config/opencode/skills");
        assert_eq!(project.relative_root.as_str(), ".opencode/skills");
        assert_eq!(user.layout, SkillSourceLayout::Directory);
        assert_eq!(project.document_name.as_str(), "SKILL.md");
    }

    #[test]
    fn prompt_command_policy_requires_verified_v2_and_typed_config_anchor() {
        let v2 = verified_v2();
        let user = OpenCodeAdapter
            .prompt_command_target_policy(HarnessScope::User, VersionObservation::Verified(&v2))
            .unwrap();
        let project = OpenCodeAdapter
            .prompt_command_target_policy(HarnessScope::Project, VersionObservation::Verified(&v2))
            .unwrap();
        assert_eq!(user.relative_root.as_str(), "commands");
        assert_eq!(user.anchor, TargetAnchor::HarnessConfiguration);
        assert_eq!(project.relative_root.as_str(), ".opencode/commands");
        assert_eq!(
            OpenCodeAdapter
                .prompt_command_target_policy(HarnessScope::User, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.harness_version_unverified"
        );
    }

    #[test]
    fn agent_policy_requires_verified_line_and_uses_direct_registry() {
        let current = verified();
        let user = OpenCodeAdapter
            .agent_target_policy(HarnessScope::User, VersionObservation::Verified(&current))
            .unwrap();
        assert_eq!(user.relative_root.as_str(), "agents");
        assert_eq!(user.anchor, TargetAnchor::HarnessConfiguration);
        assert_eq!(
            user.discovery,
            kitrove_adapter_api::AgentDiscovery::DirectFiles
        );
        assert_eq!(
            OpenCodeAdapter
                .agent_target_policy(HarnessScope::Project, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.harness_version_unverified"
        );
    }

    #[test]
    fn mcp_policy_requires_verified_v2_and_uses_canonical_jsonc_documents() {
        let v2 = verified_v2();
        let user = OpenCodeAdapter
            .mcp_target_policy(HarnessScope::User, VersionObservation::Verified(&v2))
            .unwrap();
        let project = OpenCodeAdapter
            .mcp_target_policy(HarnessScope::Project, VersionObservation::Verified(&v2))
            .unwrap();
        assert_eq!(user.relative_document.as_str(), "opencode.jsonc");
        assert_eq!(user.anchor, TargetAnchor::HarnessConfiguration);
        assert_eq!(
            project.relative_document.as_str(),
            ".opencode/opencode.jsonc"
        );
        assert_eq!(
            OpenCodeAdapter
                .mcp_target_policy(HarnessScope::User, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.harness_version_unverified"
        );
    }

    #[test]
    fn unknown_or_future_version_cannot_select_v2_target_behavior() {
        let policy = OpenCodeAdapter
            .target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(policy.policy_line, PolicyLine::OpenCodeCurrent);
    }
}
