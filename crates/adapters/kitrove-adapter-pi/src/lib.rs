#![forbid(unsafe_code)]
//! Compiled Pi adapter and read-only observation policy.

mod policy;
mod roots;

use kitrove_adapter_api::{
    AdapterResult, CapabilityMatrix, ExtensionTargetPolicy, HarnessAdapter,
    InstructionTargetAnchor, InstructionTargetPolicy, PolicyLine, PromptCommandTargetPolicy,
    TargetAnchor, TargetPolicy, VersionObservation, select_materialization_policy,
};
use kitrove_model::{
    AssetKind, BlockedRequirement, Fidelity, FidelityEvidence, FidelityReason, FidelityResult,
    HarnessId, HarnessScope,
};

pub use policy::PiObservationPolicy;

/// Adapter boundary for Pi materialization work in later gates.
#[derive(Clone, Copy, Debug, Default)]
pub struct PiAdapter;

fn non_executable_materialization_line(
    version: VersionObservation<'_>,
) -> AdapterResult<PolicyLine> {
    select_materialization_policy(
        HarnessId::Pi,
        version,
        &[PolicyLine::PiLatest],
        Some(PolicyLine::PiLatest),
    )
}

impl HarnessAdapter for PiAdapter {
    fn id(&self) -> HarnessId {
        HarnessId::Pi
    }

    fn capability_matrix(&self, _version: Option<&str>) -> CapabilityMatrix {
        let mut matrix = CapabilityMatrix::portable_agent_skills(
            "pi-agent-skills/1",
            "Pi accepts canonical Agent Skills directory packages",
        )
        .with_portable_instructions(
            "pi-instructions/1",
            "Pi loads authored Markdown from scoped AGENTS.md context files",
        )
        .with_portable_commands(
            "pi-prompt-commands/1",
            "Pi loads scoped Markdown prompt templates with all-arguments substitution",
        );
        let extension = FidelityResult::new(
            Fidelity::Blocked,
            vec![FidelityReason::new(
                "extension.executable_trust_required",
                "Pi extensions require explicit machine-local executable trust before installation",
            )],
            vec![FidelityEvidence::new(
                "pi.docs.extensions.native",
                "Pi loads native TypeScript extensions with full process permissions",
            )],
            vec![BlockedRequirement::ExecutableTrust],
            "pi-native-extensions/1",
            None,
        )
        .expect("compiled Pi extension fidelity is valid");
        matrix = matrix.with_capability(AssetKind::Extension, extension, Vec::new());
        let agents = FidelityResult::new(
            Fidelity::Unsupported,
            vec![FidelityReason::new(
                "agent.extension_owned",
                "Pi subagents are provided by an optional executable extension, not a built-in registry",
            )],
            vec![FidelityEvidence::new(
                "pi.example.subagent_extension",
                "Pi documents subagents as an executable example extension",
            )],
            vec![],
            "pi-agents/1",
            None,
        )
        .expect("compiled Pi agent fidelity is valid");
        matrix = matrix.with_capability(AssetKind::Agent, agents, Vec::new());
        let mcp = FidelityResult::new(
            Fidelity::Unsupported,
            vec![FidelityReason::new(
                "mcp.no_builtin_registry",
                "Pi has no documented built-in MCP registry",
            )],
            vec![FidelityEvidence::new(
                "pi.docs.settings.no_mcp",
                "Pi's official settings contract exposes extensions and tools but no MCP registry",
            )],
            vec![],
            "pi-mcp/1",
            None,
        )
        .expect("compiled Pi MCP fidelity is valid");
        matrix = matrix.with_capability(AssetKind::Mcp, mcp, Vec::new());
        matrix
    }

    fn instruction_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<InstructionTargetPolicy> {
        let line = non_executable_materialization_line(version)?;
        let document = match scope {
            HarnessScope::User => ".pi/agent/AGENTS.md",
            HarnessScope::Project => "AGENTS.md",
        };
        InstructionTargetPolicy::new(
            HarnessId::Pi,
            scope,
            line,
            InstructionTargetAnchor::Scope,
            document,
            "pi-instructions/1",
            "pi.target.instructions",
        )
    }

    fn prompt_command_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<PromptCommandTargetPolicy> {
        let root = match scope {
            HarnessScope::User => ".pi/agent/prompts",
            HarnessScope::Project => ".pi/prompts",
        };
        PromptCommandTargetPolicy::new(
            HarnessId::Pi,
            scope,
            non_executable_materialization_line(version)?,
            TargetAnchor::Scope,
            root,
            "pi-prompt-commands/1",
            "pi.target.prompt_commands",
        )
    }

    fn target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<TargetPolicy> {
        let line = non_executable_materialization_line(version)?;
        let root = match scope {
            HarnessScope::User => ".pi/agent/skills",
            HarnessScope::Project => ".pi/skills",
        };
        TargetPolicy::agent_skills_directory(
            HarnessId::Pi,
            scope,
            line,
            root,
            "pi-agent-skills/1",
            "pi.target.skills",
        )
    }

    fn extension_target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<ExtensionTargetPolicy> {
        let version_evidence = kitrove_adapter_api::VersionObservationOwned::from(version);
        let line =
            select_materialization_policy(HarnessId::Pi, version, &[PolicyLine::PiLatest], None)?;
        debug_assert_eq!(line, PolicyLine::PiLatest);
        Ok(ExtensionTargetPolicy::pi_native_extensions(
            scope,
            version_evidence,
        ))
    }
}

#[cfg(test)]
mod tests {
    use kitrove_adapter_api::{
        EvidenceRef, ExtensionPackageLayout, HarnessAdapter, HarnessVersion, PolicyLine,
        TargetAnchor, VerifiedVersionEvidence, VersionObservation,
    };
    use kitrove_agent_skills::SkillSourceLayout;
    use kitrove_model::{AssetKind, Fidelity, HarnessId, HarnessScope};

    use super::PiAdapter;

    fn verified() -> VerifiedVersionEvidence {
        VerifiedVersionEvidence::new(
            HarnessId::Pi,
            HarnessVersion::parse("reviewed latest").unwrap(),
            PolicyLine::PiLatest,
            EvidenceRef::parse("fixture.pi.latest").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn adapter_has_stable_identity() {
        assert_eq!(PiAdapter.id(), HarnessId::Pi);
    }

    #[test]
    fn adapter_declares_evidence_backed_agent_skills_support() {
        let matrix = PiAdapter.capability_matrix(None);
        assert_eq!(matrix.capabilities.len(), 6);
        let support = &matrix.capabilities[&AssetKind::Skill];
        assert_eq!(support.result.fidelity(), Fidelity::Portable);
        assert!(!support.result.evidence().is_empty());
        assert_eq!(support.result.adapter_version(), "pi-agent-skills/1");
        assert_eq!(
            matrix.capabilities[&AssetKind::Instruction]
                .result
                .adapter_version(),
            "pi-instructions/1"
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Command].result.fidelity(),
            Fidelity::Portable
        );
        let extension = &matrix.capabilities[&AssetKind::Extension];
        assert_eq!(extension.result.fidelity(), Fidelity::Blocked);
        assert_eq!(
            extension.result.blocked_requirements(),
            &[kitrove_model::BlockedRequirement::ExecutableTrust]
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Agent].result.fidelity(),
            Fidelity::Unsupported
        );
        assert_eq!(
            matrix.capabilities[&AssetKind::Mcp].result.fidelity(),
            Fidelity::Unsupported
        );
    }

    #[test]
    fn instruction_policy_selects_documented_user_and_project_files() {
        let evidence = verified();
        let user = PiAdapter
            .instruction_target_policy(HarnessScope::User, VersionObservation::Verified(&evidence))
            .unwrap();
        let project = PiAdapter
            .instruction_target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&evidence),
            )
            .unwrap();
        assert_eq!(user.relative_document.as_str(), ".pi/agent/AGENTS.md");
        assert_eq!(project.relative_document.as_str(), "AGENTS.md");
    }

    #[test]
    fn target_policy_selects_documented_scope_roots() {
        let evidence = verified();
        let user = PiAdapter
            .target_policy(HarnessScope::User, VersionObservation::Verified(&evidence))
            .unwrap();
        let project = PiAdapter
            .target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&evidence),
            )
            .unwrap();
        assert_eq!(user.relative_root.as_str(), ".pi/agent/skills");
        assert_eq!(project.relative_root.as_str(), ".pi/skills");
        assert_eq!(user.layout, SkillSourceLayout::Directory);
        assert_eq!(project.document_name.as_str(), "SKILL.md");
    }

    #[test]
    fn prompt_command_policy_selects_direct_child_roots() {
        let user = PiAdapter
            .prompt_command_target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        let project = PiAdapter
            .prompt_command_target_policy(HarnessScope::Project, VersionObservation::Unknown)
            .unwrap();
        assert_eq!(user.relative_root.as_str(), ".pi/agent/prompts");
        assert_eq!(project.relative_root.as_str(), ".pi/prompts");
        assert_eq!(user.anchor, TargetAnchor::Scope);
    }

    #[test]
    fn agent_target_is_explicitly_unsupported() {
        assert_eq!(
            PiAdapter
                .agent_target_policy(HarnessScope::User, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.agent_target_unsupported"
        );
    }

    #[test]
    fn mcp_target_is_explicitly_unsupported() {
        assert_eq!(
            PiAdapter
                .mcp_target_policy(HarnessScope::User, VersionObservation::Unknown)
                .unwrap_err()
                .code,
            "apply.mcp_target_unsupported"
        );
    }

    #[test]
    fn extension_target_selects_exact_user_and_project_pi_layouts() {
        let user = PiAdapter
            .extension_target_policy(
                HarnessScope::User,
                VersionObservation::Verified(&verified()),
            )
            .unwrap();
        assert_eq!(user.relative_root.as_str(), ".pi/agent/extensions");
        assert_eq!(
            user.supported_layouts,
            vec![
                ExtensionPackageLayout::Standalone,
                ExtensionPackageLayout::Directory
            ]
        );
        let project = PiAdapter
            .extension_target_policy(
                HarnessScope::Project,
                VersionObservation::Verified(&verified()),
            )
            .unwrap();
        assert_eq!(project.relative_root.as_str(), ".pi/extensions");
        assert_eq!(
            project.supported_layouts,
            vec![
                ExtensionPackageLayout::Standalone,
                ExtensionPackageLayout::Directory
            ]
        );
    }

    #[test]
    fn unknown_or_future_version_uses_conservative_skill_policy_but_refuses_extensions() {
        let skill = PiAdapter
            .target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap();
        let extension = PiAdapter
            .extension_target_policy(HarnessScope::User, VersionObservation::Unknown)
            .unwrap_err();
        assert_eq!(skill.policy_line, PolicyLine::PiLatest);
        assert_eq!(extension.code, "apply.harness_version_unverified");
    }
}
