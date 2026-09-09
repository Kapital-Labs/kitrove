#![forbid(unsafe_code)]
//! Contracts shared by Kitrove's observation policies and harness adapters.

mod authority;
mod finding;
mod identity;
mod policy;
mod request;
mod version;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use kitrove_agent_skills::SkillSourceLayout;
use kitrove_agents::NativeAgentDialect;
use kitrove_mcp::NativeMcpDialect;
use kitrove_model::{
    AssetKind, Fidelity, FidelityEvidence, FidelityResult, HarnessId, HarnessScope, PortablePath,
};

pub use authority::{
    PolicyRuntimeAuthority, ReceiptAuthority, RelatedRootAuthority, RootAuthority,
    RootEvidenceAuthority, RootIdAuthority, RootPathAuthority, RootRankAuthority,
};
pub use finding::{FindingSeverity, FindingSubject, ScanFinding};
pub use identity::{
    EvidenceRef, NativeRootKey, ObservationId, ObservationIdentity, RootId, SourceRelativePath,
};
pub use policy::{
    CandidateDecision, CandidateLocator, CandidateSummary, DuplicateDecision,
    HarnessObservationPolicy, LocalRootHookMeter, LocatorDecision, NativeAcceptance, ObservedRoot,
    PolicyProfile, PortablePolicyDecision, ReceiptAnchor, RelatedDocumentPattern, RelatedRoot,
    RootHookMeter, RootHookReport, RootTier,
};
pub use request::{
    EnvironmentInput, ExplicitRoot, LocalStateInput, ProjectBoundary, ProjectTrustKey,
    ProjectTrustObservation, RootContext, ScanLimits, ScanRequest, ScopeSelection,
    SuppliedNativeRoot,
};
pub use version::{
    HarnessVersion, PolicyLine, VerifiedVersionEvidence, VersionObservation,
    VersionObservationOwned, select_materialization_policy,
};

/// Declared support for one capability kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySupport {
    /// Typical result when all documented conditions are met.
    pub result: FidelityResult,
    /// Evidence or version caveats.
    pub notes: Vec<String>,
}

/// Version-aware adapter capability matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityMatrix {
    /// Support by capability kind.
    pub capabilities: BTreeMap<AssetKind, CapabilitySupport>,
}

impl CapabilityMatrix {
    /// Creates an empty matrix for an adapter scaffold.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            capabilities: BTreeMap::new(),
        }
    }

    /// Adds one fully validated capability declaration.
    #[must_use]
    pub fn with_capability(
        mut self,
        kind: AssetKind,
        result: FidelityResult,
        notes: Vec<String>,
    ) -> Self {
        self.capabilities
            .insert(kind, CapabilitySupport { result, notes });
        self
    }

    /// Declares exact support for the canonical Agent Skills directory format.
    ///
    /// The adapter version and evidence detail are implementation-owned constants, so callers
    /// cannot turn unverified runtime text into a fidelity claim.
    #[must_use]
    pub fn portable_agent_skills(
        adapter_version: &'static str,
        evidence_detail: &'static str,
    ) -> Self {
        let result = FidelityResult::exact(
            Fidelity::Portable,
            vec![FidelityEvidence::new(
                "adapter.capability_matrix",
                evidence_detail,
            )],
            adapter_version,
            None,
        );
        let result = match result {
            Ok(result) => result,
            Err(_) => unreachable!("static Agent Skills capability evidence must be valid"),
        };

        Self {
            capabilities: BTreeMap::from([(
                AssetKind::Skill,
                CapabilitySupport {
                    result,
                    notes: Vec::new(),
                },
            )]),
        }
    }

    /// Adds evidence-backed portable standing-instruction support.
    #[must_use]
    pub fn with_portable_instructions(
        self,
        adapter_version: &'static str,
        evidence_detail: &'static str,
    ) -> Self {
        self.with_portable_authored_capability(
            AssetKind::Instruction,
            adapter_version,
            evidence_detail,
        )
    }

    /// Adds evidence-backed portable prompt-command support.
    #[must_use]
    pub fn with_portable_commands(
        self,
        adapter_version: &'static str,
        evidence_detail: &'static str,
    ) -> Self {
        self.with_portable_authored_capability(AssetKind::Command, adapter_version, evidence_detail)
    }

    /// Adds evidence-backed portable subagent-definition support.
    #[must_use]
    pub fn with_portable_agents(
        self,
        adapter_version: &'static str,
        evidence_detail: &'static str,
    ) -> Self {
        self.with_portable_authored_capability(AssetKind::Agent, adapter_version, evidence_detail)
    }

    /// Adds evidence-backed portable remote-MCP support.
    #[must_use]
    pub fn with_portable_mcp(
        self,
        adapter_version: &'static str,
        evidence_detail: &'static str,
    ) -> Self {
        self.with_portable_authored_capability(AssetKind::Mcp, adapter_version, evidence_detail)
    }

    fn with_portable_authored_capability(
        self,
        kind: AssetKind,
        adapter_version: &'static str,
        evidence_detail: &'static str,
    ) -> Self {
        let result = FidelityResult::exact(
            Fidelity::Portable,
            vec![FidelityEvidence::new(
                "adapter.capability_matrix",
                evidence_detail,
            )],
            adapter_version,
            None,
        )
        .expect("static authored-capability evidence must be valid");
        self.with_capability(kind, result, Vec::new())
    }
}

/// Pure compiled policy for one harness materialization destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetPolicy {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub relative_root: PortablePath,
    pub layout: SkillSourceLayout,
    pub document_name: PortablePath,
    pub adapter_version: &'static str,
    pub evidence: EvidenceRef,
}

impl TargetPolicy {
    /// Builds the shared canonical directory-package target shape.
    pub fn agent_skills_directory(
        harness: HarnessId,
        scope: HarnessScope,
        policy_line: PolicyLine,
        relative_root: &str,
        adapter_version: &'static str,
        evidence: &str,
    ) -> AdapterResult<Self> {
        let relative_root = PortablePath::parse(relative_root).map_err(|_| {
            AdapterError::new(
                "adapter.target_policy_invalid",
                "the compiled target root is not a portable relative path",
            )
        })?;
        let evidence = EvidenceRef::parse(evidence).map_err(|_| {
            AdapterError::new(
                "adapter.target_policy_invalid",
                "the compiled target evidence reference is invalid",
            )
        })?;
        Ok(Self {
            harness,
            scope,
            policy_line,
            relative_root,
            layout: SkillSourceLayout::Directory,
            document_name: PortablePath::parse("SKILL.md")
                .expect("the canonical Agent Skills document name is portable"),
            adapter_version,
            evidence,
        })
    }
}

/// Machine-local anchor required to resolve an authored-file target policy.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetAnchor {
    /// Resolve beneath the user home or validated project root selected by `scope`.
    Scope,
    /// Resolve beneath a caller-supplied harness configuration directory.
    HarnessConfiguration,
}

/// Backward-compatible name for the shared authored-file target anchor.
pub type InstructionTargetAnchor = TargetAnchor;

fn validate_authored_target_identity(
    harness: &HarnessId,
    scope: HarnessScope,
    policy_line: PolicyLine,
    anchor: TargetAnchor,
    code: &'static str,
    message: &'static str,
) -> AdapterResult<()> {
    if policy_line.harness() != *harness
        || (anchor == TargetAnchor::HarnessConfiguration && scope != HarnessScope::User)
    {
        return Err(AdapterError::new(code, message));
    }
    Ok(())
}

/// Pure compiled policy for one co-owned standing-instruction document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionTargetPolicy {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub anchor: InstructionTargetAnchor,
    pub relative_document: PortablePath,
    pub adapter_version: &'static str,
    pub evidence: EvidenceRef,
}

/// Pure compiled policy for one whole-file prompt-command destination root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptCommandTargetPolicy {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub anchor: TargetAnchor,
    pub relative_root: PortablePath,
    pub adapter_version: &'static str,
    pub evidence: EvidenceRef,
}

/// Traversal shape documented for one native agent registry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AgentDiscovery {
    DirectFiles,
    Recursive,
}

/// Pure compiled policy for one whole-file native agent destination root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentTargetPolicy {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub anchor: TargetAnchor,
    pub relative_root: PortablePath,
    pub dialect: NativeAgentDialect,
    pub discovery: AgentDiscovery,
    pub adapter_version: &'static str,
    pub evidence: EvidenceRef,
}

/// Pure compiled policy for one logical MCP entry in a shared native configuration document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpTargetPolicy {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub anchor: TargetAnchor,
    pub relative_document: PortablePath,
    pub dialect: NativeMcpDialect,
    pub adapter_version: &'static str,
    pub evidence: EvidenceRef,
}

impl McpTargetPolicy {
    pub fn new(
        scope: HarnessScope,
        policy_line: PolicyLine,
        anchor: TargetAnchor,
        relative_document: &str,
        dialect: NativeMcpDialect,
        adapter_version: &'static str,
        evidence: &str,
    ) -> AdapterResult<Self> {
        let harness = dialect.harness();
        validate_authored_target_identity(
            &harness,
            scope,
            policy_line,
            anchor,
            "adapter.mcp_target_invalid",
            "the MCP target policy is internally inconsistent",
        )?;
        let relative_document = PortablePath::parse(relative_document).map_err(|_| {
            AdapterError::new(
                "adapter.mcp_target_invalid",
                "the compiled MCP document is not a portable relative path",
            )
        })?;
        let evidence = EvidenceRef::parse(evidence).map_err(|_| {
            AdapterError::new(
                "adapter.mcp_target_invalid",
                "the compiled MCP evidence reference is invalid",
            )
        })?;
        Ok(Self {
            harness,
            scope,
            policy_line,
            anchor,
            relative_document,
            dialect,
            adapter_version,
            evidence,
        })
    }

    pub fn validate(&self) -> AdapterResult<()> {
        validate_authored_target_identity(
            &self.harness,
            self.scope,
            self.policy_line,
            self.anchor,
            "adapter.mcp_target_invalid",
            "the MCP target policy is internally inconsistent",
        )?;
        if self.dialect.harness() != self.harness {
            return Err(AdapterError::new(
                "adapter.mcp_target_invalid",
                "the MCP dialect is inconsistent with its harness",
            ));
        }
        Ok(())
    }
}

impl AgentTargetPolicy {
    pub fn new(
        scope: HarnessScope,
        policy_line: PolicyLine,
        anchor: TargetAnchor,
        relative_root: &str,
        dialect: NativeAgentDialect,
        adapter_version: &'static str,
        evidence: &str,
    ) -> AdapterResult<Self> {
        let harness = dialect.harness();
        validate_authored_target_identity(
            &harness,
            scope,
            policy_line,
            anchor,
            "adapter.agent_target_invalid",
            "the agent target policy is internally inconsistent",
        )?;
        let relative_root = PortablePath::parse(relative_root).map_err(|_| {
            AdapterError::new(
                "adapter.agent_target_invalid",
                "the compiled agent root is not a portable relative path",
            )
        })?;
        let evidence = EvidenceRef::parse(evidence).map_err(|_| {
            AdapterError::new(
                "adapter.agent_target_invalid",
                "the compiled agent evidence reference is invalid",
            )
        })?;
        let discovery = if dialect.supports_recursive_discovery() {
            AgentDiscovery::Recursive
        } else {
            AgentDiscovery::DirectFiles
        };
        Ok(Self {
            harness,
            scope,
            policy_line,
            anchor,
            relative_root,
            dialect,
            discovery,
            adapter_version,
            evidence,
        })
    }

    pub fn validate(&self) -> AdapterResult<()> {
        validate_authored_target_identity(
            &self.harness,
            self.scope,
            self.policy_line,
            self.anchor,
            "adapter.agent_target_invalid",
            "the agent target policy is internally inconsistent",
        )?;
        if self.dialect.harness() != self.harness
            || self.dialect.supports_recursive_discovery()
                != (self.discovery == AgentDiscovery::Recursive)
        {
            return Err(AdapterError::new(
                "adapter.agent_target_invalid",
                "the agent dialect or discovery policy is inconsistent with its harness",
            ));
        }
        Ok(())
    }
}

impl PromptCommandTargetPolicy {
    pub fn new(
        harness: HarnessId,
        scope: HarnessScope,
        policy_line: PolicyLine,
        anchor: TargetAnchor,
        relative_root: &str,
        adapter_version: &'static str,
        evidence: &str,
    ) -> AdapterResult<Self> {
        validate_authored_target_identity(
            &harness,
            scope,
            policy_line,
            anchor,
            "adapter.prompt_command_target_invalid",
            "the prompt-command target policy is internally inconsistent",
        )?;
        let relative_root = PortablePath::parse(relative_root).map_err(|_| {
            AdapterError::new(
                "adapter.prompt_command_target_invalid",
                "the compiled prompt-command root is not a portable relative path",
            )
        })?;
        let evidence = EvidenceRef::parse(evidence).map_err(|_| {
            AdapterError::new(
                "adapter.prompt_command_target_invalid",
                "the compiled prompt-command evidence reference is invalid",
            )
        })?;
        Ok(Self {
            harness,
            scope,
            policy_line,
            anchor,
            relative_root,
            adapter_version,
            evidence,
        })
    }

    pub fn validate(&self) -> AdapterResult<()> {
        validate_authored_target_identity(
            &self.harness,
            self.scope,
            self.policy_line,
            self.anchor,
            "adapter.prompt_command_target_invalid",
            "the prompt-command target policy is internally inconsistent",
        )
    }
}

impl InstructionTargetPolicy {
    /// Constructs a reviewed relative instruction target without ambient path discovery.
    pub fn new(
        harness: HarnessId,
        scope: HarnessScope,
        policy_line: PolicyLine,
        anchor: InstructionTargetAnchor,
        relative_document: &str,
        adapter_version: &'static str,
        evidence: &str,
    ) -> AdapterResult<Self> {
        validate_authored_target_identity(
            &harness,
            scope,
            policy_line,
            anchor,
            "adapter.instruction_target_invalid",
            "the instruction target policy is internally inconsistent",
        )?;
        let relative_document = PortablePath::parse(relative_document).map_err(|_| {
            AdapterError::new(
                "adapter.instruction_target_invalid",
                "the compiled instruction document is not a portable relative path",
            )
        })?;
        let evidence = EvidenceRef::parse(evidence).map_err(|_| {
            AdapterError::new(
                "adapter.instruction_target_invalid",
                "the compiled instruction evidence reference is invalid",
            )
        })?;
        Ok(Self {
            harness,
            scope,
            policy_line,
            anchor,
            relative_document,
            adapter_version,
            evidence,
        })
    }

    /// Revalidates a policy crossing a public struct boundary.
    pub fn validate(&self) -> AdapterResult<()> {
        validate_authored_target_identity(
            &self.harness,
            self.scope,
            self.policy_line,
            self.anchor,
            "adapter.instruction_target_invalid",
            "the instruction target policy is internally inconsistent",
        )
    }
}

/// Adapter-owned on-disk shape for one native extension package.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExtensionPackageLayout {
    Standalone,
    Directory,
}

/// Pure compiled policy for a harness-native executable extension destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionTargetPolicy {
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub policy_line: PolicyLine,
    pub version: VersionObservationOwned,
    pub relative_root: PortablePath,
    pub supported_layouts: Vec<ExtensionPackageLayout>,
    pub adapter_version: &'static str,
    pub evidence: EvidenceRef,
}

impl ExtensionTargetPolicy {
    /// Builds the single compiled Pi native-extension destination policy.
    #[must_use]
    pub fn pi_native_extensions(scope: HarnessScope, version: VersionObservationOwned) -> Self {
        let (relative_root, evidence) = match scope {
            HarnessScope::User => (".pi/agent/extensions", "pi.target.native_extensions"),
            HarnessScope::Project => (".pi/extensions", "pi.target.native_extensions.project"),
        };
        Self {
            harness: HarnessId::Pi,
            scope,
            policy_line: PolicyLine::PiLatest,
            version,
            relative_root: PortablePath::parse(relative_root)
                .expect("compiled Pi extension target root"),
            supported_layouts: vec![
                ExtensionPackageLayout::Standalone,
                ExtensionPackageLayout::Directory,
            ],
            adapter_version: "pi-native-extensions/1",
            evidence: EvidenceRef::parse(evidence).expect("compiled Pi extension target evidence"),
        }
    }

    /// Revalidates the complete Pi policy identity after it crosses a public struct boundary.
    pub fn validate_pi_native_extensions(&self) -> AdapterResult<()> {
        if self == &Self::pi_native_extensions(self.scope, self.version.clone()) {
            Ok(())
        } else {
            Err(AdapterError::new(
                "apply.extension_policy_invalid",
                "the selected Pi extension policy is not the compiled target policy",
            ))
        }
    }
}

/// Adapter failure with a stable code and redacted catalog message.
///
/// Runtime strings are deliberately rejected so candidate bodies, arbitrary paths, and
/// filesystem error text cannot cross the adapter/report boundary.
///
/// ```compile_fail
/// use kitrove_adapter_api::AdapterError;
///
/// let runtime_detail = String::from("candidate-controlled detail");
/// let _ = AdapterError::new("adapter.invalid", runtime_detail);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterError {
    /// Machine-readable category.
    pub code: &'static str,
    /// Human-readable detail.
    pub message: &'static str,
}

impl AdapterError {
    /// Creates an adapter error with a stable code.
    #[must_use]
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Creates an error used by unfinished scaffold operations.
    #[must_use]
    pub const fn not_implemented(_operation: &'static str) -> Self {
        Self::new(
            "adapter.not_implemented",
            "the requested adapter operation is not implemented",
        )
    }
}

impl Display for AdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AdapterError {}

/// Result type used by adapter operations.
pub type AdapterResult<T> = Result<T, AdapterError>;

/// C4 planning and rendering boundary implemented by every harness adapter.
pub trait HarnessAdapter {
    /// Stable harness identity.
    fn id(&self) -> HarnessId;

    /// Declares version-aware capability support.
    fn capability_matrix(&self, _version: Option<&str>) -> CapabilityMatrix {
        CapabilityMatrix::empty()
    }

    /// Selects a reviewed relative destination without receiving ambient path authority.
    fn target_policy(
        &self,
        scope: HarnessScope,
        version: VersionObservation<'_>,
    ) -> AdapterResult<TargetPolicy>;

    /// Selects a reviewed co-owned standing-instruction document.
    fn instruction_target_policy(
        &self,
        _scope: HarnessScope,
        _version: VersionObservation<'_>,
    ) -> AdapterResult<InstructionTargetPolicy> {
        Err(AdapterError::new(
            "apply.instruction_target_unsupported",
            "the selected harness has no compiled standing-instruction target",
        ))
    }

    /// Selects a reviewed whole-file prompt-command destination root.
    fn prompt_command_target_policy(
        &self,
        _scope: HarnessScope,
        _version: VersionObservation<'_>,
    ) -> AdapterResult<PromptCommandTargetPolicy> {
        Err(AdapterError::new(
            "apply.prompt_command_target_unsupported",
            "the selected harness has no compiled prompt-command target",
        ))
    }

    /// Selects a reviewed whole-file native agent destination root.
    fn agent_target_policy(
        &self,
        _scope: HarnessScope,
        _version: VersionObservation<'_>,
    ) -> AdapterResult<AgentTargetPolicy> {
        Err(AdapterError::new(
            "apply.agent_target_unsupported",
            "the selected harness has no compiled agent target",
        ))
    }

    /// Selects a reviewed shared-document MCP entry destination.
    fn mcp_target_policy(
        &self,
        _scope: HarnessScope,
        _version: VersionObservation<'_>,
    ) -> AdapterResult<McpTargetPolicy> {
        Err(AdapterError::new(
            "apply.mcp_target_unsupported",
            "the selected harness has no compiled MCP target",
        ))
    }

    /// Selects a reviewed native-extension destination without ambient path authority.
    fn extension_target_policy(
        &self,
        _scope: HarnessScope,
        _version: VersionObservation<'_>,
    ) -> AdapterResult<ExtensionTargetPolicy> {
        Err(AdapterError::new(
            "apply.extension_target_unsupported",
            "the selected harness has no compiled native extension target",
        ))
    }
}

#[cfg(test)]
mod mcp_target_tests {
    use super::*;

    #[test]
    fn mcp_target_constructor_and_validation_reject_inconsistent_authority() {
        assert_eq!(
            McpTargetPolicy::new(
                HarnessScope::User,
                PolicyLine::CodexCurrent,
                TargetAnchor::Scope,
                ".claude.json",
                NativeMcpDialect::ClaudeCurrent,
                "claude-mcp/1",
                "claude.target.mcp.current",
            )
            .unwrap_err()
            .code,
            "adapter.mcp_target_invalid"
        );
        assert_eq!(
            McpTargetPolicy::new(
                HarnessScope::Project,
                PolicyLine::OpenCodeV2,
                TargetAnchor::HarnessConfiguration,
                "opencode.jsonc",
                NativeMcpDialect::OpenCodeV2,
                "opencode-mcp/1",
                "opencode.target.mcp.v2",
            )
            .unwrap_err()
            .code,
            "adapter.mcp_target_invalid"
        );

        let mut policy = McpTargetPolicy::new(
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            TargetAnchor::Scope,
            ".claude.json",
            NativeMcpDialect::ClaudeCurrent,
            "claude-mcp/1",
            "claude.target.mcp.current",
        )
        .unwrap();
        policy.harness = HarnessId::Codex;
        assert_eq!(
            policy.validate().unwrap_err().code,
            "adapter.mcp_target_invalid"
        );
    }
}
