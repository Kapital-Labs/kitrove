use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use kitrove_adapter_api::{
    AdapterError, AdapterResult, FindingSeverity, FindingSubject, RootId, RootTier, ScanFinding,
    SourceRelativePath,
};
use kitrove_agent_skills::{CaptureLimits, CaptureMeter};
use kitrove_agents::{
    AgentLimits, AgentPortability, NativeAgentDialect, ObservedAgent, parse_native_agent,
};
use kitrove_model::{AssetKind, ContentHash, HarnessId, HarnessScope};

use crate::observation_identity::WholeFileObservationIdentity;
use crate::read_only_fs::{ReadOnlyFileError, read_bounded_regular_file};
use crate::{
    AgentScanEntry, RelatedCapabilityObservation, RelatedDocumentLocator, ScanClassification,
};

pub(crate) enum AgentCaptureOutcome {
    Captured {
        entry: Box<AgentScanEntry>,
        observation: Box<AgentObservation>,
    },
    Refused(RelatedCapabilityObservation),
}

/// One exact native agent bound to the compiled origin that authorized its capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentObservation {
    harness: HarnessId,
    scope: HarnessScope,
    root_tier: RootTier,
    logical_root: RootId,
    policy_rank: u32,
    observed: ObservedAgent,
    identity: ContentHash,
}

impl AgentObservation {
    pub(crate) fn new(
        harness: HarnessId,
        scope: HarnessScope,
        root_tier: RootTier,
        logical_root: RootId,
        policy_rank: u32,
        observed: ObservedAgent,
    ) -> Result<Self, AgentObservationError> {
        if observed.dialect().harness() != harness {
            return Err(observation_error(
                "agent.observation_harness_mismatch",
                "native agent dialect does not match its compiled observation origin",
            ));
        }
        let identity = observation_identity(
            &harness,
            scope,
            root_tier,
            &logical_root,
            policy_rank,
            &observed,
        );
        Ok(Self {
            harness,
            scope,
            root_tier,
            logical_root,
            policy_rank,
            observed,
            identity,
        })
    }

    #[must_use]
    pub const fn harness(&self) -> &HarnessId {
        &self.harness
    }

    #[must_use]
    pub const fn scope(&self) -> HarnessScope {
        self.scope
    }

    #[must_use]
    pub const fn root_tier(&self) -> RootTier {
        self.root_tier
    }

    #[must_use]
    pub const fn logical_root(&self) -> &RootId {
        &self.logical_root
    }

    #[must_use]
    pub const fn policy_rank(&self) -> u32 {
        self.policy_rank
    }

    #[must_use]
    pub const fn observed(&self) -> &ObservedAgent {
        &self.observed
    }

    #[must_use]
    pub const fn identity(&self) -> &ContentHash {
        &self.identity
    }
}

/// Stable, redacted native-agent observation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentObservationError {
    code: &'static str,
    message: &'static str,
}

impl AgentObservationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl Display for AgentObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AgentObservationError {}

/// Reads and parses one regular native agent through the request-global capture meter.
pub fn observe_agent_file_metered(
    path: &Path,
    document_name: &str,
    dialect: NativeAgentDialect,
    limits: AgentLimits,
    capture_byte_limit: usize,
    meter: &mut dyn CaptureMeter,
) -> Result<ObservedAgent, AgentObservationError> {
    if !meter.try_file_attempt() {
        return Err(observation_error(
            "agent.capture_limit",
            "agent capture exhausted the request file-attempt limit",
        ));
    }
    let remaining_bytes = usize::try_from(meter.remaining_bytes()).unwrap_or(usize::MAX);
    let read_limit = limits
        .max_document_bytes
        .min(capture_byte_limit)
        .min(remaining_bytes);
    let bytes = read_bounded_regular_file(path, read_limit).map_err(|error| match error {
        ReadOnlyFileError::Limit if read_limit < limits.max_document_bytes => observation_error(
            "agent.capture_limit",
            "agent capture exhausted the request byte limit",
        ),
        ReadOnlyFileError::Limit => observation_error(
            "agent.document_limit",
            "native agent exceeds the configured document byte limit",
        ),
        ReadOnlyFileError::Missing | ReadOnlyFileError::Unsafe => observation_error(
            "agent.capture_unsafe",
            "native agent is missing or is not a safe regular file",
        ),
    })?;
    if !meter.try_charge_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)) {
        return Err(observation_error(
            "agent.capture_limit",
            "agent capture exhausted the request byte limit",
        ));
    }
    parse_native_agent(dialect, document_name, &bytes, limits).map_err(|_| {
        observation_error(
            "agent.document_invalid",
            "native agent does not satisfy the bounded dialect parser",
        )
    })
}

pub(crate) fn capture_agent_locator(
    harness: &HarnessId,
    locator: RelatedDocumentLocator,
    capture_limits: CaptureLimits,
    meter: &mut dyn CaptureMeter,
) -> AdapterResult<AgentCaptureOutcome> {
    let dialect = agent_dialect(harness).ok_or_else(|| {
        AdapterError::new(
            "scan.agent_dialect_missing",
            "an agent root was registered without a compiled native dialect",
        )
    })?;
    let limits = AgentLimits::default();
    let capture_byte_limit = usize::try_from(
        capture_limits
            .max_file_bytes
            .min(capture_limits.max_total_bytes),
    )
    .unwrap_or(usize::MAX);
    let observed = match observe_agent_file_metered(
        &locator.absolute_path,
        &locator.source_relative_path,
        dialect,
        limits,
        capture_byte_limit,
        meter,
    ) {
        Ok(observed) => observed,
        Err(_) => {
            return Ok(AgentCaptureOutcome::Refused(RelatedCapabilityObservation {
                harness: harness.clone(),
                scope: locator.root.scope,
                root_tier: locator.root.tier,
                logical_root: locator.root.logical_id.clone(),
                policy_rank: locator.root.policy_rank,
                source_relative_path: locator.source_relative_path,
                kind: AssetKind::Agent,
                findings: vec![ScanFinding::new(
                    "scan.agent_capture_failed",
                    FindingSeverity::Attention,
                    FindingSubject::Root(locator.root.logical_id),
                    vec![locator.root.evidence],
                    "inspect the agent document, path safety, and capture limits",
                )],
            }));
        }
    };
    let (portable_hash, blocked_reason) = match observed.portability() {
        AgentPortability::Portable(agent) => (Some(agent.content_hash()), None),
        AgentPortability::Blocked(reason) => (None, Some(*reason)),
    };
    let observation = AgentObservation::new(
        harness.clone(),
        locator.root.scope,
        locator.root.tier,
        locator.root.logical_id.clone(),
        locator.root.policy_rank,
        observed,
    )
    .map_err(|_| {
        AdapterError::new(
            "scan.agent_observation_invalid",
            "captured agent could not be bound to its compiled origin",
        )
    })?;
    let subject = FindingSubject::Related {
        logical_root: locator.root.logical_id.clone(),
        source_relative_path: SourceRelativePath::parse(locator.source_relative_path.clone())
            .expect("discovery retains validated UTF-8 relative paths"),
    };
    let finding = ScanFinding::new(
        if blocked_reason.is_some() {
            "scan.agent_not_portable"
        } else {
            "scan.agent_portable"
        },
        if blocked_reason.is_some() {
            FindingSeverity::Attention
        } else {
            FindingSeverity::Informational
        },
        subject,
        vec![locator.root.evidence],
        if blocked_reason.is_some() {
            "keep the definition native or remove runtime authority outside portable v1"
        } else {
            "review the inert portable agent projection before adoption"
        },
    );
    let normalized_destination = crate::materialization::normalized_destination_from_path(
        &locator.absolute_path,
    )
    .map_err(|_| {
        AdapterError::new(
            "scan.agent_identity_invalid",
            "captured agent destination could not be represented portably",
        )
    })?;
    let entry = AgentScanEntry {
        observation_id: Some(observation.identity().clone()),
        harness: harness.clone(),
        scope: locator.root.scope,
        root_tier: Some(locator.root.tier),
        logical_root: Some(locator.root.logical_id),
        policy_rank: Some(locator.root.policy_rank),
        source_relative_path: Some(locator.source_relative_path),
        dialect,
        name: observation.observed().name().clone(),
        asset_id: None,
        receipt_id: None,
        normalized_destination: Some(normalized_destination),
        receipt_rendered_hash: None,
        exact_source_hash: Some(observation.observed().exact_hash().clone()),
        observed_target_hash: None,
        portable_hash,
        content_class: observation.observed().content_class(),
        blocked_reason,
        classification: ScanClassification::Unmanaged,
        findings: vec![finding],
    };
    Ok(AgentCaptureOutcome::Captured {
        entry: Box::new(entry),
        observation: Box::new(observation),
    })
}

pub(crate) const fn agent_dialect(harness: &HarnessId) -> Option<NativeAgentDialect> {
    match harness {
        HarnessId::Claude => Some(NativeAgentDialect::ClaudeCurrent),
        HarnessId::Codex => Some(NativeAgentDialect::CodexCurrent),
        HarnessId::OpenCode => Some(NativeAgentDialect::OpenCodeCurrent),
        HarnessId::Pi | HarnessId::Other(_) => None,
    }
}

fn observation_identity(
    harness: &HarnessId,
    scope: HarnessScope,
    root_tier: RootTier,
    logical_root: &RootId,
    policy_rank: u32,
    observed: &ObservedAgent,
) -> ContentHash {
    WholeFileObservationIdentity {
        domain: b"kitrove-agent-observation-v1\0",
        harness,
        scope,
        root_tier,
        logical_root,
        policy_rank,
        source_document: observed.source_document(),
        exact_hash: observed.exact_hash(),
        dialect_tag: match observed.dialect() {
            NativeAgentDialect::ClaudeCurrent => 0,
            NativeAgentDialect::CodexCurrent => 1,
            NativeAgentDialect::OpenCodeCurrent => 2,
        },
    }
    .digest()
}

const fn observation_error(code: &'static str, message: &'static str) -> AgentObservationError {
    AgentObservationError { code, message }
}

#[cfg(test)]
mod tests {
    use kitrove_agent_skills::CaptureUsage;
    use tempfile::tempdir;

    use super::*;

    fn claude_source() -> &'static str {
        "---\nname: review\ndescription: SECRET-DESCRIPTION\n---\nSECRET-INSTRUCTIONS\n"
    }

    #[test]
    fn metered_capture_is_read_only_bounded_and_redacted() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().canonicalize().unwrap().join("review.md");
        std::fs::write(&path, claude_source()).unwrap();
        let before = std::fs::metadata(&path).unwrap().permissions();
        let mut meter = CaptureUsage::default();
        let observed = observe_agent_file_metered(
            &path,
            "review.md",
            NativeAgentDialect::ClaudeCurrent,
            AgentLimits::default(),
            512 * 1024,
            &mut meter,
        )
        .unwrap();

        assert_eq!(observed.exact_bytes(), claude_source().as_bytes());
        assert_eq!(meter.file_attempts, 1);
        assert_eq!(meter.bytes_read, claude_source().len() as u64);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions(), before);
        let debug = format!("{observed:?}");
        assert!(!debug.contains("SECRET-DESCRIPTION"));
        assert!(!debug.contains("SECRET-INSTRUCTIONS"));
    }

    #[test]
    fn observation_identity_binds_compiled_origin_and_rejects_cross_harness_dialect() {
        let observed = parse_native_agent(
            NativeAgentDialect::ClaudeCurrent,
            "review.md",
            claude_source().as_bytes(),
            AgentLimits::default(),
        )
        .unwrap();
        let root = RootId::parse("claude.user.agents").unwrap();
        let user = AgentObservation::new(
            HarnessId::Claude,
            HarnessScope::User,
            RootTier::User,
            root.clone(),
            20,
            observed.clone(),
        )
        .unwrap();
        let project = AgentObservation::new(
            HarnessId::Claude,
            HarnessScope::Project,
            RootTier::Project,
            root,
            30,
            observed.clone(),
        )
        .unwrap();
        assert_ne!(user.identity(), project.identity());
        assert_eq!(
            AgentObservation::new(
                HarnessId::Codex,
                HarnessScope::User,
                RootTier::User,
                RootId::parse("codex.user.agents").unwrap(),
                20,
                observed,
            )
            .unwrap_err()
            .code(),
            "agent.observation_harness_mismatch"
        );
    }

    #[test]
    fn capture_budget_failure_never_reads_the_file() {
        struct DenyingMeter;

        impl CaptureMeter for DenyingMeter {
            fn try_file_attempt(&mut self) -> bool {
                false
            }

            fn remaining_bytes(&self) -> u64 {
                0
            }

            fn try_charge_bytes(&mut self, _bytes: u64) -> bool {
                false
            }
        }

        let temporary = tempdir().unwrap();
        let path = temporary.path().canonicalize().unwrap().join("review.md");
        std::fs::write(&path, claude_source()).unwrap();
        let mut meter = DenyingMeter;
        assert_eq!(
            observe_agent_file_metered(
                &path,
                "review.md",
                NativeAgentDialect::ClaudeCurrent,
                AgentLimits::default(),
                1024,
                &mut meter,
            )
            .unwrap_err()
            .code(),
            "agent.capture_limit"
        );
    }
}
