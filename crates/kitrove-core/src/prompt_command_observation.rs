use std::path::Path;

use kitrove_adapter_api::{
    AdapterError, AdapterResult, FindingSeverity, FindingSubject, RootId, RootTier, ScanFinding,
    SourceRelativePath,
};
use kitrove_agent_skills::{CaptureLimits, CaptureMeter};
use kitrove_model::{AssetKind, ContentHash, HarnessId, HarnessScope};
use kitrove_prompt_commands::{
    NativePromptDialect, ObservedPromptCommand, PromptCommandBlockReason, PromptCommandLimits,
    PromptCommandPortability, parse_native_prompt_command,
};

use crate::observation_identity::WholeFileObservationIdentity;
use crate::read_only_fs::{ReadOnlyFileError, read_bounded_regular_file};
use crate::{
    PromptCommandScanEntry, RelatedCapabilityObservation, RelatedDocumentLocator,
    ScanClassification,
};

pub(crate) enum PromptCommandCaptureOutcome {
    Captured {
        entry: PromptCommandScanEntry,
        observation: Box<PromptCommandObservation>,
    },
    Refused(RelatedCapabilityObservation),
}

/// One exact prompt command bound to the compiled origin that authorized its capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptCommandObservation {
    harness: HarnessId,
    scope: HarnessScope,
    root_tier: RootTier,
    logical_root: RootId,
    policy_rank: u32,
    observed: ObservedPromptCommand,
    identity: ContentHash,
}

impl PromptCommandObservation {
    pub(crate) fn new(
        harness: HarnessId,
        scope: HarnessScope,
        root_tier: RootTier,
        logical_root: RootId,
        policy_rank: u32,
        observed: ObservedPromptCommand,
    ) -> Self {
        let identity = prompt_command_observation_identity(
            &harness,
            scope,
            root_tier,
            &logical_root,
            policy_rank,
            &observed,
        );
        Self {
            harness,
            scope,
            root_tier,
            logical_root,
            policy_rank,
            observed,
            identity,
        }
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
    pub const fn observed(&self) -> &ObservedPromptCommand {
        &self.observed
    }

    #[must_use]
    pub const fn identity(&self) -> &ContentHash {
        &self.identity
    }
}

fn prompt_command_observation_identity(
    harness: &HarnessId,
    scope: HarnessScope,
    root_tier: RootTier,
    logical_root: &RootId,
    policy_rank: u32,
    observed: &ObservedPromptCommand,
) -> ContentHash {
    WholeFileObservationIdentity {
        domain: b"kitrove-prompt-command-observation-v1\0",
        harness,
        scope,
        root_tier,
        logical_root,
        policy_rank,
        source_document: observed.source_document(),
        exact_hash: observed.exact_hash(),
        dialect_tag: match observed.dialect() {
            NativePromptDialect::ClaudeLegacy => 0,
            NativePromptDialect::PiLatest => 1,
            NativePromptDialect::OpenCodeV2 => 2,
        },
    }
    .digest()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromptCommandCaptureError {
    CaptureLimit,
    DocumentLimit,
    Unsafe,
    Invalid,
}

pub(crate) fn capture_prompt_command_locator(
    harness: &HarnessId,
    locator: RelatedDocumentLocator,
    capture_limits: CaptureLimits,
    meter: &mut dyn CaptureMeter,
) -> AdapterResult<PromptCommandCaptureOutcome> {
    let Some(dialect) = prompt_command_dialect(harness) else {
        return Err(AdapterError::new(
            "scan.prompt_command_dialect_missing",
            "a command root was registered without a compiled native dialect",
        ));
    };
    let defaults = PromptCommandLimits::default();
    let capture_byte_limit = usize::try_from(
        capture_limits
            .max_file_bytes
            .min(capture_limits.max_total_bytes),
    )
    .unwrap_or(usize::MAX);
    let observed = match capture_prompt_command_metered(
        &locator.absolute_path,
        dialect,
        &locator.source_relative_path,
        defaults,
        capture_byte_limit,
        meter,
    ) {
        Ok(observed) => observed,
        Err(error) => {
            return Ok(PromptCommandCaptureOutcome::Refused(
                prompt_command_capture_failure(harness, locator, error),
            ));
        }
    };
    let (portable_hash, blocked_reason) = match observed.portability() {
        PromptCommandPortability::Portable(command) => (Some(command.content_hash()), None),
        PromptCommandPortability::Blocked(reason) => (None, Some(*reason)),
    };
    let finding = prompt_command_finding(&locator, blocked_reason);
    let observation = PromptCommandObservation::new(
        harness.clone(),
        locator.root.scope,
        locator.root.tier,
        locator.root.logical_id.clone(),
        locator.root.policy_rank,
        observed,
    );
    let entry = PromptCommandScanEntry {
        observation_id: observation.identity().clone(),
        harness: harness.clone(),
        scope: locator.root.scope,
        root_tier: locator.root.tier,
        logical_root: locator.root.logical_id,
        policy_rank: locator.root.policy_rank,
        source_relative_path: locator.source_relative_path,
        dialect,
        name: observation.observed.name().clone(),
        exact_source_hash: observation.observed.exact_hash().clone(),
        portable_hash,
        content_class: observation.observed.content_class(),
        blocked_reason,
        classification: ScanClassification::Unmanaged,
        findings: vec![finding],
    };
    Ok(PromptCommandCaptureOutcome::Captured {
        entry,
        observation: Box::new(observation),
    })
}

fn capture_prompt_command_metered(
    path: &Path,
    dialect: NativePromptDialect,
    document_name: &str,
    limits: PromptCommandLimits,
    capture_byte_limit: usize,
    meter: &mut dyn CaptureMeter,
) -> Result<ObservedPromptCommand, PromptCommandCaptureError> {
    if !meter.try_file_attempt() {
        return Err(PromptCommandCaptureError::CaptureLimit);
    }
    let remaining_bytes = usize::try_from(meter.remaining_bytes()).unwrap_or(usize::MAX);
    let read_limit = limits
        .max_document_bytes
        .min(capture_byte_limit)
        .min(remaining_bytes);
    let bytes = read_bounded_regular_file(path, read_limit).map_err(|error| match error {
        ReadOnlyFileError::Limit if read_limit < limits.max_document_bytes => {
            PromptCommandCaptureError::CaptureLimit
        }
        ReadOnlyFileError::Limit => PromptCommandCaptureError::DocumentLimit,
        ReadOnlyFileError::Missing | ReadOnlyFileError::Unsafe => PromptCommandCaptureError::Unsafe,
    })?;
    if !meter.try_charge_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)) {
        return Err(PromptCommandCaptureError::CaptureLimit);
    }
    parse_native_prompt_command(dialect, document_name, &bytes, limits)
        .map_err(|_| PromptCommandCaptureError::Invalid)
}

pub(crate) const fn prompt_command_dialect(harness: &HarnessId) -> Option<NativePromptDialect> {
    match harness {
        HarnessId::Claude => Some(NativePromptDialect::ClaudeLegacy),
        HarnessId::Pi => Some(NativePromptDialect::PiLatest),
        HarnessId::OpenCode => Some(NativePromptDialect::OpenCodeV2),
        HarnessId::Codex | HarnessId::Other(_) => None,
    }
}

fn prompt_command_finding(
    locator: &RelatedDocumentLocator,
    blocked_reason: Option<PromptCommandBlockReason>,
) -> ScanFinding {
    let subject = related_subject(locator);
    match blocked_reason {
        None => ScanFinding::new(
            "scan.prompt_command_portable",
            FindingSeverity::Informational,
            subject,
            vec![locator.root.evidence.clone()],
            "review the portable prompt-command projection before adoption",
        ),
        Some(PromptCommandBlockReason::ExecutableInterpolation) => ScanFinding::new(
            "scan.prompt_command_executable",
            FindingSeverity::Attention,
            subject,
            vec![locator.root.evidence.clone()],
            "keep executable interpolation native unless separately reviewed and trusted",
        ),
        Some(_) => ScanFinding::new(
            "scan.prompt_command_not_portable",
            FindingSeverity::Informational,
            subject,
            vec![locator.root.evidence.clone()],
            "keep the command native or remove features outside the portable v1 boundary",
        ),
    }
}

fn prompt_command_capture_failure(
    harness: &HarnessId,
    locator: RelatedDocumentLocator,
    error: PromptCommandCaptureError,
) -> RelatedCapabilityObservation {
    let (code, action) = match error {
        PromptCommandCaptureError::CaptureLimit => (
            "scan.prompt_command_capture_limit",
            "reduce prompt-command inputs or increase the request capture limit",
        ),
        PromptCommandCaptureError::DocumentLimit => (
            "scan.prompt_command_document_limit",
            "reduce the prompt-command document size",
        ),
        PromptCommandCaptureError::Unsafe => (
            "scan.prompt_command_unsafe",
            "replace the changing, linked, or unreadable prompt-command document",
        ),
        PromptCommandCaptureError::Invalid => (
            "scan.prompt_command_invalid",
            "repair the prompt-command name, UTF-8 document, or frontmatter",
        ),
    };
    let finding = ScanFinding::new(
        code,
        FindingSeverity::Attention,
        related_subject(&locator),
        vec![locator.root.evidence.clone()],
        action,
    );
    RelatedCapabilityObservation {
        harness: harness.clone(),
        scope: locator.root.scope,
        root_tier: locator.root.tier,
        logical_root: locator.root.logical_id,
        policy_rank: locator.root.policy_rank,
        source_relative_path: locator.source_relative_path,
        kind: AssetKind::Command,
        findings: vec![finding],
    }
}

fn related_subject(locator: &RelatedDocumentLocator) -> FindingSubject {
    FindingSubject::Related {
        logical_root: locator.root.logical_id.clone(),
        source_relative_path: SourceRelativePath::parse(locator.source_relative_path.clone())
            .expect("discovery retains only validated UTF-8 relative paths"),
    }
}
