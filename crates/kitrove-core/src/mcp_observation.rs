use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_adapter_api::McpTargetPolicy;
use kitrove_agent_skills::{CaptureMeter, CaptureUsage};
use kitrove_mcp::{McpParseLimits, ObservedMcpDocument, parse_native_mcp_document};
use kitrove_model::{HarnessId, HarnessScope, NormalizedDestination};

use crate::materialization::{normalized_destination_from_path, validate_target_anchor};
use crate::read_only_fs::{
    ReadOnlyFileError, RegularFileMode, read_bounded_regular_file_with_mode,
};

/// Stable, path-free failure from read-only MCP document observation.
#[derive(Clone, Eq, PartialEq)]
pub struct McpObservationError {
    code: &'static str,
    message: &'static str,
}

impl McpObservationError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for McpObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpObservationError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for McpObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for McpObservationError {}

/// Exact shared MCP document captured through one compiled, read-only target policy.
#[derive(Clone, Eq, PartialEq)]
pub struct McpDocumentObservation {
    policy: McpTargetPolicy,
    destination: NormalizedDestination,
    document: Option<Vec<u8>>,
    mode: RegularFileMode,
    parsed: Option<ObservedMcpDocument>,
}

impl McpDocumentObservation {
    #[must_use]
    pub const fn harness(&self) -> &HarnessId {
        &self.policy.harness
    }

    #[must_use]
    pub const fn scope(&self) -> HarnessScope {
        self.policy.scope
    }

    #[must_use]
    pub const fn policy(&self) -> &McpTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    #[must_use]
    pub const fn parsed(&self) -> Option<&ObservedMcpDocument> {
        self.parsed.as_ref()
    }

    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.document.is_some()
    }

    #[must_use]
    pub fn document_bytes(&self) -> Option<&[u8]> {
        self.document.as_deref()
    }

    pub(crate) fn document_text(&self) -> Option<&str> {
        self.document
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    #[must_use]
    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }

    #[must_use]
    pub fn has_same_physical_authority(&self, other: &Self) -> bool {
        self.destination == other.destination
            && self.document == other.document
            && self.mode == other.mode
            && self.parsed == other.parsed
    }
}

impl Debug for McpDocumentObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDocumentObservation")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("policy_line", &self.policy.policy_line)
            .field("present", &self.is_present())
            .field("mode", &self.mode)
            .field("document_byte_count", &self.document.as_ref().map(Vec::len))
            .field(
                "document_hash",
                &self
                    .parsed
                    .as_ref()
                    .map(ObservedMcpDocument::exact_document_hash),
            )
            .field(
                "entry_count",
                &self
                    .parsed
                    .as_ref()
                    .map(|document| document.entries().len()),
            )
            .finish()
    }
}

/// Reads and parses one compiled MCP target without following links or mutating the document.
pub fn observe_mcp_document(
    anchor: &Path,
    policy: &McpTargetPolicy,
    limits: McpParseLimits,
) -> Result<McpDocumentObservation, McpObservationError> {
    observe_mcp_document_metered(anchor, policy, limits, &mut CaptureUsage::default())
}

/// Reads one MCP document while charging a caller-owned request-global capture meter.
pub fn observe_mcp_document_metered(
    anchor: &Path,
    policy: &McpTargetPolicy,
    limits: McpParseLimits,
    meter: &mut impl CaptureMeter,
) -> Result<McpDocumentObservation, McpObservationError> {
    let limits = limits
        .validated()
        .map_err(|error| observation_error(error.code(), error.message()))?;
    policy.validate().map_err(|_| {
        observation_error(
            "mcp.policy_invalid",
            "MCP target policy is internally inconsistent",
        )
    })?;
    validate_target_anchor(anchor).map_err(|_| {
        observation_error(
            "mcp.anchor_invalid",
            "MCP target anchor must be absolute without relative components",
        )
    })?;

    let path = anchor.join(policy.relative_document.as_str());
    let destination = normalized_destination_from_path(&path).map_err(|_| {
        observation_error(
            "mcp.destination_invalid",
            "MCP target is not a supported normalized destination",
        )
    })?;
    if !meter.try_file_attempt() {
        return Err(observation_error(
            "mcp.capture_limit",
            "MCP observation exhausted the request-wide file capture limit",
        ));
    }
    let remaining_bytes = usize::try_from(meter.remaining_bytes()).unwrap_or(usize::MAX);
    let read_limit = limits.max_document_bytes.min(remaining_bytes);
    let observed_file = match read_bounded_regular_file_with_mode(&path, read_limit) {
        Ok(file) => file,
        Err(ReadOnlyFileError::Missing) => {
            return Ok(McpDocumentObservation {
                policy: policy.clone(),
                destination,
                document: None,
                mode: RegularFileMode::conservative(),
                parsed: None,
            });
        }
        Err(ReadOnlyFileError::Unsafe) => {
            return Err(observation_error(
                "mcp.document_unsafe",
                "MCP document could not be read without following or racing an unsafe path",
            ));
        }
        Err(ReadOnlyFileError::Limit) => {
            let (code, message) = if read_limit < limits.max_document_bytes {
                (
                    "mcp.capture_limit",
                    "MCP observation exhausted the request-wide byte capture limit",
                )
            } else {
                (
                    "mcp.document_limit",
                    "MCP document exceeds the configured observation byte limit",
                )
            };
            return Err(observation_error(code, message));
        }
    };
    let bytes = observed_file.bytes;
    if !meter.try_charge_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)) {
        return Err(observation_error(
            "mcp.capture_limit",
            "MCP observation exhausted the request-wide byte capture limit",
        ));
    }
    let input = std::str::from_utf8(&bytes).map_err(|_| {
        observation_error("mcp.document_invalid", "MCP document is not valid UTF-8")
    })?;
    let parsed = parse_native_mcp_document(input, policy.dialect, limits)
        .map_err(|error| observation_error(error.code(), error.message()))?;

    Ok(McpDocumentObservation {
        policy: policy.clone(),
        destination,
        document: Some(bytes),
        mode: observed_file.mode,
        parsed: Some(parsed),
    })
}

const fn observation_error(code: &'static str, message: &'static str) -> McpObservationError {
    McpObservationError::new(code, message)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kitrove_adapter_api::{McpTargetPolicy, PolicyLine, TargetAnchor};
    use kitrove_mcp::{McpParseLimits, NativeMcpDialect};
    use kitrove_model::HarnessScope;
    use tempfile::tempdir;

    use super::*;

    fn policy() -> McpTargetPolicy {
        McpTargetPolicy::new(
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            TargetAnchor::Scope,
            ".claude.json",
            NativeMcpDialect::ClaudeCurrent,
            "claude-mcp/1",
            "fixture.claude.mcp",
        )
        .unwrap()
    }

    #[test]
    fn observes_present_and_missing_documents_without_disclosing_authored_bytes() {
        let directory = tempdir().unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        let missing = observe_mcp_document(&anchor, &policy(), McpParseLimits::default()).unwrap();
        assert!(!missing.is_present());

        let source = r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com"}}}"#;
        fs::write(anchor.join(".claude.json"), source).unwrap();
        let observed = observe_mcp_document(&anchor, &policy(), McpParseLimits::default()).unwrap();
        assert_eq!(observed.parsed().unwrap().entries().len(), 1);
        assert_eq!(observed.document_bytes(), Some(source.as_bytes()));
        assert!(!format!("{observed:?}").contains("mcp.example.com"));
    }

    #[test]
    fn parser_failures_are_redacted_and_preserve_their_stable_code() {
        let directory = tempdir().unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        fs::write(
            anchor.join(".claude.json"),
            r#"{"mcpServers":{},"mcpServers":{"SECRET":{}}}"#,
        )
        .unwrap();

        let error =
            observe_mcp_document(&anchor, &policy(), McpParseLimits::default()).unwrap_err();
        assert_eq!(error.code(), "mcp.duplicate_key");
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }

    #[test]
    fn rejects_invalid_limits_before_reading_the_document() {
        let directory = tempdir().unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        fs::write(anchor.join(".claude.json"), "{}").unwrap();
        let invalid = McpParseLimits {
            max_document_bytes: usize::MAX,
            ..McpParseLimits::default()
        };

        assert_eq!(
            observe_mcp_document(&anchor, &policy(), invalid)
                .unwrap_err()
                .code(),
            "mcp.parse_limits_invalid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_document() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        fs::write(anchor.join("real.json"), "{}").unwrap();
        symlink(anchor.join("real.json"), anchor.join(".claude.json")).unwrap();

        assert_eq!(
            observe_mcp_document(&anchor, &policy(), McpParseLimits::default(),)
                .unwrap_err()
                .code(),
            "mcp.document_unsafe"
        );
    }
}
