#![forbid(unsafe_code)]
//! Harness-neutral, inert agent-definition primitives.

mod native;
mod native_stored;
mod render;
mod stored;

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

pub use native::{
    AgentBlockReason, AgentLimits, AgentPortability, NativeAgentDialect, ObservedAgent,
    parse_native_agent,
};
pub use native_stored::StoredNativeAgent;
pub use render::render_native_agent;
pub use stored::StoredAgent;

/// Default maximum size accepted for canonical system instructions.
pub const DEFAULT_MAX_AGENT_INSTRUCTIONS_BYTES: usize = 256 * 1024;

const MAX_AGENT_NAME_BYTES: usize = 64;
const MAX_AGENT_DESCRIPTION_BYTES: usize = 1_024;

/// Stable, path-free agent validation or storage failure.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentError {
    code: &'static str,
    message: &'static str,
}

impl AgentError {
    pub(crate) const fn new(code: &'static str, message: &'static str) -> Self {
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

impl Debug for AgentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for AgentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AgentError {}

/// Conservative portable name shared by the supported subagent registries.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentName(String);

impl AgentName {
    pub fn parse(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_AGENT_NAME_BYTES
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || value.contains("--")
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || *byte == b'-')
        {
            return Err(agent_error(
                "agent.name_invalid",
                "agent name must be lowercase words separated by single hyphens and no longer than 64 bytes",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AgentName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AgentName").field(&self.0).finish()
    }
}

impl Display for AgentName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for AgentName {
    type Error = AgentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<AgentName> for String {
    fn from(value: AgentName) -> Self {
        value.0
    }
}

/// Bounded, single-line agent description.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentDescription(String);

impl AgentDescription {
    pub fn parse(value: impl Into<String>) -> Result<Self, AgentError> {
        let value = value.into();
        if value.trim() != value
            || value.is_empty()
            || value.len() > MAX_AGENT_DESCRIPTION_BYTES
            || value.chars().any(|character| {
                character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
            })
        {
            return Err(agent_error(
                "agent.description_invalid",
                "agent description must be trimmed, bounded, non-empty single-line UTF-8",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for AgentDescription {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentDescription")
            .field("byte_count", &self.0.len())
            .finish()
    }
}

impl TryFrom<String> for AgentDescription {
    type Error = AgentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<AgentDescription> for String {
    fn from(value: AgentDescription) -> Self {
        value.0
    }
}

/// Canonical, inert system instructions.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentInstructions(String);

impl AgentInstructions {
    pub fn parse(input: &str, max_bytes: usize) -> Result<Self, AgentError> {
        if input.is_empty() || input.contains('\0') || input.len() > max_bytes {
            return Err(agent_error(
                "agent.instructions_invalid",
                "agent instructions must be bounded, non-empty UTF-8 without NUL bytes",
            ));
        }
        let normalized = input.replace("\r\n", "\n");
        if normalized.contains('\r') {
            return Err(agent_error(
                "agent.instructions_line_endings",
                "agent instructions must use LF or CRLF line endings",
            ));
        }
        let normalized = format!("{}\n", normalized.trim_end_matches('\n'));
        if normalized.trim().is_empty() || normalized.len() > max_bytes {
            return Err(agent_error(
                "agent.instructions_invalid",
                "agent instructions must contain bounded non-whitespace content",
            ));
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        hash_text(b"kitrove-agent-instructions-v1\0", &self.0)
    }
}

impl Debug for AgentInstructions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentInstructions")
            .field("byte_count", &self.0.len())
            .field("content_hash", &self.content_hash())
            .finish()
    }
}

/// Canonical portable subagent definition. It contains no runtime authority.
#[derive(Clone, Eq, PartialEq)]
pub struct Agent {
    name: AgentName,
    description: AgentDescription,
    instructions: AgentInstructions,
}

impl Agent {
    #[must_use]
    pub const fn new(
        name: AgentName,
        description: AgentDescription,
        instructions: AgentInstructions,
    ) -> Self {
        Self {
            name,
            description,
            instructions,
        }
    }

    #[must_use]
    pub const fn name(&self) -> &AgentName {
        &self.name
    }

    #[must_use]
    pub const fn description(&self) -> &AgentDescription {
        &self.description
    }

    #[must_use]
    pub const fn instructions(&self) -> &AgentInstructions {
        &self.instructions
    }

    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-agent-v1\0");
        hash_record(&mut hasher, self.name.as_str().as_bytes());
        hash_record(&mut hasher, self.description.as_str().as_bytes());
        hash_record(&mut hasher, self.instructions.as_str().as_bytes());
        digest(hasher)
    }
}

impl Debug for Agent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Agent")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("instructions", &self.instructions)
            .finish()
    }
}

pub(crate) fn hash_record(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub(crate) fn digest(hasher: blake3::Hasher) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

fn hash_text(domain: &[u8], value: &str) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_record(&mut hasher, value.as_bytes());
    digest(hasher)
}

const fn agent_error(code: &'static str, message: &'static str) -> AgentError {
    AgentError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_agent_normalizes_only_document_line_endings() {
        let instructions = AgentInstructions::parse("Review.\r\n\r\n", 1024).unwrap();
        assert_eq!(instructions.as_str(), "Review.\n");
        assert!(AgentName::parse("code-review").is_ok());
        for invalid in ["Code-review", "code2", "-code", "code-", "code--review"] {
            assert_eq!(
                AgentName::parse(invalid).unwrap_err().code(),
                "agent.name_invalid"
            );
        }
    }

    #[test]
    fn description_limit_is_utf8_bytes_and_debug_redacts_authored_text() {
        assert!(AgentDescription::parse("é".repeat(512)).is_ok());
        assert_eq!(
            AgentDescription::parse("é".repeat(513)).unwrap_err().code(),
            "agent.description_invalid"
        );
        let agent = Agent::new(
            AgentName::parse("review").unwrap(),
            AgentDescription::parse("SECRET-DESCRIPTION").unwrap(),
            AgentInstructions::parse("SECRET-INSTRUCTIONS\n", 1024).unwrap(),
        );
        let debug = format!("{agent:?}");
        assert!(!debug.contains("SECRET-DESCRIPTION"));
        assert!(!debug.contains("SECRET-INSTRUCTIONS"));
    }
}
