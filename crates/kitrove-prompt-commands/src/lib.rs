#![forbid(unsafe_code)]
//! Harness-neutral prompt-command primitives.

mod native;
mod native_stored;
mod render;
mod stored;

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

pub use native::{
    NativePromptDialect, ObservedPromptCommand, PromptCommandBlockReason, PromptCommandLimits,
    PromptCommandPortability, parse_native_prompt_command,
};
pub use native_stored::StoredNativePromptCommand;
pub use render::render_native_prompt_command;
pub use stored::StoredPromptCommand;

/// Portable placeholder rendered to a target's documented all-arguments syntax.
pub const ALL_ARGUMENTS_PLACEHOLDER: &str = "${KITROVE_ARGUMENTS}";

/// Default maximum size accepted for one canonical prompt body.
pub const DEFAULT_MAX_PROMPT_BODY_BYTES: usize = 256 * 1024;

const MAX_COMMAND_NAME_BYTES: usize = 64;
const MAX_DESCRIPTION_CHARACTERS: usize = 1_024;

/// Stable, path-free prompt-command validation or storage failure.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandError {
    code: &'static str,
    message: &'static str,
}

impl PromptCommandError {
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

impl Debug for PromptCommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PromptCommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PromptCommandError {}

/// A portable, single-segment command name.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct PromptCommandName(String);

impl PromptCommandName {
    /// Parses the conservative v1 command-name intersection.
    pub fn parse(value: impl Into<String>) -> Result<Self, PromptCommandError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_COMMAND_NAME_BYTES
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || value.contains("--")
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(prompt_error(
                "prompt_command.name_invalid",
                "command name must be one lowercase hyphenated segment no longer than 64 bytes",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for PromptCommandName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PromptCommandName")
            .field(&self.0)
            .finish()
    }
}

impl Display for PromptCommandName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for PromptCommandName {
    type Error = PromptCommandError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<PromptCommandName> for String {
    fn from(value: PromptCommandName) -> Self {
        value.0
    }
}

/// The argument behavior represented by the v1 portable core.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptArgumentMode {
    None,
    AllArguments,
}

/// Canonical non-empty Markdown prompt bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptBody(String);

impl PromptBody {
    /// Normalizes CRLF to LF and ensures exactly one trailing newline.
    pub fn parse(input: &str, max_body_bytes: usize) -> Result<Self, PromptCommandError> {
        if input.is_empty() || input.contains('\0') {
            return Err(prompt_error(
                "prompt_command.body_invalid",
                "prompt body must be non-empty UTF-8 without NUL bytes",
            ));
        }
        if input.len() > max_body_bytes {
            return Err(prompt_error(
                "prompt_command.body_limit",
                "prompt body exceeds the configured byte limit",
            ));
        }

        let normalized = input.replace("\r\n", "\n");
        if normalized.contains('\r') {
            return Err(prompt_error(
                "prompt_command.body_line_endings",
                "prompt body must use LF or CRLF line endings",
            ));
        }
        let normalized = format!("{}\n", normalized.trim_end_matches('\n'));
        if normalized.trim().is_empty() || normalized.len() > max_body_bytes {
            return Err(prompt_error(
                "prompt_command.body_limit",
                "prompt body is empty or exceeds the configured byte limit",
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
        hash_text(b"kitrove-prompt-body-v1\0", &self.0)
    }
}

impl Debug for PromptBody {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptBody")
            .field("byte_count", &self.0.len())
            .field("content_hash", &self.content_hash())
            .finish()
    }
}

/// A bounded, canonical command description for native command listings.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct PromptDescription(String);

impl PromptDescription {
    pub fn parse(value: impl Into<String>) -> Result<Self, PromptCommandError> {
        let value = value.into();
        if value.trim() != value
            || !(1..=MAX_DESCRIPTION_CHARACTERS).contains(&value.chars().count())
            || value.chars().any(|character| {
                character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
            })
        {
            return Err(prompt_error(
                "prompt_command.description_invalid",
                "description must be trimmed, single-line text containing at most 1,024 characters",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for PromptDescription {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptDescription")
            .field("character_count", &self.0.chars().count())
            .finish()
    }
}

impl TryFrom<String> for PromptDescription {
    type Error = PromptCommandError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<PromptDescription> for String {
    fn from(value: PromptDescription) -> Self {
        value.0
    }
}

/// Canonical portable content for one prompt command.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommand {
    name: PromptCommandName,
    description: Option<PromptDescription>,
    body: PromptBody,
    argument_mode: PromptArgumentMode,
}

impl PromptCommand {
    pub fn try_new(
        name: PromptCommandName,
        description: Option<PromptDescription>,
        body: PromptBody,
        argument_mode: PromptArgumentMode,
    ) -> Result<Self, PromptCommandError> {
        let has_placeholder = body.as_str().contains(ALL_ARGUMENTS_PLACEHOLDER);
        if has_placeholder != (argument_mode == PromptArgumentMode::AllArguments) {
            return Err(prompt_error(
                "prompt_command.argument_contract",
                "argument mode must exactly describe use of the portable all-arguments placeholder",
            ));
        }
        Ok(Self {
            name,
            description,
            body,
            argument_mode,
        })
    }

    #[must_use]
    pub const fn name(&self) -> &PromptCommandName {
        &self.name
    }

    #[must_use]
    pub const fn description(&self) -> Option<&PromptDescription> {
        self.description.as_ref()
    }

    #[must_use]
    pub const fn body(&self) -> &PromptBody {
        &self.body
    }

    #[must_use]
    pub const fn argument_mode(&self) -> PromptArgumentMode {
        self.argument_mode
    }

    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-prompt-command-v1\0");
        hash_record(&mut hasher, self.name.as_str());
        match &self.description {
            Some(description) => {
                hasher.update(&[1]);
                hash_record(&mut hasher, description.as_str());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hash_record(&mut hasher, self.body.content_hash().as_str());
        hasher.update(&[match self.argument_mode {
            PromptArgumentMode::None => 0,
            PromptArgumentMode::AllArguments => 1,
        }]);
        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid content hash")
    }
}

impl Debug for PromptCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommand")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("body", &self.body)
            .field("argument_mode", &self.argument_mode)
            .field("content_hash", &self.content_hash())
            .finish()
    }
}

fn hash_text(domain: &[u8], value: &str) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_record(&mut hasher, value);
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

fn hash_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn prompt_error(code: &'static str, message: &'static str) -> PromptCommandError {
    PromptCommandError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(body: &str, mode: PromptArgumentMode) -> PromptCommand {
        PromptCommand::try_new(
            PromptCommandName::parse("review-changes").unwrap(),
            Some(PromptDescription::parse("Review current changes").unwrap()),
            PromptBody::parse(body, 1024).unwrap(),
            mode,
        )
        .unwrap()
    }

    #[test]
    fn canonical_command_enforces_name_description_and_body_bounds() {
        for invalid in ["", "-review", "review-", "review--changes", "Review", "a/b"] {
            assert_eq!(
                PromptCommandName::parse(invalid).unwrap_err().code(),
                "prompt_command.name_invalid"
            );
        }
        assert_eq!(
            PromptCommandName::parse("a".repeat(65)).unwrap_err().code(),
            "prompt_command.name_invalid"
        );
        for invalid in [
            "",
            " padded",
            "line\nbreak",
            "control\tcharacter",
            "unicode\u{2028}line",
        ] {
            assert_eq!(
                PromptDescription::parse(invalid).unwrap_err().code(),
                "prompt_command.description_invalid"
            );
        }
        assert_eq!(
            PromptBody::parse("body\rwith-return", 1024)
                .unwrap_err()
                .code(),
            "prompt_command.body_line_endings"
        );
        assert_eq!(
            PromptBody::parse("12345", 5).unwrap_err().code(),
            "prompt_command.body_limit"
        );
    }

    #[test]
    fn body_normalization_and_hashing_are_deterministic() {
        let lf = PromptBody::parse("Review changes.\n", 1024).unwrap();
        let crlf = PromptBody::parse("Review changes.\r\n\r\n", 1024).unwrap();
        assert_eq!(lf, crlf);
        assert_eq!(lf.as_str(), "Review changes.\n");
        assert_eq!(lf.content_hash(), crlf.content_hash());
    }

    #[test]
    fn argument_mode_exactly_matches_portable_placeholder() {
        assert_eq!(
            PromptCommand::try_new(
                PromptCommandName::parse("review").unwrap(),
                None,
                PromptBody::parse("Review.\n", 1024).unwrap(),
                PromptArgumentMode::AllArguments,
            )
            .unwrap_err()
            .code(),
            "prompt_command.argument_contract"
        );
        assert_eq!(
            PromptCommand::try_new(
                PromptCommandName::parse("review").unwrap(),
                None,
                PromptBody::parse("Review ${KITROVE_ARGUMENTS}.\n", 1024).unwrap(),
                PromptArgumentMode::None,
            )
            .unwrap_err()
            .code(),
            "prompt_command.argument_contract"
        );
        assert_eq!(
            command(
                "Review ${KITROVE_ARGUMENTS}.\n",
                PromptArgumentMode::AllArguments
            )
            .argument_mode(),
            PromptArgumentMode::AllArguments
        );
    }

    #[test]
    fn debug_omits_authored_prompt_and_description() {
        let debug = format!(
            "{:?}",
            command("PRIVATE PROMPT\n", PromptArgumentMode::None)
        );
        assert!(!debug.contains("PRIVATE PROMPT"));
        assert!(!debug.contains("Review current changes"));
    }
}
