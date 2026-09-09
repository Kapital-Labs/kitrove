use std::fmt::{self, Debug, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

use crate::{
    PromptArgumentMode, PromptBody, PromptCommand, PromptCommandError, PromptCommandName,
    PromptDescription,
};

const FORMAT: &str = "kitrove-prompt-command/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_PROMPT_COMMAND_BYTES: usize = 512 * 1024;

/// Strict portable storage envelope for one canonical prompt command.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredPromptCommand {
    command: PromptCommand,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPromptCommand {
    schema_version: u32,
    format: String,
    name: PromptCommandName,
    description: Option<PromptDescription>,
    body: String,
    argument_mode: PromptArgumentMode,
    object_hash: ContentHash,
}

impl StoredPromptCommand {
    #[must_use]
    pub fn new(command: PromptCommand) -> Self {
        let object_hash = hash_object(&command);
        Self {
            command,
            object_hash,
        }
    }

    pub fn from_json(input: &str, max_body_bytes: usize) -> Result<Self, PromptCommandError> {
        if input.len() > MAX_STORED_PROMPT_COMMAND_BYTES {
            return Err(storage_error(
                "prompt_command.storage_limit",
                "stored prompt command exceeds the portable envelope byte limit",
            ));
        }
        let persisted: PersistedPromptCommand = serde_json::from_str(input).map_err(|_| {
            storage_error(
                "prompt_command.storage_invalid",
                "stored prompt command is not strict version-1 JSON",
            )
        })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(storage_error(
                "prompt_command.storage_version",
                "stored prompt-command schema or format is unsupported",
            ));
        }
        let body = PromptBody::parse(&persisted.body, max_body_bytes)?;
        if body.as_str() != persisted.body {
            return Err(storage_error(
                "prompt_command.storage_noncanonical",
                "stored prompt-command body is not in canonical form",
            ));
        }
        let command = PromptCommand::try_new(
            persisted.name,
            persisted.description,
            body,
            persisted.argument_mode,
        )?;
        let stored = Self::new(command);
        if stored.object_hash != persisted.object_hash {
            return Err(storage_error(
                "prompt_command.storage_hash_mismatch",
                "stored prompt-command identity does not match its canonical content",
            ));
        }
        Ok(stored)
    }

    pub fn to_json(&self) -> Result<String, PromptCommandError> {
        let persisted = PersistedPromptCommand {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            name: self.command.name().clone(),
            description: self.command.description().cloned(),
            body: self.command.body().as_str().to_owned(),
            argument_mode: self.command.argument_mode(),
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            storage_error(
                "prompt_command.storage_serialize",
                "stored prompt command could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_PROMPT_COMMAND_BYTES {
            return Err(storage_error(
                "prompt_command.storage_limit",
                "stored prompt command exceeds the portable envelope byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn command(&self) -> &PromptCommand {
        &self.command
    }

    #[must_use]
    pub const fn object_hash(&self) -> &ContentHash {
        &self.object_hash
    }

    #[must_use]
    pub const fn format() -> &'static str {
        FORMAT
    }
}

impl Debug for StoredPromptCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredPromptCommand")
            .field("command", &self.command)
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn hash_object(command: &PromptCommand) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-stored-prompt-command-v1\0");
    let command_hash = command.content_hash();
    hasher.update(&(command_hash.as_str().len() as u64).to_be_bytes());
    hasher.update(command_hash.as_str().as_bytes());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

const fn storage_error(code: &'static str, message: &'static str) -> PromptCommandError {
    PromptCommandError::new(code, message)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::ALL_ARGUMENTS_PLACEHOLDER;

    fn stored() -> StoredPromptCommand {
        StoredPromptCommand::new(
            PromptCommand::try_new(
                PromptCommandName::parse("review").unwrap(),
                Some(PromptDescription::parse("Review a selected area").unwrap()),
                PromptBody::parse(&format!("Review {ALL_ARGUMENTS_PLACEHOLDER}.\n"), 1024).unwrap(),
                PromptArgumentMode::AllArguments,
            )
            .unwrap(),
        )
    }

    #[test]
    fn strict_envelope_round_trips_deterministically() {
        let original = stored();
        let encoded = original.to_json().unwrap();
        let decoded = StoredPromptCommand::from_json(&encoded, 1024).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.to_json().unwrap(), encoded);
        assert_eq!(StoredPromptCommand::format(), "kitrove-prompt-command/v1");
    }

    #[test]
    fn every_persisted_authority_field_is_verified() {
        let encoded = stored().to_json().unwrap();
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        for (field, replacement, code) in [
            (
                "schema_version",
                Value::from(2),
                "prompt_command.storage_version",
            ),
            (
                "format",
                Value::from("future"),
                "prompt_command.storage_version",
            ),
            (
                "object_hash",
                Value::from(format!("blake3:{}", "0".repeat(64))),
                "prompt_command.storage_hash_mismatch",
            ),
            (
                "name",
                Value::from("inspect"),
                "prompt_command.storage_hash_mismatch",
            ),
            (
                "description",
                Value::from("Inspect a selected area"),
                "prompt_command.storage_hash_mismatch",
            ),
            (
                "body",
                Value::from("Inspect ${KITROVE_ARGUMENTS}.\n"),
                "prompt_command.storage_hash_mismatch",
            ),
        ] {
            let original = value[field].clone();
            value[field] = replacement;
            assert_eq!(
                StoredPromptCommand::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                    .unwrap_err()
                    .code(),
                code
            );
            value[field] = original;
        }
    }

    #[test]
    fn rejects_unknown_fields_noncanonical_body_and_argument_mismatch() {
        let mut value: Value = serde_json::from_str(&stored().to_json().unwrap()).unwrap();
        value["unknown"] = Value::from(true);
        assert_eq!(
            StoredPromptCommand::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "prompt_command.storage_invalid"
        );

        let mut value: Value = serde_json::from_str(&stored().to_json().unwrap()).unwrap();
        value["body"] = Value::from("body without final newline");
        assert_eq!(
            StoredPromptCommand::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "prompt_command.storage_noncanonical"
        );

        let mut value: Value = serde_json::from_str(&stored().to_json().unwrap()).unwrap();
        value["argument_mode"] = Value::from("none");
        assert_eq!(
            StoredPromptCommand::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "prompt_command.argument_contract"
        );
    }

    #[test]
    fn debug_omits_authored_content() {
        let debug = format!("{:?}", stored());
        assert!(!debug.contains("Review a selected area"));
        assert!(!debug.contains("${KITROVE_ARGUMENTS}"));
    }
}
