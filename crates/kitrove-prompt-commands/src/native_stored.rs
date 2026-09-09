use std::fmt::{self, Debug, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

use crate::{
    NativePromptDialect, ObservedPromptCommand, PromptCommandError, PromptCommandLimits,
    parse_native_prompt_command,
};

const FORMAT: &str = "kitrove-native-prompt-command/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_NATIVE_COMMAND_BYTES: usize = 768 * 1024;

/// Strict lossless storage for one safely parsed origin-native prompt command.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredNativePromptCommand {
    observed: ObservedPromptCommand,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedNativePromptCommand {
    schema_version: u32,
    format: String,
    dialect: NativePromptDialect,
    source_document: String,
    exact_source: String,
    object_hash: ContentHash,
}

impl StoredNativePromptCommand {
    pub fn new(observed: ObservedPromptCommand) -> Result<Self, PromptCommandError> {
        let object_hash = hash_object(&observed);
        let stored = Self {
            observed,
            object_hash,
        };
        stored.to_json()?;
        Ok(stored)
    }

    pub fn from_json(input: &str) -> Result<Self, PromptCommandError> {
        if input.len() > MAX_STORED_NATIVE_COMMAND_BYTES {
            return Err(native_storage_error(
                "prompt_command.native_storage_limit",
                "native prompt command exceeds the storage byte limit",
            ));
        }
        let persisted: PersistedNativePromptCommand =
            serde_json::from_str(input).map_err(|_| {
                native_storage_error(
                    "prompt_command.native_storage_invalid",
                    "native prompt command is not strict version-1 JSON",
                )
            })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(native_storage_error(
                "prompt_command.native_storage_version",
                "native prompt-command schema or format is unsupported",
            ));
        }
        let observed = parse_native_prompt_command(
            persisted.dialect,
            &persisted.source_document,
            persisted.exact_source.as_bytes(),
            PromptCommandLimits::default(),
        )?;
        let stored = Self::new(observed)?;
        if stored.object_hash != persisted.object_hash {
            return Err(native_storage_error(
                "prompt_command.native_storage_hash_mismatch",
                "native prompt-command identity does not match its exact source",
            ));
        }
        Ok(stored)
    }

    pub fn to_json(&self) -> Result<String, PromptCommandError> {
        let exact_source =
            String::from_utf8(self.observed.exact_bytes().to_vec()).map_err(|_| {
                native_storage_error(
                    "prompt_command.native_source_invalid",
                    "native prompt-command source must be valid UTF-8",
                )
            })?;
        let persisted = PersistedNativePromptCommand {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            dialect: self.observed.dialect(),
            source_document: self.observed.source_document().to_owned(),
            exact_source,
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            native_storage_error(
                "prompt_command.native_storage_serialize",
                "native prompt command could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_NATIVE_COMMAND_BYTES {
            return Err(native_storage_error(
                "prompt_command.native_storage_limit",
                "native prompt command exceeds the storage byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn observed(&self) -> &ObservedPromptCommand {
        &self.observed
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

impl Debug for StoredNativePromptCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredNativePromptCommand")
            .field("observed", &self.observed)
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn hash_object(observed: &ObservedPromptCommand) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-prompt-command-object-v1\0");
    let exact_hash = observed.exact_hash();
    hasher.update(&(exact_hash.as_str().len() as u64).to_be_bytes());
    hasher.update(exact_hash.as_str().as_bytes());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

const fn native_storage_error(code: &'static str, message: &'static str) -> PromptCommandError {
    PromptCommandError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredNativePromptCommand {
        let observed = parse_native_prompt_command(
            NativePromptDialect::PiLatest,
            "review.md",
            b"---\ndescription: Review an area\n---\nReview $ARGUMENTS.\n",
            PromptCommandLimits::default(),
        )
        .unwrap();
        StoredNativePromptCommand::new(observed).unwrap()
    }

    #[test]
    fn strict_native_envelope_round_trips_deterministically() {
        let original = stored();
        let encoded = original.to_json().unwrap();
        let decoded = StoredNativePromptCommand::from_json(&encoded).unwrap();

        assert_eq!(decoded, original);
        assert_eq!(decoded.to_json().unwrap(), encoded);
        assert_eq!(
            StoredNativePromptCommand::format(),
            "kitrove-native-prompt-command/v1"
        );
    }

    #[test]
    fn envelope_rejects_unknown_fields_and_identity_changes() {
        let stored = stored();
        let mut value: serde_json::Value =
            serde_json::from_str(&stored.to_json().unwrap()).unwrap();
        value["extra"] = serde_json::json!(true);
        assert_eq!(
            StoredNativePromptCommand::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "prompt_command.native_storage_invalid"
        );

        let mut value: serde_json::Value =
            serde_json::from_str(&stored.to_json().unwrap()).unwrap();
        value["exact_source"] = serde_json::json!("Changed.\n");
        assert_eq!(
            StoredNativePromptCommand::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "prompt_command.native_storage_hash_mismatch"
        );
    }

    #[test]
    fn debug_omits_exact_native_source() {
        let debug = format!("{:?}", stored());
        assert!(!debug.contains("Review an area"));
        assert!(!debug.contains("$ARGUMENTS"));
    }
}
