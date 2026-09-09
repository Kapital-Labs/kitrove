use std::fmt::{self, Debug, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

use crate::{InstructionBody, InstructionError};

const FORMAT: &str = "kitrove-instruction/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_INSTRUCTION_BYTES: usize = 512 * 1024;

/// Strict portable storage envelope for one canonical standing instruction.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredInstruction {
    body: InstructionBody,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedInstruction {
    schema_version: u32,
    format: String,
    body: String,
    object_hash: ContentHash,
}

impl StoredInstruction {
    /// Creates a stored object and derives its domain-separated identity.
    #[must_use]
    pub fn new(body: InstructionBody) -> Self {
        let object_hash = hash_object(&body);
        Self { body, object_hash }
    }

    /// Parses and verifies one strict version-1 JSON envelope.
    pub fn from_json(input: &str, max_body_bytes: usize) -> Result<Self, InstructionError> {
        if input.len() > MAX_STORED_INSTRUCTION_BYTES {
            return Err(storage_error(
                "instruction.storage_limit",
                "stored instruction exceeds the portable envelope byte limit",
            ));
        }
        let persisted: PersistedInstruction = serde_json::from_str(input).map_err(|_| {
            storage_error(
                "instruction.storage_invalid",
                "stored instruction is not strict version-1 JSON",
            )
        })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(storage_error(
                "instruction.storage_version",
                "stored instruction schema or format is unsupported",
            ));
        }
        let body = InstructionBody::parse(&persisted.body, max_body_bytes)?;
        if body.as_str() != persisted.body {
            return Err(storage_error(
                "instruction.storage_noncanonical",
                "stored instruction body is not in canonical form",
            ));
        }
        let stored = Self::new(body);
        if stored.object_hash != persisted.object_hash {
            return Err(storage_error(
                "instruction.storage_hash_mismatch",
                "stored instruction identity does not match its canonical body",
            ));
        }
        Ok(stored)
    }

    /// Serializes deterministic strict JSON with one final newline.
    pub fn to_json(&self) -> Result<String, InstructionError> {
        let persisted = PersistedInstruction {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            body: self.body.as_str().to_owned(),
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            storage_error(
                "instruction.storage_serialize",
                "stored instruction could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_INSTRUCTION_BYTES {
            return Err(storage_error(
                "instruction.storage_limit",
                "stored instruction exceeds the portable envelope byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn body(&self) -> &InstructionBody {
        &self.body
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

impl Debug for StoredInstruction {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredInstruction")
            .field("body_byte_count", &self.body.as_str().len())
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn hash_object(body: &InstructionBody) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-stored-instruction-v1\0");
    let body_hash = body.content_hash();
    hasher.update(&(body_hash.as_str().len() as u64).to_be_bytes());
    hasher.update(body_hash.as_str().as_bytes());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

const fn storage_error(code: &'static str, message: &'static str) -> InstructionError {
    InstructionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn stored() -> StoredInstruction {
        StoredInstruction::new(InstructionBody::parse("# Rules\n\n- Test.\n", 1024).unwrap())
    }

    #[test]
    fn strict_envelope_round_trips_deterministically() {
        let original = stored();
        let encoded = original.to_json().unwrap();
        let decoded = StoredInstruction::from_json(&encoded, 1024).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.to_json().unwrap(), encoded);
        assert_eq!(StoredInstruction::format(), "kitrove-instruction/v1");
    }

    #[test]
    fn every_persisted_authority_field_is_verified() {
        let encoded = stored().to_json().unwrap();
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        for (field, replacement, code) in [
            (
                "schema_version",
                Value::from(2),
                "instruction.storage_version",
            ),
            (
                "format",
                Value::from("future"),
                "instruction.storage_version",
            ),
            (
                "object_hash",
                Value::from(format!("blake3:{}", "0".repeat(64))),
                "instruction.storage_hash_mismatch",
            ),
        ] {
            let original = value[field].clone();
            value[field] = replacement;
            assert_eq!(
                StoredInstruction::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                    .unwrap_err()
                    .code(),
                code
            );
            value[field] = original;
        }
    }

    #[test]
    fn rejects_unknown_fields_noncanonical_body_and_body_budget() {
        let mut value: Value = serde_json::from_str(&stored().to_json().unwrap()).unwrap();
        value["unknown"] = Value::from(true);
        assert_eq!(
            StoredInstruction::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "instruction.storage_invalid"
        );

        let mut value: Value = serde_json::from_str(&stored().to_json().unwrap()).unwrap();
        value["body"] = Value::from("body without final newline");
        assert_eq!(
            StoredInstruction::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "instruction.storage_noncanonical"
        );
        assert_eq!(
            StoredInstruction::from_json(&stored().to_json().unwrap(), 4)
                .unwrap_err()
                .code(),
            "instruction.body_limit"
        );
    }

    #[test]
    fn debug_omits_authored_instruction_body() {
        assert!(!format!("{:?}", stored()).contains("Test"));
    }
}
