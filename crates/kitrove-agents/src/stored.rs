use std::fmt::{self, Debug, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

use crate::{
    Agent, AgentDescription, AgentError, AgentInstructions, AgentName, digest, hash_record,
};

const FORMAT: &str = "kitrove-agent/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_AGENT_BYTES: usize = 2 * 1024 * 1024;

/// Strict portable storage envelope for one canonical agent.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredAgent {
    agent: Agent,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedAgent {
    schema_version: u32,
    format: String,
    name: AgentName,
    description: AgentDescription,
    instructions: String,
    object_hash: ContentHash,
}

impl StoredAgent {
    #[must_use]
    pub fn new(agent: Agent) -> Self {
        let object_hash = hash_object(&agent);
        Self { agent, object_hash }
    }

    pub fn from_json(input: &str, max_instructions_bytes: usize) -> Result<Self, AgentError> {
        if input.len() > MAX_STORED_AGENT_BYTES {
            return Err(storage_error(
                "agent.storage_limit",
                "stored agent exceeds the portable envelope byte limit",
            ));
        }
        let persisted: PersistedAgent = serde_json::from_str(input).map_err(|_| {
            storage_error(
                "agent.storage_invalid",
                "stored agent is not strict version-1 JSON",
            )
        })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(storage_error(
                "agent.storage_version",
                "stored agent schema or format is unsupported",
            ));
        }
        let instructions =
            AgentInstructions::parse(&persisted.instructions, max_instructions_bytes)?;
        if instructions.as_str() != persisted.instructions {
            return Err(storage_error(
                "agent.storage_noncanonical",
                "stored agent instructions are not in canonical form",
            ));
        }
        let stored = Self::new(Agent::new(
            persisted.name,
            persisted.description,
            instructions,
        ));
        if stored.object_hash != persisted.object_hash {
            return Err(storage_error(
                "agent.storage_hash_mismatch",
                "stored agent identity does not match its canonical content",
            ));
        }
        Ok(stored)
    }

    pub fn to_json(&self) -> Result<String, AgentError> {
        let persisted = PersistedAgent {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            name: self.agent.name().clone(),
            description: self.agent.description().clone(),
            instructions: self.agent.instructions().as_str().to_owned(),
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            storage_error(
                "agent.storage_serialize",
                "stored agent could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_AGENT_BYTES {
            return Err(storage_error(
                "agent.storage_limit",
                "stored agent exceeds the portable envelope byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn agent(&self) -> &Agent {
        &self.agent
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

impl Debug for StoredAgent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredAgent")
            .field("agent", &self.agent)
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn hash_object(agent: &Agent) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-stored-agent-v1\0");
    hash_record(&mut hasher, agent.content_hash().as_str().as_bytes());
    digest(hasher)
}

const fn storage_error(code: &'static str, message: &'static str) -> AgentError {
    AgentError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredAgent {
        StoredAgent::new(Agent::new(
            AgentName::parse("review").unwrap(),
            AgentDescription::parse("Review changes").unwrap(),
            AgentInstructions::parse("Review carefully.\n", 1024).unwrap(),
        ))
    }

    #[test]
    fn strict_envelope_round_trips_and_rejects_mutation() {
        let original = stored();
        let encoded = original.to_json().unwrap();
        assert_eq!(StoredAgent::from_json(&encoded, 1024).unwrap(), original);

        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        value["description"] = serde_json::json!("Changed");
        assert_eq!(
            StoredAgent::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "agent.storage_hash_mismatch"
        );
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            StoredAgent::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                .unwrap_err()
                .code(),
            "agent.storage_invalid"
        );
    }

    #[test]
    fn every_persisted_authority_field_is_verified() {
        let encoded = stored().to_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        for (field, replacement, code) in [
            (
                "schema_version",
                serde_json::json!(2),
                "agent.storage_version",
            ),
            (
                "format",
                serde_json::json!("future"),
                "agent.storage_version",
            ),
            (
                "name",
                serde_json::json!("inspect"),
                "agent.storage_hash_mismatch",
            ),
            (
                "description",
                serde_json::json!("Inspect changes"),
                "agent.storage_hash_mismatch",
            ),
            (
                "instructions",
                serde_json::json!("Inspect carefully.\n"),
                "agent.storage_hash_mismatch",
            ),
            (
                "object_hash",
                serde_json::json!(format!("blake3:{}", "0".repeat(64))),
                "agent.storage_hash_mismatch",
            ),
        ] {
            let original = value[field].clone();
            value[field] = replacement;
            assert_eq!(
                StoredAgent::from_json(&serde_json::to_string(&value).unwrap(), 1024)
                    .unwrap_err()
                    .code(),
                code
            );
            value[field] = original;
        }
    }
}
