use std::fmt::{self, Debug, Formatter};

use kitrove_model::ContentHash;
use serde::{Deserialize, Serialize};

use crate::{
    AgentError, AgentLimits, NativeAgentDialect, ObservedAgent, digest, hash_record,
    parse_native_agent,
};

const FORMAT: &str = "kitrove-native-agent/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_NATIVE_AGENT_BYTES: usize = 4 * 1024 * 1024;

/// Strict lossless storage for one safely parsed origin-native agent.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredNativeAgent {
    observed: ObservedAgent,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedNativeAgent {
    schema_version: u32,
    format: String,
    dialect: NativeAgentDialect,
    source_document: String,
    exact_source: String,
    object_hash: ContentHash,
}

impl StoredNativeAgent {
    pub fn new(observed: ObservedAgent) -> Result<Self, AgentError> {
        let reparsed = parse_native_agent(
            observed.dialect(),
            observed.source_document(),
            observed.exact_bytes(),
            AgentLimits::default(),
        )?;
        if reparsed != observed {
            return Err(storage_error(
                "agent.native_storage_noncanonical",
                "native agent cannot be reproduced under canonical storage limits",
            ));
        }
        let exact_hash = observed.exact_hash().clone();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-native-agent-object-v1\0");
        hash_record(&mut hasher, exact_hash.as_str().as_bytes());
        let stored = Self {
            observed,
            object_hash: digest(hasher),
        };
        stored.to_json()?;
        Ok(stored)
    }

    pub fn from_json(input: &str) -> Result<Self, AgentError> {
        if input.len() > MAX_STORED_NATIVE_AGENT_BYTES {
            return Err(storage_error(
                "agent.native_storage_limit",
                "native agent exceeds the storage byte limit",
            ));
        }
        let persisted: PersistedNativeAgent = serde_json::from_str(input).map_err(|_| {
            storage_error(
                "agent.native_storage_invalid",
                "native agent is not strict version-1 JSON",
            )
        })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(storage_error(
                "agent.native_storage_version",
                "native agent schema or format is unsupported",
            ));
        }
        let stored = Self::new(parse_native_agent(
            persisted.dialect,
            &persisted.source_document,
            persisted.exact_source.as_bytes(),
            AgentLimits::default(),
        )?)?;
        if stored.object_hash != persisted.object_hash {
            return Err(storage_error(
                "agent.native_storage_hash_mismatch",
                "native agent identity does not match its exact source",
            ));
        }
        Ok(stored)
    }

    pub fn to_json(&self) -> Result<String, AgentError> {
        let exact_source =
            String::from_utf8(self.observed.exact_bytes().to_vec()).map_err(|_| {
                storage_error(
                    "agent.native_source_invalid",
                    "native agent source must be valid UTF-8",
                )
            })?;
        let persisted = PersistedNativeAgent {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            dialect: self.observed.dialect(),
            source_document: self.observed.source_document().to_owned(),
            exact_source,
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            storage_error(
                "agent.native_storage_serialize",
                "native agent could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_NATIVE_AGENT_BYTES {
            return Err(storage_error(
                "agent.native_storage_limit",
                "native agent exceeds the storage byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn observed(&self) -> &ObservedAgent {
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

impl Debug for StoredNativeAgent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredNativeAgent")
            .field("observed", &self.observed)
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

const fn storage_error(code: &'static str, message: &'static str) -> AgentError {
    AgentError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_native_envelope_round_trips_and_rejects_changes() {
        let observed = parse_native_agent(
            NativeAgentDialect::ClaudeCurrent,
            "review.md",
            b"---\nname: review\ndescription: Review changes\n---\nReview carefully.\n",
            AgentLimits::default(),
        )
        .unwrap();
        let original = StoredNativeAgent::new(observed).unwrap();
        let encoded = original.to_json().unwrap();
        assert_eq!(StoredNativeAgent::from_json(&encoded).unwrap(), original);

        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        value["exact_source"] = serde_json::json!(
            "---\nname: review\ndescription: Review changes\n---\nReview differently.\n"
        );
        assert_eq!(
            StoredNativeAgent::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "agent.native_storage_hash_mismatch"
        );

        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            StoredNativeAgent::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "agent.native_storage_invalid"
        );
    }
}
