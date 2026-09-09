use std::fmt::{self, Debug, Formatter};

use kitrove_model::{BindingName, ContentHash};
use serde::{Deserialize, Serialize};

use crate::{
    McpError, McpHttpsEndpoint, McpServer, McpServerName, McpTransport, digest, hash_record,
};

const FORMAT: &str = "kitrove-mcp-server/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_MCP_SERVER_BYTES: usize = 16 * 1024;

/// Strict portable storage envelope for one canonical MCP server declaration.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredMcpServer {
    server: McpServer,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedMcpServer {
    schema_version: u32,
    format: String,
    name: McpServerName,
    transport: McpTransport,
    endpoint: McpHttpsEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bearer_token_binding: Option<BindingName>,
    object_hash: ContentHash,
}

impl StoredMcpServer {
    #[must_use]
    pub fn new(server: McpServer) -> Self {
        let object_hash = hash_object(&server);
        Self {
            server,
            object_hash,
        }
    }

    pub fn from_json(input: &str) -> Result<Self, McpError> {
        if input.len() > MAX_STORED_MCP_SERVER_BYTES {
            return Err(storage_error(
                "mcp.storage_limit",
                "stored MCP server exceeds the portable envelope byte limit",
            ));
        }
        let persisted: PersistedMcpServer = serde_json::from_str(input).map_err(|_| {
            storage_error(
                "mcp.storage_invalid",
                "stored MCP server is not strict version-1 JSON",
            )
        })?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(storage_error(
                "mcp.storage_version",
                "stored MCP server schema or format is unsupported",
            ));
        }
        if persisted.transport != McpTransport::StreamableHttp {
            return Err(storage_error(
                "mcp.storage_transport",
                "stored MCP server transport is unsupported",
            ));
        }
        let stored = Self::new(McpServer::new(
            persisted.name,
            persisted.endpoint,
            persisted.bearer_token_binding,
        )?);
        if stored.object_hash != persisted.object_hash {
            return Err(storage_error(
                "mcp.storage_hash_mismatch",
                "stored MCP server identity does not match its canonical content",
            ));
        }
        Ok(stored)
    }

    pub fn to_json(&self) -> Result<String, McpError> {
        let persisted = PersistedMcpServer {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            name: self.server.name().clone(),
            transport: self.server.transport(),
            endpoint: self.server.endpoint().clone(),
            bearer_token_binding: self.server.bearer_token_binding().cloned(),
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            storage_error(
                "mcp.storage_serialize",
                "stored MCP server could not be serialized",
            )
        })?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_MCP_SERVER_BYTES {
            return Err(storage_error(
                "mcp.storage_limit",
                "stored MCP server exceeds the portable envelope byte limit",
            ));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn server(&self) -> &McpServer {
        &self.server
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

impl Debug for StoredMcpServer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredMcpServer")
            .field("server", &self.server)
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn hash_object(server: &McpServer) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-stored-mcp-server-v1\0");
    hash_record(&mut hasher, server.content_hash().as_str().as_bytes());
    digest(hasher)
}

const fn storage_error(code: &'static str, message: &'static str) -> McpError {
    McpError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredMcpServer {
        StoredMcpServer::new(
            McpServer::new(
                McpServerName::parse("company-tools").unwrap(),
                McpHttpsEndpoint::parse("https://mcp.example.com/mcp").unwrap(),
                Some(BindingName::parse("company_mcp_token").unwrap()),
            )
            .unwrap(),
        )
    }

    #[test]
    fn strict_envelope_round_trips_and_rejects_mutation() {
        let original = stored();
        let encoded = original.to_json().unwrap();
        assert_eq!(StoredMcpServer::from_json(&encoded).unwrap(), original);

        let mut value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        value["endpoint"] = serde_json::json!("https://other.example.com/mcp");
        assert_eq!(
            StoredMcpServer::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "mcp.storage_hash_mismatch"
        );
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            StoredMcpServer::from_json(&serde_json::to_string(&value).unwrap())
                .unwrap_err()
                .code(),
            "mcp.storage_invalid"
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
                "mcp.storage_version",
            ),
            ("format", serde_json::json!("future"), "mcp.storage_version"),
            (
                "name",
                serde_json::json!("other"),
                "mcp.storage_hash_mismatch",
            ),
            (
                "transport",
                serde_json::json!("future"),
                "mcp.storage_invalid",
            ),
            (
                "endpoint",
                serde_json::json!("https://other.example.com/mcp"),
                "mcp.storage_hash_mismatch",
            ),
            (
                "bearer_token_binding",
                serde_json::json!("other_token"),
                "mcp.storage_hash_mismatch",
            ),
            (
                "object_hash",
                serde_json::json!(format!("blake3:{}", "0".repeat(64))),
                "mcp.storage_hash_mismatch",
            ),
        ] {
            let original = value[field].clone();
            value[field] = replacement;
            assert_eq!(
                StoredMcpServer::from_json(&serde_json::to_string(&value).unwrap())
                    .unwrap_err()
                    .code(),
                code
            );
            value[field] = original;
        }
    }
}
