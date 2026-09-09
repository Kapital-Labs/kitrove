use std::fmt::{self, Debug, Formatter};

use kitrove_model::{ContentClass, ContentHash};
use serde::{Deserialize, Serialize};

use crate::native::{hash_native_entry, validate_isolated_portable_entry};
use crate::{
    McpError, McpPortability, NativeMcpDialect, ObservedMcpServer, digest, hash_record, mcp_error,
};

const FORMAT: &str = "kitrove-native-mcp-entry/v1";
const SCHEMA_VERSION: u32 = 1;
const MAX_STORED_NATIVE_MCP_BYTES: usize = 160 * 1024;

/// Strict exact-origin envelope for one credential-free native MCP entry.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredNativeMcpEntry {
    dialect: NativeMcpDialect,
    native_name: String,
    exact_entry: String,
    exact_entry_hash: ContentHash,
    exact_document_hash: ContentHash,
    object_hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedNativeMcpEntry {
    schema_version: u32,
    format: String,
    dialect: NativeMcpDialect,
    native_name: String,
    exact_entry: String,
    exact_entry_hash: ContentHash,
    exact_document_hash: ContentHash,
    object_hash: ContentHash,
}

impl StoredNativeMcpEntry {
    pub fn new(
        dialect: NativeMcpDialect,
        exact_document_hash: ContentHash,
        observed: &ObservedMcpServer,
    ) -> Result<Self, McpError> {
        if observed.content_class() != ContentClass::AgentActive
            || !matches!(observed.portability(), McpPortability::Portable(_))
        {
            return Err(native_storage_error("mcp.native_storage_nonportable"));
        }
        let verified = validate_isolated_portable_entry(
            dialect,
            observed.native_name(),
            observed.exact_entry(),
        )?;
        if verified.exact_entry_hash() != observed.exact_entry_hash() {
            return Err(native_storage_error("mcp.native_storage_hash_mismatch"));
        }
        Ok(Self::from_verified(
            dialect,
            observed.native_name().to_owned(),
            observed.exact_entry().to_owned(),
            observed.exact_entry_hash().clone(),
            exact_document_hash,
        ))
    }

    pub fn from_json(input: &str) -> Result<Self, McpError> {
        if input.len() > MAX_STORED_NATIVE_MCP_BYTES {
            return Err(native_storage_error("mcp.native_storage_limit"));
        }
        let persisted: PersistedNativeMcpEntry = serde_json::from_str(input)
            .map_err(|_| native_storage_error("mcp.native_storage_invalid"))?;
        if persisted.schema_version != SCHEMA_VERSION || persisted.format != FORMAT {
            return Err(native_storage_error("mcp.native_storage_version"));
        }
        let verified = validate_isolated_portable_entry(
            persisted.dialect,
            &persisted.native_name,
            &persisted.exact_entry,
        )?;
        let expected_entry_hash = hash_native_entry(
            persisted.dialect,
            &persisted.native_name,
            &persisted.exact_entry,
        );
        if verified.exact_entry_hash() != &expected_entry_hash
            || persisted.exact_entry_hash != expected_entry_hash
        {
            return Err(native_storage_error("mcp.native_storage_hash_mismatch"));
        }
        let stored = Self::from_verified(
            persisted.dialect,
            persisted.native_name,
            persisted.exact_entry,
            persisted.exact_entry_hash,
            persisted.exact_document_hash,
        );
        if stored.object_hash != persisted.object_hash {
            return Err(native_storage_error("mcp.native_storage_hash_mismatch"));
        }
        Ok(stored)
    }

    pub fn to_json(&self) -> Result<String, McpError> {
        let persisted = PersistedNativeMcpEntry {
            schema_version: SCHEMA_VERSION,
            format: FORMAT.to_owned(),
            dialect: self.dialect,
            native_name: self.native_name.clone(),
            exact_entry: self.exact_entry.clone(),
            exact_entry_hash: self.exact_entry_hash.clone(),
            exact_document_hash: self.exact_document_hash.clone(),
            object_hash: self.object_hash.clone(),
        };
        let mut encoded = serde_json::to_string_pretty(&persisted)
            .map_err(|_| native_storage_error("mcp.native_storage_serialize"))?;
        encoded.push('\n');
        if encoded.len() > MAX_STORED_NATIVE_MCP_BYTES {
            return Err(native_storage_error("mcp.native_storage_limit"));
        }
        Ok(encoded)
    }

    #[must_use]
    pub const fn dialect(&self) -> NativeMcpDialect {
        self.dialect
    }

    #[must_use]
    pub fn native_name(&self) -> &str {
        &self.native_name
    }

    #[must_use]
    pub fn exact_entry(&self) -> &str {
        &self.exact_entry
    }

    #[must_use]
    pub const fn exact_entry_hash(&self) -> &ContentHash {
        &self.exact_entry_hash
    }

    #[must_use]
    pub const fn exact_document_hash(&self) -> &ContentHash {
        &self.exact_document_hash
    }

    #[must_use]
    pub const fn object_hash(&self) -> &ContentHash {
        &self.object_hash
    }

    #[must_use]
    pub const fn format() -> &'static str {
        FORMAT
    }

    fn from_verified(
        dialect: NativeMcpDialect,
        native_name: String,
        exact_entry: String,
        exact_entry_hash: ContentHash,
        exact_document_hash: ContentHash,
    ) -> Self {
        let object_hash = hash_object(
            dialect,
            &native_name,
            &exact_entry_hash,
            &exact_document_hash,
        );
        Self {
            dialect,
            native_name,
            exact_entry,
            exact_entry_hash,
            exact_document_hash,
            object_hash,
        }
    }
}

impl Debug for StoredNativeMcpEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredNativeMcpEntry")
            .field("dialect", &self.dialect)
            .field("exact_entry_hash", &self.exact_entry_hash)
            .field("exact_document_hash", &self.exact_document_hash)
            .field("object_hash", &self.object_hash)
            .finish()
    }
}

fn hash_object(
    dialect: NativeMcpDialect,
    native_name: &str,
    exact_entry_hash: &ContentHash,
    exact_document_hash: &ContentHash,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-stored-native-mcp-entry-v1\0");
    hasher.update(&[match dialect {
        NativeMcpDialect::ClaudeCurrent => 0,
        NativeMcpDialect::CodexCurrent => 1,
        NativeMcpDialect::OpenCodeV2 => 2,
    }]);
    hash_record(&mut hasher, native_name.as_bytes());
    hash_record(&mut hasher, exact_entry_hash.as_str().as_bytes());
    hash_record(&mut hasher, exact_document_hash.as_str().as_bytes());
    digest(hasher)
}

const fn native_storage_error(code: &'static str) -> McpError {
    mcp_error(
        code,
        "stored native MCP entry is invalid or exceeds bounded storage policy",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{McpParseLimits, parse_native_mcp_document};

    #[test]
    fn exact_native_entries_round_trip_for_every_dialect() {
        let fixtures = [
            (
                NativeMcpDialect::ClaudeCurrent,
                r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp"}}}"#,
            ),
            (
                NativeMcpDialect::CodexCurrent,
                "[mcp_servers.docs]\nurl = \"https://mcp.example.com/mcp\"\n",
            ),
            (
                NativeMcpDialect::OpenCodeV2,
                r#"{"mcp":{"servers":{"docs":{"type":"remote","url":"https://mcp.example.com/mcp"}}}}"#,
            ),
        ];
        for (dialect, input) in fixtures {
            let document =
                parse_native_mcp_document(input, dialect, McpParseLimits::default()).unwrap();
            let stored = StoredNativeMcpEntry::new(
                dialect,
                document.exact_document_hash().clone(),
                &document.entries()[0],
            )
            .unwrap_or_else(|error| panic!("{dialect:?}: {error}"));
            let encoded = stored.to_json().unwrap();
            assert_eq!(StoredNativeMcpEntry::from_json(&encoded).unwrap(), stored);
        }
    }

    #[test]
    fn decoder_rejects_mutation_and_debug_redacts_exact_content() {
        let input =
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp"}}}"#;
        let document = parse_native_mcp_document(
            input,
            NativeMcpDialect::ClaudeCurrent,
            McpParseLimits::default(),
        )
        .unwrap();
        let stored = StoredNativeMcpEntry::new(
            NativeMcpDialect::ClaudeCurrent,
            document.exact_document_hash().clone(),
            &document.entries()[0],
        )
        .unwrap();
        assert!(!format!("{stored:?}").contains("mcp.example.com"));
        let mut value: serde_json::Value =
            serde_json::from_str(&stored.to_json().unwrap()).unwrap();
        value["exact_entry"] = serde_json::json!({"type":"http"});
        assert!(StoredNativeMcpEntry::from_json(&value.to_string()).is_err());
    }
}
