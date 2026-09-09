#![forbid(unsafe_code)]
//! Harness-neutral remote MCP declaration primitives.

mod edit;
mod native;
mod native_stored;
mod render;
mod stored;

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{BindingName, ContentHash, is_portable_mcp_server_name};
use kitrove_risk::is_credential_shaped;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub use edit::{EditedMcpDocument, McpDocumentMutation, edit_native_mcp_document};
pub use native::{
    McpBlockReason, McpNativeProjection, McpParseLimits, McpPortability, ObservedMcpDocument,
    ObservedMcpServer, parse_native_mcp_document,
};
pub use native_stored::StoredNativeMcpEntry;
pub use render::{RenderedMcpEntry, render_native_mcp_entry};
pub use stored::StoredMcpServer;

const MAX_MCP_ENDPOINT_BYTES: usize = 2_048;
const MAX_MCP_BINDING_NAME_BYTES: usize = 255;

/// Stable, value-redacting MCP validation or storage failure.
#[derive(Clone, Eq, PartialEq)]
pub struct McpError {
    code: &'static str,
    message: &'static str,
}

impl McpError {
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

impl Debug for McpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for McpError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for McpError {}

/// Conservative logical name shared by supported MCP registries.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct McpServerName(String);

impl McpServerName {
    pub fn parse(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        if !is_portable_mcp_server_name(&value) {
            return Err(mcp_error(
                "mcp.name_invalid",
                "MCP server name must be a bounded lowercase ASCII identifier with single hyphens",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for McpServerName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("McpServerName")
            .field(&self.0)
            .finish()
    }
}

impl Display for McpServerName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for McpServerName {
    type Error = McpError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<McpServerName> for String {
    fn from(value: McpServerName) -> Self {
        value.0
    }
}

/// Canonical credential-free HTTPS endpoint for Streamable HTTP.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct McpHttpsEndpoint(String);

impl McpHttpsEndpoint {
    pub fn parse(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_MCP_ENDPOINT_BYTES || value.contains('\0') {
            return Err(endpoint_error());
        }

        let parsed = Url::parse(&value).map_err(|_| endpoint_error())?;
        let domain = match parsed.host() {
            Some(Host::Domain(domain)) => domain,
            Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => return Err(endpoint_error()),
        };
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str() != value
            || domain == "localhost"
            || domain.ends_with(".localhost")
            || !safe_endpoint_path(parsed.path())
        {
            return Err(endpoint_error());
        }
        if domain
            .split('.')
            .chain(
                parsed
                    .path()
                    .split('/')
                    .filter(|segment| !segment.is_empty()),
            )
            .any(is_credential_shaped)
        {
            return Err(McpError::new(
                "mcp.endpoint_credential_shaped",
                "MCP endpoint contains a credential-shaped component",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        hash_text(b"kitrove-mcp-https-endpoint-v1\0", &self.0)
    }
}

impl Debug for McpHttpsEndpoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpHttpsEndpoint")
            .field("byte_count", &self.0.len())
            .field("content_hash", &self.content_hash())
            .finish()
    }
}

impl TryFrom<String> for McpHttpsEndpoint {
    type Error = McpError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<McpHttpsEndpoint> for String {
    fn from(value: McpHttpsEndpoint) -> Self {
        value.0
    }
}

/// The only transport admitted by the version-1 portable MCP schema.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    StreamableHttp,
}

/// Reviewed native shared-document dialect for one MCP server entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMcpDialect {
    ClaudeCurrent,
    CodexCurrent,
    OpenCodeV2,
}

impl NativeMcpDialect {
    #[must_use]
    pub const fn harness(self) -> kitrove_model::HarnessId {
        match self {
            Self::ClaudeCurrent => kitrove_model::HarnessId::Claude,
            Self::CodexCurrent => kitrove_model::HarnessId::Codex,
            Self::OpenCodeV2 => kitrove_model::HarnessId::OpenCode,
        }
    }
}

/// Canonical portable remote MCP declaration.
#[derive(Clone, Eq, PartialEq)]
pub struct McpServer {
    name: McpServerName,
    endpoint: McpHttpsEndpoint,
    bearer_token_binding: Option<BindingName>,
}

impl McpServer {
    pub fn new(
        name: McpServerName,
        endpoint: McpHttpsEndpoint,
        bearer_token_binding: Option<BindingName>,
    ) -> Result<Self, McpError> {
        if bearer_token_binding.as_ref().is_some_and(|binding| {
            binding.as_str().len() > MAX_MCP_BINDING_NAME_BYTES
                || is_credential_shaped(binding.as_str())
        }) {
            return Err(mcp_error(
                "mcp.binding_invalid",
                "MCP bearer binding name exceeds the portable byte limit",
            ));
        }
        Ok(Self {
            name,
            endpoint,
            bearer_token_binding,
        })
    }

    #[must_use]
    pub const fn name(&self) -> &McpServerName {
        &self.name
    }

    #[must_use]
    pub const fn transport(&self) -> McpTransport {
        McpTransport::StreamableHttp
    }

    #[must_use]
    pub const fn endpoint(&self) -> &McpHttpsEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub const fn bearer_token_binding(&self) -> Option<&BindingName> {
        self.bearer_token_binding.as_ref()
    }

    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-mcp-server-v1\0");
        hash_record(&mut hasher, self.name.as_str().as_bytes());
        hash_record(&mut hasher, b"streamable_http");
        hash_record(&mut hasher, self.endpoint.as_str().as_bytes());
        match &self.bearer_token_binding {
            Some(binding) => {
                hasher.update(b"binding\0");
                hash_record(&mut hasher, binding.as_str().as_bytes());
            }
            None => {
                hasher.update(b"no-binding\0");
            }
        }
        digest(hasher)
    }
}

impl Debug for McpServer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpServer")
            .field("name", &self.name)
            .field("transport", &self.transport())
            .field("endpoint", &self.endpoint)
            .field("bearer_token_binding", &self.bearer_token_binding)
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

fn safe_endpoint_path(path: &str) -> bool {
    path.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~')
    })
}

const fn endpoint_error() -> McpError {
    McpError::new(
        "mcp.endpoint_invalid",
        "MCP endpoint must be a canonical credential-free HTTPS URL with a DNS host and simple path",
    )
}

const fn mcp_error(code: &'static str, message: &'static str) -> McpError {
    McpError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_name_uses_the_conservative_cross_harness_grammar() {
        for valid in ["a", "context7", "company-tools"] {
            assert!(McpServerName::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "7context",
            "Company",
            "company_tools",
            "company--tools",
            "company-",
        ] {
            assert_eq!(
                McpServerName::parse(invalid).unwrap_err().code(),
                "mcp.name_invalid",
                "{invalid}"
            );
        }
    }

    #[test]
    fn endpoint_accepts_only_canonical_credential_free_https() {
        let endpoint = McpHttpsEndpoint::parse("https://mcp.example.com/v1/mcp").unwrap();
        assert_eq!(endpoint.as_str(), "https://mcp.example.com/v1/mcp");

        for invalid in [
            "http://mcp.example.com/mcp",
            "https://mcp.example.com",
            "https://USER@mcp.example.com/mcp",
            "https://mcp.example.com/mcp?account=one",
            "https://mcp.example.com/mcp#tools",
            "https://127.0.0.1/mcp",
            "https://[::1]/mcp",
            "https://localhost/mcp",
            "https://tools.localhost/mcp",
            "https://MCP.example.com/mcp",
            "https://mcp.example.com/a%2Fb",
        ] {
            assert_eq!(
                McpHttpsEndpoint::parse(invalid).unwrap_err().code(),
                "mcp.endpoint_invalid",
                "{invalid}"
            );
        }
        assert_eq!(
            McpHttpsEndpoint::parse("https://mcp.example.com/sk-live-12345678901234567890")
                .unwrap_err()
                .code(),
            "mcp.endpoint_credential_shaped"
        );
    }

    #[test]
    fn debug_output_redacts_endpoint_but_retains_symbolic_identity() {
        let server = McpServer::new(
            McpServerName::parse("company-tools").unwrap(),
            McpHttpsEndpoint::parse("https://private.example.com/mcp").unwrap(),
            Some(BindingName::parse("company_mcp_token").unwrap()),
        )
        .unwrap();
        let debug = format!("{server:?}");
        assert!(!debug.contains("private.example.com"));
        assert!(debug.contains("company-tools"));
        assert!(debug.contains("company_mcp_token"));
    }

    #[test]
    fn server_rejects_an_unbounded_logical_binding() {
        let error = McpServer::new(
            McpServerName::parse("company-tools").unwrap(),
            McpHttpsEndpoint::parse("https://mcp.example.com/mcp").unwrap(),
            Some(BindingName::parse("a".repeat(256)).unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "mcp.binding_invalid");

        let credential_shaped = McpServer::new(
            McpServerName::parse("company-tools").unwrap(),
            McpHttpsEndpoint::parse("https://mcp.example.com/mcp").unwrap(),
            Some(BindingName::parse("sk-live-12345678901234567890").unwrap()),
        )
        .unwrap_err();
        assert_eq!(credential_shaped.code(), "mcp.binding_invalid");
    }
}
