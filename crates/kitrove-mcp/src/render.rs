use std::fmt::{self, Debug, Formatter};

use kitrove_model::{ContentHash, EnvironmentVariableName};

use crate::{McpError, McpServer, NativeMcpDialect, digest, hash_record, mcp_error};

const MAX_RENDERED_ENTRY_BYTES: usize = 128 * 1024;

/// Canonical credential-free native projection for one portable MCP server.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedMcpEntry {
    dialect: NativeMcpDialect,
    native_name: String,
    text: String,
    hash: ContentHash,
}

impl RenderedMcpEntry {
    #[must_use]
    pub const fn dialect(&self) -> NativeMcpDialect {
        self.dialect
    }
    #[must_use]
    pub fn native_name(&self) -> &str {
        &self.native_name
    }
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    #[must_use]
    pub const fn hash(&self) -> &ContentHash {
        &self.hash
    }
}

impl Debug for RenderedMcpEntry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedMcpEntry")
            .field("dialect", &self.dialect)
            .field("hash", &self.hash)
            .finish()
    }
}

/// Renders only symbolic environment authority; it never resolves or reads a binding value.
pub fn render_native_mcp_entry(
    server: &McpServer,
    dialect: NativeMcpDialect,
    bearer_environment: Option<&EnvironmentVariableName>,
) -> Result<RenderedMcpEntry, McpError> {
    if server.bearer_token_binding().is_some() != bearer_environment.is_some() {
        return Err(render_error("mcp.render_binding_mismatch"));
    }
    let text = match dialect {
        NativeMcpDialect::ClaudeCurrent => render_json(server, bearer_environment, false)?,
        NativeMcpDialect::OpenCodeV2 => render_json(server, bearer_environment, true)?,
        NativeMcpDialect::CodexCurrent => render_codex(server, bearer_environment)?,
    };
    if text.len() > MAX_RENDERED_ENTRY_BYTES {
        return Err(render_error("mcp.render_limit"));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-rendered-mcp-entry-v1\0");
    hasher.update(&[match dialect {
        NativeMcpDialect::ClaudeCurrent => 0,
        NativeMcpDialect::CodexCurrent => 1,
        NativeMcpDialect::OpenCodeV2 => 2,
    }]);
    hash_record(&mut hasher, server.name().as_str().as_bytes());
    hash_record(&mut hasher, text.as_bytes());
    Ok(RenderedMcpEntry {
        dialect,
        native_name: server.name().as_str().to_owned(),
        text,
        hash: digest(hasher),
    })
}

fn render_json(
    server: &McpServer,
    bearer_environment: Option<&EnvironmentVariableName>,
    opencode: bool,
) -> Result<String, McpError> {
    let mut entry = serde_json::Map::new();
    entry.insert(
        "type".to_owned(),
        serde_json::Value::String(if opencode { "remote" } else { "http" }.to_owned()),
    );
    entry.insert(
        "url".to_owned(),
        serde_json::Value::String(server.endpoint().as_str().to_owned()),
    );
    if let Some(environment) = bearer_environment {
        let reference = if opencode {
            format!("Bearer {{env:{}}}", environment.as_str())
        } else {
            format!("Bearer ${{{}}}", environment.as_str())
        };
        entry.insert(
            "headers".to_owned(),
            serde_json::json!({"Authorization": reference}),
        );
        if opencode {
            entry.insert("oauth".to_owned(), serde_json::Value::Bool(false));
        }
    }
    serde_json::to_string(&entry).map_err(|_| render_error("mcp.render_serialize"))
}

fn render_codex(
    server: &McpServer,
    bearer_environment: Option<&EnvironmentVariableName>,
) -> Result<String, McpError> {
    let name = server.name().as_str();
    let endpoint = toml_edit::Value::from(server.endpoint().as_str());
    let mut output = format!("[mcp_servers.{name}]\nurl = {endpoint}\n");
    if let Some(environment) = bearer_environment {
        let value = toml_edit::Value::from(environment.as_str());
        output.push_str(&format!("bearer_token_env_var = {value}\n"));
    }
    Ok(output)
}

const fn render_error(code: &'static str) -> McpError {
    mcp_error(
        code,
        "portable MCP entry could not be rendered without local or credential authority",
    )
}

#[cfg(test)]
mod tests {
    use kitrove_model::BindingName;

    use super::*;
    use crate::{
        McpHttpsEndpoint, McpParseLimits, McpPortability, McpServerName, parse_native_mcp_document,
    };

    fn server(binding: bool) -> McpServer {
        McpServer::new(
            McpServerName::parse("company-tools").unwrap(),
            McpHttpsEndpoint::parse("https://mcp.example.com/mcp").unwrap(),
            binding.then(|| BindingName::parse("company_mcp_token").unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn every_dialect_round_trips_through_the_native_parser() {
        let environment = EnvironmentVariableName::parse("KITROVE_MCP_TOKEN").unwrap();
        for dialect in [
            NativeMcpDialect::ClaudeCurrent,
            NativeMcpDialect::CodexCurrent,
            NativeMcpDialect::OpenCodeV2,
        ] {
            let rendered =
                render_native_mcp_entry(&server(true), dialect, Some(&environment)).unwrap();
            let input = match dialect {
                NativeMcpDialect::ClaudeCurrent => format!(
                    r#"{{"mcpServers":{{"company-tools":{}}}}}"#,
                    rendered.text()
                ),
                NativeMcpDialect::CodexCurrent => rendered.text().to_owned(),
                NativeMcpDialect::OpenCodeV2 => format!(
                    r#"{{"mcp":{{"servers":{{"company-tools":{}}}}}}}"#,
                    rendered.text()
                ),
            };
            let document =
                parse_native_mcp_document(&input, dialect, McpParseLimits::default()).unwrap();
            let McpPortability::Portable(projection) = document.entries()[0].portability() else {
                panic!("rendered entry must remain portable")
            };
            assert_eq!(projection.name().as_str(), "company-tools");
            assert_eq!(projection.bearer_environment(), Some(&environment));
            assert!(!format!("{rendered:?}").contains("mcp.example.com"));
        }
    }

    #[test]
    fn binding_authority_must_match_the_portable_declaration() {
        let environment = EnvironmentVariableName::parse("KITROVE_MCP_TOKEN").unwrap();
        assert!(
            render_native_mcp_entry(&server(true), NativeMcpDialect::ClaudeCurrent, None).is_err()
        );
        assert!(
            render_native_mcp_entry(
                &server(false),
                NativeMcpDialect::ClaudeCurrent,
                Some(&environment)
            )
            .is_err()
        );
    }
}
