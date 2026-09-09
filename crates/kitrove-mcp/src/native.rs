use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use jsonc_parser::ast::{Object as JsonObject, Value as JsonValue};
use jsonc_parser::common::Ranged;
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use kitrove_model::{ContentClass, ContentHash, EnvironmentVariableName};
use kitrove_risk::contains_credential_shaped_text;
use toml_edit::{Document, Item};

use crate::{
    McpError, McpHttpsEndpoint, McpServerName, NativeMcpDialect, digest, hash_record, mcp_error,
};

const HARD_MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_ENTRIES: usize = 512;
const HARD_MAX_NODES: usize = 16 * 1024;
const HARD_MAX_DEPTH: usize = 64;
const HARD_MAX_ENTRY_BYTES: usize = 128 * 1024;
const MAX_NATIVE_NAME_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpParseLimits {
    pub max_document_bytes: usize,
    pub max_entries: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_entry_bytes: usize,
}

impl Default for McpParseLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: 1024 * 1024,
            max_entries: 256,
            max_nodes: 8 * 1024,
            max_depth: 32,
            max_entry_bytes: 64 * 1024,
        }
    }
}

impl McpParseLimits {
    /// Verifies caller-selected limits against the parser's non-configurable hard ceilings.
    pub fn validated(self) -> Result<Self, McpError> {
        if self.max_document_bytes == 0
            || self.max_document_bytes > HARD_MAX_DOCUMENT_BYTES
            || self.max_entries == 0
            || self.max_entries > HARD_MAX_ENTRIES
            || self.max_nodes == 0
            || self.max_nodes > HARD_MAX_NODES
            || self.max_depth == 0
            || self.max_depth > HARD_MAX_DEPTH
            || self.max_entry_bytes == 0
            || self.max_entry_bytes > HARD_MAX_ENTRY_BYTES
        {
            return Err(mcp_error(
                "mcp.parse_limits_invalid",
                "MCP document parse limits are zero or exceed hard ceilings",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum McpBlockReason {
    Disabled,
    InvalidName,
    LocalStdio,
    MalformedEntry,
    NativeFields,
    OAuthConfiguration,
    StaticCredential,
    UnsupportedTransport,
    UnsafeEndpoint,
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpNativeProjection {
    name: McpServerName,
    endpoint: McpHttpsEndpoint,
    bearer_environment: Option<EnvironmentVariableName>,
}

impl McpNativeProjection {
    #[must_use]
    pub const fn name(&self) -> &McpServerName {
        &self.name
    }

    #[must_use]
    pub const fn endpoint(&self) -> &McpHttpsEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub const fn bearer_environment(&self) -> Option<&EnvironmentVariableName> {
        self.bearer_environment.as_ref()
    }
}

impl Debug for McpNativeProjection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpNativeProjection")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("has_bearer_environment", &self.bearer_environment.is_some())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpPortability {
    Portable(McpNativeProjection),
    Blocked(BTreeSet<McpBlockReason>),
}

#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMcpServer {
    native_name: String,
    exact_entry: String,
    exact_entry_hash: ContentHash,
    content_class: ContentClass,
    portability: McpPortability,
}

impl ObservedMcpServer {
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
    pub const fn content_class(&self) -> ContentClass {
        self.content_class
    }

    #[must_use]
    pub const fn portability(&self) -> &McpPortability {
        &self.portability
    }
}

impl Debug for ObservedMcpServer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedMcpServer")
            .field("native_name_hash", &hash_native_name(&self.native_name))
            .field("exact_entry_hash", &self.exact_entry_hash)
            .field("content_class", &self.content_class)
            .field("portability", &self.portability)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMcpDocument {
    dialect: NativeMcpDialect,
    exact_document_hash: ContentHash,
    entries: Vec<ObservedMcpServer>,
}

impl ObservedMcpDocument {
    #[must_use]
    pub const fn dialect(&self) -> NativeMcpDialect {
        self.dialect
    }

    #[must_use]
    pub const fn exact_document_hash(&self) -> &ContentHash {
        &self.exact_document_hash
    }

    #[must_use]
    pub fn entries(&self) -> &[ObservedMcpServer] {
        &self.entries
    }
}

impl Debug for ObservedMcpDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedMcpDocument")
            .field("dialect", &self.dialect)
            .field("exact_document_hash", &self.exact_document_hash)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

pub fn parse_native_mcp_document(
    input: &str,
    dialect: NativeMcpDialect,
    limits: McpParseLimits,
) -> Result<ObservedMcpDocument, McpError> {
    let limits = limits.validated()?;
    if input.len() > limits.max_document_bytes || input.contains('\0') {
        return Err(document_error("mcp.document_limit"));
    }
    let entries = match dialect {
        NativeMcpDialect::ClaudeCurrent => parse_json_entries(input, dialect, limits, false)?,
        NativeMcpDialect::CodexCurrent => parse_codex_entries(input, dialect, limits)?,
        NativeMcpDialect::OpenCodeV2 => parse_json_entries(input, dialect, limits, true)?,
    };
    Ok(ObservedMcpDocument {
        dialect,
        exact_document_hash: hash_exact(b"kitrove-mcp-document-v1\0", dialect, input),
        entries,
    })
}

fn parse_json_entries(
    input: &str,
    dialect: NativeMcpDialect,
    limits: McpParseLimits,
    jsonc: bool,
) -> Result<Vec<ObservedMcpServer>, McpError> {
    let options = ParseOptions {
        allow_comments: jsonc,
        allow_loose_object_property_names: false,
        allow_trailing_commas: jsonc,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
    };
    let parsed = parse_to_ast(input, &CollectOptions::default(), &options)
        .map_err(|_| document_error("mcp.document_invalid"))?;
    let value = parsed
        .value
        .ok_or_else(|| document_error("mcp.document_invalid"))?;
    validate_json_tree(&value, limits)?;
    let root = value
        .as_object()
        .ok_or_else(|| document_error("mcp.document_shape"))?;
    let servers = match dialect {
        NativeMcpDialect::ClaudeCurrent => optional_object(root, "mcpServers")?,
        NativeMcpDialect::OpenCodeV2 => {
            let Some(mcp) = optional_object(root, "mcp")? else {
                return Ok(Vec::new());
            };
            optional_object(mcp, "servers")?
        }
        NativeMcpDialect::CodexCurrent => unreachable!("Codex uses TOML"),
    };
    let Some(servers) = servers else {
        return Ok(Vec::new());
    };
    if servers.properties.len() > limits.max_entries {
        return Err(document_error("mcp.entry_limit"));
    }
    servers
        .properties
        .iter()
        .map(|property| {
            let exact = property.value.text(input);
            if exact.len() > limits.max_entry_bytes {
                return Err(document_error("mcp.entry_limit"));
            }
            let portability = match property.value.as_object() {
                Some(entry) => parse_json_entry(property.name.as_str(), entry, dialect),
                None => blocked([McpBlockReason::MalformedEntry]),
            };
            Ok(observed_entry(
                property.name.as_str(),
                exact,
                dialect,
                portability,
            ))
        })
        .collect()
}

fn parse_json_entry(
    native_name: &str,
    entry: &JsonObject<'_>,
    dialect: NativeMcpDialect,
) -> McpPortability {
    let allowed: &[&str] = match dialect {
        NativeMcpDialect::ClaudeCurrent => &["type", "url", "headers"],
        NativeMcpDialect::OpenCodeV2 => &["type", "url", "headers", "oauth", "disabled"],
        NativeMcpDialect::CodexCurrent => unreachable!("Codex uses TOML"),
    };
    let mut reasons = BTreeSet::new();
    if entry
        .properties
        .iter()
        .any(|property| !allowed.contains(&property.name.as_str()))
    {
        reasons.insert(McpBlockReason::NativeFields);
    }
    let expected_type = match dialect {
        NativeMcpDialect::ClaudeCurrent => ["http", "streamable-http"].as_slice(),
        NativeMcpDialect::OpenCodeV2 => ["remote"].as_slice(),
        NativeMcpDialect::CodexCurrent => unreachable!("Codex uses TOML"),
    };
    let type_value = entry.get_string("type").map(|value| value.value.as_ref());
    if !type_value.is_some_and(|value| expected_type.contains(&value)) {
        if entry.get("command").is_some() || type_value == Some("local") {
            reasons.insert(McpBlockReason::LocalStdio);
        } else {
            reasons.insert(McpBlockReason::UnsupportedTransport);
        }
    }
    if dialect == NativeMcpDialect::OpenCodeV2
        && entry
            .get_boolean("disabled")
            .is_some_and(|value| value.value)
    {
        reasons.insert(McpBlockReason::Disabled);
    }
    let bearer_environment = parse_json_bearer(entry, dialect, &mut reasons);
    let name = McpServerName::parse(native_name.to_owned()).map_err(|_| {
        reasons.insert(McpBlockReason::InvalidName);
    });
    let endpoint = entry
        .get_string("url")
        .ok_or(())
        .and_then(|value| McpHttpsEndpoint::parse(value.value.as_ref()).map_err(|_| ()))
        .map_err(|_| {
            reasons.insert(McpBlockReason::UnsafeEndpoint);
        });
    if reasons.is_empty() {
        McpPortability::Portable(McpNativeProjection {
            name: name.expect("empty reasons prove a valid name"),
            endpoint: endpoint.expect("empty reasons prove a valid endpoint"),
            bearer_environment,
        })
    } else {
        McpPortability::Blocked(reasons)
    }
}

fn parse_json_bearer(
    entry: &JsonObject<'_>,
    dialect: NativeMcpDialect,
    reasons: &mut BTreeSet<McpBlockReason>,
) -> Option<EnvironmentVariableName> {
    let headers = match optional_object(entry, "headers") {
        Ok(headers) => headers,
        Err(_) => {
            reasons.insert(McpBlockReason::MalformedEntry);
            return None;
        }
    };
    let Some(headers) = headers else {
        if dialect == NativeMcpDialect::OpenCodeV2 && entry.get("oauth").is_some() {
            reasons.insert(McpBlockReason::OAuthConfiguration);
        }
        return None;
    };
    if headers.properties.len() != 1 {
        reasons.insert(McpBlockReason::NativeFields);
        return None;
    }
    let header = &headers.properties[0];
    if !header.name.as_str().eq_ignore_ascii_case("authorization") {
        reasons.insert(McpBlockReason::NativeFields);
        return None;
    }
    let Some(value) = header.value.as_string_lit() else {
        reasons.insert(McpBlockReason::MalformedEntry);
        return None;
    };
    let prefix = match dialect {
        NativeMcpDialect::ClaudeCurrent => "Bearer ${",
        NativeMcpDialect::OpenCodeV2 => "Bearer {env:",
        NativeMcpDialect::CodexCurrent => unreachable!("Codex uses TOML"),
    };
    let Some(variable) = value
        .value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix('}'))
        .and_then(|value| EnvironmentVariableName::parse(value.to_owned()).ok())
    else {
        if contains_credential_shaped_text(&value.value) {
            reasons.insert(McpBlockReason::StaticCredential);
        } else {
            reasons.insert(McpBlockReason::NativeFields);
        }
        return None;
    };
    if dialect == NativeMcpDialect::OpenCodeV2 {
        match entry.get_boolean("oauth") {
            Some(value) if !value.value => {}
            _ => {
                reasons.insert(McpBlockReason::OAuthConfiguration);
            }
        }
    }
    Some(variable)
}

fn parse_codex_entries(
    input: &str,
    dialect: NativeMcpDialect,
    limits: McpParseLimits,
) -> Result<Vec<ObservedMcpServer>, McpError> {
    let document = Document::parse(input).map_err(|_| document_error("mcp.document_invalid"))?;
    let mut nodes = 0;
    validate_toml_tree(document.as_item(), limits, 0, &mut nodes)?;
    let Some(servers) = document.get("mcp_servers").and_then(Item::as_table_like) else {
        return Ok(Vec::new());
    };
    if servers.len() > limits.max_entries {
        return Err(document_error("mcp.entry_limit"));
    }
    let mut table_starts = Vec::new();
    collect_table_starts(document.as_item(), &mut table_starts);
    table_starts.sort_unstable();
    table_starts.dedup();
    servers
        .iter()
        .map(|(name, item)| {
            let exact = match item_exact_range(item).and_then(|mut range| {
                range.end = table_starts
                    .iter()
                    .copied()
                    .find(|start| *start > range.end)
                    .unwrap_or(input.len());
                input.get(range)
            }) {
                Some(exact) => exact.to_owned(),
                None => item.to_string(),
            };
            if exact.len() > limits.max_entry_bytes {
                return Err(document_error("mcp.entry_limit"));
            }
            let portability = parse_codex_entry(name, item);
            Ok(observed_entry(name, &exact, dialect, portability))
        })
        .collect()
}

fn collect_table_starts(item: &Item, starts: &mut Vec<usize>) {
    match item {
        Item::Table(table) => {
            if let Some(span) = table.span() {
                starts.push(span.start);
            }
            for (_, child) in table.iter() {
                collect_table_starts(child, starts);
            }
        }
        Item::ArrayOfTables(tables) => {
            if let Some(span) = tables.span() {
                starts.push(span.start);
            }
            for table in tables.iter() {
                for (_, child) in table.iter() {
                    collect_table_starts(child, starts);
                }
            }
        }
        Item::Value(_) | Item::None => {}
    }
}

fn item_exact_range(item: &Item) -> Option<std::ops::Range<usize>> {
    let mut range = item.span()?;
    extend_item_range(item, &mut range);
    Some(range)
}

fn extend_item_range(item: &Item, range: &mut std::ops::Range<usize>) {
    if let Some(span) = item.span() {
        range.start = range.start.min(span.start);
        range.end = range.end.max(span.end);
    }
    match item {
        Item::Table(table) => {
            for (_, child) in table.iter() {
                extend_item_range(child, range);
            }
        }
        Item::ArrayOfTables(tables) => {
            for table in tables.iter() {
                for (_, child) in table.iter() {
                    extend_item_range(child, range);
                }
            }
        }
        Item::Value(value) => extend_value_range(value, range),
        Item::None => {}
    }
}

fn extend_value_range(value: &toml_edit::Value, range: &mut std::ops::Range<usize>) {
    if let Some(span) = value.span() {
        range.start = range.start.min(span.start);
        range.end = range.end.max(span.end);
    }
    match value {
        toml_edit::Value::Array(array) => {
            for child in array.iter() {
                extend_value_range(child, range);
            }
        }
        toml_edit::Value::InlineTable(table) => {
            for (_, child) in table.iter() {
                extend_value_range(child, range);
            }
        }
        _ => {}
    }
}

fn parse_codex_entry(native_name: &str, item: &Item) -> McpPortability {
    let Some(table) = item.as_table_like() else {
        return blocked([McpBlockReason::MalformedEntry]);
    };
    let allowed = ["url", "bearer_token_env_var", "enabled"];
    let mut reasons = BTreeSet::new();
    if table.iter().any(|(key, _)| !allowed.contains(&key)) {
        reasons.insert(if table.get("command").is_some() {
            McpBlockReason::LocalStdio
        } else {
            McpBlockReason::NativeFields
        });
    }
    if contains_credential_shaped_text(&item.to_string()) {
        reasons.insert(McpBlockReason::StaticCredential);
    }
    if table
        .get("enabled")
        .and_then(Item::as_bool)
        .is_some_and(|enabled| !enabled)
    {
        reasons.insert(McpBlockReason::Disabled);
    }
    let name = McpServerName::parse(native_name.to_owned()).map_err(|_| {
        reasons.insert(McpBlockReason::InvalidName);
    });
    let endpoint = table
        .get("url")
        .and_then(Item::as_str)
        .ok_or(())
        .and_then(|value| McpHttpsEndpoint::parse(value.to_owned()).map_err(|_| ()))
        .map_err(|_| {
            reasons.insert(McpBlockReason::UnsafeEndpoint);
        });
    let bearer_environment = match table.get("bearer_token_env_var") {
        Some(item) => match item
            .as_str()
            .and_then(|value| EnvironmentVariableName::parse(value.to_owned()).ok())
        {
            Some(variable) => Some(variable),
            None => {
                reasons.insert(McpBlockReason::MalformedEntry);
                None
            }
        },
        None => None,
    };
    if reasons.is_empty() {
        McpPortability::Portable(McpNativeProjection {
            name: name.expect("empty reasons prove a valid name"),
            endpoint: endpoint.expect("empty reasons prove a valid endpoint"),
            bearer_environment,
        })
    } else {
        McpPortability::Blocked(reasons)
    }
}

fn optional_object<'a>(
    object: &'a JsonObject<'a>,
    key: &str,
) -> Result<Option<&'a JsonObject<'a>>, McpError> {
    match object.get(key) {
        Some(property) => property
            .value
            .as_object()
            .map(Some)
            .ok_or_else(|| document_error("mcp.document_shape")),
        None => Ok(None),
    }
}

fn validate_json_tree(value: &JsonValue<'_>, limits: McpParseLimits) -> Result<(), McpError> {
    let mut stack = vec![(value, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| document_error("mcp.node_limit"))?;
        if nodes > limits.max_nodes || depth > limits.max_depth {
            return Err(document_error("mcp.node_limit"));
        }
        match value {
            JsonValue::Object(object) => {
                let mut keys = BTreeSet::new();
                for property in &object.properties {
                    if !keys.insert(property.name.as_str()) {
                        return Err(document_error("mcp.duplicate_key"));
                    }
                    stack.push((&property.value, depth + 1));
                }
            }
            JsonValue::Array(array) => {
                stack.extend(array.elements.iter().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_toml_tree(
    item: &Item,
    limits: McpParseLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), McpError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| document_error("mcp.node_limit"))?;
    if *nodes > limits.max_nodes || depth > limits.max_depth {
        return Err(document_error("mcp.node_limit"));
    }
    match item {
        Item::Table(table) => {
            for (_, child) in table.iter() {
                validate_toml_tree(child, limits, depth + 1, nodes)?;
            }
        }
        Item::ArrayOfTables(tables) => {
            for table in tables.iter() {
                for (_, child) in table.iter() {
                    validate_toml_tree(child, limits, depth + 1, nodes)?;
                }
            }
        }
        Item::Value(value) => validate_toml_value(value, limits, depth + 1, nodes)?,
        Item::None => {}
    }
    Ok(())
}

fn validate_toml_value(
    value: &toml_edit::Value,
    limits: McpParseLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), McpError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| document_error("mcp.node_limit"))?;
    if *nodes > limits.max_nodes || depth > limits.max_depth {
        return Err(document_error("mcp.node_limit"));
    }
    match value {
        toml_edit::Value::Array(array) => {
            for child in array.iter() {
                validate_toml_value(child, limits, depth + 1, nodes)?;
            }
        }
        toml_edit::Value::InlineTable(table) => {
            for (_, child) in table.iter() {
                validate_toml_value(child, limits, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn observed_entry(
    native_name: &str,
    exact: &str,
    dialect: NativeMcpDialect,
    portability: McpPortability,
) -> ObservedMcpServer {
    let content_class = match &portability {
        McpPortability::Blocked(reasons) if reasons.contains(&McpBlockReason::LocalStdio) => {
            ContentClass::Executable
        }
        _ => ContentClass::AgentActive,
    };
    ObservedMcpServer {
        native_name: bounded_native_name(native_name),
        exact_entry: exact.to_owned(),
        exact_entry_hash: hash_native_entry(dialect, native_name, exact),
        content_class,
        portability,
    }
}

fn bounded_native_name(value: &str) -> String {
    if value.len() <= MAX_NATIVE_NAME_BYTES {
        value.to_owned()
    } else {
        format!("oversized-{}", hash_native_name(value).as_str())
    }
}

fn blocked(reasons: impl IntoIterator<Item = McpBlockReason>) -> McpPortability {
    McpPortability::Blocked(reasons.into_iter().collect())
}

fn hash_exact(domain: &[u8], dialect: NativeMcpDialect, value: &str) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[dialect_tag(dialect)]);
    hash_record(&mut hasher, value.as_bytes());
    digest(hasher)
}

fn hash_native_name(value: &str) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-mcp-name-v1\0");
    hash_record(&mut hasher, value.as_bytes());
    digest(hasher)
}

pub(crate) fn hash_native_entry(
    dialect: NativeMcpDialect,
    native_name: &str,
    exact: &str,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-mcp-entry-v1\0");
    hasher.update(&[dialect_tag(dialect)]);
    hash_record(&mut hasher, native_name.as_bytes());
    hash_record(&mut hasher, exact.as_bytes());
    digest(hasher)
}

pub(crate) fn validate_isolated_portable_entry(
    dialect: NativeMcpDialect,
    native_name: &str,
    exact: &str,
) -> Result<ObservedMcpServer, McpError> {
    let documents = isolated_documents(dialect, native_name, exact)?;
    for document in documents {
        let Ok(parsed) = parse_native_mcp_document(&document, dialect, McpParseLimits::default())
        else {
            continue;
        };
        if let Some(entry) = parsed
            .entries()
            .iter()
            .find(|entry| entry.native_name() == native_name)
        {
            if matches!(entry.portability(), McpPortability::Portable(_)) {
                return Ok(observed_entry(
                    native_name,
                    exact,
                    dialect,
                    entry.portability().clone(),
                ));
            }
        }
    }
    Err(document_error("mcp.native_entry_invalid"))
}

fn isolated_documents(
    dialect: NativeMcpDialect,
    native_name: &str,
    exact: &str,
) -> Result<Vec<String>, McpError> {
    if exact.len() > HARD_MAX_ENTRY_BYTES {
        return Err(document_error("mcp.entry_limit"));
    }
    match dialect {
        NativeMcpDialect::ClaudeCurrent => {
            let name = serde_json::to_string(native_name)
                .map_err(|_| document_error("mcp.native_entry_invalid"))?;
            Ok(vec![format!(r#"{{"mcpServers":{{{name}:{exact}}}}}"#)])
        }
        NativeMcpDialect::OpenCodeV2 => {
            let name = serde_json::to_string(native_name)
                .map_err(|_| document_error("mcp.native_entry_invalid"))?;
            Ok(vec![format!(
                r#"{{"mcp":{{"servers":{{{name}:{exact}}}}}}}"#
            )])
        }
        NativeMcpDialect::CodexCurrent => Ok(vec![
            exact.to_owned(),
            format!("[mcp_servers.{native_name}]\n{exact}"),
            format!("mcp_servers = {{ {native_name} = {exact} }}"),
        ]),
    }
}

const fn dialect_tag(dialect: NativeMcpDialect) -> u8 {
    match dialect {
        NativeMcpDialect::ClaudeCurrent => 0,
        NativeMcpDialect::CodexCurrent => 1,
        NativeMcpDialect::OpenCodeV2 => 2,
    }
}

const fn document_error(code: &'static str) -> McpError {
    McpError::new(
        code,
        "native MCP document is invalid or exceeds bounded parsing policy",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_portable_remote_intersection_for_all_supported_dialects() {
        let fixtures = [
            (
                NativeMcpDialect::ClaudeCurrent,
                r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${DOCS_TOKEN}"}}}}"#,
                "DOCS_TOKEN",
            ),
            (
                NativeMcpDialect::CodexCurrent,
                "[mcp_servers.docs]\nurl = \"https://mcp.example.com/mcp\"\nbearer_token_env_var = \"DOCS_TOKEN\"\n",
                "DOCS_TOKEN",
            ),
            (
                NativeMcpDialect::OpenCodeV2,
                r#"{
                  // comments and trailing commas are native
                  "mcp": { "servers": { "docs": {
                    "type": "remote",
                    "url": "https://mcp.example.com/mcp",
                    "headers": { "Authorization": "Bearer {env:DOCS_TOKEN}" },
                    "oauth": false,
                  } } },
                }"#,
                "DOCS_TOKEN",
            ),
        ];
        for (dialect, input, variable) in fixtures {
            let document =
                parse_native_mcp_document(input, dialect, McpParseLimits::default()).unwrap();
            assert_eq!(document.entries().len(), 1);
            let McpPortability::Portable(projection) = document.entries()[0].portability() else {
                panic!("portable fixture was blocked");
            };
            assert_eq!(projection.name().as_str(), "docs");
            assert_eq!(projection.bearer_environment().unwrap().as_str(), variable);
            assert_eq!(
                projection.endpoint().as_str(),
                "https://mcp.example.com/mcp"
            );
            if dialect == NativeMcpDialect::CodexCurrent {
                assert_eq!(document.entries()[0].exact_entry(), input);
                assert!(document.entries()[0].exact_entry().contains("url ="));
                assert!(
                    document.entries()[0]
                        .exact_entry()
                        .contains("bearer_token_env_var =")
                );
            }
        }
    }

    #[test]
    fn codex_exact_entries_stop_before_the_next_table() {
        let input = concat!(
            "[mcp_servers.one]\n",
            "url = \"https://one.example.com/mcp\"\n",
            "# retained with one\n",
            "[mcp_servers.two]\n",
            "url = \"https://two.example.com/mcp\"\n",
            "[unrelated]\n",
            "enabled = true\n",
        );
        let document = parse_native_mcp_document(
            input,
            NativeMcpDialect::CodexCurrent,
            McpParseLimits::default(),
        )
        .unwrap();

        assert_eq!(document.entries().len(), 2);
        let one = document
            .entries()
            .iter()
            .find(|entry| entry.native_name() == "one")
            .unwrap();
        assert!(one.exact_entry().contains("# retained with one"));
        assert!(!one.exact_entry().contains("mcp_servers.two"));
        let two = document
            .entries()
            .iter()
            .find(|entry| entry.native_name() == "two")
            .unwrap();
        assert!(!two.exact_entry().contains("[unrelated]"));
    }

    #[test]
    fn blocks_native_authority_without_leaking_it_or_starting_a_server() {
        let document = parse_native_mcp_document(
            r#"{"mcpServers":{"local":{"command":"SECRET-COMMAND","args":["SECRET-ARG"]},"token":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer sk-live-12345678901234567890"}}}}"#,
            NativeMcpDialect::ClaudeCurrent,
            McpParseLimits::default(),
        )
        .unwrap();
        assert_eq!(
            document.entries()[0].content_class(),
            ContentClass::Executable
        );
        assert!(matches!(
            document.entries()[0].portability(),
            McpPortability::Blocked(reasons) if reasons.contains(&McpBlockReason::LocalStdio)
        ));
        assert!(matches!(
            document.entries()[1].portability(),
            McpPortability::Blocked(reasons) if reasons.contains(&McpBlockReason::StaticCredential)
        ));
        let debug = format!("{document:?} {:?}", document.entries());
        assert!(!debug.contains("SECRET-COMMAND"));
        assert!(!debug.contains("SECRET-ARG"));
        assert!(!debug.contains("sk-live"));
    }

    #[test]
    fn rejects_duplicate_keys_loose_jsonc_and_bounded_resource_attacks() {
        for input in [
            r#"{"mcpServers":{},"mcpServers":{}}"#,
            r#"{mcp:{servers:{}}}"#,
            r#"{'mcp':{'servers':{}}}"#,
        ] {
            assert!(
                parse_native_mcp_document(
                    input,
                    NativeMcpDialect::OpenCodeV2,
                    McpParseLimits::default()
                )
                .is_err()
            );
        }
        let deep = format!("{}0{}", "[".repeat(40), "]".repeat(40));
        assert_eq!(
            parse_native_mcp_document(
                &deep,
                NativeMcpDialect::OpenCodeV2,
                McpParseLimits::default()
            )
            .unwrap_err()
            .code(),
            "mcp.node_limit"
        );
        let tiny = McpParseLimits {
            max_entries: 1,
            ..McpParseLimits::default()
        };
        assert_eq!(
            parse_native_mcp_document(
                r#"{"mcpServers":{"one":{},"two":{}}}"#,
                NativeMcpDialect::ClaudeCurrent,
                tiny,
            )
            .unwrap_err()
            .code(),
            "mcp.entry_limit"
        );
    }

    #[test]
    fn debug_and_errors_do_not_disclose_malformed_authored_values() {
        let error = parse_native_mcp_document(
            "{ SECRET-DOCUMENT",
            NativeMcpDialect::ClaudeCurrent,
            McpParseLimits::default(),
        )
        .unwrap_err();
        assert!(!format!("{error:?}").contains("SECRET-DOCUMENT"));
        assert!(!error.to_string().contains("SECRET-DOCUMENT"));
        assert!(kitrove_risk::is_credential_shaped(
            "sk-live-12345678901234567890"
        ));
    }

    #[test]
    fn entry_identity_includes_the_native_name() {
        let document = parse_native_mcp_document(
            r#"{"mcpServers":{"one":{"type":"http","url":"https://mcp.example.com"},"two":{"type":"http","url":"https://mcp.example.com"}}}"#,
            NativeMcpDialect::ClaudeCurrent,
            McpParseLimits::default(),
        )
        .unwrap();

        assert_ne!(
            document.entries()[0].exact_entry_hash(),
            document.entries()[1].exact_entry_hash()
        );
    }

    #[test]
    fn codex_static_credentials_are_blocked() {
        let document = parse_native_mcp_document(
            "[mcp_servers.docs]\nurl = \"https://mcp.example.com\"\nheaders = { Authorization = \"Bearer sk-live-12345678901234567890\" }\n",
            NativeMcpDialect::CodexCurrent,
            McpParseLimits::default(),
        )
        .unwrap();

        assert!(matches!(
            document.entries()[0].portability(),
            McpPortability::Blocked(reasons) if reasons.contains(&McpBlockReason::StaticCredential)
        ));
        assert!(!format!("{document:?} {:?}", document.entries()).contains("sk-live"));
    }
}
