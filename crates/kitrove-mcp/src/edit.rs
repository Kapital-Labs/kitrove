use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::ops::Range;

use jsonc_parser::ast::Object as JsonObject;
use jsonc_parser::common::Ranged;
use jsonc_parser::{CollectOptions, ParseOptions, parse_to_ast};
use kitrove_model::ContentHash;
use toml_edit::{Document, Item, Table};

use crate::{
    McpError, McpParseLimits, McpPortability, McpServerName, NativeMcpDialect, RenderedMcpEntry,
    parse_native_mcp_document,
};

/// One authority-checked logical mutation inside a shared native MCP document.
#[derive(Clone, Eq, PartialEq)]
pub enum McpDocumentMutation {
    Upsert {
        rendered: RenderedMcpEntry,
        expected_existing: Option<ContentHash>,
    },
    Remove {
        native_name: String,
        expected_existing: ContentHash,
    },
}

impl McpDocumentMutation {
    fn native_name(&self) -> &str {
        match self {
            Self::Upsert { rendered, .. } => rendered.native_name(),
            Self::Remove { native_name, .. } => native_name,
        }
    }
}

impl Debug for McpDocumentMutation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upsert {
                rendered,
                expected_existing,
            } => formatter
                .debug_struct("McpDocumentMutation::Upsert")
                .field("rendered_hash", rendered.hash())
                .field("expected_existing", expected_existing)
                .finish(),
            Self::Remove {
                expected_existing, ..
            } => formatter
                .debug_struct("McpDocumentMutation::Remove")
                .field("expected_existing", expected_existing)
                .finish(),
        }
    }
}

/// Exact post-edit document bytes and independently reparsed identity.
#[derive(Clone, Eq, PartialEq)]
pub struct EditedMcpDocument {
    text: String,
    exact_document_hash: ContentHash,
}

impl EditedMcpDocument {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    #[must_use]
    pub const fn exact_document_hash(&self) -> &ContentHash {
        &self.exact_document_hash
    }
}

impl Debug for EditedMcpDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EditedMcpDocument")
            .field("byte_count", &self.text.len())
            .field("exact_document_hash", &self.exact_document_hash)
            .finish()
    }
}

/// Applies a bounded set of entry-authorized edits without executing or resolving MCP authority.
pub fn edit_native_mcp_document(
    input: &str,
    dialect: NativeMcpDialect,
    mutations: &[McpDocumentMutation],
    limits: McpParseLimits,
) -> Result<EditedMcpDocument, McpError> {
    let limits = limits.validated()?;
    if mutations.len() > limits.max_entries {
        return Err(edit_error("mcp.edit_limit"));
    }
    let mut names = BTreeSet::new();
    for mutation in mutations {
        McpServerName::parse(mutation.native_name().to_owned())
            .map_err(|_| edit_error("mcp.edit_name_invalid"))?;
        if !names.insert(mutation.native_name()) {
            return Err(edit_error("mcp.edit_duplicate_name"));
        }
        if matches!(mutation, McpDocumentMutation::Upsert { rendered, .. } if rendered.dialect() != dialect)
        {
            return Err(edit_error("mcp.edit_dialect_mismatch"));
        }
    }
    let observed = parse_native_mcp_document(input, dialect, limits)?;
    validate_authority(&observed, mutations)?;
    if mutations.is_empty() {
        return Ok(EditedMcpDocument {
            text: input.to_owned(),
            exact_document_hash: observed.exact_document_hash().clone(),
        });
    }
    let text = match dialect {
        NativeMcpDialect::ClaudeCurrent | NativeMcpDialect::OpenCodeV2 => {
            edit_json(input, dialect, mutations)?
        }
        NativeMcpDialect::CodexCurrent => edit_toml(input, mutations)?,
    };
    if text.len() > limits.max_document_bytes {
        return Err(edit_error("mcp.edit_limit"));
    }
    let reparsed = parse_native_mcp_document(&text, dialect, limits)?;
    verify_result(&reparsed, mutations, limits)?;
    Ok(EditedMcpDocument {
        text,
        exact_document_hash: reparsed.exact_document_hash().clone(),
    })
}

fn validate_authority(
    observed: &crate::ObservedMcpDocument,
    mutations: &[McpDocumentMutation],
) -> Result<(), McpError> {
    for mutation in mutations {
        let actual = observed
            .entries()
            .iter()
            .find(|entry| entry.native_name() == mutation.native_name())
            .map(crate::ObservedMcpServer::exact_entry_hash);
        let expected = match mutation {
            McpDocumentMutation::Upsert {
                expected_existing, ..
            } => expected_existing.as_ref(),
            McpDocumentMutation::Remove {
                expected_existing, ..
            } => Some(expected_existing),
        };
        if actual != expected {
            return Err(edit_error("mcp.edit_stale_entry"));
        }
    }
    Ok(())
}

fn verify_result(
    observed: &crate::ObservedMcpDocument,
    mutations: &[McpDocumentMutation],
    limits: McpParseLimits,
) -> Result<(), McpError> {
    for mutation in mutations {
        let present = observed
            .entries()
            .iter()
            .find(|entry| entry.native_name() == mutation.native_name());
        match mutation {
            McpDocumentMutation::Upsert { rendered, .. }
                if present.is_some_and(|entry| {
                    expected_portability(rendered, limits)
                        .is_ok_and(|expected| entry.portability() == &expected)
                }) => {}
            McpDocumentMutation::Remove { .. } if present.is_none() => {}
            _ => return Err(edit_error("mcp.edit_verification_failed")),
        }
    }
    Ok(())
}

fn expected_portability(
    rendered: &RenderedMcpEntry,
    limits: McpParseLimits,
) -> Result<McpPortability, McpError> {
    let document = match rendered.dialect() {
        NativeMcpDialect::ClaudeCurrent => format!(
            r#"{{"mcpServers":{{{}:{}}}}}"#,
            serde_json::to_string(rendered.native_name())
                .map_err(|_| edit_error("mcp.edit_serialize"))?,
            rendered.text()
        ),
        NativeMcpDialect::OpenCodeV2 => format!(
            r#"{{"mcp":{{"servers":{{{}:{}}}}}}}"#,
            serde_json::to_string(rendered.native_name())
                .map_err(|_| edit_error("mcp.edit_serialize"))?,
            rendered.text()
        ),
        NativeMcpDialect::CodexCurrent => rendered.text().to_owned(),
    };
    let parsed = parse_native_mcp_document(&document, rendered.dialect(), limits)?;
    parsed
        .entries()
        .first()
        .map(|entry| entry.portability().clone())
        .ok_or_else(|| edit_error("mcp.edit_serialize"))
}

fn json_options(dialect: NativeMcpDialect) -> ParseOptions {
    let jsonc = dialect == NativeMcpDialect::OpenCodeV2;
    ParseOptions {
        allow_comments: jsonc,
        allow_loose_object_property_names: false,
        allow_trailing_commas: jsonc,
        allow_missing_commas: false,
        allow_single_quoted_strings: false,
        allow_hexadecimal_numbers: false,
        allow_unary_plus_numbers: false,
    }
}

fn edit_json(
    input: &str,
    dialect: NativeMcpDialect,
    mutations: &[McpDocumentMutation],
) -> Result<String, McpError> {
    let parsed = parse_to_ast(input, &CollectOptions::default(), &json_options(dialect))
        .map_err(|_| edit_error("mcp.edit_invalid"))?;
    let value = parsed.value.ok_or_else(|| edit_error("mcp.edit_invalid"))?;
    let root = value
        .as_object()
        .ok_or_else(|| edit_error("mcp.edit_invalid"))?;
    let target = json_target(root, dialect)?;
    let mut replacements = Vec::new();
    if let JsonTarget::Servers(servers) = target {
        let mut removals = Vec::new();
        for mutation in mutations {
            if let Some((index, property)) = servers
                .properties
                .iter()
                .enumerate()
                .find(|(_, property)| property.name.as_str() == mutation.native_name())
            {
                match mutation {
                    McpDocumentMutation::Upsert { rendered, .. } => replacements.push((
                        property.value.range().start..property.value.range().end,
                        rendered.text().to_owned(),
                    )),
                    McpDocumentMutation::Remove { .. } => removals.push(index),
                }
            }
        }
        replacements.extend(json_removal_ranges(input, servers, &removals)?);
        let additions = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                McpDocumentMutation::Upsert {
                    rendered,
                    expected_existing: None,
                } => Some(rendered),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !additions.is_empty() {
            let insertion = json_properties(&additions)?;
            replacements.push(json_object_insertion(input, servers, &insertion)?);
        }
    } else {
        if mutations
            .iter()
            .any(|mutation| matches!(mutation, McpDocumentMutation::Remove { .. }))
        {
            return Err(edit_error("mcp.edit_stale_entry"));
        }
        let additions = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                McpDocumentMutation::Upsert { rendered, .. } => Some(rendered),
                _ => None,
            })
            .collect::<Vec<_>>();
        let properties = json_properties(&additions)?;
        let (object, container) = match target {
            JsonTarget::MissingRoot => {
                let container = match dialect {
                    NativeMcpDialect::ClaudeCurrent => {
                        format!(r#""mcpServers":{{{properties}}}"#)
                    }
                    NativeMcpDialect::OpenCodeV2 => {
                        format!(r#""mcp":{{"servers":{{{properties}}}}}"#)
                    }
                    NativeMcpDialect::CodexCurrent => unreachable!(),
                };
                (root, container)
            }
            JsonTarget::MissingOpenCodeServers(mcp) => {
                (mcp, format!(r#""servers":{{{properties}}}"#))
            }
            JsonTarget::Servers(_) => unreachable!(),
        };
        replacements.push(json_object_insertion(input, object, &container)?);
    }
    apply_replacements(input, replacements)
}

#[derive(Clone, Copy)]
enum JsonTarget<'a> {
    Servers(&'a JsonObject<'a>),
    MissingOpenCodeServers(&'a JsonObject<'a>),
    MissingRoot,
}

fn json_target<'a>(
    root: &'a JsonObject<'a>,
    dialect: NativeMcpDialect,
) -> Result<JsonTarget<'a>, McpError> {
    match dialect {
        NativeMcpDialect::ClaudeCurrent => Ok(optional_json_object(root, "mcpServers")?
            .map_or(JsonTarget::MissingRoot, JsonTarget::Servers)),
        NativeMcpDialect::OpenCodeV2 => {
            let Some(mcp) = optional_json_object(root, "mcp")? else {
                return Ok(JsonTarget::MissingRoot);
            };
            Ok(optional_json_object(mcp, "servers")?
                .map_or(JsonTarget::MissingOpenCodeServers(mcp), JsonTarget::Servers))
        }
        NativeMcpDialect::CodexCurrent => unreachable!(),
    }
}

fn optional_json_object<'a>(
    object: &'a JsonObject<'a>,
    name: &str,
) -> Result<Option<&'a JsonObject<'a>>, McpError> {
    match object.get(name) {
        Some(property) => property
            .value
            .as_object()
            .map(Some)
            .ok_or_else(|| edit_error("mcp.edit_ambiguous_shape")),
        None => Ok(None),
    }
}

fn json_object_insertion(
    input: &str,
    object: &JsonObject<'_>,
    properties: &str,
) -> Result<(Range<usize>, String), McpError> {
    let Some(last) = object.properties.last() else {
        let position = object.range.start + 1;
        return Ok((position..position, properties.to_owned()));
    };
    let suffix = checked_slice(input, last.range.end..object.range.end - 1)?;
    if let Some(comma) = json_separator_comma(suffix)? {
        let position = last.range.end + comma + 1;
        Ok((position..position, format!("{properties},")))
    } else {
        Ok((last.range.end..last.range.end, format!(",{properties}")))
    }
}

fn json_properties(entries: &[&RenderedMcpEntry]) -> Result<String, McpError> {
    entries
        .iter()
        .map(|entry| {
            serde_json::to_string(entry.native_name())
                .map(|name| format!("{name}:{}", entry.text()))
                .map_err(|_| edit_error("mcp.edit_serialize"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|entries| entries.join(","))
}

fn json_removal_ranges(
    input: &str,
    object: &JsonObject<'_>,
    indices: &[usize],
) -> Result<Vec<(Range<usize>, String)>, McpError> {
    let mut indices = indices.to_vec();
    indices.sort_unstable();
    let mut claimed_commas = BTreeSet::new();
    let mut ranges = Vec::with_capacity(indices.len().saturating_mul(2));
    for index in indices {
        let property = object
            .properties
            .get(index)
            .ok_or_else(|| edit_error("mcp.edit_ambiguous_shape"))?;
        ranges.push((property.range.start..property.range.end, String::new()));
        let after = object
            .properties
            .get(index + 1)
            .map_or(property.range.end..object.range.end - 1, |next| {
                property.range.end..next.range.start
            });
        let before =
            (index > 0).then(|| object.properties[index - 1].range.end..property.range.start);
        let separator = find_comma(input, after)?
            .filter(|comma| !claimed_commas.contains(comma))
            .or(match before {
                Some(range) => {
                    find_comma(input, range)?.filter(|comma| !claimed_commas.contains(comma))
                }
                None => None,
            });
        if let Some(comma) = separator {
            claimed_commas.insert(comma);
            ranges.push((comma..comma + 1, String::new()));
        }
    }
    Ok(ranges)
}

fn find_comma(input: &str, range: Range<usize>) -> Result<Option<usize>, McpError> {
    Ok(json_separator_comma(checked_slice(input, range.clone())?)?
        .map(|offset| range.start + offset))
}

fn json_separator_comma(separator: &str) -> Result<Option<usize>, McpError> {
    let bytes = separator.as_bytes();
    let mut index = 0;
    let mut comma = None;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b',' if comma.is_none() => {
                comma = Some(index);
                index += 1;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' && bytes[index] != b'\r' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let Some(end) = separator[index + 2..].find("*/") else {
                    return Err(edit_error("mcp.edit_ambiguous_shape"));
                };
                index += end + 4;
            }
            _ => return Err(edit_error("mcp.edit_ambiguous_shape")),
        }
    }
    Ok(comma)
}

fn checked_slice(input: &str, range: Range<usize>) -> Result<&str, McpError> {
    input
        .get(range)
        .ok_or_else(|| edit_error("mcp.edit_ambiguous_shape"))
}

fn edit_toml(input: &str, mutations: &[McpDocumentMutation]) -> Result<String, McpError> {
    let parsed = Document::parse(input).map_err(|_| edit_error("mcp.edit_invalid"))?;
    validate_toml_shape(&parsed)?;
    let mut document = parsed.into_mut();
    if document.get("mcp_servers").is_none() {
        document.insert("mcp_servers", Item::Table(Table::new()));
    }
    let servers = document
        .get_mut("mcp_servers")
        .and_then(Item::as_table_mut)
        .ok_or_else(|| edit_error("mcp.edit_ambiguous_shape"))?;
    for mutation in mutations {
        match mutation {
            McpDocumentMutation::Upsert { rendered, .. } => {
                let rendered_document = Document::parse(rendered.text())
                    .map_err(|_| edit_error("mcp.edit_serialize"))?;
                let item = rendered_document
                    .get("mcp_servers")
                    .and_then(Item::as_table)
                    .and_then(|table| table.get(rendered.native_name()))
                    .cloned()
                    .ok_or_else(|| edit_error("mcp.edit_serialize"))?;
                servers.insert(rendered.native_name(), item);
            }
            McpDocumentMutation::Remove { native_name, .. } => {
                servers.remove(native_name);
            }
        }
    }
    Ok(document.to_string())
}

fn validate_toml_shape(document: &Document<&str>) -> Result<(), McpError> {
    let Some(item) = document.get("mcp_servers") else {
        return Ok(());
    };
    let Some(servers) = item.as_table() else {
        return Err(edit_error("mcp.edit_ambiguous_shape"));
    };
    if servers.is_dotted()
        || servers
            .iter()
            .any(|(_, item)| item.as_table().is_none_or(Table::is_dotted))
    {
        return Err(edit_error("mcp.edit_ambiguous_shape"));
    }
    Ok(())
}

fn apply_replacements(
    input: &str,
    mut replacements: Vec<(Range<usize>, String)>,
) -> Result<String, McpError> {
    replacements.sort_by_key(|replacement| Reverse(replacement.0.start));
    let mut output = input.to_owned();
    let mut last_start = input.len();
    for (range, replacement) in replacements {
        if range.end > last_start
            || range.start > range.end
            || !output.is_char_boundary(range.start)
            || !output.is_char_boundary(range.end)
        {
            return Err(edit_error("mcp.edit_ambiguous_shape"));
        }
        output.replace_range(range.clone(), &replacement);
        last_start = range.start;
    }
    Ok(output)
}

const fn edit_error(code: &'static str) -> McpError {
    crate::mcp_error(
        code,
        "shared MCP document edit was stale, ambiguous, invalid, or exceeded bounded policy",
    )
}

#[cfg(test)]
mod tests {
    use kitrove_model::{BindingName, EnvironmentVariableName};

    use super::*;
    use crate::{McpHttpsEndpoint, McpServer, render_native_mcp_entry};

    fn server(name: &str, endpoint: &str, bound: bool) -> McpServer {
        McpServer::new(
            McpServerName::parse(name).unwrap(),
            McpHttpsEndpoint::parse(endpoint).unwrap(),
            bound.then(|| BindingName::parse(format!("{name}_token")).unwrap()),
        )
        .unwrap()
    }

    fn rendered(name: &str, dialect: NativeMcpDialect) -> RenderedMcpEntry {
        render_native_mcp_entry(
            &server(name, &format!("https://{name}.example.com/mcp"), false),
            dialect,
            None,
        )
        .unwrap()
    }

    fn rendered_with_binding(name: &str, dialect: NativeMcpDialect) -> RenderedMcpEntry {
        render_native_mcp_entry(
            &server(name, &format!("https://{name}.example.com/mcp"), true),
            dialect,
            Some(&EnvironmentVariableName::parse("KITROVE_MCP_TOKEN").unwrap()),
        )
        .unwrap()
    }

    fn entry_hash(input: &str, dialect: NativeMcpDialect, name: &str) -> ContentHash {
        parse_native_mcp_document(input, dialect, McpParseLimits::default())
            .unwrap()
            .entries()
            .iter()
            .find(|entry| entry.native_name() == name)
            .unwrap()
            .exact_entry_hash()
            .clone()
    }

    fn upsert(rendered: RenderedMcpEntry) -> McpDocumentMutation {
        McpDocumentMutation::Upsert {
            rendered,
            expected_existing: None,
        }
    }

    #[test]
    fn claude_add_replace_and_remove_preserve_unrelated_bytes() {
        let input = "{\n  \"theme\": \"SECRET-UNRELATED\",\n  \"mcpServers\": {\n    \"old\": {\"type\":\"http\",\"url\":\"https://old.example.com/mcp\"}\n  }\n}\n";
        let replacement = rendered("old", NativeMcpDialect::ClaudeCurrent);
        let addition = rendered("new", NativeMcpDialect::ClaudeCurrent);
        let edited = edit_native_mcp_document(
            input,
            NativeMcpDialect::ClaudeCurrent,
            &[
                McpDocumentMutation::Upsert {
                    rendered: replacement,
                    expected_existing: Some(entry_hash(
                        input,
                        NativeMcpDialect::ClaudeCurrent,
                        "old",
                    )),
                },
                upsert(addition),
            ],
            McpParseLimits::default(),
        )
        .unwrap();
        assert!(edited.text().contains("\"theme\": \"SECRET-UNRELATED\""));
        assert_eq!(
            edited.exact_document_hash(),
            parse_native_mcp_document(
                edited.text(),
                NativeMcpDialect::ClaudeCurrent,
                McpParseLimits::default(),
            )
            .unwrap()
            .exact_document_hash()
        );

        let removed = edit_native_mcp_document(
            edited.text(),
            NativeMcpDialect::ClaudeCurrent,
            &[McpDocumentMutation::Remove {
                native_name: "old".to_owned(),
                expected_existing: entry_hash(
                    edited.text(),
                    NativeMcpDialect::ClaudeCurrent,
                    "old",
                ),
            }],
            McpParseLimits::default(),
        )
        .unwrap();
        assert!(removed.text().contains("\"theme\": \"SECRET-UNRELATED\""));
        assert!(!removed.text().contains("\"old\""));
        assert!(removed.text().contains("\"new\""));
    }

    #[test]
    fn opencode_jsonc_preserves_comments_and_handles_partial_containers() {
        let input = "{\n  // root comment\n  \"mcp\": {\n    \"mode\": \"SECRET-MODE\", // keep me\n  },\n}\n";
        let edited = edit_native_mcp_document(
            input,
            NativeMcpDialect::OpenCodeV2,
            &[upsert(rendered("docs", NativeMcpDialect::OpenCodeV2))],
            McpParseLimits::default(),
        )
        .unwrap();
        assert!(edited.text().contains("// root comment"));
        assert!(edited.text().contains("// keep me"));
        assert!(edited.text().contains("\"mode\": \"SECRET-MODE\""));
        assert_eq!(edited.text().matches("\"mcp\"").count(), 1);
        assert_eq!(edited.text().matches("\"servers\"").count(), 1);

        let trailing = "{\"mcp\":{\"servers\":{\"one\":{\"type\":\"remote\",\"url\":\"https://one.example.com/mcp\"}, /* separator */}},}\n";
        let changed = edit_native_mcp_document(
            trailing,
            NativeMcpDialect::OpenCodeV2,
            &[upsert(rendered("two", NativeMcpDialect::OpenCodeV2))],
            McpParseLimits::default(),
        )
        .unwrap();
        assert!(changed.text().contains("/* separator */"));
        assert!(changed.text().contains("\"one\""));
        assert!(changed.text().contains("\"two\""));
    }

    #[test]
    fn removing_json_property_erases_only_property_and_one_comma() {
        let input = "{\"mcp\":{\"servers\":{\"one\":{\"type\":\"remote\",\"url\":\"https://one.example.com/mcp\"} /* KEEP, INCLUDING COMMA */, \"two\":{\"type\":\"remote\",\"url\":\"https://two.example.com/mcp\"}, \"three\":{\"type\":\"remote\",\"url\":\"https://three.example.com/mcp\"}}}}";
        let edited = edit_native_mcp_document(
            input,
            NativeMcpDialect::OpenCodeV2,
            &[
                McpDocumentMutation::Remove {
                    native_name: "two".to_owned(),
                    expected_existing: entry_hash(input, NativeMcpDialect::OpenCodeV2, "two"),
                },
                McpDocumentMutation::Remove {
                    native_name: "three".to_owned(),
                    expected_existing: entry_hash(input, NativeMcpDialect::OpenCodeV2, "three"),
                },
            ],
            McpParseLimits::default(),
        )
        .unwrap();
        assert!(edited.text().contains("/* KEEP, INCLUDING COMMA */"));
        assert!(edited.text().contains("\"one\""));
        assert!(!edited.text().contains("\"two\""));
        assert!(!edited.text().contains("\"three\""));
    }

    #[test]
    fn codex_edits_preserve_unrelated_tables_and_comments() {
        let input = "# KEEP HEADER\n[unrelated]\nvalue = \"SECRET-VALUE\"\n\n[mcp_servers.docs]\nurl = \"https://old.example.com/mcp\"\n\n# KEEP NEXT\n[other]\nenabled = true\n";
        let changed = edit_native_mcp_document(
            input,
            NativeMcpDialect::CodexCurrent,
            &[
                McpDocumentMutation::Upsert {
                    rendered: rendered_with_binding("docs", NativeMcpDialect::CodexCurrent),
                    expected_existing: Some(entry_hash(
                        input,
                        NativeMcpDialect::CodexCurrent,
                        "docs",
                    )),
                },
                upsert(rendered("search", NativeMcpDialect::CodexCurrent)),
            ],
            McpParseLimits::default(),
        )
        .unwrap();
        for preserved in ["# KEEP HEADER", "SECRET-VALUE", "# KEEP NEXT", "[other]"] {
            assert!(changed.text().contains(preserved));
        }
        let removed = edit_native_mcp_document(
            changed.text(),
            NativeMcpDialect::CodexCurrent,
            &[McpDocumentMutation::Remove {
                native_name: "docs".to_owned(),
                expected_existing: entry_hash(
                    changed.text(),
                    NativeMcpDialect::CodexCurrent,
                    "docs",
                ),
            }],
            McpParseLimits::default(),
        )
        .unwrap();
        assert!(removed.text().contains("[mcp_servers.search]"));
        assert!(!removed.text().contains("[mcp_servers.docs]"));
        assert!(removed.text().contains("# KEEP NEXT"));
    }

    #[test]
    fn stale_duplicate_ambiguous_and_unbounded_edits_fail_closed() {
        let docs = rendered("docs", NativeMcpDialect::ClaudeCurrent);
        let duplicate = vec![upsert(docs.clone()), upsert(docs)];
        assert_eq!(
            edit_native_mcp_document(
                r#"{"mcpServers":{}}"#,
                NativeMcpDialect::ClaudeCurrent,
                &duplicate,
                McpParseLimits::default(),
            )
            .unwrap_err()
            .code(),
            "mcp.edit_duplicate_name"
        );
        assert_eq!(
            edit_native_mcp_document(
                r#"{"mcpServers":{"docs":{"type":"http","url":"https://docs.example.com/mcp"}}}"#,
                NativeMcpDialect::ClaudeCurrent,
                &[McpDocumentMutation::Remove {
                    native_name: "docs".to_owned(),
                    expected_existing: ContentHash::parse(format!("blake3:{}", "a".repeat(64)))
                        .unwrap(),
                }],
                McpParseLimits::default(),
            )
            .unwrap_err()
            .code(),
            "mcp.edit_stale_entry"
        );
        for ambiguous in [
            "mcp_servers = { docs = { url = \"https://docs.example.com\" } }\n",
            "[mcp_servers]\ndocs.url = \"https://docs.example.com\"\n",
        ] {
            assert!(
                edit_native_mcp_document(
                    ambiguous,
                    NativeMcpDialect::CodexCurrent,
                    &[upsert(rendered("search", NativeMcpDialect::CodexCurrent))],
                    McpParseLimits::default(),
                )
                .is_err()
            );
        }
        let tiny = McpParseLimits {
            max_document_bytes: 8,
            ..McpParseLimits::default()
        };
        assert!(
            edit_native_mcp_document(
                r#"{"mcpServers":{}}"#,
                NativeMcpDialect::ClaudeCurrent,
                &[],
                tiny,
            )
            .is_err()
        );
    }

    #[test]
    fn debug_redacts_rendered_authority_and_empty_edits_are_byte_exact() {
        let mutation = upsert(rendered_with_binding(
            "docs",
            NativeMcpDialect::ClaudeCurrent,
        ));
        let debug = format!("{mutation:?}");
        assert!(!debug.contains("docs.example.com"));
        assert!(!debug.contains("KITROVE_MCP_TOKEN"));
        let input = "{\n  \"mcpServers\": {}\n}\n";
        let unchanged = edit_native_mcp_document(
            input,
            NativeMcpDialect::ClaudeCurrent,
            &[],
            McpParseLimits::default(),
        )
        .unwrap();
        assert_eq!(unchanged.text(), input);
        assert!(!format!("{unchanged:?}").contains(input));
    }
}
