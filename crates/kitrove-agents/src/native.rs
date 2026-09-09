use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use kitrove_frontmatter::{
    FlatFrontmatterError, FlatFrontmatterLimits, ObservedFrontmatterValue,
    parse_optional_observed_markdown,
};
use kitrove_model::{ContentClass, ContentHash, HarnessId};
use serde::{Deserialize, Serialize};

use crate::{
    Agent, AgentDescription, AgentError, AgentInstructions, AgentName, digest, hash_record,
};

const MAX_FRONTMATTER_BYTES: usize = 32 * 1024;
const MAX_FRONTMATTER_FIELDS: usize = 64;

/// Native syntax selected by a compiled agent target policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAgentDialect {
    ClaudeCurrent,
    CodexCurrent,
    OpenCodeCurrent,
}

impl NativeAgentDialect {
    /// Harness whose documented registry uses this syntax.
    #[must_use]
    pub const fn harness(self) -> HarnessId {
        match self {
            Self::ClaudeCurrent => HarnessId::Claude,
            Self::CodexCurrent => HarnessId::Codex,
            Self::OpenCodeCurrent => HarnessId::OpenCode,
        }
    }

    /// Whether the documented registry recursively discovers nested definitions.
    #[must_use]
    pub const fn supports_recursive_discovery(self) -> bool {
        matches!(self, Self::ClaudeCurrent)
    }
}

/// Bounded inputs for one native agent observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentLimits {
    pub max_document_bytes: usize,
    pub max_instructions_bytes: usize,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: 512 * 1024,
            max_instructions_bytes: crate::DEFAULT_MAX_AGENT_INSTRUCTIONS_BYTES,
        }
    }
}

/// Stable reason exact native semantics cannot enter the inert portable core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentBlockReason {
    UnsupportedConfiguration,
    UnsupportedMode,
}

/// Portable projection result retained alongside exact native evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentPortability {
    Portable(Agent),
    Blocked(AgentBlockReason),
}

/// One exact native definition plus its conservative portable projection.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedAgent {
    dialect: NativeAgentDialect,
    source_document: String,
    name: AgentName,
    exact_bytes: Vec<u8>,
    exact_hash: ContentHash,
    native_fields: BTreeSet<String>,
    portability: AgentPortability,
}

impl ObservedAgent {
    #[must_use]
    pub const fn dialect(&self) -> NativeAgentDialect {
        self.dialect
    }

    #[must_use]
    pub fn source_document(&self) -> &str {
        &self.source_document
    }

    #[must_use]
    pub const fn name(&self) -> &AgentName {
        &self.name
    }

    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    #[must_use]
    pub const fn exact_hash(&self) -> &ContentHash {
        &self.exact_hash
    }

    pub fn native_fields(&self) -> impl ExactSizeIterator<Item = &str> {
        self.native_fields.iter().map(String::as_str)
    }

    #[must_use]
    pub const fn content_class(&self) -> ContentClass {
        ContentClass::AgentActive
    }

    #[must_use]
    pub const fn portability(&self) -> &AgentPortability {
        &self.portability
    }
}

impl Debug for ObservedAgent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedAgent")
            .field("dialect", &self.dialect)
            .field("name", &self.name)
            .field("exact_byte_count", &self.exact_bytes.len())
            .field("exact_hash", &self.exact_hash)
            .field("native_field_count", &self.native_fields.len())
            .field("portability", &self.portability)
            .finish()
    }
}

/// Parses one exact native definition without launching a harness or evaluating its content.
pub fn parse_native_agent(
    dialect: NativeAgentDialect,
    document_name: &str,
    bytes: &[u8],
    limits: AgentLimits,
) -> Result<ObservedAgent, AgentError> {
    if bytes.len() > limits.max_document_bytes {
        return Err(native_error(
            "agent.document_limit",
            "native agent exceeds the configured document byte limit",
        ));
    }
    let source = std::str::from_utf8(bytes).map_err(|_| {
        native_error(
            "agent.document_utf8",
            "native agent must contain valid UTF-8",
        )
    })?;
    if source.contains('\0') {
        return Err(native_error(
            "agent.document_nul",
            "native agent must not contain NUL bytes",
        ));
    }

    validate_document_name(dialect, document_name)?;
    let parsed = match dialect {
        NativeAgentDialect::ClaudeCurrent | NativeAgentDialect::OpenCodeCurrent => {
            parse_markdown(dialect, document_name, source, limits)?
        }
        NativeAgentDialect::CodexCurrent => parse_codex(document_name, source, limits)?,
    };
    let exact_hash = hash_native(dialect, document_name, bytes);
    Ok(ObservedAgent {
        dialect,
        source_document: document_name.to_owned(),
        name: parsed.name,
        exact_bytes: bytes.to_vec(),
        exact_hash,
        native_fields: parsed.native_fields,
        portability: parsed.portability,
    })
}

struct ParsedAgent {
    name: AgentName,
    native_fields: BTreeSet<String>,
    portability: AgentPortability,
}

fn parse_markdown(
    dialect: NativeAgentDialect,
    document_name: &str,
    source: &str,
    limits: AgentLimits,
) -> Result<ParsedAgent, AgentError> {
    let parsed = parse_optional_observed_markdown(
        source,
        FlatFrontmatterLimits {
            max_bytes: MAX_FRONTMATTER_BYTES,
            max_fields: MAX_FRONTMATTER_FIELDS,
        },
    )
    .map_err(map_frontmatter_error)?;
    let fields: BTreeSet<String> = parsed.fields.keys().cloned().collect();
    let description = required_string(&parsed.fields, "description")?;
    let description = AgentDescription::parse(description)?;
    let instructions = AgentInstructions::parse(parsed.body, limits.max_instructions_bytes)?;

    let (name, projection_block) = match dialect {
        NativeAgentDialect::ClaudeCurrent => (
            AgentName::parse(required_string(&parsed.fields, "name")?)?,
            None,
        ),
        NativeAgentDialect::OpenCodeCurrent => {
            let name = AgentName::parse(direct_stem(document_name, ".md")?)?;
            let mode = parsed
                .fields
                .get("mode")
                .and_then(|value| observed_string(value).ok());
            let blocked =
                (mode.as_deref() != Some("subagent")).then_some(AgentBlockReason::UnsupportedMode);
            (name, blocked)
        }
        NativeAgentDialect::CodexCurrent => unreachable!("Codex uses TOML parsing"),
    };
    let expected: &[&str] = match dialect {
        NativeAgentDialect::ClaudeCurrent => &["description", "name"],
        NativeAgentDialect::OpenCodeCurrent => &["description", "mode"],
        NativeAgentDialect::CodexCurrent => unreachable!("Codex uses TOML parsing"),
    };
    let block = projection_block.or_else(|| {
        fields
            .iter()
            .any(|field| !expected.contains(&field.as_str()))
            .then_some(AgentBlockReason::UnsupportedConfiguration)
    });
    let agent = Agent::new(name.clone(), description, instructions);
    Ok(ParsedAgent {
        name,
        native_fields: fields,
        portability: block.map_or(AgentPortability::Portable(agent), AgentPortability::Blocked),
    })
}

fn parse_codex(
    document_name: &str,
    source: &str,
    limits: AgentLimits,
) -> Result<ParsedAgent, AgentError> {
    let _ = direct_stem(document_name, ".toml")?;
    let table: toml::Table = toml::from_str(source).map_err(|_| {
        native_error(
            "agent.toml_invalid",
            "Codex agent must be valid TOML with unique keys",
        )
    })?;
    let fields: BTreeSet<String> = table.keys().cloned().collect();
    let name = AgentName::parse(required_toml_string(&table, "name")?)?;
    let description = AgentDescription::parse(required_toml_string(&table, "description")?)?;
    let instructions = AgentInstructions::parse(
        required_toml_string(&table, "developer_instructions")?,
        limits.max_instructions_bytes,
    )?;
    let expected = ["description", "developer_instructions", "name"];
    let block = fields
        .iter()
        .any(|field| !expected.contains(&field.as_str()))
        .then_some(AgentBlockReason::UnsupportedConfiguration);
    let agent = Agent::new(name.clone(), description, instructions);
    Ok(ParsedAgent {
        name,
        native_fields: fields,
        portability: block.map_or(AgentPortability::Portable(agent), AgentPortability::Blocked),
    })
}

fn required_string(
    fields: &BTreeMap<String, ObservedFrontmatterValue<'_>>,
    name: &'static str,
) -> Result<String, AgentError> {
    fields
        .get(name)
        .ok_or_else(|| {
            native_error(
                "agent.required_field",
                "native agent is missing a required string field",
            )
        })
        .and_then(|value| observed_string(value))
}

fn observed_string(value: &ObservedFrontmatterValue<'_>) -> Result<String, AgentError> {
    let ObservedFrontmatterValue::Scalar(value) = value else {
        return Err(native_error(
            "agent.field_invalid",
            "native agent field must be a YAML string scalar",
        ));
    };
    parse_string_scalar(value)
}

fn parse_string_scalar(value: &str) -> Result<String, AgentError> {
    match serde::Deserialize::deserialize(yaml_serde::Deserializer::from_str(value)) {
        Ok(yaml_serde::Value::String(value)) => Ok(value),
        _ => Err(native_error(
            "agent.field_invalid",
            "native agent field must be a YAML string scalar",
        )),
    }
}

fn required_toml_string<'a>(
    table: &'a toml::Table,
    name: &'static str,
) -> Result<&'a str, AgentError> {
    table
        .get(name)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            native_error(
                "agent.required_field",
                "native agent is missing a required string field",
            )
        })
}

fn validate_document_name(
    dialect: NativeAgentDialect,
    document_name: &str,
) -> Result<(), AgentError> {
    if document_name.contains('\\')
        || document_name.starts_with('/')
        || document_name
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(native_error(
            "agent.document_name_invalid",
            "agent must use a validated relative document path",
        ));
    }
    let nested = document_name.contains('/');
    match dialect {
        NativeAgentDialect::ClaudeCurrent if document_name.ends_with(".md") => Ok(()),
        NativeAgentDialect::OpenCodeCurrent if !nested && document_name.ends_with(".md") => Ok(()),
        NativeAgentDialect::CodexCurrent if !nested && document_name.ends_with(".toml") => Ok(()),
        _ => Err(native_error(
            "agent.document_name_invalid",
            "agent document path or extension is unsupported by the selected dialect",
        )),
    }
}

fn direct_stem<'a>(document_name: &'a str, extension: &str) -> Result<&'a str, AgentError> {
    document_name.strip_suffix(extension).ok_or_else(|| {
        native_error(
            "agent.document_name_invalid",
            "agent document has an invalid extension",
        )
    })
}

fn map_frontmatter_error(error: FlatFrontmatterError) -> AgentError {
    match error {
        FlatFrontmatterError::ByteLimit | FlatFrontmatterError::FieldLimit => native_error(
            "agent.frontmatter_limit",
            "agent frontmatter exceeds a configured limit",
        ),
        FlatFrontmatterError::Unclosed => native_error(
            "agent.frontmatter_unclosed",
            "agent frontmatter is missing a closing delimiter",
        ),
        FlatFrontmatterError::Nested => native_error(
            "agent.frontmatter_nested",
            "agent frontmatter must contain only flat scalar fields",
        ),
        FlatFrontmatterError::Invalid => native_error(
            "agent.frontmatter_invalid",
            "agent frontmatter must contain simple named scalar fields",
        ),
        FlatFrontmatterError::DuplicateKey => native_error(
            "agent.frontmatter_duplicate_key",
            "agent frontmatter contains a duplicate field",
        ),
    }
}

fn hash_native(dialect: NativeAgentDialect, document_name: &str, bytes: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-agent-v1\0");
    hasher.update(&[match dialect {
        NativeAgentDialect::ClaudeCurrent => 0,
        NativeAgentDialect::CodexCurrent => 1,
        NativeAgentDialect::OpenCodeCurrent => 2,
    }]);
    hash_record(&mut hasher, document_name.as_bytes());
    hash_record(&mut hasher, bytes);
    digest(hasher)
}

const fn native_error(code: &'static str, message: &'static str) -> AgentError {
    AgentError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(
        dialect: NativeAgentDialect,
        document: &str,
        source: &str,
    ) -> Result<ObservedAgent, AgentError> {
        parse_native_agent(dialect, document, source.as_bytes(), AgentLimits::default())
    }

    #[test]
    fn inert_common_core_projects_for_all_supported_dialects() {
        let cases = [
            (
                NativeAgentDialect::ClaudeCurrent,
                "teams/review.md",
                "---\nname: code-review\ndescription: Review changes\n---\nReview carefully.\n",
            ),
            (
                NativeAgentDialect::OpenCodeCurrent,
                "code-review.md",
                "---\ndescription: Review changes\nmode: subagent\n---\nReview carefully.\n",
            ),
            (
                NativeAgentDialect::CodexCurrent,
                "code-review.toml",
                "name = \"code-review\"\ndescription = \"Review changes\"\ndeveloper_instructions = \"Review carefully.\\n\"\n",
            ),
        ];
        for (dialect, document, source) in cases {
            let observed = parse(dialect, document, source).unwrap();
            assert_eq!(observed.content_class(), ContentClass::AgentActive);
            let AgentPortability::Portable(agent) = observed.portability() else {
                panic!("inert {dialect:?} agent was blocked")
            };
            assert_eq!(agent.name().as_str(), "code-review");
            assert_eq!(agent.instructions().as_str(), "Review carefully.\n");
        }
    }

    #[test]
    fn authority_fields_and_non_subagent_modes_retain_evidence_and_block() {
        let cases = [
            (
                NativeAgentDialect::ClaudeCurrent,
                "review.md",
                "---\nname: review\ndescription: Review\nhooks:\n  Stop: *unresolved-alias\n---\nReview.\n",
                AgentBlockReason::UnsupportedConfiguration,
                "hooks",
            ),
            (
                NativeAgentDialect::OpenCodeCurrent,
                "review.md",
                "---\ndescription: Review\nmode: primary\n---\nReview.\n",
                AgentBlockReason::UnsupportedMode,
                "mode",
            ),
            (
                NativeAgentDialect::CodexCurrent,
                "review.toml",
                "name = \"review\"\ndescription = \"Review\"\ndeveloper_instructions = \"Review.\"\nmodel = \"powerful\"\n",
                AgentBlockReason::UnsupportedConfiguration,
                "model",
            ),
        ];
        for (dialect, document, source, reason, retained_field) in cases {
            let observed = parse(dialect, document, source).unwrap();
            assert_eq!(observed.portability(), &AgentPortability::Blocked(reason));
            assert!(
                observed
                    .native_fields()
                    .any(|field| field == retained_field)
            );
            assert_eq!(observed.exact_bytes(), source.as_bytes());
        }
    }

    #[test]
    fn markdown_frontmatter_refuses_structural_ambiguity() {
        for (source, code) in [
            (
                "---\nname: review\ndescription: &copy Review\n---\nReview.\n",
                "agent.field_invalid",
            ),
            (
                "---\nname: review\ndescription:\n  text: Review\n---\nReview.\n",
                "agent.field_invalid",
            ),
            (
                "---\nname: review\nname: other\ndescription: Review\n---\nReview.\n",
                "agent.frontmatter_duplicate_key",
            ),
            (
                "---\nname: review\ndescription: Review\n",
                "agent.frontmatter_unclosed",
            ),
        ] {
            assert_eq!(
                parse(NativeAgentDialect::ClaudeCurrent, "review.md", source)
                    .unwrap_err()
                    .code(),
                code
            );
        }
    }

    #[test]
    fn codex_duplicate_keys_and_unsupported_nested_paths_fail_closed() {
        assert_eq!(
            parse(
                NativeAgentDialect::CodexCurrent,
                "review.toml",
                "name = \"review\"\nname = \"other\"\ndescription = \"Review\"\ndeveloper_instructions = \"Review.\"\n",
            )
            .unwrap_err()
            .code(),
            "agent.toml_invalid"
        );
        for (dialect, document) in [
            (NativeAgentDialect::CodexCurrent, "nested/review.toml"),
            (NativeAgentDialect::OpenCodeCurrent, "nested/review.md"),
        ] {
            assert_eq!(
                parse(dialect, document, "unused").unwrap_err().code(),
                "agent.document_name_invalid"
            );
        }
    }

    #[test]
    fn exact_identity_and_debug_are_lossless_but_redacted() {
        let source = "---\nname: review\ndescription: SECRET-DESCRIPTION\n---\nSECRET-BODY\n";
        let original = parse(NativeAgentDialect::ClaudeCurrent, "review.md", source).unwrap();
        let changed = parse(
            NativeAgentDialect::ClaudeCurrent,
            "review.md",
            &source.replace("SECRET-BODY", "SECRET-BODY "),
        )
        .unwrap();
        assert_ne!(original.exact_hash(), changed.exact_hash());
        let debug = format!("{original:?}");
        assert!(!debug.contains("SECRET-DESCRIPTION"));
        assert!(!debug.contains("SECRET-BODY"));
    }
}
