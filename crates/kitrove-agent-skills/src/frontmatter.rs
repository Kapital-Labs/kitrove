#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};

use crate::{BoundedYamlValue, ObservedSkillDocument, SkillError};

const MAX_SKILL_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_YAML_DEPTH: usize = 64;
const MAX_YAML_NODES: usize = 4_096;
const MAX_YAML_ALIAS_EXPANDED_NODES: usize = 4_096;

/// The standard Agent Skills fields extracted from a parsed `SKILL.md` document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillManifest {
    pub name: kitrove_model::AssetId,
    pub description: String,
    pub license: Option<String>,
    pub compatibility: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub allowed_tools: Option<String>,
}

/// A `SKILL.md` split into standard fields, its exact body, and native field names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedSkillDocument {
    pub manifest: SkillManifest,
    pub body: String,
    pub native_fields: BTreeSet<String>,
}

/// Parses and validates an Agent Skills `SKILL.md` document.
pub fn parse_skill_document(path: &Path, bytes: &[u8]) -> Result<ParsedSkillDocument, SkillError> {
    let observed = parse_observed_skill_document(path, bytes)?;
    if !starts_frontmatter_delimiter(bytes) {
        return Err(SkillError::new(
            "skill.frontmatter_missing",
            path,
            "skill document must begin with a frontmatter delimiter",
        ));
    }

    let name = observed.declared_name.ok_or_else(|| {
        SkillError::new(
            "skill.name_invalid",
            path,
            "required field must be a string",
        )
    })?;
    if !is_standard_skill_name(&name) {
        return Err(SkillError::new(
            "skill.name_invalid",
            path,
            "name must be a lowercase hyphenated identifier no longer than 64 bytes",
        ));
    }
    let name = kitrove_model::AssetId::parse(name).map_err(|_| {
        SkillError::new(
            "skill.name_invalid",
            path,
            "name must be a valid asset identifier",
        )
    })?;

    let description = observed.description.ok_or_else(|| {
        SkillError::new(
            "skill.description_invalid",
            path,
            "required field must be a string",
        )
    })?;
    if !is_standard_skill_description(&description) {
        return Err(SkillError::new(
            "skill.description_invalid",
            path,
            "description must contain between 1 and 1,024 characters",
        ));
    }

    let license = observed.license;
    if observed.frontmatter.contains_key("license") && license.is_none() {
        return Err(SkillError::new(
            "skill.frontmatter_invalid",
            path,
            "frontmatter must be valid YAML with string top-level keys",
        ));
    }
    let compatibility = observed.compatibility;
    if observed.frontmatter.contains_key("compatibility") && compatibility.is_none() {
        return Err(SkillError::new(
            "skill.compatibility_invalid",
            path,
            "optional field must be a string",
        ));
    }
    if compatibility
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.chars().count() > 500)
    {
        return Err(SkillError::new(
            "skill.compatibility_invalid",
            path,
            "compatibility must contain between 1 and 500 characters when present",
        ));
    }
    let metadata = match observed.metadata {
        Some(metadata) => metadata,
        None if observed.frontmatter.contains_key("metadata") => {
            return Err(SkillError::new(
                "skill.metadata_invalid",
                path,
                "metadata must be a mapping of string keys to string values",
            ));
        }
        None => BTreeMap::new(),
    };
    reject_secret_metadata_keys(path, &metadata)?;

    let allowed_tools = observed.allowed_tools;
    if observed.frontmatter.contains_key("allowed-tools") && allowed_tools.is_none() {
        return Err(SkillError::new(
            "skill.frontmatter_invalid",
            path,
            "frontmatter must be valid YAML with string top-level keys",
        ));
    }

    Ok(ParsedSkillDocument {
        manifest: SkillManifest {
            name,
            description,
            license,
            compatibility,
            metadata,
            allowed_tools,
        },
        body: observed.body,
        native_fields: observed.native_fields,
    })
}

/// Parses a skill document while retaining native frontmatter and allowing absent portable fields.
pub fn parse_observed_skill_document(
    path: &Path,
    bytes: &[u8],
) -> Result<ObservedSkillDocument, SkillError> {
    if bytes.len() > MAX_SKILL_DOCUMENT_BYTES {
        return Err(SkillError::new(
            "skill.document_size_limit",
            path,
            format!("skill document exceeds the {MAX_SKILL_DOCUMENT_BYTES} byte limit"),
        ));
    }
    let source = std::str::from_utf8(bytes).map_err(|_| {
        SkillError::new(
            "skill.frontmatter_invalid",
            path,
            "skill document must be valid UTF-8",
        )
    })?;
    let (frontmatter, body) = match split_frontmatter(path, source) {
        Ok(parts) => parts,
        Err(error)
            if error.code() == "skill.frontmatter_missing"
                && !starts_frontmatter_delimiter(source.as_bytes()) =>
        {
            return Ok(ObservedSkillDocument {
                frontmatter: BTreeMap::new(),
                declared_name: None,
                description: None,
                license: None,
                compatibility: None,
                metadata: None,
                allowed_tools: None,
                body: source.to_owned(),
                native_fields: BTreeSet::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let mut observed = parse_frontmatter(path, frontmatter)?;
    observed.body = body.to_owned();
    Ok(observed)
}

fn split_frontmatter<'a>(path: &Path, source: &'a str) -> Result<(&'a str, &'a str), SkillError> {
    let frontmatter_start = if source.starts_with("---\n") {
        4
    } else if source.starts_with("---\r\n") {
        5
    } else {
        return Err(SkillError::new(
            "skill.frontmatter_missing",
            path,
            "skill document must begin with a frontmatter delimiter",
        ));
    };

    let mut line_start = frontmatter_start;
    while line_start <= source.len() {
        let remainder = &source[line_start..];
        let line_end = remainder
            .find('\n')
            .map_or(source.len(), |offset| line_start + offset);
        let line = source[line_start..line_end]
            .strip_suffix('\r')
            .unwrap_or(&source[line_start..line_end]);
        let after_line = if line_end == source.len() {
            line_end
        } else {
            line_end + 1
        };

        if line == "---" {
            return Ok((
                &source[frontmatter_start..line_start],
                &source[after_line..],
            ));
        }
        if line_end == source.len() {
            break;
        }
        line_start = after_line;
    }

    Err(SkillError::new(
        "skill.frontmatter_missing",
        path,
        "skill document is missing a closing frontmatter delimiter",
    ))
}

fn starts_frontmatter_delimiter(bytes: &[u8]) -> bool {
    bytes.starts_with(b"---\n") || bytes.starts_with(b"---\r\n")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrontmatterFailure {
    DuplicateTopLevelKey,
    DuplicateMetadataKey,
    DuplicateMappingKey,
    NonStringTopLevelKey,
    InvalidMetadata,
    DepthLimit,
    NodeLimit,
    AliasLimit,
}

#[derive(Clone, Copy)]
struct YamlBudget<'a> {
    nodes: &'a Cell<usize>,
    failure: &'a Cell<Option<FrontmatterFailure>>,
    aliases_present: bool,
}

impl YamlBudget<'_> {
    fn claim<E: de::Error>(self, depth: usize) -> Result<(), E> {
        if depth > MAX_YAML_DEPTH {
            self.failure.set(Some(FrontmatterFailure::DepthLimit));
            return Err(E::custom("YAML nesting limit exceeded"));
        }

        let nodes = self.nodes.get().saturating_add(1);
        self.nodes.set(nodes);
        let node_limit = if self.aliases_present {
            MAX_YAML_ALIAS_EXPANDED_NODES
        } else {
            MAX_YAML_NODES
        };
        if nodes > node_limit {
            self.failure.set(Some(if self.aliases_present {
                FrontmatterFailure::AliasLimit
            } else {
                FrontmatterFailure::NodeLimit
            }));
            return Err(E::custom("YAML node limit exceeded"));
        }
        Ok(())
    }
}

fn parse_frontmatter(path: &Path, source: &str) -> Result<ObservedSkillDocument, SkillError> {
    let failure = Cell::new(None);
    let nodes = Cell::new(0);
    let budget = YamlBudget {
        nodes: &nodes,
        failure: &failure,
        // Alias targets are charged against the node budget every time they are expanded by
        // the deserializer. Exhausting that expanded budget receives its own stable error code.
        aliases_present: contains_yaml_alias_reference(source),
    };
    let deserializer = yaml_serde::Deserializer::from_str(source);

    FrontmatterSeed { budget }
        .deserialize(deserializer)
        .map_err(|_| frontmatter_error(path, failure.get()))
}

fn frontmatter_error(path: &Path, failure: Option<FrontmatterFailure>) -> SkillError {
    match failure {
        Some(FrontmatterFailure::DuplicateTopLevelKey) => SkillError::new(
            "skill.frontmatter_duplicate_key",
            path,
            "frontmatter contains duplicate top-level keys",
        ),
        Some(FrontmatterFailure::DuplicateMetadataKey) => SkillError::new(
            "skill.metadata_duplicate_key",
            path,
            "metadata contains duplicate keys",
        ),
        Some(FrontmatterFailure::DuplicateMappingKey) => SkillError::new(
            "skill.frontmatter_duplicate_key",
            path,
            "frontmatter contains duplicate mapping keys",
        ),
        Some(FrontmatterFailure::InvalidMetadata) => SkillError::new(
            "skill.metadata_invalid",
            path,
            "metadata must be a mapping of string keys to string values",
        ),
        Some(FrontmatterFailure::DepthLimit) => SkillError::new(
            "skill.frontmatter_depth_limit",
            path,
            format!("frontmatter exceeds the {MAX_YAML_DEPTH} level nesting limit"),
        ),
        Some(FrontmatterFailure::NodeLimit) => SkillError::new(
            "skill.frontmatter_node_limit",
            path,
            format!("frontmatter exceeds the {MAX_YAML_NODES} node limit"),
        ),
        Some(FrontmatterFailure::AliasLimit) => SkillError::new(
            "skill.frontmatter_alias_limit",
            path,
            format!(
                "frontmatter aliases exceed the {MAX_YAML_ALIAS_EXPANDED_NODES} expanded-node limit"
            ),
        ),
        Some(FrontmatterFailure::NonStringTopLevelKey) | None => SkillError::new(
            "skill.frontmatter_invalid",
            path,
            "frontmatter must be valid YAML with string top-level keys",
        ),
    }
}

struct FrontmatterSeed<'a> {
    budget: YamlBudget<'a>,
}

impl<'de> DeserializeSeed<'de> for FrontmatterSeed<'_> {
    type Value = ObservedSkillDocument;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.claim(0)?;
        deserializer.deserialize_map(FrontmatterVisitor {
            budget: self.budget,
        })
    }
}

struct FrontmatterVisitor<'a> {
    budget: YamlBudget<'a>,
}

impl<'de> Visitor<'de> for FrontmatterVisitor<'_> {
    type Value = ObservedSkillDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a mapping with unique string keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut frontmatter = BTreeMap::new();
        let mut native_fields = BTreeSet::new();
        let mut keys = BTreeSet::new();
        loop {
            let key = match map.next_key_seed(YamlStringSeed {
                budget: self.budget,
                depth: 1,
            }) {
                Ok(key) => key,
                Err(error) => {
                    if self.budget.failure.get().is_none() {
                        self.budget
                            .failure
                            .set(Some(FrontmatterFailure::NonStringTopLevelKey));
                    }
                    return Err(error);
                }
            };
            let Some(key) = key else {
                break;
            };
            if !keys.insert(key.clone()) {
                self.budget
                    .failure
                    .set(Some(FrontmatterFailure::DuplicateTopLevelKey));
                return Err(de::Error::custom("duplicate top-level key"));
            }

            let duplicate_failure = if key == "metadata" {
                FrontmatterFailure::DuplicateMetadataKey
            } else {
                FrontmatterFailure::DuplicateMappingKey
            };
            let value = map.next_value_seed(YamlBoundedSeed {
                budget: self.budget,
                depth: 1,
                duplicate_failure,
            })?;
            if !is_standard_field(&key) {
                native_fields.insert(key.clone());
            }
            frontmatter.insert(key, value);
        }
        let declared_name = string_field(&frontmatter, "name");
        let description = string_field(&frontmatter, "description");
        let license = string_field(&frontmatter, "license");
        let compatibility = string_field(&frontmatter, "compatibility");
        let metadata = string_mapping_field(&frontmatter, "metadata");
        let allowed_tools = string_field(&frontmatter, "allowed-tools");

        Ok(ObservedSkillDocument {
            frontmatter,
            declared_name,
            description,
            license,
            compatibility,
            metadata,
            allowed_tools,
            body: String::new(),
            native_fields,
        })
    }
}

fn is_standard_field(key: &str) -> bool {
    matches!(
        key,
        "name" | "description" | "license" | "compatibility" | "metadata" | "allowed-tools"
    )
}

fn string_field(frontmatter: &BTreeMap<String, BoundedYamlValue>, key: &str) -> Option<String> {
    match frontmatter.get(key) {
        Some(BoundedYamlValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn string_mapping_field(
    frontmatter: &BTreeMap<String, BoundedYamlValue>,
    key: &str,
) -> Option<BTreeMap<String, String>> {
    let BoundedYamlValue::Mapping(mapping) = frontmatter.get(key)? else {
        return None;
    };
    mapping
        .iter()
        .map(|(key, value)| match value {
            BoundedYamlValue::String(value) => Some((key.clone(), value.clone())),
            _ => None,
        })
        .collect()
}

struct YamlStringSeed<'a> {
    budget: YamlBudget<'a>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for YamlStringSeed<'_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.claim(self.depth)?;
        deserializer.deserialize_any(YamlStringVisitor)
    }
}

struct YamlStringVisitor;

impl Visitor<'_> for YamlStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(value)
    }
}

struct YamlBoundedSeed<'a> {
    budget: YamlBudget<'a>,
    depth: usize,
    duplicate_failure: FrontmatterFailure,
}

impl<'de> DeserializeSeed<'de> for YamlBoundedSeed<'_> {
    type Value = BoundedYamlValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.claim(self.depth)?;
        deserializer.deserialize_any(YamlBoundedVisitor {
            budget: self.budget,
            depth: self.depth,
            duplicate_failure: self.duplicate_failure,
        })
    }
}

struct YamlBoundedVisitor<'a> {
    budget: YamlBudget<'a>,
    depth: usize,
    duplicate_failure: FrontmatterFailure,
}

impl<'de> Visitor<'de> for YamlBoundedVisitor<'_> {
    type Value = BoundedYamlValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded YAML value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Boolean(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Number(value.to_string()))
    }

    fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Number(value.to_string()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Number(value.to_string()))
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Number(value.to_string()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Number(value.to_string()))
    }

    fn visit_char<E>(self, value: char) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::String(value.to_string()))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(BoundedYamlValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::String(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(BoundedYamlValue::String(
            String::from_utf8_lossy(value).into_owned(),
        ))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::String(
            String::from_utf8_lossy(&value).into_owned(),
        ))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        YamlBoundedSeed {
            budget: self.budget,
            depth: self.depth.saturating_add(1),
            duplicate_failure: FrontmatterFailure::DuplicateMappingKey,
        }
        .deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(BoundedYamlValue::Null)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        YamlBoundedSeed {
            budget: self.budget,
            depth: self.depth.saturating_add(1),
            duplicate_failure: FrontmatterFailure::DuplicateMappingKey,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(YamlBoundedSeed {
            budget: self.budget,
            depth: self.depth.saturating_add(1),
            duplicate_failure: FrontmatterFailure::DuplicateMappingKey,
        })? {
            values.push(value);
        }
        Ok(BoundedYamlValue::Sequence(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        loop {
            let key = match map.next_key_seed(YamlStringSeed {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
            }) {
                Ok(key) => key,
                Err(error) => {
                    if self.budget.failure.get().is_none()
                        && self.duplicate_failure == FrontmatterFailure::DuplicateMetadataKey
                    {
                        self.budget
                            .failure
                            .set(Some(FrontmatterFailure::InvalidMetadata));
                    }
                    return Err(error);
                }
            };
            let Some(key) = key else {
                break;
            };
            let vacant = match values.entry(key) {
                std::collections::btree_map::Entry::Occupied(_) => {
                    self.budget.failure.set(Some(self.duplicate_failure));
                    return Err(de::Error::custom("duplicate mapping key"));
                }
                std::collections::btree_map::Entry::Vacant(vacant) => vacant,
            };
            let value = map.next_value_seed(YamlBoundedSeed {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
                duplicate_failure: FrontmatterFailure::DuplicateMappingKey,
            })?;
            vacant.insert(value);
        }
        Ok(BoundedYamlValue::Mapping(values))
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (name, variant) = data.variant_seed(YamlStringSeed {
            budget: self.budget,
            depth: self.depth.saturating_add(1),
        })?;
        let value = variant.newtype_variant_seed(YamlBoundedSeed {
            budget: self.budget,
            depth: self.depth.saturating_add(1),
            duplicate_failure: FrontmatterFailure::DuplicateMappingKey,
        })?;
        Ok(BoundedYamlValue::Mapping(
            [(name, value)].into_iter().collect(),
        ))
    }
}

#[derive(Clone, Copy)]
struct YamlBlockScalar {
    parent_indent: usize,
    content_indent: Option<usize>,
}

impl YamlBlockScalar {
    fn consumes(&mut self, line: &[u8]) -> bool {
        if line.iter().all(u8::is_ascii_whitespace) {
            return true;
        }

        let indent = line.iter().take_while(|byte| **byte == b' ').count();
        match self.content_indent {
            Some(content_indent) => indent >= content_indent,
            None if indent > self.parent_indent => {
                self.content_indent = Some(indent);
                true
            }
            None => false,
        }
    }
}

#[derive(Clone, Copy)]
struct YamlBlockHeader {
    parent_indent: usize,
    explicit_indent: Option<usize>,
}

enum YamlLineScan {
    Alias,
    BlockScalar(YamlBlockHeader),
    Neither,
}

fn contains_yaml_alias_reference(source: &str) -> bool {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut block_scalar: Option<YamlBlockScalar> = None;

    for line in source.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line).as_bytes();
        if let Some(active) = block_scalar.as_mut() {
            if active.consumes(line) {
                continue;
            }
            block_scalar = None;
        }

        match scan_yaml_line(line, &mut in_single_quote, &mut in_double_quote) {
            YamlLineScan::Alias => return true,
            YamlLineScan::BlockScalar(header) => {
                block_scalar = Some(YamlBlockScalar {
                    parent_indent: header.parent_indent,
                    content_indent: header
                        .explicit_indent
                        .map(|indent| header.parent_indent.saturating_add(indent)),
                });
            }
            YamlLineScan::Neither => {}
        }
    }
    false
}

fn scan_yaml_line(
    bytes: &[u8],
    in_single_quote: &mut bool,
    in_double_quote: &mut bool,
) -> YamlLineScan {
    let (sequence_parent_indent, mapping_key_indent) = yaml_line_indents(bytes);
    let mut mapping_value_indent = None;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if *in_single_quote {
            if byte == b'\'' {
                if bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                *in_single_quote = false;
            }
            index += 1;
            continue;
        }
        if *in_double_quote {
            if byte == b'\\' {
                index = index.saturating_add(2);
                continue;
            }
            if byte == b'"' {
                *in_double_quote = false;
            }
            index += 1;
            continue;
        }

        match byte {
            b'\'' => *in_single_quote = true,
            b'"' => *in_double_quote = true,
            b'#' if index == 0 || bytes[index - 1].is_ascii_whitespace() => {
                return YamlLineScan::Neither;
            }
            b':' if index >= mapping_key_indent
                && bytes
                    .get(index + 1)
                    .is_none_or(|next| next.is_ascii_whitespace()) =>
            {
                mapping_value_indent = Some(mapping_key_indent);
            }
            b'*' if (index == 0
                || bytes[index - 1].is_ascii_whitespace()
                || matches!(bytes[index - 1], b'[' | b'{' | b',' | b':' | b'?' | b'-'))
                && bytes.get(index + 1).is_some_and(|next| {
                    !next.is_ascii_whitespace() && !matches!(next, b',' | b'[' | b']' | b'{' | b'}')
                }) =>
            {
                return YamlLineScan::Alias;
            }
            b'|' | b'>' if index == 0 || bytes[index - 1].is_ascii_whitespace() => {
                let parent_indent = mapping_value_indent.unwrap_or(sequence_parent_indent);
                if let Some(header) = parse_yaml_block_header(&bytes[index + 1..], parent_indent) {
                    return YamlLineScan::BlockScalar(header);
                }
            }
            _ => {}
        }
        index += 1;
    }
    YamlLineScan::Neither
}

fn yaml_line_indents(bytes: &[u8]) -> (usize, usize) {
    // A compact sequence mapping starts its key after each leading `- `, while a
    // bare sequence scalar remains relative to the innermost sequence indicator.
    let line_indent = bytes.iter().take_while(|byte| **byte == b' ').count();
    let mut sequence_parent_indent = line_indent;
    let mut cursor = line_indent;
    while bytes.get(cursor) == Some(&b'-')
        && bytes
            .get(cursor + 1)
            .is_some_and(|next| next.is_ascii_whitespace())
    {
        sequence_parent_indent = cursor;
        cursor += 1;
        while bytes
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            cursor += 1;
        }
    }
    (sequence_parent_indent, cursor)
}

fn parse_yaml_block_header(mut suffix: &[u8], parent_indent: usize) -> Option<YamlBlockHeader> {
    let mut explicit_indent = None;
    let mut chomping_indicator = false;
    for _ in 0..2 {
        match suffix.first().copied() {
            Some(b'1'..=b'9') if explicit_indent.is_none() => {
                explicit_indent = Some(usize::from(suffix[0] - b'0'));
                suffix = &suffix[1..];
            }
            Some(b'+' | b'-') if !chomping_indicator => {
                chomping_indicator = true;
                suffix = &suffix[1..];
            }
            _ => break,
        }
    }

    if suffix
        .first()
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        return None;
    }
    suffix = suffix.trim_ascii_start();
    if suffix.is_empty() || suffix.starts_with(b"#") {
        Some(YamlBlockHeader {
            parent_indent,
            explicit_indent,
        })
    } else {
        None
    }
}

pub(crate) fn reject_secret_metadata_keys(
    path: &Path,
    metadata: &BTreeMap<String, String>,
) -> Result<(), SkillError> {
    if metadata.keys().any(|key| secret_metadata_key(key)) {
        return Err(SkillError::new(
            "skill.credential_metadata",
            path,
            "secret-like metadata keys are not eligible for portable projection",
        ));
    }
    Ok(())
}

/// Metadata keys are split into ASCII case-folded components at hyphens, underscores, and ASCII
/// whitespace. Bare credential concepts remain exact after separator removal for compatibility
/// with conventional spellings such as `pass-word`; compound keys are refused only when their
/// final component is a credential concept or their final pair is `api key` or `private key`.
/// This recognizes conventional prefixes without substring matches such as `tokenizer`.
fn secret_metadata_key(key: &str) -> bool {
    let components: Vec<String> = key
        .split(|character: char| character.is_ascii_whitespace() || matches!(character, '-' | '_'))
        .filter(|component| !component.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let compact = components.concat();
    if matches!(
        compact.as_str(),
        "token"
            | "tokens"
            | "secret"
            | "secrets"
            | "password"
            | "passwords"
            | "credential"
            | "credentials"
            | "privatekey"
            | "privatekeys"
            | "apikey"
            | "apikeys"
    ) {
        return true;
    }

    if components
        .last()
        .is_some_and(|component| terminal_credential_concept(component))
    {
        return true;
    }

    matches!(
        components.as_slice(),
        [.., qualifier, key]
            if matches!(qualifier.as_str(), "api" | "private")
                && matches!(key.as_str(), "key" | "keys")
    )
}

fn terminal_credential_concept(component: &str) -> bool {
    matches!(
        component,
        "token"
            | "tokens"
            | "secret"
            | "secrets"
            | "password"
            | "passwords"
            | "credential"
            | "credentials"
    )
}

/// Returns whether a value satisfies the standard Agent Skills `name` grammar.
#[must_use]
pub fn is_standard_skill_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && !value.contains("--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Returns whether a value satisfies the standard Agent Skills `description` bounds.
#[must_use]
pub fn is_standard_skill_description(value: &str) -> bool {
    (1..=1_024).contains(&value.chars().count())
}
