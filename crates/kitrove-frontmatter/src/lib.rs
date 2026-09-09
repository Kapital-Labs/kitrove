#![forbid(unsafe_code)]
//! Bounded parsers for inert Markdown frontmatter envelopes.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Resource bounds for one flat frontmatter envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlatFrontmatterLimits {
    pub max_bytes: usize,
    pub max_fields: usize,
}

/// One Markdown document split into strict flat scalar frontmatter and its exact body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlatMarkdownDocument<'a> {
    pub fields: BTreeMap<String, &'a str>,
    pub body: &'a str,
}

/// A top-level value observed without deserializing its native YAML representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedFrontmatterValue<'a> {
    Scalar(&'a str),
    Complex,
}

/// One Markdown document with bounded top-level field evidence and its exact body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedMarkdownDocument<'a> {
    pub fields: BTreeMap<String, ObservedFrontmatterValue<'a>>,
    pub body: &'a str,
}

/// Stable structural failure from bounded frontmatter parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlatFrontmatterError {
    ByteLimit,
    FieldLimit,
    Unclosed,
    Nested,
    Invalid,
    DuplicateKey,
}

impl Display for FlatFrontmatterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ByteLimit => "frontmatter exceeds its byte limit",
            Self::FieldLimit => "frontmatter contains too many fields",
            Self::Unclosed => "frontmatter is missing a closing delimiter",
            Self::Nested => "frontmatter must contain only flat scalar fields",
            Self::Invalid => "frontmatter must contain simple named scalar fields",
            Self::DuplicateKey => "frontmatter contains a duplicate field",
        })
    }
}

impl Error for FlatFrontmatterError {}

/// Splits optional YAML frontmatter without materializing nested YAML or expanding aliases.
pub fn parse_optional_flat_markdown(
    source: &str,
    limits: FlatFrontmatterLimits,
) -> Result<FlatMarkdownDocument<'_>, FlatFrontmatterError> {
    let Some((frontmatter, body)) = split_optional_frontmatter(source, limits.max_bytes)? else {
        return Ok(FlatMarkdownDocument {
            fields: BTreeMap::new(),
            body: source,
        });
    };

    Ok(FlatMarkdownDocument {
        fields: parse_flat_fields(frontmatter, limits.max_fields)?,
        body,
    })
}

/// Observes top-level fields while retaining complex native values as blocked evidence.
///
/// Complex values are never materialized, aliases are never expanded, and callers must not treat
/// a `Complex` value as portable data.
pub fn parse_optional_observed_markdown(
    source: &str,
    limits: FlatFrontmatterLimits,
) -> Result<ObservedMarkdownDocument<'_>, FlatFrontmatterError> {
    let Some((frontmatter, body)) = split_optional_frontmatter(source, limits.max_bytes)? else {
        return Ok(ObservedMarkdownDocument {
            fields: BTreeMap::new(),
            body: source,
        });
    };

    Ok(ObservedMarkdownDocument {
        fields: parse_observed_fields(frontmatter, limits.max_fields)?,
        body,
    })
}

fn split_optional_frontmatter(
    source: &str,
    max_bytes: usize,
) -> Result<Option<(&str, &str)>, FlatFrontmatterError> {
    let opening_bytes = if source.starts_with("---\n") {
        4
    } else if source.starts_with("---\r\n") {
        5
    } else {
        return Ok(None);
    };

    let mut line_start = opening_bytes;
    while line_start <= source.len() {
        let remainder = &source[line_start..];
        let line_end = remainder
            .find('\n')
            .map_or(source.len(), |offset| line_start + offset);
        let line = source[line_start..line_end]
            .strip_suffix('\r')
            .unwrap_or(&source[line_start..line_end]);
        let after_line = usize::min(line_end.saturating_add(1), source.len());
        if line == "---" {
            let frontmatter = &source[opening_bytes..line_start];
            if frontmatter.len() > max_bytes {
                return Err(FlatFrontmatterError::ByteLimit);
            }
            return Ok(Some((frontmatter, &source[after_line..])));
        }
        if line_end == source.len() {
            break;
        }
        line_start = after_line;
    }
    Err(FlatFrontmatterError::Unclosed)
}

fn parse_observed_fields(
    source: &str,
    max_fields: usize,
) -> Result<BTreeMap<String, ObservedFrontmatterValue<'_>>, FlatFrontmatterError> {
    let mut fields = BTreeMap::new();
    let mut current_key: Option<String> = None;
    for raw_line in source.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            let Some(key) = current_key.as_ref() else {
                return Err(FlatFrontmatterError::Invalid);
            };
            fields.insert(key.clone(), ObservedFrontmatterValue::Complex);
            continue;
        }
        let Some((key, scalar)) = line.split_once(':') else {
            return Err(FlatFrontmatterError::Invalid);
        };
        if !valid_field_name(key) {
            return Err(FlatFrontmatterError::Invalid);
        }
        if fields.len() >= max_fields {
            return Err(FlatFrontmatterError::FieldLimit);
        }
        let scalar = scalar.trim_start();
        let value = if scalar.is_empty() || complex_yaml_scalar(scalar) {
            ObservedFrontmatterValue::Complex
        } else {
            ObservedFrontmatterValue::Scalar(scalar)
        };
        if fields.insert(key.to_owned(), value).is_some() {
            return Err(FlatFrontmatterError::DuplicateKey);
        }
        current_key = Some(key.to_owned());
    }
    Ok(fields)
}

fn parse_flat_fields(
    source: &str,
    max_fields: usize,
) -> Result<BTreeMap<String, &str>, FlatFrontmatterError> {
    let mut fields = BTreeMap::new();
    for raw_line in source.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            return Err(FlatFrontmatterError::Nested);
        }
        let Some((key, scalar)) = line.split_once(':') else {
            return Err(FlatFrontmatterError::Invalid);
        };
        if !valid_field_name(key) || scalar.trim().is_empty() {
            return Err(FlatFrontmatterError::Invalid);
        }
        if fields.len() >= max_fields {
            return Err(FlatFrontmatterError::FieldLimit);
        }
        let scalar = scalar.trim_start();
        if complex_yaml_scalar(scalar) {
            return Err(FlatFrontmatterError::Nested);
        }
        if fields.insert(key.to_owned(), scalar).is_some() {
            return Err(FlatFrontmatterError::DuplicateKey);
        }
    }
    Ok(fields)
}

fn valid_field_name(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn complex_yaml_scalar(value: &str) -> bool {
    matches!(
        value.as_bytes().first(),
        Some(b'&' | b'*' | b'!' | b'|' | b'>' | b'[' | b'{')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: FlatFrontmatterLimits = FlatFrontmatterLimits {
        max_bytes: 128,
        max_fields: 3,
    };

    #[test]
    fn preserves_exact_body_and_scalar_source() {
        let parsed = parse_optional_flat_markdown(
            "---\r\ndescription: 'Review carefully'\r\nmode: subagent\r\n---\r\nBody\r\n",
            LIMITS,
        )
        .unwrap();

        assert_eq!(parsed.fields["description"], "'Review carefully'");
        assert_eq!(parsed.fields["mode"], "subagent");
        assert_eq!(parsed.body, "Body\r\n");
    }

    #[test]
    fn absent_frontmatter_keeps_the_whole_document_as_body() {
        let parsed = parse_optional_flat_markdown("Body\n", LIMITS).unwrap();
        assert!(parsed.fields.is_empty());
        assert_eq!(parsed.body, "Body\n");
    }

    #[test]
    fn rejects_structural_ambiguity_without_parsing_yaml() {
        for (source, expected) in [
            (
                "---\nvalue: &anchor text\n---\n",
                FlatFrontmatterError::Nested,
            ),
            (
                "---\nvalue:\n  nested: text\n---\n",
                FlatFrontmatterError::Invalid,
            ),
            (
                "---\nvalue: one\nvalue: two\n---\n",
                FlatFrontmatterError::DuplicateKey,
            ),
            ("---\nvalue: one\n", FlatFrontmatterError::Unclosed),
        ] {
            assert_eq!(parse_optional_flat_markdown(source, LIMITS), Err(expected));
        }
    }

    #[test]
    fn observed_mode_retains_complex_top_level_fields_without_materializing_them() {
        let parsed = parse_optional_observed_markdown(
            "---\nname: review\nhooks:\n  Stop: *unresolved-alias\npermissions: {shell: deny}\n---\nBody\n",
            LIMITS,
        )
        .unwrap();

        assert_eq!(
            parsed.fields["name"],
            ObservedFrontmatterValue::Scalar("review")
        );
        assert_eq!(parsed.fields["hooks"], ObservedFrontmatterValue::Complex);
        assert_eq!(
            parsed.fields["permissions"],
            ObservedFrontmatterValue::Complex
        );
        assert_eq!(parsed.body, "Body\n");
    }

    #[test]
    fn enforces_byte_and_field_limits() {
        assert_eq!(
            parse_optional_flat_markdown(
                &format!("---\nvalue: {}\n---\n", "x".repeat(129)),
                LIMITS,
            ),
            Err(FlatFrontmatterError::ByteLimit)
        );
        assert_eq!(
            parse_optional_flat_markdown("---\na: 1\nb: 2\nc: 3\nd: 4\n---\n", LIMITS),
            Err(FlatFrontmatterError::FieldLimit)
        );
    }
}
