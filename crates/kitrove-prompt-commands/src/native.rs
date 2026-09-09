use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

use kitrove_frontmatter::{
    FlatFrontmatterError, FlatFrontmatterLimits, parse_optional_flat_markdown,
};
use kitrove_model::{ContentClass, ContentHash};
use serde::{Deserialize, Serialize};

use crate::{
    ALL_ARGUMENTS_PLACEHOLDER, PromptArgumentMode, PromptBody, PromptCommand, PromptCommandError,
    PromptCommandName, PromptDescription,
};

const MAX_FRONTMATTER_BYTES: usize = 16 * 1024;
const MAX_FRONTMATTER_FIELDS: usize = 64;

/// Native prompt-command syntax selected by compiled adapter policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePromptDialect {
    ClaudeLegacy,
    PiLatest,
    OpenCodeV2,
}

impl NativePromptDialect {
    /// Whether the harness supplies invocation arguments without an explicit placeholder.
    #[must_use]
    pub const fn appends_implicit_arguments(self) -> bool {
        matches!(self, Self::OpenCodeV2)
    }
}

/// Bounded inputs for one native prompt-command observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromptCommandLimits {
    pub max_document_bytes: usize,
    pub max_body_bytes: usize,
}

impl Default for PromptCommandLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: 512 * 1024,
            max_body_bytes: crate::DEFAULT_MAX_PROMPT_BODY_BYTES,
        }
    }
}

/// Stable reason a native command cannot enter the v1 portable core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptCommandBlockReason {
    NestedDocument,
    ExecutableInterpolation,
    FileInterpolation,
    UnsupportedFrontmatter,
    UnsupportedArguments,
    ImplicitArguments,
    InvalidBody,
}

/// Portable projection result retained alongside exact native evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptCommandPortability {
    Portable(PromptCommand),
    Blocked(PromptCommandBlockReason),
}

/// One exact native command plus a conservative portable projection decision.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedPromptCommand {
    dialect: NativePromptDialect,
    source_document: String,
    name: PromptCommandName,
    exact_bytes: Vec<u8>,
    exact_hash: ContentHash,
    frontmatter_fields: BTreeSet<String>,
    content_class: ContentClass,
    portability: PromptCommandPortability,
}

impl ObservedPromptCommand {
    #[must_use]
    pub const fn dialect(&self) -> NativePromptDialect {
        self.dialect
    }

    #[must_use]
    pub fn source_document(&self) -> &str {
        &self.source_document
    }

    #[must_use]
    pub const fn name(&self) -> &PromptCommandName {
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

    pub fn frontmatter_fields(&self) -> impl ExactSizeIterator<Item = &str> {
        self.frontmatter_fields.iter().map(String::as_str)
    }

    #[must_use]
    pub const fn content_class(&self) -> ContentClass {
        self.content_class
    }

    #[must_use]
    pub const fn portability(&self) -> &PromptCommandPortability {
        &self.portability
    }
}

impl Debug for ObservedPromptCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedPromptCommand")
            .field("dialect", &self.dialect)
            .field("name", &self.name)
            .field("exact_byte_count", &self.exact_bytes.len())
            .field("exact_hash", &self.exact_hash)
            .field("frontmatter_field_count", &self.frontmatter_fields.len())
            .field("content_class", &self.content_class)
            .field("portability", &self.portability)
            .finish()
    }
}

struct ParsedDocument<'a> {
    description: Option<PromptDescription>,
    fields: BTreeSet<String>,
    body: &'a str,
}

/// Parses an exact Markdown command without evaluating native syntax.
pub fn parse_native_prompt_command(
    dialect: NativePromptDialect,
    document_name: &str,
    bytes: &[u8],
    limits: PromptCommandLimits,
) -> Result<ObservedPromptCommand, PromptCommandError> {
    if bytes.len() > limits.max_document_bytes {
        return Err(native_error(
            "prompt_command.document_limit",
            "native prompt command exceeds the configured document byte limit",
        ));
    }
    let source = std::str::from_utf8(bytes).map_err(|_| {
        native_error(
            "prompt_command.document_utf8",
            "native prompt command must contain valid UTF-8",
        )
    })?;
    if source.contains('\0') {
        return Err(native_error(
            "prompt_command.document_nul",
            "native prompt command must not contain NUL bytes",
        ));
    }

    let (name, nested) = command_name_from_document(document_name)?;
    let parsed = parse_document(source)?;
    let exact_hash = hash_native(dialect, document_name, bytes);
    let execution = recognizes_shell_interpolation(dialect, parsed.body);
    let content_class = if execution {
        ContentClass::Executable
    } else {
        ContentClass::AgentActive
    };
    let portability = if nested {
        PromptCommandPortability::Blocked(PromptCommandBlockReason::NestedDocument)
    } else {
        project_portable(dialect, &name, &parsed, limits.max_body_bytes, execution)
    };

    Ok(ObservedPromptCommand {
        dialect,
        source_document: document_name.to_owned(),
        name,
        exact_bytes: bytes.to_vec(),
        exact_hash,
        frontmatter_fields: parsed.fields,
        content_class,
        portability,
    })
}

fn command_name_from_document(
    document_name: &str,
) -> Result<(PromptCommandName, bool), PromptCommandError> {
    if document_name.contains('\\')
        || document_name.starts_with('/')
        || document_name
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(native_error(
            "prompt_command.document_name_invalid",
            "prompt command must use a validated relative Markdown document path",
        ));
    }
    let (name, nested) = document_name
        .rsplit_once('/')
        .map_or((document_name, false), |(_, name)| (name, true));
    let Some(name) = name.strip_suffix(".md") else {
        return Err(native_error(
            "prompt_command.document_name_invalid",
            "prompt command document must use the lowercase .md extension",
        ));
    };
    PromptCommandName::parse(name).map(|name| (name, nested))
}

fn parse_document(source: &str) -> Result<ParsedDocument<'_>, PromptCommandError> {
    let parsed = parse_optional_flat_markdown(
        source,
        FlatFrontmatterLimits {
            max_bytes: MAX_FRONTMATTER_BYTES,
            max_fields: MAX_FRONTMATTER_FIELDS,
        },
    )
    .map_err(map_frontmatter_error)?;
    let mut description = None;
    for (key, scalar) in &parsed.fields {
        if key == "description" {
            let value = parse_string_scalar(scalar, "prompt_command.description_invalid")?;
            description = Some(PromptDescription::parse(value)?);
        } else if key == "argument-hint" {
            let value = parse_string_scalar(scalar, "prompt_command.argument_hint_invalid")?;
            if value.trim() != value
                || value.is_empty()
                || value.chars().count() > 1_024
                || value.chars().any(|character| {
                    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
                })
            {
                return Err(native_error(
                    "prompt_command.argument_hint_invalid",
                    "prompt-command argument hint must be bounded single-line text",
                ));
            }
        }
    }
    Ok(ParsedDocument {
        description,
        fields: parsed.fields.into_keys().collect(),
        body: parsed.body,
    })
}

fn map_frontmatter_error(error: FlatFrontmatterError) -> PromptCommandError {
    match error {
        FlatFrontmatterError::ByteLimit | FlatFrontmatterError::FieldLimit => native_error(
            "prompt_command.frontmatter_limit",
            "prompt-command frontmatter exceeds a configured limit",
        ),
        FlatFrontmatterError::Unclosed => native_error(
            "prompt_command.frontmatter_unclosed",
            "prompt-command frontmatter is missing a closing delimiter",
        ),
        FlatFrontmatterError::Nested => native_error(
            "prompt_command.frontmatter_nested",
            "prompt-command frontmatter must contain only flat scalar fields",
        ),
        FlatFrontmatterError::Invalid => native_error(
            "prompt_command.frontmatter_invalid",
            "prompt-command frontmatter must contain simple named scalar fields",
        ),
        FlatFrontmatterError::DuplicateKey => native_error(
            "prompt_command.frontmatter_duplicate_key",
            "prompt-command frontmatter contains a duplicate field",
        ),
    }
}

fn parse_string_scalar(scalar: &str, code: &'static str) -> Result<String, PromptCommandError> {
    match yaml_serde::Value::deserialize(yaml_serde::Deserializer::from_str(scalar)) {
        Ok(yaml_serde::Value::String(value)) => Ok(value),
        _ => Err(native_error(
            code,
            "prompt-command frontmatter field must be a YAML string scalar",
        )),
    }
}

fn project_portable(
    dialect: NativePromptDialect,
    name: &PromptCommandName,
    parsed: &ParsedDocument<'_>,
    max_body_bytes: usize,
    execution: bool,
) -> PromptCommandPortability {
    if execution {
        return PromptCommandPortability::Blocked(
            PromptCommandBlockReason::ExecutableInterpolation,
        );
    }
    if dialect == NativePromptDialect::ClaudeLegacy && recognizes_file_interpolation(parsed.body) {
        return PromptCommandPortability::Blocked(PromptCommandBlockReason::FileInterpolation);
    }
    if has_unsupported_fields(dialect, &parsed.fields) {
        return PromptCommandPortability::Blocked(PromptCommandBlockReason::UnsupportedFrontmatter);
    }
    let Some((body, argument_mode)) = normalize_arguments(dialect, parsed.body) else {
        return PromptCommandPortability::Blocked(PromptCommandBlockReason::UnsupportedArguments);
    };
    if dialect.appends_implicit_arguments() && argument_mode == PromptArgumentMode::None {
        return PromptCommandPortability::Blocked(PromptCommandBlockReason::ImplicitArguments);
    }
    let Ok(body) = PromptBody::parse(&body, max_body_bytes) else {
        return PromptCommandPortability::Blocked(PromptCommandBlockReason::InvalidBody);
    };
    match PromptCommand::try_new(
        name.clone(),
        parsed.description.clone(),
        body,
        argument_mode,
    ) {
        Ok(command) => PromptCommandPortability::Portable(command),
        Err(_) => PromptCommandPortability::Blocked(PromptCommandBlockReason::InvalidBody),
    }
}

fn has_unsupported_fields(dialect: NativePromptDialect, fields: &BTreeSet<String>) -> bool {
    fields.iter().any(|field| match dialect {
        NativePromptDialect::ClaudeLegacy | NativePromptDialect::PiLatest => {
            !matches!(field.as_str(), "description" | "argument-hint")
        }
        NativePromptDialect::OpenCodeV2 => field != "description",
    })
}

fn recognizes_shell_interpolation(dialect: NativePromptDialect, body: &str) -> bool {
    matches!(
        dialect,
        NativePromptDialect::ClaudeLegacy | NativePromptDialect::OpenCodeV2
    ) && body.contains("!`")
}

fn recognizes_file_interpolation(body: &str) -> bool {
    body.char_indices().any(|(index, character)| {
        character == '@'
            && (index == 0
                || body[..index].chars().next_back().is_some_and(|previous| {
                    !previous.is_ascii_alphanumeric() && !matches!(previous, '_' | '-')
                }))
            && body[index + 1..].chars().next().is_some_and(|next| {
                next.is_ascii_alphanumeric() || matches!(next, '.' | '/' | '_' | '-')
            })
    })
}

fn normalize_arguments(
    dialect: NativePromptDialect,
    body: &str,
) -> Option<(String, PromptArgumentMode)> {
    if body.contains(ALL_ARGUMENTS_PLACEHOLDER) {
        return None;
    }
    let mut normalized = body.replace("$ARGUMENTS", ALL_ARGUMENTS_PLACEHOLDER);
    if dialect == NativePromptDialect::PiLatest {
        normalized = normalized.replace("$@", ALL_ARGUMENTS_PLACEHOLDER);
    }
    if contains_unsupported_dollar_syntax(&normalized) {
        return None;
    }
    let mode = if normalized.contains(ALL_ARGUMENTS_PLACEHOLDER) {
        PromptArgumentMode::AllArguments
    } else {
        PromptArgumentMode::None
    };
    Some((normalized, mode))
}

fn contains_unsupported_dollar_syntax(body: &str) -> bool {
    let bytes = body.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'$'
            && bytes.get(index + 1).is_some_and(|next| {
                next.is_ascii_alphanumeric() || matches!(next, b'_' | b'{' | b'@')
            })
            && !body[index..].starts_with(ALL_ARGUMENTS_PLACEHOLDER)
    })
}

fn hash_native(dialect: NativePromptDialect, document_name: &str, bytes: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-prompt-command-v1\0");
    hasher.update(&[match dialect {
        NativePromptDialect::ClaudeLegacy => 0,
        NativePromptDialect::PiLatest => 1,
        NativePromptDialect::OpenCodeV2 => 2,
    }]);
    hash_record(&mut hasher, document_name.as_bytes());
    hash_record(&mut hasher, bytes);
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

fn hash_record(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

const fn native_error(code: &'static str, message: &'static str) -> PromptCommandError {
    PromptCommandError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(dialect: NativePromptDialect, source: &str) -> ObservedPromptCommand {
        parse_native_prompt_command(
            dialect,
            "review.md",
            source.as_bytes(),
            PromptCommandLimits::default(),
        )
        .unwrap()
    }

    fn portable(observed: &ObservedPromptCommand) -> &PromptCommand {
        let PromptCommandPortability::Portable(command) = observed.portability() else {
            panic!("expected portable command")
        };
        command
    }

    #[test]
    fn pi_and_opencode_all_arguments_normalize_to_one_portable_placeholder() {
        let pi = parse(
            NativePromptDialect::PiLatest,
            "---\ndescription: Review an area\nargument-hint: <area>\n---\nReview $@.\n",
        );
        let opencode = parse(
            NativePromptDialect::OpenCodeV2,
            "---\ndescription: Review an area\n---\nReview $ARGUMENTS.\n",
        );
        assert_eq!(portable(&pi), portable(&opencode));
        assert_eq!(
            portable(&pi).body().as_str(),
            "Review ${KITROVE_ARGUMENTS}.\n"
        );
        assert_eq!(
            portable(&pi).argument_mode(),
            PromptArgumentMode::AllArguments
        );
    }

    #[test]
    fn claude_plain_command_is_portable_but_deprecated_fidelity_stays_adapter_work() {
        let observed = parse(
            NativePromptDialect::ClaudeLegacy,
            "---\ndescription: Review code\n---\nReview this code.\n",
        );
        assert_eq!(observed.content_class(), ContentClass::AgentActive);
        assert_eq!(
            portable(&observed).argument_mode(),
            PromptArgumentMode::None
        );
    }

    #[test]
    fn executable_and_file_interpolation_fail_closed_without_evaluation() {
        let executable = parse(
            NativePromptDialect::OpenCodeV2,
            "Review $ARGUMENTS.\n!`touch should-not-exist`\n",
        );
        assert_eq!(executable.content_class(), ContentClass::Executable);
        assert_eq!(
            executable.portability(),
            &PromptCommandPortability::Blocked(PromptCommandBlockReason::ExecutableInterpolation)
        );

        let file = parse(
            NativePromptDialect::ClaudeLegacy,
            "Review @secrets.env with $ARGUMENTS.\n",
        );
        assert_eq!(file.content_class(), ContentClass::AgentActive);
        assert_eq!(
            file.portability(),
            &PromptCommandPortability::Blocked(PromptCommandBlockReason::FileInterpolation)
        );

        let punctuation = parse(
            NativePromptDialect::ClaudeLegacy,
            "Review (@secrets.env) with $ARGUMENTS.\n",
        );
        assert_eq!(
            punctuation.portability(),
            &PromptCommandPortability::Blocked(PromptCommandBlockReason::FileInterpolation)
        );
        assert!(matches!(
            parse(
                NativePromptDialect::ClaudeLegacy,
                "Email dev@example.com about $ARGUMENTS.\n"
            )
            .portability(),
            PromptCommandPortability::Portable(_)
        ));
    }

    #[test]
    fn target_specific_active_fields_and_argument_syntax_are_blocked() {
        for (dialect, source, reason) in [
            (
                NativePromptDialect::ClaudeLegacy,
                "---\nallowed-tools: Bash\n---\nReview $ARGUMENTS.\n",
                PromptCommandBlockReason::UnsupportedFrontmatter,
            ),
            (
                NativePromptDialect::OpenCodeV2,
                "---\nagent: plan\n---\nReview $ARGUMENTS.\n",
                PromptCommandBlockReason::UnsupportedFrontmatter,
            ),
            (
                NativePromptDialect::PiLatest,
                "Review $1 and ${@:2}.\n",
                PromptCommandBlockReason::UnsupportedArguments,
            ),
            (
                NativePromptDialect::OpenCodeV2,
                "Review this code.\n",
                PromptCommandBlockReason::ImplicitArguments,
            ),
            (
                NativePromptDialect::PiLatest,
                "Review ${KITROVE_ARGUMENTS}.\n",
                PromptCommandBlockReason::UnsupportedArguments,
            ),
            (
                NativePromptDialect::PiLatest,
                "\n",
                PromptCommandBlockReason::InvalidBody,
            ),
        ] {
            assert_eq!(
                parse(dialect, source).portability(),
                &PromptCommandPortability::Blocked(reason)
            );
        }
    }

    #[test]
    fn frontmatter_is_flat_bounded_and_duplicate_safe() {
        for (source, code) in [
            (
                "---\ndescription: first\ndescription: second\n---\nBody\n",
                "prompt_command.frontmatter_duplicate_key",
            ),
            (
                "---\ndescription: |\n  multiline\n---\nBody\n",
                "prompt_command.frontmatter_nested",
            ),
            (
                "---\ndescription: [nested]\n---\nBody\n",
                "prompt_command.frontmatter_nested",
            ),
            (
                "---\nargument-hint: 123\n---\nBody\n",
                "prompt_command.argument_hint_invalid",
            ),
            (
                "---\ndescription: missing close\nBody\n",
                "prompt_command.frontmatter_unclosed",
            ),
        ] {
            assert_eq!(
                parse_native_prompt_command(
                    NativePromptDialect::PiLatest,
                    "review.md",
                    source.as_bytes(),
                    PromptCommandLimits::default(),
                )
                .unwrap_err()
                .code(),
                code
            );
        }
    }

    #[test]
    fn frontmatter_field_and_byte_limits_stop_before_projection() {
        let fields = (0..=MAX_FRONTMATTER_FIELDS)
            .map(|index| format!("field-{index}: value"))
            .collect::<Vec<_>>()
            .join("\n");
        let too_many = format!("---\n{fields}\n---\nBody\n");
        assert_eq!(
            parse_native_prompt_command(
                NativePromptDialect::PiLatest,
                "review.md",
                too_many.as_bytes(),
                PromptCommandLimits::default(),
            )
            .unwrap_err()
            .code(),
            "prompt_command.frontmatter_limit"
        );

        let too_large = format!(
            "---\ndescription: {}\n---\nBody\n",
            "a".repeat(MAX_FRONTMATTER_BYTES)
        );
        assert_eq!(
            parse_native_prompt_command(
                NativePromptDialect::PiLatest,
                "review.md",
                too_large.as_bytes(),
                PromptCommandLimits::default(),
            )
            .unwrap_err()
            .code(),
            "prompt_command.frontmatter_limit"
        );
    }

    #[test]
    fn relative_name_utf8_and_document_limits_are_enforced() {
        for (name, bytes, limits, code) in [
            (
                "nested/../review.md",
                b"Body\n".as_slice(),
                PromptCommandLimits::default(),
                "prompt_command.document_name_invalid",
            ),
            (
                "review.MD",
                b"Body\n".as_slice(),
                PromptCommandLimits::default(),
                "prompt_command.document_name_invalid",
            ),
            (
                "review.md",
                b"\xff".as_slice(),
                PromptCommandLimits::default(),
                "prompt_command.document_utf8",
            ),
            (
                "review.md",
                b"too large".as_slice(),
                PromptCommandLimits {
                    max_document_bytes: 4,
                    ..PromptCommandLimits::default()
                },
                "prompt_command.document_limit",
            ),
        ] {
            assert_eq!(
                parse_native_prompt_command(NativePromptDialect::PiLatest, name, bytes, limits)
                    .unwrap_err()
                    .code(),
                code
            );
        }
    }

    #[test]
    fn exact_identity_binds_dialect_name_and_every_native_byte() {
        let baseline = parse(NativePromptDialect::PiLatest, "Review $ARGUMENTS.\n");
        let dialect = parse(NativePromptDialect::OpenCodeV2, "Review $ARGUMENTS.\n");
        let bytes = parse(NativePromptDialect::PiLatest, "Review $ARGUMENTS!\n");
        let name = parse_native_prompt_command(
            NativePromptDialect::PiLatest,
            "inspect.md",
            b"Review $ARGUMENTS.\n",
            PromptCommandLimits::default(),
        )
        .unwrap();
        assert_ne!(baseline.exact_hash(), dialect.exact_hash());
        assert_ne!(baseline.exact_hash(), bytes.exact_hash());
        assert_ne!(baseline.exact_hash(), name.exact_hash());
    }

    #[test]
    fn nested_documents_retain_exact_evidence_but_do_not_enter_portable_v1() {
        let observed = parse_native_prompt_command(
            NativePromptDialect::OpenCodeV2,
            "team/review.md",
            b"Review $ARGUMENTS.\n",
            PromptCommandLimits::default(),
        )
        .unwrap();

        assert_eq!(observed.name().as_str(), "review");
        assert_eq!(
            observed.portability(),
            &PromptCommandPortability::Blocked(PromptCommandBlockReason::NestedDocument)
        );
    }

    #[test]
    fn debug_omits_native_body_description_and_field_names() {
        let observed = parse(
            NativePromptDialect::PiLatest,
            "---\ndescription: PRIVATE DESCRIPTION\nargument-hint: PRIVATE FIELD\n---\nPRIVATE BODY $ARGUMENTS\n",
        );
        let debug = format!("{observed:?}");
        assert!(!debug.contains("PRIVATE"));
        assert!(!debug.contains("argument-hint"));
    }
}
