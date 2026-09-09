#![forbid(unsafe_code)]
//! Harness-neutral standing-instruction and managed-region primitives.

mod native;
mod stored;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::ops::Range;

use kitrove_model::{AssetId, ContentHash};

pub use native::NativeInstructionRegion;
pub use stored::StoredInstruction;

const MARKER_NAMESPACE: &str = "<!-- kitrove:instruction";
const MARKER_PREFIX: &str = "<!-- kitrove:instruction ";
const BEGIN_SUFFIX: &str = " begin -->";
const END_SUFFIX: &str = " end -->";
const MAX_ASSET_ID_BYTES: usize = 128;

/// Default maximum size accepted for one co-owned instruction document.
pub const DEFAULT_MAX_INSTRUCTION_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Request-local bounds for parsing a co-owned instruction document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstructionLimits {
    pub max_document_bytes: usize,
    pub max_body_bytes: usize,
    pub max_regions: usize,
}

impl Default for InstructionLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: DEFAULT_MAX_INSTRUCTION_DOCUMENT_BYTES,
            max_body_bytes: 256 * 1024,
            max_regions: 256,
        }
    }
}

/// A stable, path-free instruction parsing or rendering failure.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionError {
    code: &'static str,
    message: &'static str,
}

impl InstructionError {
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

impl Debug for InstructionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for InstructionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for InstructionError {}

/// Canonical, non-empty Markdown instruction bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionBody(String);

impl InstructionBody {
    /// Normalizes CRLF to LF and ensures exactly one trailing newline.
    pub fn parse(input: &str, max_body_bytes: usize) -> Result<Self, InstructionError> {
        if input.is_empty() || input.contains('\0') {
            return Err(error(
                "instruction.body_invalid",
                "instruction body must be non-empty UTF-8 without NUL bytes",
            ));
        }
        if input.len() > max_body_bytes {
            return Err(error(
                "instruction.body_limit",
                "instruction body exceeds the configured byte limit",
            ));
        }

        let normalized = input.replace("\r\n", "\n");
        if normalized.contains('\r') {
            return Err(error(
                "instruction.body_line_endings",
                "instruction body must use LF or CRLF line endings",
            ));
        }
        let normalized = format!("{}\n", normalized.trim_end_matches('\n'));
        if normalized.trim().is_empty() || normalized.len() > max_body_bytes {
            return Err(error(
                "instruction.body_limit",
                "instruction body is empty or exceeds the configured byte limit",
            ));
        }
        if normalized
            .lines()
            .any(|line| line.starts_with(MARKER_NAMESPACE))
        {
            return Err(error(
                "instruction.body_marker",
                "instruction body must not contain Kitrove managed-region markers",
            ));
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Computes the portable instruction-body identity.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-instruction-body-v1\0");
        hasher.update(&(self.0.len() as u64).to_be_bytes());
        hasher.update(self.0.as_bytes());
        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid content hash")
    }
}

impl Debug for InstructionBody {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionBody")
            .field("byte_count", &self.0.len())
            .field("content_hash", &self.content_hash())
            .finish()
    }
}

/// One strictly parsed Kitrove-owned region inside a co-owned file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRegion {
    asset_id: AssetId,
    range: Range<usize>,
    body_range: Range<usize>,
}

impl ManagedRegion {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn range(&self) -> &Range<usize> {
        &self.range
    }

    #[must_use]
    pub const fn body_range(&self) -> &Range<usize> {
        &self.body_range
    }
}

/// Strict structural view of all Kitrove regions in one co-owned document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedDocument {
    regions: BTreeMap<AssetId, ManagedRegion>,
}

impl ManagedDocument {
    #[must_use]
    pub fn region(&self, asset_id: &AssetId) -> Option<&ManagedRegion> {
        self.regions.get(asset_id)
    }

    pub fn regions(&self) -> impl ExactSizeIterator<Item = &ManagedRegion> {
        self.regions.values()
    }
}

#[derive(Clone, Debug)]
struct OpenRegion {
    asset_id: AssetId,
    start: usize,
    body_start: usize,
}

#[derive(Clone, Debug)]
enum Marker {
    Begin(AssetId),
    End(AssetId),
}

/// Parses exact managed-region marker lines while leaving all other document bytes unowned.
pub fn inspect_managed_document(
    input: &[u8],
    limits: InstructionLimits,
) -> Result<ManagedDocument, InstructionError> {
    if input.len() > limits.max_document_bytes {
        return Err(error(
            "instruction.document_limit",
            "co-owned instruction document exceeds the configured byte limit",
        ));
    }
    let text = std::str::from_utf8(input).map_err(|_| {
        error(
            "instruction.document_utf8",
            "co-owned instruction document must contain valid UTF-8",
        )
    })?;
    if text.contains('\0') {
        return Err(error(
            "instruction.document_nul",
            "co-owned instruction document must not contain NUL bytes",
        ));
    }

    let mut regions = BTreeMap::new();
    let mut open: Option<OpenRegion> = None;
    let mut offset = 0;
    for line_with_ending in text.split_inclusive('\n') {
        let line = line_with_ending
            .strip_suffix('\n')
            .unwrap_or(line_with_ending);
        let marker = parse_marker(line)?;
        match (marker, open.take()) {
            (None, current) => open = current,
            (Some(Marker::Begin(_)), Some(current)) => {
                let _ = current;
                return Err(error(
                    "instruction.region_nested",
                    "managed instruction regions must not be nested",
                ));
            }
            (Some(Marker::End(_)), None) => {
                return Err(error(
                    "instruction.region_unmatched_end",
                    "managed instruction end marker has no matching begin marker",
                ));
            }
            (Some(Marker::Begin(asset_id)), None) => {
                if regions.len() >= limits.max_regions {
                    return Err(error(
                        "instruction.region_limit",
                        "co-owned instruction document contains too many managed regions",
                    ));
                }
                open = Some(OpenRegion {
                    asset_id,
                    start: offset,
                    body_start: offset + line_with_ending.len(),
                });
            }
            (Some(Marker::End(asset_id)), Some(current)) => {
                if asset_id != current.asset_id {
                    return Err(error(
                        "instruction.region_mismatch",
                        "managed instruction marker asset identifiers do not match",
                    ));
                }
                let body_range = current.body_start..offset;
                if body_range.len() > limits.max_body_bytes {
                    return Err(error(
                        "instruction.body_limit",
                        "managed instruction body exceeds the configured byte limit",
                    ));
                }
                let range = current.start..offset + line_with_ending.len();
                let region = ManagedRegion {
                    asset_id: current.asset_id.clone(),
                    range,
                    body_range,
                };
                if regions.insert(current.asset_id, region).is_some() {
                    return Err(error(
                        "instruction.region_duplicate",
                        "co-owned instruction document contains a duplicate managed region",
                    ));
                }
            }
        }
        offset += line_with_ending.len();
    }
    if open.is_some() {
        return Err(error(
            "instruction.region_unclosed",
            "managed instruction begin marker has no matching end marker",
        ));
    }
    Ok(ManagedDocument { regions })
}

/// Renders one canonical managed region and its domain-separated identity.
pub fn render_managed_region(
    asset_id: &AssetId,
    body: &InstructionBody,
) -> Result<(String, ContentHash), InstructionError> {
    validate_asset_id(asset_id)?;
    let rendered = format!(
        "{MARKER_PREFIX}{}{BEGIN_SUFFIX}\n{}{MARKER_PREFIX}{}{END_SUFFIX}\n",
        asset_id.as_str(),
        body.as_str(),
        asset_id.as_str()
    );
    let hash = hash_managed_region(rendered.as_bytes());
    Ok((rendered, hash))
}

/// Computes the exact identity of already-bounded managed-region bytes.
#[must_use]
pub fn hash_managed_region(input: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-managed-instruction-region-v1\0");
    hasher.update(&(input.len() as u64).to_be_bytes());
    hasher.update(input);
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

/// Computes the exact identity of an already-bounded co-owned instruction document.
#[must_use]
pub fn hash_instruction_document(input: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-document-v1\0");
    hasher.update(&(input.len() as u64).to_be_bytes());
    hasher.update(input);
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

/// Inserts or exactly replaces one managed region while preserving all co-owned bytes.
pub fn upsert_managed_region(
    input: &[u8],
    asset_id: &AssetId,
    body: &InstructionBody,
    limits: InstructionLimits,
) -> Result<Vec<u8>, InstructionError> {
    let document = inspect_managed_document(input, limits)?;
    let (rendered, _) = render_managed_region(asset_id, body)?;
    let mut output =
        Vec::with_capacity(input.len().saturating_add(rendered.len()).saturating_add(2));
    if let Some(existing) = document.region(asset_id) {
        output.extend_from_slice(&input[..existing.range.start]);
        output.extend_from_slice(rendered.as_bytes());
        output.extend_from_slice(&input[existing.range.end..]);
    } else {
        output.extend_from_slice(input);
        match input.last() {
            None => {}
            Some(b'\n') if !input.ends_with(b"\n\n") => output.push(b'\n'),
            Some(b'\n') => {}
            Some(_) => output.extend_from_slice(b"\n\n"),
        }
        output.extend_from_slice(rendered.as_bytes());
    }
    if output.len() > limits.max_document_bytes {
        return Err(error(
            "instruction.document_limit",
            "updated instruction document exceeds the configured byte limit",
        ));
    }
    Ok(output)
}

/// Removes exactly one managed region while preserving every surrounding byte.
pub fn remove_managed_region(
    input: &[u8],
    asset_id: &AssetId,
    limits: InstructionLimits,
) -> Result<Option<Vec<u8>>, InstructionError> {
    let document = inspect_managed_document(input, limits)?;
    let Some(existing) = document.region(asset_id) else {
        return Ok(None);
    };
    let mut output = Vec::with_capacity(input.len() - existing.range.len());
    output.extend_from_slice(&input[..existing.range.start]);
    output.extend_from_slice(&input[existing.range.end..]);
    Ok(Some(output))
}

fn parse_marker(line: &str) -> Result<Option<Marker>, InstructionError> {
    if !line.starts_with(MARKER_NAMESPACE) {
        return Ok(None);
    }
    let Some(rest) = line.strip_prefix(MARKER_PREFIX) else {
        return Err(error(
            "instruction.marker_invalid",
            "Kitrove instruction marker line is malformed",
        ));
    };
    let (raw_id, begin) = if let Some(raw_id) = rest.strip_suffix(BEGIN_SUFFIX) {
        (raw_id, true)
    } else if let Some(raw_id) = rest.strip_suffix(END_SUFFIX) {
        (raw_id, false)
    } else {
        return Err(error(
            "instruction.marker_invalid",
            "Kitrove instruction marker line is malformed",
        ));
    };
    if raw_id.len() > MAX_ASSET_ID_BYTES {
        return Err(error(
            "instruction.marker_invalid",
            "Kitrove instruction marker asset identifier is invalid",
        ));
    }
    let asset_id = AssetId::parse(raw_id.to_owned()).map_err(|_| {
        error(
            "instruction.marker_invalid",
            "Kitrove instruction marker asset identifier is invalid",
        )
    })?;
    Ok(Some(if begin {
        Marker::Begin(asset_id)
    } else {
        Marker::End(asset_id)
    }))
}

fn validate_asset_id(asset_id: &AssetId) -> Result<(), InstructionError> {
    if asset_id.as_str().len() > MAX_ASSET_ID_BYTES {
        return Err(error(
            "instruction.asset_id_limit",
            "instruction asset identifier exceeds the managed-marker limit",
        ));
    }
    Ok(())
}

const fn error(code: &'static str, message: &'static str) -> InstructionError {
    InstructionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(value: &str) -> AssetId {
        AssetId::parse(value).unwrap()
    }

    fn body(value: &str) -> InstructionBody {
        InstructionBody::parse(value, 1024).unwrap()
    }

    #[test]
    fn body_normalizes_crlf_and_one_final_newline() {
        assert_eq!(
            body("# Rules\r\n\r\n- test\r\n\r\n").as_str(),
            "# Rules\n\n- test\n"
        );
    }

    #[test]
    fn insert_and_replace_preserve_co_owned_bytes() {
        let id = asset("shared-rules");
        let limits = InstructionLimits::default();
        let original = b"# Human notes\r\nkeep this\r\n";
        let inserted = upsert_managed_region(original, &id, &body("first"), limits).unwrap();
        assert!(inserted.starts_with(original));
        let replaced = upsert_managed_region(&inserted, &id, &body("second"), limits).unwrap();
        assert!(replaced.starts_with(original));
        assert!(!String::from_utf8_lossy(&replaced).contains("first"));
        assert_eq!(
            inspect_managed_document(&replaced, limits)
                .unwrap()
                .regions()
                .len(),
            1
        );
    }

    #[test]
    fn remove_preserves_every_byte_outside_the_region() {
        let id = asset("shared-rules");
        let limits = InstructionLimits::default();
        let (region, _) = render_managed_region(&id, &body("body")).unwrap();
        let document = format!("prefix\r\n{region}suffix\r\n");
        let removed = remove_managed_region(document.as_bytes(), &id, limits)
            .unwrap()
            .unwrap();
        assert_eq!(removed, b"prefix\r\nsuffix\r\n");
    }

    #[test]
    fn rejects_nested_duplicate_mismatched_and_malformed_regions() {
        let limits = InstructionLimits::default();
        for (document, code) in [
            (
                "<!-- kitrove:instruction a begin -->\n<!-- kitrove:instruction b begin -->\n",
                "instruction.region_nested",
            ),
            (
                "<!-- kitrove:instruction a begin -->\n<!-- kitrove:instruction b end -->\n",
                "instruction.region_mismatch",
            ),
            (
                "<!-- kitrove:instruction a nope -->\n",
                "instruction.marker_invalid",
            ),
            (
                "<!-- kitrove:instruction a begin -->\nx\n<!-- kitrove:instruction a end -->\n<!-- kitrove:instruction a begin -->\ny\n<!-- kitrove:instruction a end -->\n",
                "instruction.region_duplicate",
            ),
        ] {
            assert_eq!(
                inspect_managed_document(document.as_bytes(), limits)
                    .unwrap_err()
                    .code(),
                code
            );
        }
    }

    #[test]
    fn rejects_marker_text_in_authored_body() {
        for value in [
            "<!-- kitrove:instruction x begin -->",
            "<!-- kitrove:instruction-malformed -->",
        ] {
            assert_eq!(
                InstructionBody::parse(value, 1024).unwrap_err().code(),
                "instruction.body_marker"
            );
        }
    }

    #[test]
    fn rejects_whitespace_only_and_preallocation_oversize_bodies() {
        assert_eq!(
            InstructionBody::parse(" \n\t", 1024).unwrap_err().code(),
            "instruction.body_limit"
        );
        assert_eq!(
            InstructionBody::parse("1234", 3).unwrap_err().code(),
            "instruction.body_limit"
        );
    }

    #[test]
    fn rejects_every_reserved_marker_namespace_line() {
        for document in [
            "<!-- kitrove:instruction-->\n",
            "<!-- kitrove:instruction-malformed -->\n",
            "<!-- kitrove:instruction x begin -->\r\n",
        ] {
            assert_eq!(
                inspect_managed_document(document.as_bytes(), InstructionLimits::default())
                    .unwrap_err()
                    .code(),
                "instruction.marker_invalid"
            );
        }
    }

    #[test]
    fn region_hash_is_stable_and_sensitive_to_asset_identity() {
        let body = body("same");
        let (_, first) = render_managed_region(&asset("first"), &body).unwrap();
        let (_, second) = render_managed_region(&asset("second"), &body).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            first,
            render_managed_region(&asset("first"), &body).unwrap().1
        );
    }
}
