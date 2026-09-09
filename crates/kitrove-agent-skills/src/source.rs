#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use kitrove_model::{ContentClass, ContentHash, PortablePath};

use crate::risk::{classify, credential_like_path, reject_credential_artifacts};
use crate::tree::{
    capture_standalone_tree_metered, capture_tree_metered, contains_parent_component,
};
use crate::{
    CaptureLimits, CapturedTree, FileMode, ObservedSkillDocument, SkillError,
    parse_observed_skill_document,
};

/// The native layout used to author a skill source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SkillSourceLayout {
    Directory,
    Standalone,
}

/// A safely capturable native skill source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillSource {
    Directory { path: PathBuf },
    Standalone { path: PathBuf },
}

/// Request-global capture capacity consumed by a caller's capture attempts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CaptureUsage {
    pub file_attempts: usize,
    pub bytes_read: u64,
}

/// Refusing request-global meter consulted at every actual file-open and read boundary.
pub trait CaptureMeter {
    fn try_file_attempt(&mut self) -> bool;
    fn remaining_bytes(&self) -> u64;
    fn try_charge_bytes(&mut self, bytes: u64) -> bool;
}

impl CaptureMeter for CaptureUsage {
    fn try_file_attempt(&mut self) -> bool {
        self.file_attempts = self.file_attempts.saturating_add(1);
        true
    }

    fn remaining_bytes(&self) -> u64 {
        u64::MAX.saturating_sub(self.bytes_read)
    }

    fn try_charge_bytes(&mut self, bytes: u64) -> bool {
        self.bytes_read = self.bytes_read.saturating_add(bytes);
        true
    }
}

/// Immutable evidence captured from one native skill source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedSkillSource {
    pub layout: SkillSourceLayout,
    pub original_document_name: String,
    pub document: ObservedSkillDocument,
    pub exact: CapturedTree,
    pub exact_source_hash: ContentHash,
    pub content_class: ContentClass,
}

/// Captures one native skill source with a fresh, local usage counter.
pub fn capture_skill_source(
    source: &SkillSource,
    limits: CaptureLimits,
) -> Result<CapturedSkillSource, SkillError> {
    capture_skill_source_metered(source, limits, &mut CaptureUsage::default())
}

/// Captures one native skill source while charging the caller-owned usage counter.
pub fn capture_skill_source_metered(
    source: &SkillSource,
    limits: CaptureLimits,
    usage: &mut CaptureUsage,
) -> Result<CapturedSkillSource, SkillError> {
    capture_skill_source_with_meter(source, limits, usage)
}

/// Captures one source while a refusing caller-owned meter gates each actual operation.
pub fn capture_skill_source_with_meter(
    source: &SkillSource,
    limits: CaptureLimits,
    meter: &mut dyn CaptureMeter,
) -> Result<CapturedSkillSource, SkillError> {
    let (layout, source_path, original_document_name, exact) = match source {
        SkillSource::Directory { path } => {
            let exact = capture_tree_metered(path, limits, meter)?;
            let document_name = "SKILL.md".to_owned();
            if !exact.files.contains_key(
                &PortablePath::parse(&document_name).expect("valid skill document path"),
            ) {
                return Err(SkillError::new(
                    "skill.document_missing",
                    path.join(&document_name),
                    "skill directory must contain a regular SKILL.md file",
                ));
            }
            (SkillSourceLayout::Directory, path, document_name, exact)
        }
        SkillSource::Standalone { path } => {
            preflight_standalone_path(path)?;
            let (original_document_name, exact) =
                capture_standalone_tree_metered(path, limits, meter)?;
            (
                SkillSourceLayout::Standalone,
                path,
                original_document_name,
                exact,
            )
        }
    };

    let document_path = match layout {
        SkillSourceLayout::Directory => source_path.join(&original_document_name),
        SkillSourceLayout::Standalone => source_path.to_path_buf(),
    };
    let document = exact
        .files
        .get(&PortablePath::parse(&original_document_name).expect("validated document path"))
        .expect("captured source contains its principal document");

    let credential_root = match layout {
        SkillSourceLayout::Directory => source_path,
        SkillSourceLayout::Standalone => source_path.parent().unwrap_or(source_path),
    };
    reject_credential_artifacts(credential_root, &exact)?;
    let observed = parse_observed_skill_document(&document_path, &document.bytes)?;
    let content_class = classify(&exact, &observed.native_fields);
    let exact_source_hash = hash_skill_source(layout, &original_document_name, &exact);

    Ok(CapturedSkillSource {
        layout,
        original_document_name,
        document: observed,
        exact,
        exact_source_hash,
        content_class,
    })
}

fn preflight_standalone_path(path: &Path) -> Result<(), SkillError> {
    if contains_parent_component(path) {
        return Err(SkillError::new(
            "capture.invalid_root_path",
            path,
            "capture root must not contain parent-directory components",
        ));
    }
    let Some(file_name) = path.file_name() else {
        return Ok(());
    };
    let Some(name) = file_name.to_str() else {
        return Err(SkillError::new(
            "capture.non_utf8_path",
            path,
            "captured paths must contain only valid UTF-8",
        ));
    };
    if credential_like_path(name) {
        return Err(SkillError::new(
            "skill.credential_artifact",
            path,
            "credential-like filename is not eligible for portable capture",
        ));
    }
    if !name.ends_with(".md") {
        return Err(SkillError::new(
            "capture.standalone_not_markdown",
            path,
            "standalone sources must be regular Markdown files",
        ));
    }
    Ok(())
}

/// Hashes exact source evidence using the versioned layout-aware source frame.
#[must_use]
pub fn hash_skill_source(
    layout: SkillSourceLayout,
    original_document_name: &str,
    tree: &CapturedTree,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-skill-source-v1\0");
    hasher.update(&[match layout {
        SkillSourceLayout::Directory => 0,
        SkillSourceLayout::Standalone => 1,
    }]);
    write_text_record(&mut hasher, original_document_name);
    for (path, file) in &tree.files {
        write_text_record(&mut hasher, path.as_str());
        hasher.update(&[match file.mode {
            FileMode::Regular => 0,
            FileMode::Executable => 1,
        }]);
        hasher.update(&(file.bytes.len() as u64).to_be_bytes());
        hasher.update(&file.bytes);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid ContentHash")
}

fn write_text_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
