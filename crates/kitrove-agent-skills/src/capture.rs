#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kitrove_model::{ContentClass, PortablePath};

use crate::{
    CaptureLimits, CapturedTree, ParsedSkillDocument, SkillError, SkillManifest, SkillSource,
    capture_skill_source, capture_tree, parse_skill_document, project_skill_source,
};

/// A validated skill capture containing immutable evidence and its portable projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillSnapshot {
    pub source_directory: PathBuf,
    pub manifest: SkillManifest,
    pub body: String,
    pub native_fields: BTreeSet<String>,
    pub exact: CapturedTree,
    pub portable: CapturedTree,
    pub content_class: ContentClass,
}

/// Captures, validates, projects, and classifies one Agent Skill directory.
pub fn capture_skill(directory: &Path, limits: CaptureLimits) -> Result<SkillSnapshot, SkillError> {
    let captured = match capture_skill_source(
        &SkillSource::Directory {
            path: directory.to_path_buf(),
        },
        limits,
    ) {
        Ok(captured) => captured,
        Err(error) if error.code() == "skill.credential_artifact" => {
            // C1 validates the principal document and directory policy before reporting
            // credential artifacts. Preserve that stable error order while delegating normal
            // directory capture to the generic source API.
            let exact = capture_tree(directory, limits)?;
            let parsed = parse_c1_document(directory, &exact)?;
            validate_directory_name(directory, &parsed)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    let parsed = parse_c1_document(directory, &captured.exact)?;

    validate_directory_name(directory, &parsed)?;
    let projection = project_skill_source(
        &captured,
        parsed.manifest.name.clone(),
        parsed.manifest.description.clone(),
        Vec::new(),
    )?;
    let crate::PortableProjection::Available { tree: portable, .. } = projection else {
        unreachable!("a supplied portable identity always produces a portable projection");
    };

    Ok(SkillSnapshot {
        source_directory: directory.to_path_buf(),
        manifest: parsed.manifest,
        body: parsed.body,
        native_fields: parsed.native_fields,
        exact: captured.exact,
        portable,
        content_class: captured.content_class,
    })
}

fn parse_c1_document(
    directory: &Path,
    exact: &CapturedTree,
) -> Result<ParsedSkillDocument, SkillError> {
    let skill_path = PortablePath::parse("SKILL.md").expect("SKILL.md is a valid portable path");
    let document_path = directory.join("SKILL.md");
    let skill_file = exact.files.get(&skill_path).ok_or_else(|| {
        SkillError::new(
            "skill.document_missing",
            &document_path,
            "skill directory must contain a regular SKILL.md file",
        )
    })?;
    parse_skill_document(&document_path, &skill_file.bytes)
}

fn validate_directory_name(
    directory: &Path,
    parsed: &ParsedSkillDocument,
) -> Result<(), SkillError> {
    let directory_name = directory.file_name().and_then(|name| name.to_str());
    if directory_name != Some(parsed.manifest.name.as_str()) {
        return Err(SkillError::new(
            "skill.directory_name_mismatch",
            directory,
            "skill directory name must match the manifest name",
        ));
    }
    Ok(())
}
