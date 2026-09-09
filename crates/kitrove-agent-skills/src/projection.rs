#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

use kitrove_model::{AssetId, FidelityReason, PortablePath};
use serde::Serialize;

use crate::frontmatter::{is_standard_skill_name, reject_secret_metadata_keys};
use crate::{
    CapturedSkillSource, CapturedTree, ObservedSkillDocument, SkillError, SkillManifest, hash_tree,
    is_standard_skill_description,
};

/// A policy-authorized portable representation of a captured skill source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortableProjection {
    /// A portable tree was rendered from the captured source and policy inputs.
    Available {
        manifest: Box<SkillManifest>,
        body: String,
        tree: CapturedTree,
        reasons: Vec<FidelityReason>,
    },
    /// Policy determined that this source cannot be represented portably.
    Unavailable { reasons: Vec<FidelityReason> },
}

#[derive(Serialize)]
struct ProjectedManifest<'a> {
    name: &'a str,
    description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compatibility: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "allowed-tools", skip_serializing_if = "Option::is_none")]
    allowed_tools: Option<&'a str>,
}

/// Projects a layout-specific captured source into Kitrove's portable skill tree.
pub fn project_skill_source(
    captured: &CapturedSkillSource,
    name: AssetId,
    description: String,
    reasons: Vec<FidelityReason>,
) -> Result<PortableProjection, SkillError> {
    let document_path = Path::new(&captured.original_document_name);
    let manifest = projected_manifest(document_path, &captured.document, name, description)?;
    let projected_document = project_document(document_path, &manifest, &captured.document.body)?;
    let original_document_path = PortablePath::parse(&captured.original_document_name)
        .expect("captured principal document has a validated portable path");
    let mut files = captured.exact.files.clone();
    files.remove(&original_document_path);
    if files.contains_key(&skill_document_path()) {
        return Err(SkillError::new(
            "skill.projection_failed",
            document_path,
            "portable SKILL.md would conflict with a supporting file",
        ));
    }
    files.insert(
        skill_document_path(),
        crate::CapturedFile {
            mode: captured.exact.files[&original_document_path].mode,
            bytes: projected_document,
        },
    );
    let hash = hash_tree(&files);
    Ok(PortableProjection::Available {
        manifest: Box::new(manifest),
        body: captured.document.body.clone(),
        tree: CapturedTree { files, hash },
        reasons,
    })
}

fn projected_manifest(
    path: &Path,
    document: &ObservedSkillDocument,
    name: AssetId,
    description: String,
) -> Result<SkillManifest, SkillError> {
    if !is_standard_skill_name(name.as_str()) {
        return Err(SkillError::new(
            "skill.name_invalid",
            path,
            "name must be a lowercase hyphenated identifier no longer than 64 bytes",
        ));
    }
    if !is_standard_skill_description(&description) {
        return Err(SkillError::new(
            "skill.description_invalid",
            path,
            "description must contain between 1 and 1,024 characters",
        ));
    }
    if document.frontmatter.contains_key("license") && document.license.is_none() {
        return Err(SkillError::new(
            "skill.frontmatter_invalid",
            path,
            "frontmatter must be valid YAML with string top-level keys",
        ));
    }
    let compatibility = document.compatibility.clone();
    if document.frontmatter.contains_key("compatibility") && compatibility.is_none() {
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
    let metadata = match document.metadata.clone() {
        Some(metadata) => metadata,
        None if document.frontmatter.contains_key("metadata") => {
            return Err(SkillError::new(
                "skill.metadata_invalid",
                path,
                "metadata must be a mapping of string keys to string values",
            ));
        }
        None => BTreeMap::new(),
    };
    reject_secret_metadata_keys(path, &metadata)?;
    let allowed_tools = document.allowed_tools.clone();
    if document.frontmatter.contains_key("allowed-tools") && allowed_tools.is_none() {
        return Err(SkillError::new(
            "skill.frontmatter_invalid",
            path,
            "frontmatter must be valid YAML with string top-level keys",
        ));
    }

    Ok(SkillManifest {
        name,
        description,
        license: document.license.clone(),
        compatibility,
        metadata,
        allowed_tools,
    })
}

pub(crate) fn project_document(
    path: &Path,
    manifest: &SkillManifest,
    body: &str,
) -> Result<Vec<u8>, SkillError> {
    let projected = ProjectedManifest {
        name: manifest.name.as_str(),
        description: &manifest.description,
        license: manifest.license.as_deref(),
        compatibility: manifest.compatibility.as_deref(),
        metadata: (!manifest.metadata.is_empty()).then_some(&manifest.metadata),
        allowed_tools: manifest.allowed_tools.as_deref(),
    };
    let frontmatter = yaml_serde::to_string(&projected).map_err(|_| {
        SkillError::new(
            "skill.projection_failed",
            path,
            "portable SKILL.md frontmatter could not be rendered",
        )
    })?;

    let mut bytes = Vec::with_capacity(frontmatter.len() + body.len() + 9);
    bytes.extend_from_slice(b"---\n");
    bytes.extend_from_slice(frontmatter.as_bytes());
    bytes.extend_from_slice(b"---\n");

    let normalized_body = body.replace("\r\n", "\n").replace('\r', "\n");
    let body_without_terminal_newlines = normalized_body.trim_end_matches('\n');
    if !body_without_terminal_newlines.is_empty() {
        bytes.extend_from_slice(body_without_terminal_newlines.as_bytes());
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn skill_document_path() -> PortablePath {
    PortablePath::parse("SKILL.md").expect("SKILL.md is a valid portable path")
}
