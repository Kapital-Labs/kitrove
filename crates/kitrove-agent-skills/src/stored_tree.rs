use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_model::PortablePath;
use serde::{Deserialize, Serialize};

use crate::tree::has_supported_platform_path_collision;
use crate::{CapturedFile, CapturedTree, FileMode, SkillError, hash_tree};

pub(crate) const MAX_STORED_METADATA_BYTES: usize = 4 * 1024 * 1024;

/// A portable storage envelope for one versioned Agent Skill tree.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredSkillTree {
    tree: CapturedTree,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredTreeMetadata {
    schema_version: u32,
    files: BTreeMap<PortablePath, StoredFileMode>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredFileMode {
    Regular,
    Executable,
}

impl StoredSkillTree {
    /// Builds an envelope only when the supplied tree carries its canonical hash.
    pub fn new(tree: CapturedTree) -> Result<Self, SkillError> {
        if has_supported_platform_path_collision(tree.files.keys()) {
            return Err(storage_error(
                "stored_tree.path_collision",
                "stored tree paths collide on a supported platform",
            ));
        }
        if hash_tree(&tree.files) != tree.hash {
            return Err(storage_error(
                "stored_tree.hash_mismatch",
                "stored tree hash does not match its paths, modes, and bytes",
            ));
        }
        let stored = Self { tree };
        if stored.metadata_json().len() > MAX_STORED_METADATA_BYTES {
            return Err(storage_error(
                "stored_tree.metadata_limit",
                "stored tree metadata exceeds the portable storage limit",
            ));
        }
        Ok(stored)
    }

    /// Reconstructs a tree from strict portable metadata and captured payload bytes.
    pub fn from_stored(metadata_json: &str, payload: CapturedTree) -> Result<Self, SkillError> {
        if metadata_json.len() > MAX_STORED_METADATA_BYTES {
            return Err(storage_error(
                "stored_tree.metadata_limit",
                "stored tree metadata exceeds the portable storage limit",
            ));
        }
        let metadata: StoredTreeMetadata = serde_json::from_str(metadata_json).map_err(|_| {
            storage_error(
                "stored_tree.invalid_metadata",
                "stored tree metadata is not strict version-1 JSON",
            )
        })?;
        Self::from_metadata(metadata, payload)
    }

    /// Returns deterministic metadata recording portable paths and modes.
    #[must_use]
    pub fn metadata_json(&self) -> String {
        encode_metadata(&self.metadata())
    }

    /// Returns the canonical tree represented by this envelope.
    #[must_use]
    pub const fn tree(&self) -> &CapturedTree {
        &self.tree
    }

    pub(crate) fn metadata(&self) -> StoredTreeMetadata {
        StoredTreeMetadata {
            schema_version: 1,
            files: self
                .tree
                .files
                .iter()
                .map(|(path, file)| {
                    (
                        path.clone(),
                        match file.mode {
                            FileMode::Regular => StoredFileMode::Regular,
                            FileMode::Executable => StoredFileMode::Executable,
                        },
                    )
                })
                .collect(),
        }
    }

    pub(crate) fn from_metadata(
        metadata: StoredTreeMetadata,
        payload: CapturedTree,
    ) -> Result<Self, SkillError> {
        if metadata.schema_version != 1 {
            return Err(storage_error(
                "stored_tree.unsupported_version",
                "stored tree metadata schema version is unsupported",
            ));
        }
        if metadata.files.len() != payload.files.len()
            || !metadata.files.keys().eq(payload.files.keys())
        {
            return Err(storage_error(
                "stored_tree.payload_mismatch",
                "stored tree metadata and payload paths differ",
            ));
        }
        let files = metadata
            .files
            .into_iter()
            .zip(payload.files)
            .map(|((path, mode), (payload_path, file))| {
                debug_assert_eq!(path, payload_path);
                (
                    path,
                    CapturedFile {
                        mode: match mode {
                            StoredFileMode::Regular => FileMode::Regular,
                            StoredFileMode::Executable => FileMode::Executable,
                        },
                        bytes: file.bytes,
                    },
                )
            })
            .collect();
        let tree = CapturedTree {
            hash: hash_tree(&files),
            files,
        };
        Self::new(tree)
    }
}

impl Debug for StoredSkillTree {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredSkillTree")
            .field("file_count", &self.tree.files.len())
            .field("tree_hash", &self.tree.hash)
            .finish()
    }
}

pub(crate) fn encode_metadata(metadata: &impl Serialize) -> String {
    let mut encoded = serde_json::to_string_pretty(metadata)
        .expect("stored tree metadata contains only serializable values");
    encoded.push('\n');
    encoded
}

fn storage_error(code: &'static str, message: &'static str) -> SkillError {
    SkillError::new(code, Path::new("stored-tree"), message)
}
