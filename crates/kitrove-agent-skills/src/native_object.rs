use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_model::{ContentHash, PortablePath};
use serde::{Deserialize, Serialize};

use crate::stored_tree::{MAX_STORED_METADATA_BYTES, StoredTreeMetadata, encode_metadata};
use crate::{CapturedTree, SkillError, SkillSourceLayout, StoredSkillTree};

/// A versioned origin-native skill object retaining identity outside its exact payload tree.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSkillObject {
    layout: SkillSourceLayout,
    original_document_name: String,
    native_id: String,
    tree: CapturedTree,
    hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredMetadata {
    schema_version: u32,
    layout: StoredLayout,
    original_document_name: String,
    native_id: String,
    tree: StoredTreeMetadata,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredLayout {
    Directory,
    Standalone,
}

impl NativeSkillObject {
    /// Builds and validates a complete origin-native object.
    pub fn new(
        layout: SkillSourceLayout,
        original_document_name: impl Into<String>,
        native_id: impl Into<String>,
        tree: CapturedTree,
    ) -> Result<Self, SkillError> {
        let original_document_name = original_document_name.into();
        let native_id = native_id.into();
        let stored_tree = StoredSkillTree::new(tree)?;
        validate_metadata(
            layout,
            &original_document_name,
            &native_id,
            stored_tree.tree(),
        )?;
        let tree = stored_tree.tree().clone();
        let hash = hash_native_object(layout, &original_document_name, &native_id, &tree.hash);
        let object = Self {
            layout,
            original_document_name,
            native_id,
            tree,
            hash,
        };
        if object.metadata_json().len() > MAX_STORED_METADATA_BYTES {
            return Err(object_error(
                "native_object.metadata_limit",
                "native object metadata exceeds the portable storage limit",
            ));
        }
        Ok(object)
    }

    /// Reconstructs a native object from strict stored metadata and an independently captured tree.
    pub fn from_stored(metadata_json: &str, tree: CapturedTree) -> Result<Self, SkillError> {
        if metadata_json.len() > MAX_STORED_METADATA_BYTES {
            return Err(object_error(
                "native_object.metadata_limit",
                "native object metadata exceeds the portable storage limit",
            ));
        }
        let metadata: StoredMetadata = serde_json::from_str(metadata_json).map_err(|_| {
            object_error(
                "native_object.invalid_metadata",
                "native object metadata is not strict version-1 JSON",
            )
        })?;
        if metadata.schema_version != 1 {
            return Err(object_error(
                "native_object.unsupported_version",
                "native object metadata schema version is unsupported",
            ));
        }
        let stored_tree = StoredSkillTree::from_metadata(metadata.tree, tree)?;
        Self::new(
            match metadata.layout {
                StoredLayout::Directory => SkillSourceLayout::Directory,
                StoredLayout::Standalone => SkillSourceLayout::Standalone,
            },
            metadata.original_document_name,
            metadata.native_id,
            stored_tree.tree().clone(),
        )
    }

    /// Returns deterministic metadata JSON stored beside the exact payload tree.
    #[must_use]
    pub fn metadata_json(&self) -> String {
        let metadata = StoredMetadata {
            schema_version: 1,
            layout: match self.layout {
                SkillSourceLayout::Directory => StoredLayout::Directory,
                SkillSourceLayout::Standalone => StoredLayout::Standalone,
            },
            original_document_name: self.original_document_name.clone(),
            native_id: self.native_id.clone(),
            tree: StoredSkillTree::new(self.tree.clone())
                .expect("native object retains a canonical tree")
                .metadata(),
        };
        encode_metadata(&metadata)
    }

    #[must_use]
    pub const fn layout(&self) -> SkillSourceLayout {
        self.layout
    }

    #[must_use]
    pub fn original_document_name(&self) -> &str {
        &self.original_document_name
    }

    #[must_use]
    pub fn native_id(&self) -> &str {
        &self.native_id
    }

    #[must_use]
    pub const fn tree(&self) -> &CapturedTree {
        &self.tree
    }

    #[must_use]
    pub const fn hash(&self) -> &ContentHash {
        &self.hash
    }
}

impl Debug for NativeSkillObject {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSkillObject")
            .field("layout", &self.layout)
            .field("original_document_name_present", &true)
            .field("native_id_present", &true)
            .field("file_count", &self.tree.files.len())
            .field("tree_hash", &self.tree.hash)
            .field("hash", &self.hash)
            .finish()
    }
}

fn validate_metadata(
    layout: SkillSourceLayout,
    original_document_name: &str,
    native_id: &str,
    tree: &CapturedTree,
) -> Result<(), SkillError> {
    let document = PortablePath::parse(original_document_name).map_err(|_| {
        object_error(
            "native_object.invalid_document_name",
            "native object document name must be one portable path segment",
        )
    })?;
    if original_document_name.contains('/') {
        return Err(object_error(
            "native_object.invalid_document_name",
            "native object document name must be one portable path segment",
        ));
    }
    if !tree.files.contains_key(&document) {
        return Err(object_error(
            "native_object.document_missing",
            "native object payload does not contain its original document",
        ));
    }
    if native_id.is_empty() || native_id.len() > 256 || native_id.chars().any(char::is_control) {
        return Err(object_error(
            "native_object.invalid_native_id",
            "native object identity must contain 1 to 256 bytes without controls",
        ));
    }
    if layout == SkillSourceLayout::Standalone && tree.files.len() != 1 {
        return Err(object_error(
            "native_object.standalone_shape",
            "standalone native object payload must contain exactly one file",
        ));
    }
    Ok(())
}

fn hash_native_object(
    layout: SkillSourceLayout,
    original_document_name: &str,
    native_id: &str,
    tree_hash: &ContentHash,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-skill-object-v1\0");
    hasher.update(&[match layout {
        SkillSourceLayout::Directory => 0,
        SkillSourceLayout::Standalone => 1,
    }]);
    write_record(&mut hasher, original_document_name);
    write_record(&mut hasher, native_id);
    write_record(&mut hasher, tree_hash.as_str());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid ContentHash")
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn object_error(code: &'static str, message: &'static str) -> SkillError {
    SkillError::new(code, Path::new("native-object"), message)
}
