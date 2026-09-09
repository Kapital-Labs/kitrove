use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

use kitrove_agent_skills::{
    CaptureLimits, CaptureMeter, CapturedTree, SkillError, StoredSkillTree,
    assess_native_executable_tree_risk, capture_standalone_tree_metered, capture_tree_metered,
};
use kitrove_model::{AssetId, ContentClass, ContentHash, HarnessId, PortablePath};
use serde::{Deserialize, Serialize};

const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;

/// A supported authoring shape for an origin-native extension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeExtensionLayout {
    /// One directly discovered TypeScript file.
    Standalone,
    /// One directly discovered directory whose entrypoint is `index.ts`.
    Directory,
}

pub(crate) fn valid_native_extension_identity(
    layout: NativeExtensionLayout,
    entrypoint: &str,
    native_id: &str,
    destination_leaf: &str,
) -> bool {
    if AssetId::parse(native_id).is_err() {
        return false;
    }
    match layout {
        NativeExtensionLayout::Standalone => {
            entrypoint == format!("{native_id}.ts") && destination_leaf == entrypoint
        }
        NativeExtensionLayout::Directory => {
            entrypoint == "index.ts" && destination_leaf == native_id
        }
    }
}

/// A safely capturable native extension source.
#[derive(Clone, Eq, PartialEq)]
pub enum NativeExtensionSource {
    Standalone { path: PathBuf },
    Directory { path: PathBuf },
}

/// Immutable evidence captured from one native extension source.
#[derive(Clone, Eq, PartialEq)]
pub struct CapturedNativeExtension {
    pub layout: NativeExtensionLayout,
    pub entrypoint: String,
    pub exact: CapturedTree,
    pub content_class: ContentClass,
}

/// A versioned, origin-native extension object. Payload bytes are never parsed or executed.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeExtensionObject {
    harness: HarnessId,
    layout: NativeExtensionLayout,
    entrypoint: String,
    native_id: String,
    tree: CapturedTree,
    hash: ContentHash,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredMetadata {
    schema_version: u32,
    harness: HarnessId,
    layout: StoredLayout,
    entrypoint: String,
    native_id: String,
    tree_metadata: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredLayout {
    Standalone,
    Directory,
}

/// Captures a Pi extension using bounded, no-follow filesystem primitives.
pub fn capture_pi_extension(
    source: &NativeExtensionSource,
    limits: CaptureLimits,
) -> Result<CapturedNativeExtension, SkillError> {
    let mut usage = kitrove_agent_skills::CaptureUsage::default();
    capture_pi_extension_metered(source, limits, &mut usage)
}

/// Captures a Pi extension while charging a caller-owned request-global meter.
pub fn capture_pi_extension_metered(
    source: &NativeExtensionSource,
    limits: CaptureLimits,
    meter: &mut dyn CaptureMeter,
) -> Result<CapturedNativeExtension, SkillError> {
    let captured = (|| match source {
        NativeExtensionSource::Standalone { path } => {
            validate_standalone_name(path)?;
            let (entrypoint, exact) = capture_standalone_tree_metered(path, limits, meter)?;
            finish_capture(NativeExtensionLayout::Standalone, &entrypoint, exact)
        }
        NativeExtensionSource::Directory { path } => {
            validate_directory_name(path)?;
            let exact = capture_tree_metered(path, limits, meter)?;
            finish_capture(NativeExtensionLayout::Directory, "index.ts", exact)
        }
    })();
    captured.map_err(redact_capture_error)
}

impl Debug for NativeExtensionSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionSource")
            .field(
                "layout",
                &match self {
                    Self::Standalone { .. } => NativeExtensionLayout::Standalone,
                    Self::Directory { .. } => NativeExtensionLayout::Directory,
                },
            )
            .finish_non_exhaustive()
    }
}

impl Debug for CapturedNativeExtension {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedNativeExtension")
            .field("layout", &self.layout)
            .field("entrypoint_present", &true)
            .field("file_count", &self.exact.files.len())
            .field("tree_hash", &self.exact.hash)
            .field("content_class", &self.content_class)
            .finish()
    }
}

fn finish_capture(
    layout: NativeExtensionLayout,
    entrypoint: &str,
    exact: CapturedTree,
) -> Result<CapturedNativeExtension, SkillError> {
    validate_shape(layout, entrypoint, &exact)?;
    let content_class = assess_native_executable_tree_risk(&exact)?;
    Ok(CapturedNativeExtension {
        layout,
        entrypoint: entrypoint.to_owned(),
        exact,
        content_class,
    })
}

impl NativeExtensionObject {
    pub fn new(
        harness: HarnessId,
        layout: NativeExtensionLayout,
        entrypoint: impl Into<String>,
        native_id: impl Into<String>,
        tree: CapturedTree,
    ) -> Result<Self, SkillError> {
        if harness != HarnessId::Pi {
            return Err(object_error(
                "native_extension.unsupported_harness",
                "native extension objects currently support only Pi",
            ));
        }
        let entrypoint = entrypoint.into();
        let native_id = native_id.into();
        let stored_tree = StoredSkillTree::new(tree)?;
        validate_shape(layout, &entrypoint, stored_tree.tree())?;
        validate_native_id(&native_id)?;
        assess_native_executable_tree_risk(stored_tree.tree())?;
        let tree = stored_tree.tree().clone();
        let hash = hash_native_extension(&harness, layout, &entrypoint, &native_id, &tree.hash);
        let object = Self {
            harness,
            layout,
            entrypoint,
            native_id,
            tree,
            hash,
        };
        if object.metadata_json().len() > MAX_METADATA_BYTES {
            return Err(object_error(
                "native_extension.metadata_limit",
                "native extension metadata exceeds the portable storage limit",
            ));
        }
        Ok(object)
    }

    pub fn from_stored(metadata_json: &str, tree: CapturedTree) -> Result<Self, SkillError> {
        if metadata_json.len() > MAX_METADATA_BYTES {
            return Err(object_error(
                "native_extension.metadata_limit",
                "native extension metadata exceeds the portable storage limit",
            ));
        }
        let metadata: StoredMetadata = serde_json::from_str(metadata_json).map_err(|_| {
            object_error(
                "native_extension.invalid_metadata",
                "native extension metadata is not strict version-1 JSON",
            )
        })?;
        if metadata.schema_version != 1 {
            return Err(object_error(
                "native_extension.unsupported_version",
                "native extension metadata schema version is unsupported",
            ));
        }
        let stored = StoredSkillTree::from_stored(&metadata.tree_metadata, tree)?;
        Self::new(
            metadata.harness,
            match metadata.layout {
                StoredLayout::Standalone => NativeExtensionLayout::Standalone,
                StoredLayout::Directory => NativeExtensionLayout::Directory,
            },
            metadata.entrypoint,
            metadata.native_id,
            stored.tree().clone(),
        )
    }

    #[must_use]
    pub fn metadata_json(&self) -> String {
        let metadata = StoredMetadata {
            schema_version: 1,
            harness: self.harness.clone(),
            layout: match self.layout {
                NativeExtensionLayout::Standalone => StoredLayout::Standalone,
                NativeExtensionLayout::Directory => StoredLayout::Directory,
            },
            entrypoint: self.entrypoint.clone(),
            native_id: self.native_id.clone(),
            tree_metadata: StoredSkillTree::new(self.tree.clone())
                .expect("native extension retains a canonical tree")
                .metadata_json(),
        };
        let mut encoded = serde_json::to_string_pretty(&metadata)
            .expect("native extension metadata contains only serializable values");
        encoded.push('\n');
        encoded
    }

    #[must_use]
    pub const fn harness(&self) -> &HarnessId {
        &self.harness
    }
    #[must_use]
    pub const fn layout(&self) -> NativeExtensionLayout {
        self.layout
    }
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
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

impl Debug for NativeExtensionObject {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeExtensionObject")
            .field("harness", &self.harness)
            .field("layout", &self.layout)
            .field("entrypoint_present", &true)
            .field("native_id_present", &true)
            .field("file_count", &self.tree.files.len())
            .field("tree_hash", &self.tree.hash)
            .field("hash", &self.hash)
            .finish()
    }
}

fn validate_standalone_name(path: &Path) -> Result<(), SkillError> {
    let valid = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".ts") && name != "index.d.ts");
    if valid {
        Ok(())
    } else {
        Err(extension_error(
            "extension.standalone_not_typescript",
            path,
            "standalone Pi extensions must be direct TypeScript files",
        ))
    }
}

fn validate_directory_name(path: &Path) -> Result<(), SkillError> {
    if path.file_name().and_then(|name| name.to_str()).is_some() {
        Ok(())
    } else {
        Err(extension_error(
            "extension.invalid_directory",
            path,
            "Pi extension directory must have a UTF-8 name",
        ))
    }
}

fn validate_shape(
    layout: NativeExtensionLayout,
    entrypoint: &str,
    tree: &CapturedTree,
) -> Result<(), SkillError> {
    let entry = PortablePath::parse(entrypoint).map_err(|_| {
        object_error(
            "native_extension.invalid_entrypoint",
            "native extension entrypoint must be one portable path segment",
        )
    })?;
    if entrypoint.contains('/') || !entrypoint.ends_with(".ts") || entrypoint == "index.d.ts" {
        return Err(object_error(
            "native_extension.invalid_entrypoint",
            "native extension entrypoint must be one direct TypeScript file",
        ));
    }
    if !tree.files.contains_key(&entry) {
        return Err(object_error(
            "native_extension.entrypoint_missing",
            "native extension payload does not contain its entrypoint",
        ));
    }
    match layout {
        NativeExtensionLayout::Standalone if tree.files.len() != 1 => Err(object_error(
            "native_extension.standalone_shape",
            "standalone native extension payload must contain exactly one file",
        )),
        NativeExtensionLayout::Directory if entrypoint != "index.ts" => Err(object_error(
            "native_extension.directory_entrypoint",
            "directory native extension entrypoint must be index.ts",
        )),
        _ => Ok(()),
    }
}

fn validate_native_id(native_id: &str) -> Result<(), SkillError> {
    if native_id.is_empty() || native_id.len() > 256 || native_id.chars().any(char::is_control) {
        Err(object_error(
            "native_extension.invalid_native_id",
            "native extension identity must contain 1 to 256 bytes without controls",
        ))
    } else {
        Ok(())
    }
}

fn hash_native_extension(
    harness: &HarnessId,
    layout: NativeExtensionLayout,
    entrypoint: &str,
    native_id: &str,
    tree_hash: &ContentHash,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-native-pi-extension-object-v1\0");
    write_record(&mut hasher, harness.as_str());
    hasher.update(&[match layout {
        NativeExtensionLayout::Standalone => 0,
        NativeExtensionLayout::Directory => 1,
    }]);
    write_record(&mut hasher, entrypoint);
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
    SkillError::new(code, Path::new("native-extension-object"), message)
}

fn extension_error(code: &'static str, path: &Path, message: &'static str) -> SkillError {
    SkillError::new(code, path, message)
}

fn redact_capture_error(error: SkillError) -> SkillError {
    SkillError::new(
        error.code(),
        Path::new("native-extension-source"),
        "native extension capture was refused",
    )
}
