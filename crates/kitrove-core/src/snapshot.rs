use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use kitrove_agents::{StoredAgent, StoredNativeAgent};
use kitrove_instructions::{NativeInstructionRegion, StoredInstruction};
use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    ContentHash, EnvironmentManifest, Lockfile, ObjectDescriptor, Revision, SnapshotDigest,
    SnapshotObjectKind, SyncLimits,
};
use kitrove_prompt_commands::{StoredNativePromptCommand, StoredPromptCommand};
use serde::{Deserialize, Serialize};

use crate::{derive_lockfile, derive_manifest_revision};

const SNAPSHOT_FRAME: &[u8] = b"kitrove-portable-snapshot-v1\0";

/// Maps one supported portable object format to its synchronization envelope kind.
#[must_use]
pub fn portable_snapshot_object_kind(format: &str) -> Option<SnapshotObjectKind> {
    match format {
        "agent-skills/v1" => Some(SnapshotObjectKind::PortableSkillTree),
        format if format == StoredInstruction::format() => {
            Some(SnapshotObjectKind::PortableInstruction)
        }
        format if format == StoredPromptCommand::format() => {
            Some(SnapshotObjectKind::PortablePromptCommand)
        }
        format if format == StoredAgent::format() => Some(SnapshotObjectKind::PortableAgent),
        format if format == StoredMcpServer::format() => Some(SnapshotObjectKind::PortableMcp),
        _ => None,
    }
}

/// Maps one supported native object format to its synchronization envelope kind.
#[must_use]
pub fn native_snapshot_object_kind(format: &str) -> Option<SnapshotObjectKind> {
    match format {
        "kitrove-native-skill-object/v1" => Some(SnapshotObjectKind::NativeSkillObject),
        "kitrove-native-pi-extension-object/v1" => Some(SnapshotObjectKind::NativeExtensionObject),
        format if format == NativeInstructionRegion::format() => {
            Some(SnapshotObjectKind::NativeInstruction)
        }
        format if format == StoredNativePromptCommand::format() => {
            Some(SnapshotObjectKind::NativePromptCommand)
        }
        format if format == StoredNativeAgent::format() => Some(SnapshotObjectKind::NativeAgent),
        format if format == StoredNativeMcpEntry::format() => Some(SnapshotObjectKind::NativeMcp),
        _ => None,
    }
}

/// A stable, non-authored failure to construct or verify a portable snapshot.
#[derive(Clone, Eq, PartialEq)]
pub struct SnapshotError {
    code: &'static str,
    message: &'static str,
}

impl SnapshotError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the compiled non-authored explanation.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SnapshotError {}

/// A canonical, validated portable synchronization envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct PortableSnapshotV1 {
    manifest: EnvironmentManifest,
    manifest_toml: String,
    manifest_revision: Revision,
    lockfile: Lockfile,
    lock_json: String,
    lock_digest: ContentHash,
    objects: BTreeSet<ObjectDescriptor>,
    snapshot_digest: SnapshotDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSnapshot {
    schema_version: u32,
    manifest_toml: String,
    manifest_revision: Revision,
    lock_json: String,
    lock_digest: ContentHash,
    objects: Vec<ObjectDescriptor>,
    snapshot_digest: SnapshotDigest,
}

#[derive(Serialize)]
struct PersistedSnapshotRef<'a> {
    schema_version: u32,
    manifest_toml: &'a str,
    manifest_revision: &'a Revision,
    lock_json: &'a str,
    lock_digest: &'a ContentHash,
    objects: &'a BTreeSet<ObjectDescriptor>,
    snapshot_digest: &'a SnapshotDigest,
}

impl PortableSnapshotV1 {
    /// Constructs a canonical envelope from typed manifest authority and an exact object catalog.
    pub fn new(
        manifest: EnvironmentManifest,
        objects: BTreeSet<ObjectDescriptor>,
        limits: SyncLimits,
    ) -> Result<Self, SnapshotError> {
        manifest.validate().map_err(|_| {
            snapshot_error(
                "sync_snapshot.manifest_invalid",
                "snapshot manifest authority is invalid",
            )
        })?;
        validate_component_count(&manifest, limits)?;

        let manifest_toml = manifest.to_toml().map_err(|_| {
            snapshot_error(
                "sync_snapshot.manifest_invalid",
                "snapshot manifest authority is invalid",
            )
        })?;
        if manifest_toml.len() as u64 > limits.max_manifest_bytes() {
            return Err(snapshot_error(
                "sync_snapshot.manifest_too_large",
                "snapshot manifest exceeds the configured byte limit",
            ));
        }
        let manifest_revision = derive_manifest_revision(&manifest).map_err(|_| {
            snapshot_error(
                "sync_snapshot.manifest_invalid",
                "snapshot manifest authority is invalid",
            )
        })?;

        let lockfile = derive_lockfile(&manifest).map_err(|_| {
            snapshot_error(
                "sync_snapshot.lock_derivation_failed",
                "snapshot lockfile could not be derived from manifest authority",
            )
        })?;
        let lock_json = lockfile.to_json().map_err(|_| {
            snapshot_error(
                "sync_snapshot.lock_derivation_failed",
                "snapshot lockfile could not be derived from manifest authority",
            )
        })?;
        if lock_json.len() as u64 > limits.max_lock_bytes() {
            return Err(snapshot_error(
                "sync_snapshot.lock_too_large",
                "snapshot lockfile exceeds the configured byte limit",
            ));
        }

        validate_object_catalog(&manifest, &objects, limits)?;
        let lock_digest = ContentHash::digest(lock_json.as_bytes());
        let snapshot_digest = calculate_snapshot_digest(
            &manifest_toml,
            &manifest_revision,
            &lock_json,
            &lock_digest,
            &objects,
        );
        let snapshot = Self {
            manifest,
            manifest_toml,
            manifest_revision,
            lockfile,
            lock_json,
            lock_digest,
            objects,
            snapshot_digest,
        };
        snapshot.ensure_encoded_limit(limits)?;
        Ok(snapshot)
    }

    /// Parses and verifies one strict canonical version-1 snapshot envelope.
    pub fn from_json(input: &str, limits: SyncLimits) -> Result<Self, SnapshotError> {
        if input.len() as u64 > limits.max_snapshot_bytes() {
            return Err(snapshot_error(
                "sync_snapshot.too_large",
                "snapshot envelope exceeds the configured byte limit",
            ));
        }
        let persisted: PersistedSnapshot = serde_json::from_str(input).map_err(|_| {
            snapshot_error(
                "sync_snapshot.invalid_json",
                "snapshot envelope is not valid strict JSON",
            )
        })?;
        if persisted.schema_version != 1 {
            return Err(snapshot_error(
                "sync_snapshot.unsupported_version",
                "snapshot envelope schema version is unsupported",
            ));
        }
        if persisted.manifest_toml.len() as u64 > limits.max_manifest_bytes() {
            return Err(snapshot_error(
                "sync_snapshot.manifest_too_large",
                "snapshot manifest exceeds the configured byte limit",
            ));
        }
        if persisted.lock_json.len() as u64 > limits.max_lock_bytes() {
            return Err(snapshot_error(
                "sync_snapshot.lock_too_large",
                "snapshot lockfile exceeds the configured byte limit",
            ));
        }
        if persisted.objects.len() > limits.max_object_count() {
            return Err(snapshot_error(
                "sync_objects.count_exceeded",
                "object descriptor count exceeds the configured limit",
            ));
        }
        let object_count = persisted.objects.len();
        let objects: BTreeSet<_> = persisted.objects.into_iter().collect();
        if objects.len() != object_count {
            return Err(snapshot_error(
                "sync_objects.duplicate_descriptor",
                "snapshot contains a duplicate object descriptor",
            ));
        }

        let manifest = EnvironmentManifest::from_toml(&persisted.manifest_toml).map_err(|_| {
            snapshot_error(
                "sync_snapshot.manifest_invalid",
                "snapshot manifest authority is invalid",
            )
        })?;
        if manifest.to_toml().map_err(|_| {
            snapshot_error(
                "sync_snapshot.manifest_invalid",
                "snapshot manifest authority is invalid",
            )
        })? != persisted.manifest_toml
        {
            return Err(snapshot_error(
                "sync_snapshot.manifest_noncanonical",
                "snapshot manifest bytes are not canonical",
            ));
        }

        let snapshot = Self::new(manifest, objects, limits)?;
        if snapshot.manifest_revision != persisted.manifest_revision {
            return Err(snapshot_error(
                "sync_snapshot.manifest_revision_mismatch",
                "snapshot manifest revision does not match its canonical bytes",
            ));
        }
        let supplied_lock = Lockfile::from_json(&persisted.lock_json).map_err(|_| {
            snapshot_error("sync_snapshot.lock_invalid", "snapshot lockfile is invalid")
        })?;
        if supplied_lock.to_json().map_err(|_| {
            snapshot_error("sync_snapshot.lock_invalid", "snapshot lockfile is invalid")
        })? != persisted.lock_json
        {
            return Err(snapshot_error(
                "sync_snapshot.lock_noncanonical",
                "snapshot lockfile bytes are not canonical",
            ));
        }
        if snapshot.lockfile != supplied_lock {
            return Err(snapshot_error(
                "sync_snapshot.lock_mismatch",
                "snapshot lockfile does not match manifest authority",
            ));
        }
        if snapshot.lock_digest != persisted.lock_digest {
            return Err(snapshot_error(
                "sync_snapshot.lock_digest_mismatch",
                "snapshot lock digest does not match its canonical bytes",
            ));
        }
        if snapshot.snapshot_digest != persisted.snapshot_digest {
            return Err(snapshot_error(
                "sync_snapshot.digest_mismatch",
                "snapshot digest does not match the canonical envelope",
            ));
        }
        if snapshot.to_json(limits)? != input {
            return Err(snapshot_error(
                "sync_snapshot.noncanonical",
                "snapshot envelope JSON is not canonical",
            ));
        }
        Ok(snapshot)
    }

    /// Serializes the already-verified envelope in its only canonical JSON form.
    pub fn to_json(&self, limits: SyncLimits) -> Result<String, SnapshotError> {
        validate_object_catalog(&self.manifest, &self.objects, limits)?;
        let persisted = PersistedSnapshotRef {
            schema_version: 1,
            manifest_toml: &self.manifest_toml,
            manifest_revision: &self.manifest_revision,
            lock_json: &self.lock_json,
            lock_digest: &self.lock_digest,
            objects: &self.objects,
            snapshot_digest: &self.snapshot_digest,
        };
        let mut encoded = serde_json::to_string_pretty(&persisted).map_err(|_| {
            snapshot_error(
                "sync_snapshot.serialize",
                "snapshot envelope serialization failed",
            )
        })?;
        encoded.push('\n');
        if encoded.len() as u64 > limits.max_snapshot_bytes() {
            return Err(snapshot_error(
                "sync_snapshot.too_large",
                "snapshot envelope exceeds the configured byte limit",
            ));
        }
        Ok(encoded)
    }

    /// Returns validated manifest authority.
    #[must_use]
    pub const fn manifest(&self) -> &EnvironmentManifest {
        &self.manifest
    }

    /// Returns the exact canonical manifest bytes carried by the envelope.
    #[must_use]
    pub fn manifest_toml(&self) -> &str {
        &self.manifest_toml
    }

    /// Returns the revision derived from the canonical manifest bytes.
    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    /// Returns the generated lockfile derived from manifest authority.
    #[must_use]
    pub const fn lockfile(&self) -> &Lockfile {
        &self.lockfile
    }

    /// Returns the exact canonical generated lockfile bytes carried by the envelope.
    #[must_use]
    pub fn lock_json(&self) -> &str {
        &self.lock_json
    }

    /// Returns the digest of the canonical generated lockfile bytes.
    #[must_use]
    pub const fn lock_digest(&self) -> &ContentHash {
        &self.lock_digest
    }

    /// Returns the exact sorted immutable object catalog.
    #[must_use]
    pub const fn objects(&self) -> &BTreeSet<ObjectDescriptor> {
        &self.objects
    }

    /// Returns the identity of the complete canonical snapshot envelope.
    #[must_use]
    pub const fn snapshot_digest(&self) -> &SnapshotDigest {
        &self.snapshot_digest
    }

    fn ensure_encoded_limit(&self, limits: SyncLimits) -> Result<(), SnapshotError> {
        self.to_json(limits).map(|_| ())
    }
}

impl Debug for PortableSnapshotV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortableSnapshotV1")
            .field("manifest_bytes", &self.manifest_toml.len())
            .field("lock_bytes", &self.lock_json.len())
            .field("objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

fn validate_component_count(
    manifest: &EnvironmentManifest,
    limits: SyncLimits,
) -> Result<(), SnapshotError> {
    let mut count = manifest
        .assets
        .len()
        .checked_add(manifest.packs.len())
        .and_then(|value| value.checked_add(manifest.profiles.len()))
        .and_then(|value| value.checked_add(manifest.required_bindings.len()))
        .ok_or_else(component_limit_error)?;
    for asset in manifest.assets.values() {
        count = count
            .checked_add(usize::from(asset.portable.is_some()))
            .and_then(|value| value.checked_add(asset.native_variants.len()))
            .ok_or_else(component_limit_error)?;
    }
    if count > limits.max_components() {
        return Err(component_limit_error());
    }
    Ok(())
}

fn component_limit_error() -> SnapshotError {
    snapshot_error(
        "sync_snapshot.component_limit_exceeded",
        "snapshot semantic component count exceeds the configured limit",
    )
}

fn validate_object_catalog(
    manifest: &EnvironmentManifest,
    objects: &BTreeSet<ObjectDescriptor>,
    limits: SyncLimits,
) -> Result<(), SnapshotError> {
    if objects.len() > limits.max_object_count() {
        return Err(snapshot_error(
            "sync_objects.count_exceeded",
            "object descriptor count exceeds the configured limit",
        ));
    }
    let mut expected = BTreeMap::new();
    for asset in manifest.assets.values() {
        if let Some(portable) = &asset.portable {
            let kind = portable_snapshot_object_kind(&portable.format).ok_or_else(|| {
                snapshot_error(
                    "sync_snapshot.object_format_unsupported",
                    "snapshot manifest references an unsupported portable object format",
                )
            })?;
            insert_expected_object(
                &mut expected,
                portable.root.as_str(),
                kind,
                &portable.object_hash,
            )?;
        }
        for native in asset.native_variants.values() {
            let kind = native_snapshot_object_kind(&native.format).ok_or_else(|| {
                snapshot_error(
                    "sync_snapshot.object_format_unsupported",
                    "snapshot manifest references an unsupported native object format",
                )
            })?;
            insert_expected_object(
                &mut expected,
                native.root.as_str(),
                kind,
                &native.object_hash,
            )?;
        }
    }

    let mut total = 0_u64;
    for object in objects {
        if object.encoded_len() > limits.max_object_bytes() {
            return Err(snapshot_error(
                "sync_objects.object_bytes_exceeded",
                "one object descriptor exceeds the configured byte limit",
            ));
        }
        total = total.checked_add(object.encoded_len()).ok_or_else(|| {
            snapshot_error(
                "sync_objects.total_bytes_exceeded",
                "aggregate object descriptor bytes overflow the configured limit",
            )
        })?;
        if total > limits.max_total_object_bytes() {
            return Err(snapshot_error(
                "sync_objects.total_bytes_exceeded",
                "aggregate object descriptor bytes exceed the configured limit",
            ));
        }
        match expected.remove(object.root().as_str()) {
            Some((kind, hash)) if kind == object.kind() && &hash == object.object_hash() => {}
            _ => {
                return Err(snapshot_error(
                    "sync_snapshot.object_catalog_mismatch",
                    "snapshot object catalog does not exactly match manifest authority",
                ));
            }
        }
    }
    if !expected.is_empty() {
        return Err(snapshot_error(
            "sync_snapshot.object_catalog_mismatch",
            "snapshot object catalog does not exactly match manifest authority",
        ));
    }
    Ok(())
}

fn insert_expected_object(
    expected: &mut BTreeMap<String, (SnapshotObjectKind, ContentHash)>,
    root: &str,
    kind: SnapshotObjectKind,
    hash: &ContentHash,
) -> Result<(), SnapshotError> {
    if expected
        .insert(root.to_owned(), (kind, hash.clone()))
        .is_some()
    {
        return Err(snapshot_error(
            "sync_snapshot.duplicate_object_root",
            "manifest object references claim one portable root more than once",
        ));
    }
    Ok(())
}

fn calculate_snapshot_digest(
    manifest_toml: &str,
    manifest_revision: &Revision,
    lock_json: &str,
    lock_digest: &ContentHash,
    objects: &BTreeSet<ObjectDescriptor>,
) -> SnapshotDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAPSHOT_FRAME);
    hash_text(&mut hasher, manifest_toml);
    hash_text(&mut hasher, manifest_revision.as_str());
    hash_text(&mut hasher, lock_json);
    hash_text(&mut hasher, lock_digest.as_str());
    hasher.update(&(objects.len() as u64).to_le_bytes());
    for object in objects {
        hasher.update(&[match object.kind() {
            SnapshotObjectKind::PortableSkillTree => 1,
            SnapshotObjectKind::NativeSkillObject => 2,
            SnapshotObjectKind::NativeExtensionObject => 3,
            SnapshotObjectKind::PortableInstruction => 4,
            SnapshotObjectKind::NativeInstruction => 5,
            SnapshotObjectKind::PortablePromptCommand => 6,
            SnapshotObjectKind::NativePromptCommand => 7,
            SnapshotObjectKind::PortableAgent => 8,
            SnapshotObjectKind::NativeAgent => 9,
            SnapshotObjectKind::PortableMcp => 10,
            SnapshotObjectKind::NativeMcp => 11,
        }]);
        hash_text(&mut hasher, object.root().as_str());
        hash_text(&mut hasher, object.object_hash().as_str());
        hasher.update(&object.encoded_len().to_le_bytes());
    }
    SnapshotDigest::parse(format!("snapshot:blake3:{}", hasher.finalize().to_hex()))
        .expect("BLAKE3 produces a valid snapshot digest")
}

fn hash_text(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn snapshot_error(code: &'static str, message: &'static str) -> SnapshotError {
    SnapshotError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kitrove_instructions::{InstructionBody, StoredInstruction};
    use kitrove_model::{
        Asset, AssetId, AssetKind, ComponentProvenance, ContentClass, PortableContent,
        PortablePath, Revision, SchemaVersion, Source,
    };

    fn instruction_snapshot() -> (
        EnvironmentManifest,
        ObjectDescriptor,
        crate::sync_backend::VerifiedDocumentObject,
    ) {
        let id = AssetId::parse("shared-instructions").unwrap();
        let object =
            StoredInstruction::new(InstructionBody::parse("Keep changes small.\n", 1024).unwrap());
        let provenance = ComponentProvenance::new(
            Source::Local {
                path: PortablePath::parse("sources/shared-instructions.md").unwrap(),
            },
            Revision::parse("revision-1").unwrap(),
            ContentHash::digest(b"instruction-source"),
            None,
        )
        .unwrap();
        let provenance_id = provenance.provenance_id();
        let root = PortablePath::parse(format!("objects/{}/portable", id.as_str())).unwrap();
        let document =
            crate::sync_backend::VerifiedDocumentObject::PortableInstruction(object.clone());
        let envelope =
            crate::VerifiedObjectEnvelope::document(root.clone(), document.clone()).unwrap();
        let mut asset = Asset {
            id: id.clone(),
            kind: AssetKind::Instruction,
            content_hash: ContentHash::digest(b"pending"),
            provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
            portable: Some(PortableContent {
                format: StoredInstruction::format().to_owned(),
                root,
                object_hash: object.object_hash().clone(),
                provenance: provenance_id,
            }),
            native_variants: BTreeMap::new(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::AgentActive,
            required_bindings: BTreeSet::new(),
        };
        asset.refresh_content_hash();
        (
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::from([(id, asset)]),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: BTreeSet::new(),
            },
            envelope.descriptor().clone(),
            document,
        )
    }

    #[test]
    fn snapshot_catalog_uses_the_exact_portable_document_kind() {
        let (manifest, descriptor, _) = instruction_snapshot();
        assert_eq!(descriptor.kind(), SnapshotObjectKind::PortableInstruction);
        PortableSnapshotV1::new(
            manifest.clone(),
            BTreeSet::from([descriptor.clone()]),
            SyncLimits::default(),
        )
        .unwrap();

        let wrong = ObjectDescriptor::new(
            SnapshotObjectKind::PortableSkillTree,
            descriptor.root().clone(),
            descriptor.object_hash().clone(),
            descriptor.encoded_len(),
        )
        .unwrap();
        let error =
            PortableSnapshotV1::new(manifest, BTreeSet::from([wrong]), SyncLimits::default())
                .unwrap_err();
        assert_eq!(error.code(), "sync_snapshot.object_catalog_mismatch");
    }

    #[test]
    fn synchronization_format_registry_covers_every_supported_object_codec() {
        assert_eq!(
            portable_snapshot_object_kind("agent-skills/v1"),
            Some(SnapshotObjectKind::PortableSkillTree)
        );
        assert_eq!(
            portable_snapshot_object_kind(StoredInstruction::format()),
            Some(SnapshotObjectKind::PortableInstruction)
        );
        assert_eq!(
            portable_snapshot_object_kind(StoredPromptCommand::format()),
            Some(SnapshotObjectKind::PortablePromptCommand)
        );
        assert_eq!(
            portable_snapshot_object_kind(StoredAgent::format()),
            Some(SnapshotObjectKind::PortableAgent)
        );
        assert_eq!(
            portable_snapshot_object_kind(StoredMcpServer::format()),
            Some(SnapshotObjectKind::PortableMcp)
        );
        assert_eq!(
            native_snapshot_object_kind("kitrove-native-skill-object/v1"),
            Some(SnapshotObjectKind::NativeSkillObject)
        );
        assert_eq!(
            native_snapshot_object_kind("kitrove-native-pi-extension-object/v1"),
            Some(SnapshotObjectKind::NativeExtensionObject)
        );
        assert_eq!(
            native_snapshot_object_kind(NativeInstructionRegion::format()),
            Some(SnapshotObjectKind::NativeInstruction)
        );
        assert_eq!(
            native_snapshot_object_kind(StoredNativePromptCommand::format()),
            Some(SnapshotObjectKind::NativePromptCommand)
        );
        assert_eq!(
            native_snapshot_object_kind(StoredNativeAgent::format()),
            Some(SnapshotObjectKind::NativeAgent)
        );
        assert_eq!(
            native_snapshot_object_kind(StoredNativeMcpEntry::format()),
            Some(SnapshotObjectKind::NativeMcp)
        );
        assert_eq!(portable_snapshot_object_kind("unknown/v1"), None);
        assert_eq!(native_snapshot_object_kind("unknown/v1"), None);
    }

    #[test]
    fn snapshot_document_risk_is_recomputed_from_verified_content() {
        let (manifest, _, document) = instruction_snapshot();
        let catalog =
            crate::VerifiedSkillObjectCatalog::new_with_documents([], [], [], [document]).unwrap();
        crate::merge::validate_manifest_object_risk(&manifest, &catalog, SyncLimits::default())
            .unwrap();

        let credential = StoredInstruction::new(
            InstructionBody::parse("api_key = sk-secret-value-1234567890\n", 1024).unwrap(),
        );
        let mut hostile = manifest;
        let asset = hostile.assets.values_mut().next().unwrap();
        asset.portable.as_mut().unwrap().object_hash = credential.object_hash().clone();
        asset.refresh_content_hash();
        let catalog = crate::VerifiedSkillObjectCatalog::new_with_documents(
            [],
            [],
            [],
            [crate::sync_backend::VerifiedDocumentObject::PortableInstruction(credential)],
        )
        .unwrap();
        let error =
            crate::merge::validate_manifest_object_risk(&hostile, &catalog, SyncLimits::default())
                .unwrap_err();
        assert_eq!(error.code(), "sync_merge.credential_content");
    }
}
