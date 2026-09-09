use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_agent_skills::{
    NativeSkillObject, StoredSkillTree, assess_native_skill_object_risk, assess_portable_tree_risk,
    parse_skill_document,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, ComponentProvenance, ContentClass, ContentHash,
    EnvironmentManifest, Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId,
    Lockfile, NativeVariant, Pack, PortableContent, ProvenanceId, Revision, SchemaVersion, Source,
    SyncConflict, SyncConflictCode, SyncConflictSubject, SyncLimits,
};

use crate::adoption::tier_one_harnesses;
use crate::sync_backend::VerifiedDocumentObject;
use crate::{
    NativeExtensionObject, TierOneCapabilities, derive_lockfile,
    native_extension_adoption::extension_compatibility,
};

const PORTABLE_FORMAT: &str = "agent-skills/v1";
const NATIVE_FORMAT: &str = "kitrove-native-skill-object/v1";

/// A stable, redacted failure to evaluate a semantic merge.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticMergeError {
    code: &'static str,
    message: &'static str,
}

impl SemanticMergeError {
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

impl Debug for SemanticMergeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticMergeError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for SemanticMergeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SemanticMergeError {}

/// Verified immutable Agent Skills objects available to pure merge derivation.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedSkillObjectCatalog {
    portable: BTreeMap<ContentHash, StoredSkillTree>,
    native: BTreeMap<ContentHash, NativeSkillObject>,
    native_extensions: BTreeMap<ContentHash, NativeExtensionObject>,
    documents: BTreeMap<ContentHash, VerifiedDocumentObject>,
}

impl VerifiedSkillObjectCatalog {
    /// Builds a content-addressed catalog and refuses conflicting hash aliases.
    pub fn new(
        portable: impl IntoIterator<Item = StoredSkillTree>,
        native: impl IntoIterator<Item = NativeSkillObject>,
    ) -> Result<Self, SemanticMergeError> {
        Self::new_with_extensions(portable, native, [])
    }

    /// Builds a catalog that also carries verified native extension objects.
    pub fn new_with_extensions(
        portable: impl IntoIterator<Item = StoredSkillTree>,
        native: impl IntoIterator<Item = NativeSkillObject>,
        native_extensions: impl IntoIterator<Item = NativeExtensionObject>,
    ) -> Result<Self, SemanticMergeError> {
        Self::new_with_documents(portable, native, native_extensions, [])
    }

    /// Builds a complete verified object catalog, including JSON-only capability objects.
    pub fn new_with_documents(
        portable: impl IntoIterator<Item = StoredSkillTree>,
        native: impl IntoIterator<Item = NativeSkillObject>,
        native_extensions: impl IntoIterator<Item = NativeExtensionObject>,
        documents: impl IntoIterator<Item = VerifiedDocumentObject>,
    ) -> Result<Self, SemanticMergeError> {
        let mut portable_objects = BTreeMap::new();
        for object in portable {
            let hash = object.tree().hash.clone();
            if portable_objects
                .insert(hash.clone(), object.clone())
                .is_some_and(|prior| prior != object)
            {
                return Err(merge_error(
                    "sync_merge.object_hash_collision",
                    "distinct portable objects claim one content identity",
                ));
            }
        }
        let mut native_objects = BTreeMap::new();
        for object in native {
            let hash = object.hash().clone();
            if native_objects
                .insert(hash.clone(), object.clone())
                .is_some_and(|prior| prior != object)
            {
                return Err(merge_error(
                    "sync_merge.object_hash_collision",
                    "distinct native objects claim one content identity",
                ));
            }
        }
        let mut extension_objects = BTreeMap::new();
        for object in native_extensions {
            let hash = object.hash().clone();
            if extension_objects
                .insert(hash.clone(), object.clone())
                .is_some_and(|prior| prior != object)
            {
                return Err(merge_error(
                    "sync_merge.object_hash_collision",
                    "distinct native extension objects claim one content identity",
                ));
            }
        }
        let mut document_objects = BTreeMap::new();
        for object in documents {
            let hash = object.object_hash().clone();
            if document_objects
                .insert(hash.clone(), object.clone())
                .is_some_and(|prior| prior != object)
            {
                return Err(merge_error(
                    "sync_merge.object_hash_collision",
                    "distinct document objects claim one content identity",
                ));
            }
        }
        Ok(Self {
            portable: portable_objects,
            native: native_objects,
            native_extensions: extension_objects,
            documents: document_objects,
        })
    }

    fn portable(&self, hash: &ContentHash) -> Result<&StoredSkillTree, SemanticMergeError> {
        self.portable.get(hash).ok_or_else(|| {
            merge_error(
                "sync_merge.object_missing",
                "a merged portable component is missing its verified object",
            )
        })
    }

    fn native(&self, hash: &ContentHash) -> Result<&NativeSkillObject, SemanticMergeError> {
        self.native.get(hash).ok_or_else(|| {
            merge_error(
                "sync_merge.object_missing",
                "a merged native component is missing its verified object",
            )
        })
    }

    fn native_extension(
        &self,
        hash: &ContentHash,
    ) -> Result<&NativeExtensionObject, SemanticMergeError> {
        self.native_extensions.get(hash).ok_or_else(|| {
            merge_error(
                "sync_merge.object_missing",
                "a merged native extension component is missing its verified object",
            )
        })
    }

    fn document(&self, hash: &ContentHash) -> Result<&VerifiedDocumentObject, SemanticMergeError> {
        self.documents.get(hash).ok_or_else(|| {
            merge_error(
                "sync_merge.object_missing",
                "a merged document component is missing its verified object",
            )
        })
    }

    fn validate_limits(&self, limits: SyncLimits) -> Result<(), SemanticMergeError> {
        let count = self
            .portable
            .len()
            .checked_add(self.native.len())
            .and_then(|value| value.checked_add(self.native_extensions.len()))
            .and_then(|value| value.checked_add(self.documents.len()))
            .ok_or_else(object_count_error)?;
        if count > limits.max_object_count() {
            return Err(object_count_error());
        }
        let mut total = 0_u64;
        for bytes in self
            .portable
            .values()
            .map(portable_object_bytes)
            .chain(self.native.values().map(native_object_bytes))
            .chain(
                self.native_extensions
                    .values()
                    .map(native_extension_object_bytes),
            )
            .chain(self.documents.values().map(document_object_bytes))
        {
            let bytes = bytes?;
            if bytes > limits.max_object_bytes() {
                return Err(merge_error(
                    "sync_objects.object_bytes_exceeded",
                    "one verified merge object exceeds the configured byte limit",
                ));
            }
            total = total.checked_add(bytes).ok_or_else(total_object_error)?;
            if total > limits.max_total_object_bytes() {
                return Err(total_object_error());
            }
        }
        Ok(())
    }

    pub(crate) fn with_additional(
        &self,
        portable: StoredSkillTree,
        native: NativeSkillObject,
        limits: SyncLimits,
    ) -> Result<Self, SemanticMergeError> {
        let catalog = Self::new_with_documents(
            self.portable.values().cloned().chain([portable]),
            self.native.values().cloned().chain([native]),
            self.native_extensions.values().cloned(),
            self.documents.values().cloned(),
        )?;
        catalog.validate_limits(limits)?;
        Ok(catalog)
    }
}

impl Debug for VerifiedSkillObjectCatalog {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSkillObjectCatalog")
            .field("portable", &self.portable.len())
            .field("native", &self.native.len())
            .field("native_extensions", &self.native_extensions.len())
            .field("documents", &self.documents.len())
            .finish()
    }
}

/// Recomputes credential and executable risk for every object-backed asset.
pub(crate) fn validate_manifest_object_risk(
    manifest: &EnvironmentManifest,
    objects: &VerifiedSkillObjectCatalog,
    limits: SyncLimits,
) -> Result<(), SemanticMergeError> {
    objects.validate_limits(limits)?;
    manifest.validate().map_err(|_| {
        merge_error(
            "sync_merge.manifest_invalid",
            "snapshot risk validation requires validated manifest authority",
        )
    })?;
    for asset in manifest.assets.values() {
        if asset.kind == AssetKind::Extension {
            validate_extension_snapshot_asset(asset, objects)?;
            continue;
        }
        if asset
            .native_variants
            .values()
            .any(|native| native.format == "kitrove-native-pi-extension-object/v1")
        {
            return Err(merge_error(
                "sync_merge.extension_kind_invalid",
                "native extension object authority requires Extension asset kind",
            ));
        }
        if asset.kind != AssetKind::Skill {
            validate_document_snapshot_asset(asset, objects)?;
            continue;
        }
        let mut class = ContentClass::DataOnly;
        if let Some(portable) = &asset.portable {
            let object = objects.portable(&portable.object_hash)?;
            let skill_path = kitrove_model::PortablePath::parse("SKILL.md")
                .expect("SKILL.md is a portable path");
            let document = object.tree().files.get(&skill_path).ok_or_else(|| {
                merge_error(
                    "sync_merge.portable_document_missing",
                    "snapshot portable skill object is missing SKILL.md",
                )
            })?;
            let parsed = parse_skill_document(
                std::path::Path::new("portable-object/SKILL.md"),
                &document.bytes,
            )
            .map_err(|_| {
                merge_error(
                    "sync_merge.portable_document_invalid",
                    "snapshot portable skill document is invalid",
                )
            })?;
            if !parsed.native_fields.is_empty() {
                return Err(merge_error(
                    "sync_merge.portable_document_invalid",
                    "snapshot portable skill document contains native-only fields",
                ));
            }
            class = class.max(assess_portable_tree_risk(object.tree()).map_err(|_| {
                merge_error(
                    "sync_merge.derived_risk_invalid",
                    "snapshot portable object risk could not be recomputed",
                )
            })?);
        }
        for (harness, native) in &asset.native_variants {
            let native_class = assess_native_skill_object_risk(
                objects.native(&native.object_hash)?,
            )
            .map_err(|_| {
                merge_error(
                    "sync_merge.derived_risk_invalid",
                    "snapshot native object risk could not be recomputed",
                )
            })?;
            if native.content_class != native_class {
                return Err(merge_error(
                    "sync_merge.derived_risk_mismatch",
                    "snapshot native object risk does not match manifest authority",
                ));
            }
            let _ = harness;
            class = class.max(native_class);
        }
        if asset.content_class != class {
            return Err(merge_error(
                "sync_merge.derived_risk_mismatch",
                "snapshot asset risk does not match verified objects",
            ));
        }
    }
    Ok(())
}

fn validate_document_snapshot_asset(
    asset: &Asset,
    objects: &VerifiedSkillObjectCatalog,
) -> Result<(), SemanticMergeError> {
    let expected_class = match asset.kind {
        AssetKind::Instruction | AssetKind::Command | AssetKind::Agent | AssetKind::Mcp => {
            ContentClass::AgentActive
        }
        _ if asset.portable.is_none() && asset.native_variants.is_empty() => {
            if asset.content_class == ContentClass::DataOnly {
                return Ok(());
            }
            return Err(document_risk_mismatch());
        }
        _ => return Err(document_format_invalid()),
    };
    if asset.content_class != expected_class
        || asset
            .native_variants
            .values()
            .any(|native| native.content_class != expected_class)
    {
        return Err(document_risk_mismatch());
    }
    if let Some(portable) = &asset.portable {
        let object = objects.document(&portable.object_hash)?;
        let valid = matches!(
            (asset.kind, object),
            (
                AssetKind::Instruction,
                VerifiedDocumentObject::PortableInstruction(_)
            ) | (
                AssetKind::Command,
                VerifiedDocumentObject::PortablePromptCommand(_)
            ) | (AssetKind::Agent, VerifiedDocumentObject::PortableAgent(_))
                | (AssetKind::Mcp, VerifiedDocumentObject::PortableMcp(_))
        );
        if !valid
            || object.kind()
                != crate::portable_snapshot_object_kind(&portable.format)
                    .ok_or_else(document_format_invalid)?
        {
            return Err(document_format_invalid());
        }
        reject_document_credentials(object)?;
    }
    for native in asset.native_variants.values() {
        let object = objects.document(&native.object_hash)?;
        let valid = matches!(
            (asset.kind, object),
            (
                AssetKind::Instruction,
                VerifiedDocumentObject::NativeInstruction(_)
            ) | (
                AssetKind::Command,
                VerifiedDocumentObject::NativePromptCommand(_)
            ) | (AssetKind::Agent, VerifiedDocumentObject::NativeAgent(_))
                | (AssetKind::Mcp, VerifiedDocumentObject::NativeMcp(_))
        );
        if !valid
            || object.kind()
                != crate::native_snapshot_object_kind(&native.format)
                    .ok_or_else(document_format_invalid)?
        {
            return Err(document_format_invalid());
        }
        reject_document_credentials(object)?;
    }
    Ok(())
}

fn reject_document_credentials(object: &VerifiedDocumentObject) -> Result<(), SemanticMergeError> {
    let text = match object {
        VerifiedDocumentObject::PortableInstruction(object) => Some(object.body().as_str()),
        VerifiedDocumentObject::NativeInstruction(object) => {
            std::str::from_utf8(object.exact_region()).ok()
        }
        VerifiedDocumentObject::PortablePromptCommand(object) => {
            Some(object.command().body().as_str())
        }
        VerifiedDocumentObject::NativePromptCommand(object) => {
            std::str::from_utf8(object.observed().exact_bytes()).ok()
        }
        VerifiedDocumentObject::PortableAgent(object) => {
            Some(object.agent().instructions().as_str())
        }
        VerifiedDocumentObject::NativeAgent(object) => {
            std::str::from_utf8(object.observed().exact_bytes()).ok()
        }
        VerifiedDocumentObject::PortableMcp(_) | VerifiedDocumentObject::NativeMcp(_) => None,
    };
    if text.is_some_and(crate::instruction_risk::contains_credential_shaped_value) {
        Err(merge_error(
            "sync_merge.credential_content",
            "snapshot document object contains credential-shaped content",
        ))
    } else {
        Ok(())
    }
}

fn document_format_invalid() -> SemanticMergeError {
    merge_error(
        "sync_merge.document_format_invalid",
        "snapshot document object does not match manifest authority",
    )
}

fn document_risk_mismatch() -> SemanticMergeError {
    merge_error(
        "sync_merge.derived_risk_mismatch",
        "snapshot document object risk does not match manifest authority",
    )
}

pub(crate) fn validate_extension_snapshot_asset(
    asset: &Asset,
    objects: &VerifiedSkillObjectCatalog,
) -> Result<(), SemanticMergeError> {
    if asset.portable.is_some()
        || asset.native_variants.len() != 1
        || !asset.required_bindings.is_empty()
        || asset.provenance.len() != 1
    {
        return Err(merge_error(
            "sync_merge.extension_shape_invalid",
            "a native extension must contain only one Pi native component and its provenance",
        ));
    }
    let native = asset.native_variants.get(&HarnessId::Pi).ok_or_else(|| {
        merge_error(
            "sync_merge.extension_shape_invalid",
            "a native extension must contain one Pi native component",
        )
    })?;
    if native.format != "kitrove-native-pi-extension-object/v1" || native.harness != HarnessId::Pi {
        return Err(merge_error(
            "sync_merge.extension_format_invalid",
            "the native extension component format or harness is invalid",
        ));
    }
    let object = objects.native_extension(&native.object_hash)?;
    if object.harness() != &HarnessId::Pi || object.hash() != &native.object_hash {
        return Err(merge_error(
            "sync_merge.native_harness_mismatch",
            "snapshot native extension object does not match manifest authority",
        ));
    }
    let suffix = object
        .hash()
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(|| merge_error("sync_merge.extension_shape_invalid", "invalid object hash"))?;
    let expected_root = kitrove_model::PortablePath::parse(format!(
        "assets/{}/native/pi/{suffix}",
        asset.id.as_str()
    ))
    .map_err(|_| {
        merge_error(
            "sync_merge.extension_shape_invalid",
            "native extension object root is invalid",
        )
    })?;
    if native.root != expected_root {
        return Err(merge_error(
            "sync_merge.extension_shape_invalid",
            "native extension object root does not match derived authority",
        ));
    }
    let provenance = asset.provenance.get(&native.provenance).ok_or_else(|| {
        merge_error(
            "sync_merge.extension_provenance_invalid",
            "native extension provenance is missing",
        )
    })?;
    let expected_observation =
        crate::native_extension_adoption::verified_native_extension_observation_identity(
            provenance, object,
        );
    if provenance.exact_source_hash() != &object.tree().hash
        || expected_observation
            .as_ref()
            .is_none_or(|identity| identity.as_str() != provenance.revision().as_str())
    {
        return Err(merge_error(
            "sync_merge.extension_provenance_invalid",
            "native extension provenance does not match verified Pi source authority",
        ));
    }
    let class =
        kitrove_agent_skills::assess_native_executable_tree_risk(object.tree()).map_err(|_| {
            merge_error(
                "sync_merge.derived_risk_invalid",
                "snapshot native extension risk could not be recomputed",
            )
        })?;
    if native.content_class != ContentClass::Executable
        || asset.content_class != ContentClass::Executable
        || class != ContentClass::Executable
    {
        return Err(merge_error(
            "sync_merge.derived_risk_mismatch",
            "snapshot native extension risk does not match verified objects",
        ));
    }
    let expected_compatibility = extension_compatibility(object.hash()).map_err(|_| {
        merge_error(
            "sync_merge.derived_fidelity_invalid",
            "snapshot native extension fidelity could not be recomputed",
        )
    })?;
    if asset.compatibility != expected_compatibility {
        return Err(merge_error(
            "sync_merge.derived_fidelity_mismatch",
            "snapshot native extension fidelity does not match verified objects",
        ));
    }
    Ok(())
}

/// A complete non-mutating semantic merge result.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticMergeResult {
    merged_manifest: Option<EnvironmentManifest>,
    merged_lock: Option<Lockfile>,
    conflicts: Vec<SyncConflict>,
}

impl SemanticMergeResult {
    /// Returns the validated merged authority only when no conflicts exist.
    #[must_use]
    pub const fn merged_manifest(&self) -> Option<&EnvironmentManifest> {
        self.merged_manifest.as_ref()
    }

    /// Returns generated state derived from merged manifest authority.
    #[must_use]
    pub const fn merged_lock(&self) -> Option<&Lockfile> {
        self.merged_lock.as_ref()
    }

    /// Returns deterministic bounded conflicts; a non-empty list implies no merged authority.
    #[must_use]
    pub fn conflicts(&self) -> &[SyncConflict] {
        &self.conflicts
    }

    /// Returns true only when validated merged authority is available.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.merged_manifest.is_some()
    }
}

impl Debug for SemanticMergeResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticMergeResult")
            .field("ready", &self.is_ready())
            .field("conflicts", &self.conflicts.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct AssetDraft {
    id: AssetId,
    kind: AssetKind,
    provenance: BTreeMap<ProvenanceId, ComponentProvenance>,
    portable: Option<PortableContent>,
    native_variants: BTreeMap<HarnessId, NativeVariant>,
    required_bindings: BTreeSet<BindingName>,
}

#[derive(Clone, Eq, PartialEq)]
struct PackSourceDraft {
    source: Source,
    revision: Revision,
    exact_source_hash: ContentHash,
}

#[derive(Clone, Eq, PartialEq)]
struct PackDraft {
    id: AssetId,
    source: PackSourceDraft,
    members: BTreeSet<AssetId>,
}

/// Performs a pure three-way semantic merge over validated portable manifests.
pub fn merge_manifests(
    base: &EnvironmentManifest,
    local: &EnvironmentManifest,
    remote: &EnvironmentManifest,
    objects: &VerifiedSkillObjectCatalog,
    capabilities: &TierOneCapabilities,
    limits: SyncLimits,
) -> Result<SemanticMergeResult, SemanticMergeError> {
    objects.validate_limits(limits)?;
    for manifest in [base, local, remote] {
        manifest.validate().map_err(|_| {
            merge_error(
                "sync_merge.manifest_invalid",
                "semantic merge requires three validated manifests",
            )
        })?;
    }
    validate_merged_component_budget(base, local, remote, limits)?;

    let mut conflicts = Vec::new();
    let drafts = merge_assets(base, local, remote, &mut conflicts, limits)?;
    let pack_drafts = merge_packs(base, local, remote, &mut conflicts, limits)?;
    reject_changed_profiles(base, local, remote, &mut conflicts, limits)?;
    if !conflicts.is_empty() {
        sort_conflicts(&mut conflicts);
        return Ok(conflicted(conflicts));
    }

    let mut assets = BTreeMap::new();
    for (id, draft) in drafts {
        let asset = derive_asset(draft, objects, capabilities)?;
        assets.insert(id, asset);
    }
    let required_bindings = merge_bindings(base, local, remote);
    let packs = pack_drafts
        .into_iter()
        .map(|(id, draft)| {
            (
                id,
                Pack {
                    id: draft.id,
                    source: draft.source.source,
                    revision: draft.source.revision,
                    exact_source_hash: draft.source.exact_source_hash,
                    content_hash: ContentHash::digest(b"pending-semantic-pack-merge"),
                    members: draft
                        .members
                        .into_iter()
                        .map(|member| (member, ContentHash::digest(b"pending-pack-member")))
                        .collect(),
                    compatibility: BTreeMap::new(),
                    content_class: ContentClass::DataOnly,
                    required_bindings: BTreeSet::new(),
                },
            )
        })
        .collect();
    let mut merged_manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets,
        packs,
        profiles: base.profiles.clone(),
        required_bindings,
    };
    merged_manifest.refresh_pack_revisions().map_err(|_| {
        merge_error(
            "sync_merge.derived_manifest_invalid",
            "recomputed merged manifest authority is invalid",
        )
    })?;
    let merged_lock = derive_lockfile(&merged_manifest).map_err(|_| {
        merge_error(
            "sync_merge.derived_lock_invalid",
            "generated merged lock state is invalid",
        )
    })?;
    Ok(SemanticMergeResult {
        merged_manifest: Some(merged_manifest),
        merged_lock: Some(merged_lock),
        conflicts: Vec::new(),
    })
}

fn portable_object_bytes(object: &StoredSkillTree) -> Result<u64, SemanticMergeError> {
    object_bytes(object.metadata_json().len(), object.tree())
}

fn native_object_bytes(object: &NativeSkillObject) -> Result<u64, SemanticMergeError> {
    object_bytes(object.metadata_json().len(), object.tree())
}

fn native_extension_object_bytes(
    object: &NativeExtensionObject,
) -> Result<u64, SemanticMergeError> {
    object_bytes(object.metadata_json().len(), object.tree())
}

fn document_object_bytes(object: &VerifiedDocumentObject) -> Result<u64, SemanticMergeError> {
    object
        .to_json()
        .map(|encoded| encoded.len() as u64)
        .map_err(|_| {
            merge_error(
                "sync_merge.object_invalid",
                "a verified document object could not be serialized canonically",
            )
        })
}

fn object_bytes(
    metadata_bytes: usize,
    tree: &kitrove_agent_skills::CapturedTree,
) -> Result<u64, SemanticMergeError> {
    tree.files
        .values()
        .try_fold(metadata_bytes as u64, |total, file| {
            total
                .checked_add(file.bytes.len() as u64)
                .ok_or_else(total_object_error)
        })
}

fn object_count_error() -> SemanticMergeError {
    merge_error(
        "sync_objects.count_exceeded",
        "verified merge object count exceeds the configured limit",
    )
}

fn total_object_error() -> SemanticMergeError {
    merge_error(
        "sync_objects.total_bytes_exceeded",
        "verified merge object bytes exceed the configured aggregate limit",
    )
}

fn merge_assets(
    base: &EnvironmentManifest,
    local: &EnvironmentManifest,
    remote: &EnvironmentManifest,
    conflicts: &mut Vec<SyncConflict>,
    limits: SyncLimits,
) -> Result<BTreeMap<AssetId, AssetDraft>, SemanticMergeError> {
    let ids: BTreeSet<_> = base
        .assets
        .keys()
        .chain(local.assets.keys())
        .chain(remote.assets.keys())
        .cloned()
        .collect();
    let mut drafts = BTreeMap::new();
    for id in ids {
        let base_asset = base.assets.get(&id);
        let local_asset = local.assets.get(&id);
        let remote_asset = remote.assets.get(&id);
        let draft = match (base_asset, local_asset, remote_asset) {
            (Some(base_asset), None, _) | (Some(base_asset), _, None) => {
                let subject = if base_asset.kind == AssetKind::Extension
                    && base_asset.native_variants.contains_key(&HarnessId::Pi)
                {
                    SyncConflictSubject::Native {
                        asset: id.clone(),
                        harness: HarnessId::Pi,
                    }
                } else {
                    SyncConflictSubject::AssetKind { asset: id.clone() }
                };
                push_conflict(
                    conflicts,
                    SyncConflictCode::DeletionUnsupported,
                    subject,
                    limits,
                )?;
                None
            }
            (None, Some(local), Some(remote)) if local != remote => {
                push_conflict(
                    conflicts,
                    SyncConflictCode::DivergentComponent,
                    SyncConflictSubject::AssetKind { asset: id.clone() },
                    limits,
                )?;
                None
            }
            (None, Some(asset), None) | (None, None, Some(asset)) => Some(draft_from_asset(asset)),
            (None, Some(asset), Some(_)) => Some(draft_from_asset(asset)),
            (Some(base), Some(local), Some(remote)) => {
                merge_existing_asset(base, local, remote, conflicts, limits)?
            }
            (None, None, None) => None,
        };
        if let Some(draft) = draft {
            let supported_shape = match draft.kind {
                AssetKind::Skill => {
                    (draft.portable.is_some() || !draft.native_variants.is_empty())
                        && draft
                            .portable
                            .as_ref()
                            .is_none_or(|portable| portable.format == PORTABLE_FORMAT)
                        && draft
                            .native_variants
                            .values()
                            .all(|native| native.format == NATIVE_FORMAT)
                }
                AssetKind::Extension => {
                    draft.portable.is_none()
                        && draft.native_variants.len() == 1
                        && draft
                            .native_variants
                            .get(&HarnessId::Pi)
                            .is_some_and(|native| {
                                native.format == "kitrove-native-pi-extension-object/v1"
                            })
                }
                _ => false,
            };
            if !supported_shape {
                push_conflict(
                    conflicts,
                    SyncConflictCode::ComponentUnsupported,
                    SyncConflictSubject::AssetKind {
                        asset: draft.id.clone(),
                    },
                    limits,
                )?;
            }
            drafts.insert(id, draft);
        }
    }
    Ok(drafts)
}

fn merge_existing_asset(
    base: &Asset,
    local: &Asset,
    remote: &Asset,
    conflicts: &mut Vec<SyncConflict>,
    limits: SyncLimits,
) -> Result<Option<AssetDraft>, SemanticMergeError> {
    let kind = match choose(&base.kind, &local.kind, &remote.kind) {
        Some(kind) => *kind,
        None => {
            push_conflict(
                conflicts,
                SyncConflictCode::DivergentComponent,
                SyncConflictSubject::AssetKind {
                    asset: base.id.clone(),
                },
                limits,
            )?;
            base.kind
        }
    };

    let portable =
        if base.portable.is_some() && (local.portable.is_none() || remote.portable.is_none()) {
            push_conflict(
                conflicts,
                SyncConflictCode::DeletionUnsupported,
                SyncConflictSubject::Portable {
                    asset: base.id.clone(),
                },
                limits,
            )?;
            base.portable.clone()
        } else {
            match choose(&base.portable, &local.portable, &remote.portable) {
                Some(portable) => portable.clone(),
                None => {
                    push_conflict(
                        conflicts,
                        SyncConflictCode::DivergentComponent,
                        SyncConflictSubject::Portable {
                            asset: base.id.clone(),
                        },
                        limits,
                    )?;
                    base.portable.clone()
                }
            }
        };

    let harnesses: BTreeSet<_> = base
        .native_variants
        .keys()
        .chain(local.native_variants.keys())
        .chain(remote.native_variants.keys())
        .cloned()
        .collect();
    let mut native_variants = BTreeMap::new();
    for harness in harnesses {
        let base_value = base.native_variants.get(&harness);
        let local_value = local.native_variants.get(&harness);
        let remote_value = remote.native_variants.get(&harness);
        let selected = if base_value.is_some() && (local_value.is_none() || remote_value.is_none())
        {
            push_conflict(
                conflicts,
                SyncConflictCode::DeletionUnsupported,
                SyncConflictSubject::Native {
                    asset: base.id.clone(),
                    harness: harness.clone(),
                },
                limits,
            )?;
            base_value.map(normalized_native)
        } else {
            let base_component = base_value.map(normalized_native);
            let local_component = local_value.map(normalized_native);
            let remote_component = remote_value.map(normalized_native);
            match choose(&base_component, &local_component, &remote_component) {
                Some(value) => value.clone(),
                None => {
                    push_conflict(
                        conflicts,
                        SyncConflictCode::DivergentComponent,
                        SyncConflictSubject::Native {
                            asset: base.id.clone(),
                            harness: harness.clone(),
                        },
                        limits,
                    )?;
                    base_component
                }
            }
        };
        if let Some(value) = selected {
            native_variants.insert(harness, value.clone());
        }
    }

    let provenance = collect_provenance(
        portable.as_ref(),
        native_variants.values(),
        [base, local, remote],
    )?;
    let required_bindings = merge_set_membership(
        &base.required_bindings,
        &local.required_bindings,
        &remote.required_bindings,
    );
    Ok(Some(AssetDraft {
        id: base.id.clone(),
        kind,
        provenance,
        portable,
        native_variants,
        required_bindings,
    }))
}

fn normalized_native(value: &NativeVariant) -> NativeVariant {
    let mut value = value.clone();
    value.content_class = ContentClass::DataOnly;
    value
}

fn choose<'a, T: Eq>(base: &'a T, local: &'a T, remote: &'a T) -> Option<&'a T> {
    if local == remote {
        Some(local)
    } else if local == base {
        Some(remote)
    } else if remote == base {
        Some(local)
    } else {
        None
    }
}

fn collect_provenance<'a>(
    portable: Option<&PortableContent>,
    native: impl IntoIterator<Item = &'a NativeVariant>,
    sources: [&Asset; 3],
) -> Result<BTreeMap<ProvenanceId, ComponentProvenance>, SemanticMergeError> {
    let ids: BTreeSet<_> = portable
        .into_iter()
        .map(|component| component.provenance.clone())
        .chain(
            native
                .into_iter()
                .map(|component| component.provenance.clone()),
        )
        .collect();
    let mut provenance = BTreeMap::new();
    for id in ids {
        let records: Vec<_> = sources
            .iter()
            .filter_map(|asset| asset.provenance.get(&id))
            .collect();
        let Some(record) = records.first() else {
            return Err(merge_error(
                "sync_merge.provenance_missing",
                "a selected component is missing provenance",
            ));
        };
        if records.iter().any(|candidate| *candidate != *record) {
            return Err(merge_error(
                "sync_merge.provenance_collision",
                "one provenance identity maps to distinct records",
            ));
        }
        provenance.insert(id, (*record).clone());
    }
    Ok(provenance)
}

fn draft_from_asset(asset: &Asset) -> AssetDraft {
    AssetDraft {
        id: asset.id.clone(),
        kind: asset.kind,
        provenance: asset.provenance.clone(),
        portable: asset.portable.clone(),
        native_variants: asset.native_variants.clone(),
        required_bindings: asset.required_bindings.clone(),
    }
}

fn pack_source(pack: &Pack) -> PackSourceDraft {
    PackSourceDraft {
        source: pack.source.clone(),
        revision: pack.revision.clone(),
        exact_source_hash: pack.exact_source_hash.clone(),
    }
}

fn pack_members(pack: &Pack) -> BTreeSet<AssetId> {
    pack.members.keys().cloned().collect()
}

fn merge_packs(
    base: &EnvironmentManifest,
    local: &EnvironmentManifest,
    remote: &EnvironmentManifest,
    conflicts: &mut Vec<SyncConflict>,
    limits: SyncLimits,
) -> Result<BTreeMap<AssetId, PackDraft>, SemanticMergeError> {
    let pack_ids: BTreeSet<_> = base
        .packs
        .keys()
        .chain(local.packs.keys())
        .chain(remote.packs.keys())
        .cloned()
        .collect();
    let mut drafts = BTreeMap::new();
    for id in pack_ids {
        let base_pack = base.packs.get(&id);
        let local_pack = local.packs.get(&id);
        let remote_pack = remote.packs.get(&id);
        if base_pack.is_some() && (local_pack.is_none() || remote_pack.is_none()) {
            push_conflict(
                conflicts,
                SyncConflictCode::DeletionUnsupported,
                SyncConflictSubject::Pack { pack: id.clone() },
                limits,
            )?;
            continue;
        }
        let source = match (base_pack, local_pack, remote_pack) {
            (None, Some(local), Some(remote)) => {
                let local_source = pack_source(local);
                let remote_source = pack_source(remote);
                if local_source != remote_source || pack_members(local) != pack_members(remote) {
                    push_conflict(
                        conflicts,
                        SyncConflictCode::DivergentComponent,
                        SyncConflictSubject::Pack { pack: id.clone() },
                        limits,
                    )?;
                    continue;
                }
                local_source
            }
            (None, Some(pack), None) | (None, None, Some(pack)) => pack_source(pack),
            (Some(base), Some(local), Some(remote)) => {
                let base = pack_source(base);
                let local = pack_source(local);
                let remote = pack_source(remote);
                match choose(&base, &local, &remote) {
                    Some(selected) => selected.clone(),
                    None => {
                        push_conflict(
                            conflicts,
                            SyncConflictCode::DivergentComponent,
                            SyncConflictSubject::Pack { pack: id.clone() },
                            limits,
                        )?;
                        continue;
                    }
                }
            }
            (None, None, None) | (Some(_), None, _) | (Some(_), _, None) => continue,
        };

        let base_members = base_pack.map(pack_members).unwrap_or_default();
        let local_members = local_pack.map(pack_members).unwrap_or_default();
        let remote_members = remote_pack.map(pack_members).unwrap_or_default();
        if base_members
            .iter()
            .any(|member| !local_members.contains(member) || !remote_members.contains(member))
        {
            push_conflict(
                conflicts,
                SyncConflictCode::DeletionUnsupported,
                SyncConflictSubject::Pack { pack: id.clone() },
                limits,
            )?;
            continue;
        }
        let members = base_members
            .iter()
            .chain(&local_members)
            .chain(&remote_members)
            .cloned()
            .collect::<BTreeSet<_>>();
        drafts.insert(
            id.clone(),
            PackDraft {
                id,
                source,
                members,
            },
        );
    }
    Ok(drafts)
}

fn reject_changed_profiles(
    base: &EnvironmentManifest,
    local: &EnvironmentManifest,
    remote: &EnvironmentManifest,
    conflicts: &mut Vec<SyncConflict>,
    limits: SyncLimits,
) -> Result<(), SemanticMergeError> {
    let profile_ids: BTreeSet<_> = base
        .profiles
        .keys()
        .chain(local.profiles.keys())
        .chain(remote.profiles.keys())
        .cloned()
        .collect();
    for id in profile_ids {
        if base.profiles.get(&id) != local.profiles.get(&id)
            || base.profiles.get(&id) != remote.profiles.get(&id)
        {
            let code = if base.profiles.contains_key(&id)
                && (!local.profiles.contains_key(&id) || !remote.profiles.contains_key(&id))
            {
                SyncConflictCode::DeletionUnsupported
            } else {
                SyncConflictCode::ComponentUnsupported
            };
            push_conflict(
                conflicts,
                code,
                SyncConflictSubject::Profile { profile: id },
                limits,
            )?;
        }
    }
    Ok(())
}

fn merge_bindings(
    base: &EnvironmentManifest,
    local: &EnvironmentManifest,
    remote: &EnvironmentManifest,
) -> BTreeSet<BindingName> {
    merge_set_membership(
        &base.required_bindings,
        &local.required_bindings,
        &remote.required_bindings,
    )
}

fn merge_set_membership<T: Clone + Ord>(
    base: &BTreeSet<T>,
    local: &BTreeSet<T>,
    remote: &BTreeSet<T>,
) -> BTreeSet<T> {
    let names: BTreeSet<_> = base.iter().chain(local).chain(remote).cloned().collect();
    names
        .into_iter()
        .filter(|name| {
            let base_has = base.contains(name);
            let local_has = local.contains(name);
            let remote_has = remote.contains(name);
            *choose(&base_has, &local_has, &remote_has)
                .expect("boolean three-way membership cannot diverge")
        })
        .collect()
}

fn derive_asset(
    draft: AssetDraft,
    objects: &VerifiedSkillObjectCatalog,
    capabilities: &TierOneCapabilities,
) -> Result<Asset, SemanticMergeError> {
    if draft.kind == AssetKind::Extension {
        return derive_extension_asset(draft, objects);
    }
    let portable_object = draft
        .portable
        .as_ref()
        .map(|component| objects.portable(&component.object_hash))
        .transpose()?;
    let mut native_objects = BTreeMap::new();
    for (harness, component) in &draft.native_variants {
        native_objects.insert(harness.clone(), objects.native(&component.object_hash)?);
    }

    let mut content_class = ContentClass::DataOnly;
    if let Some(object) = portable_object {
        let skill_path =
            kitrove_model::PortablePath::parse("SKILL.md").expect("SKILL.md is a portable path");
        let document = object.tree().files.get(&skill_path).ok_or_else(|| {
            merge_error(
                "sync_merge.portable_document_missing",
                "merged portable skill object is missing SKILL.md",
            )
        })?;
        let parsed = parse_skill_document(
            std::path::Path::new("portable-object/SKILL.md"),
            &document.bytes,
        )
        .map_err(|_| {
            merge_error(
                "sync_merge.portable_document_invalid",
                "merged portable skill document is invalid",
            )
        })?;
        if !parsed.native_fields.is_empty() {
            return Err(merge_error(
                "sync_merge.portable_document_invalid",
                "merged portable skill document contains native-only fields",
            ));
        }
        content_class =
            content_class.max(assess_portable_tree_risk(object.tree()).map_err(|_| {
                merge_error(
                    "sync_merge.derived_risk_invalid",
                    "merged portable object risk could not be recomputed",
                )
            })?);
    }
    let mut native_classes = BTreeMap::new();
    for (harness, object) in &native_objects {
        let native_class = assess_native_skill_object_risk(object).map_err(|_| {
            merge_error(
                "sync_merge.derived_risk_invalid",
                "merged native object risk could not be recomputed",
            )
        })?;
        content_class = content_class.max(native_class);
        native_classes.insert(harness.clone(), native_class);
    }
    let mut native_variants = draft.native_variants;
    for (harness, class) in native_classes {
        native_variants
            .get_mut(&harness)
            .expect("recomputed native class retains its component")
            .content_class = class;
    }
    let compatibility = derive_compatibility(
        portable_object,
        &native_objects,
        &native_variants,
        capabilities,
    )?;
    let mut asset = Asset {
        id: draft.id,
        kind: draft.kind,
        content_hash: ContentHash::digest(b"pending-semantic-merge"),
        provenance: draft.provenance,
        portable: draft.portable,
        native_variants,
        compatibility,
        content_class,
        required_bindings: draft.required_bindings,
    };
    asset.refresh_content_hash();
    Ok(asset)
}

fn derive_extension_asset(
    draft: AssetDraft,
    objects: &VerifiedSkillObjectCatalog,
) -> Result<Asset, SemanticMergeError> {
    if draft.portable.is_some() || draft.native_variants.len() != 1 {
        return Err(merge_error(
            "sync_merge.extension_shape_invalid",
            "a native extension must have one Pi native variant and no portable component",
        ));
    }
    let component = draft.native_variants.get(&HarnessId::Pi).ok_or_else(|| {
        merge_error(
            "sync_merge.extension_shape_invalid",
            "a native extension must have one Pi native variant",
        )
    })?;
    if component.format != "kitrove-native-pi-extension-object/v1" {
        return Err(merge_error(
            "sync_merge.extension_format_invalid",
            "the native extension format is unsupported",
        ));
    }
    let object = objects.native_extension(&component.object_hash)?;
    if object.harness() != &HarnessId::Pi {
        return Err(merge_error(
            "sync_merge.native_harness_mismatch",
            "the native extension object harness does not match its component",
        ));
    }
    kitrove_agent_skills::assess_native_executable_tree_risk(object.tree()).map_err(|_| {
        merge_error(
            "sync_merge.derived_risk_invalid",
            "merged native extension risk could not be recomputed",
        )
    })?;
    let mut native_variants = draft.native_variants;
    native_variants
        .get_mut(&HarnessId::Pi)
        .expect("Pi component was validated")
        .content_class = ContentClass::Executable;
    let mut asset = Asset {
        id: draft.id,
        kind: AssetKind::Extension,
        content_hash: ContentHash::digest(b"pending-native-extension-merge"),
        provenance: draft.provenance,
        portable: None,
        native_variants,
        compatibility: extension_compatibility(object.hash()).map_err(|_| {
            merge_error(
                "sync_merge.derived_fidelity_invalid",
                "merged native extension fidelity could not be recomputed",
            )
        })?,
        content_class: ContentClass::Executable,
        required_bindings: draft.required_bindings,
    };
    asset.refresh_content_hash();
    validate_extension_snapshot_asset(&asset, objects)?;
    Ok(asset)
}

pub(crate) fn rederive_skill_asset(
    id: AssetId,
    provenance: BTreeMap<ProvenanceId, ComponentProvenance>,
    portable: PortableContent,
    native_variants: BTreeMap<HarnessId, NativeVariant>,
    objects: &VerifiedSkillObjectCatalog,
    capabilities: &TierOneCapabilities,
) -> Result<Asset, SemanticMergeError> {
    derive_asset(
        AssetDraft {
            id,
            kind: AssetKind::Skill,
            provenance,
            portable: Some(portable),
            native_variants,
            required_bindings: BTreeSet::new(),
        },
        objects,
        capabilities,
    )
}

fn derive_compatibility(
    portable: Option<&StoredSkillTree>,
    native_objects: &BTreeMap<HarnessId, &NativeSkillObject>,
    native_components: &BTreeMap<HarnessId, NativeVariant>,
    capabilities: &TierOneCapabilities,
) -> Result<BTreeMap<HarnessId, FidelityResult>, SemanticMergeError> {
    let portable_exact = portable.is_some_and(|portable| {
        native_objects
            .values()
            .all(|native| native.tree().hash == portable.tree().hash)
    });
    let mut results = BTreeMap::new();
    for harness in tier_one_harnesses() {
        let support = capabilities.skill(&harness);
        let mut evidence = support.result.evidence().to_vec();
        let result = if let Some(native) = native_components.get(&harness) {
            evidence.push(FidelityEvidence::new(
                "native.object_hash",
                native.object_hash.as_str(),
            ));
            FidelityResult::exact(
                Fidelity::Native,
                evidence,
                support.result.adapter_version(),
                support.result.harness_version().map(str::to_owned),
            )
        } else if let Some(portable) = portable {
            evidence.push(FidelityEvidence::new(
                "portable.object_hash",
                portable.tree().hash.as_str(),
            ));
            if portable_exact {
                FidelityResult::exact(
                    Fidelity::Portable,
                    evidence,
                    support.result.adapter_version(),
                    support.result.harness_version().map(str::to_owned),
                )
            } else {
                FidelityResult::new(
                    Fidelity::Partial,
                    vec![FidelityReason::new(
                        "sync.native_difference",
                        "origin-native bytes differ from the portable representation",
                    )],
                    evidence,
                    vec![],
                    support.result.adapter_version(),
                    support.result.harness_version().map(str::to_owned),
                )
            }
        } else {
            FidelityResult::new(
                Fidelity::Unsupported,
                vec![FidelityReason::new(
                    "sync.portable_missing",
                    "the merged asset has no portable representation for this target",
                )],
                evidence,
                vec![],
                support.result.adapter_version(),
                support.result.harness_version().map(str::to_owned),
            )
        };
        results.insert(
            harness,
            result.map_err(|_| {
                merge_error(
                    "sync_merge.derived_fidelity_invalid",
                    "merged target fidelity could not be recomputed",
                )
            })?,
        );
    }
    Ok(results)
}

fn validate_merged_component_budget(
    base: &EnvironmentManifest,
    local: &EnvironmentManifest,
    remote: &EnvironmentManifest,
    limits: SyncLimits,
) -> Result<(), SemanticMergeError> {
    let asset_ids: BTreeSet<_> = base
        .assets
        .keys()
        .chain(local.assets.keys())
        .chain(remote.assets.keys())
        .collect();
    let pack_ids: BTreeSet<_> = base
        .packs
        .keys()
        .chain(local.packs.keys())
        .chain(remote.packs.keys())
        .collect();
    let profile_ids: BTreeSet<_> = base
        .profiles
        .keys()
        .chain(local.profiles.keys())
        .chain(remote.profiles.keys())
        .collect();
    let bindings: BTreeSet<_> = base
        .required_bindings
        .iter()
        .chain(&local.required_bindings)
        .chain(&remote.required_bindings)
        .collect();
    let mut count = asset_ids
        .len()
        .checked_add(pack_ids.len())
        .and_then(|value| value.checked_add(profile_ids.len()))
        .and_then(|value| value.checked_add(bindings.len()))
        .ok_or_else(component_limit_error)?;
    if count > limits.max_components() {
        return Err(component_limit_error());
    }
    for id in asset_ids {
        let assets = [
            base.assets.get(id),
            local.assets.get(id),
            remote.assets.get(id),
        ];
        let has_portable = assets
            .iter()
            .flatten()
            .any(|asset| asset.portable.is_some());
        let native_harnesses: BTreeSet<_> = assets
            .iter()
            .flatten()
            .flat_map(|asset| asset.native_variants.keys())
            .collect();
        count = count
            .checked_add(usize::from(has_portable))
            .and_then(|value| value.checked_add(native_harnesses.len()))
            .ok_or_else(component_limit_error)?;
        if count > limits.max_components() {
            return Err(component_limit_error());
        }
    }
    let pack_member_edges: BTreeSet<_> = [base, local, remote]
        .into_iter()
        .flat_map(|manifest| {
            manifest.packs.iter().flat_map(|(pack, value)| {
                value
                    .members
                    .keys()
                    .map(|member| (pack.clone(), member.clone()))
            })
        })
        .collect();
    count = count
        .checked_add(pack_member_edges.len())
        .ok_or_else(component_limit_error)?;
    if count > limits.max_components() {
        return Err(component_limit_error());
    }
    Ok(())
}

fn component_limit_error() -> SemanticMergeError {
    merge_error(
        "sync_merge.component_limit_exceeded",
        "semantic component count exceeds the configured limit",
    )
}

fn push_conflict(
    conflicts: &mut Vec<SyncConflict>,
    code: SyncConflictCode,
    subject: SyncConflictSubject,
    limits: SyncLimits,
) -> Result<(), SemanticMergeError> {
    if conflicts.len() >= limits.max_conflicts() {
        return Err(merge_error(
            "sync_merge.conflict_limit_exceeded",
            "semantic conflict count exceeds the configured limit",
        ));
    }
    conflicts.push(SyncConflict { code, subject });
    Ok(())
}

fn sort_conflicts(conflicts: &mut [SyncConflict]) {
    conflicts.sort_by_key(conflict_key);
}

fn conflict_key(conflict: &SyncConflict) -> (String, u8, String, &'static str) {
    let (identity, component, detail) = match &conflict.subject {
        SyncConflictSubject::AssetKind { asset } => (asset.as_str().to_owned(), 0, String::new()),
        SyncConflictSubject::Portable { asset } => (asset.as_str().to_owned(), 1, String::new()),
        SyncConflictSubject::Native { asset, harness } => {
            (asset.as_str().to_owned(), 2, harness.as_str().to_owned())
        }
        SyncConflictSubject::Pack { pack } => (pack.as_str().to_owned(), 3, String::new()),
        SyncConflictSubject::Profile { profile } => (profile.as_str().to_owned(), 4, String::new()),
        SyncConflictSubject::RequiredBinding { binding } => {
            (binding.as_str().to_owned(), 5, String::new())
        }
        SyncConflictSubject::Bootstrap => (String::new(), 6, String::new()),
    };
    (identity, component, detail, conflict.code.as_str())
}

fn conflicted(conflicts: Vec<SyncConflict>) -> SemanticMergeResult {
    SemanticMergeResult {
        merged_manifest: None,
        merged_lock: None,
        conflicts,
    }
}

fn merge_error(code: &'static str, message: &'static str) -> SemanticMergeError {
    SemanticMergeError::new(code, message)
}

#[cfg(test)]
mod tests {
    use kitrove_model::{BindingName, HarnessScope, PortablePath, Revision};

    use super::*;

    fn extension_fixture() -> (EnvironmentManifest, VerifiedSkillObjectCatalog) {
        let plan = crate::native_extension_adoption::tests::ready_plan();
        let catalog =
            VerifiedSkillObjectCatalog::new_with_extensions([], [], [plan.native_object().clone()])
                .unwrap();
        (plan.proposed_manifest().clone(), catalog)
    }

    #[test]
    fn snapshot_validation_refuses_extension_object_under_non_extension_kind() {
        let (mut manifest, catalog) = extension_fixture();
        let asset = manifest.assets.values_mut().next().unwrap();
        asset.kind = AssetKind::Skill;
        asset.refresh_content_hash();
        assert_eq!(
            validate_manifest_object_risk(&manifest, &catalog, SyncLimits::default())
                .unwrap_err()
                .code(),
            "sync_merge.extension_kind_invalid"
        );
    }

    #[test]
    fn snapshot_validation_refuses_extension_portable_binding_and_root_substitution() {
        let (manifest, catalog) = extension_fixture();

        let mut with_portable = manifest.clone();
        let portable_manifest = kitrove_testkit::portable_manifest();
        let portable_asset = portable_manifest.assets.values().next().unwrap();
        let portable = portable_asset.portable.clone().unwrap();
        let portable_provenance = portable_asset
            .provenance
            .get(&portable.provenance)
            .unwrap()
            .clone();
        let asset = with_portable.assets.values_mut().next().unwrap();
        asset
            .provenance
            .insert(portable.provenance.clone(), portable_provenance);
        asset.portable = Some(portable);
        with_portable
            .assets
            .values_mut()
            .next()
            .unwrap()
            .refresh_content_hash();
        assert_eq!(
            validate_manifest_object_risk(&with_portable, &catalog, SyncLimits::default())
                .unwrap_err()
                .code(),
            "sync_merge.extension_shape_invalid"
        );

        let mut with_binding = manifest.clone();
        let binding = BindingName::parse("native_token").unwrap();
        with_binding.required_bindings.insert(binding.clone());
        let asset = with_binding.assets.values_mut().next().unwrap();
        asset.required_bindings.insert(binding);
        asset.refresh_content_hash();
        assert_eq!(
            validate_manifest_object_risk(&with_binding, &catalog, SyncLimits::default())
                .unwrap_err()
                .code(),
            "sync_merge.extension_shape_invalid"
        );

        let mut with_wrong_root = manifest;
        let asset = with_wrong_root.assets.values_mut().next().unwrap();
        asset.native_variants.get_mut(&HarnessId::Pi).unwrap().root =
            PortablePath::parse("assets/native-review/native/pi/forged").unwrap();
        asset.refresh_content_hash();
        assert_eq!(
            validate_manifest_object_risk(&with_wrong_root, &catalog, SyncLimits::default())
                .unwrap_err()
                .code(),
            "sync_merge.extension_shape_invalid"
        );
    }

    #[test]
    fn snapshot_validation_recomputes_and_refuses_forged_extension_provenance() {
        let (mut manifest, catalog) = extension_fixture();
        let asset = manifest.assets.values_mut().next().unwrap();
        let native = asset.native_variants.get_mut(&HarnessId::Pi).unwrap();
        let prior = asset.provenance.get(&native.provenance).unwrap();
        let forged = ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Pi,
                origin: PortablePath::parse("observations/pi/user/forged/review.ts").unwrap(),
            },
            Revision::parse(ContentHash::digest(b"forged-observation").as_str()).unwrap(),
            prior.exact_source_hash().clone(),
            Some(HarnessScope::User),
        )
        .unwrap();
        native.provenance = forged.provenance_id();
        asset.provenance = BTreeMap::from([(native.provenance.clone(), forged)]);
        asset.refresh_content_hash();
        assert_eq!(
            validate_manifest_object_risk(&manifest, &catalog, SyncLimits::default())
                .unwrap_err()
                .code(),
            "sync_merge.extension_provenance_invalid"
        );
    }

    #[test]
    fn direct_semantic_merge_refuses_forged_extension_authority() {
        let (manifest, catalog) = extension_fixture();
        for mutation in ["root", "binding", "provenance"] {
            let mut forged = manifest.clone();
            let asset = forged.assets.values_mut().next().unwrap();
            let native = asset.native_variants.get_mut(&HarnessId::Pi).unwrap();
            match mutation {
                "root" => {
                    native.root =
                        PortablePath::parse("assets/native-review/native/pi/forged").unwrap();
                }
                "binding" => {
                    let binding = BindingName::parse("native_token").unwrap();
                    asset.required_bindings.insert(binding.clone());
                    forged.required_bindings.insert(binding);
                }
                "provenance" => {
                    let prior = asset.provenance.get(&native.provenance).unwrap();
                    let forged_provenance = ComponentProvenance::new(
                        Source::Harness {
                            harness: HarnessId::Pi,
                            origin: PortablePath::parse("observations/pi/project/forged.ts")
                                .unwrap(),
                        },
                        prior.revision().clone(),
                        prior.exact_source_hash().clone(),
                        Some(HarnessScope::User),
                    )
                    .unwrap();
                    native.provenance = forged_provenance.provenance_id();
                    asset.provenance =
                        BTreeMap::from([(native.provenance.clone(), forged_provenance)]);
                }
                _ => unreachable!(),
            }
            asset.refresh_content_hash();

            let error = merge_manifests(
                &EnvironmentManifest {
                    schema_version: manifest.schema_version,
                    assets: BTreeMap::new(),
                    packs: BTreeMap::new(),
                    profiles: BTreeMap::new(),
                    required_bindings: BTreeSet::new(),
                },
                &forged,
                &EnvironmentManifest {
                    schema_version: manifest.schema_version,
                    assets: BTreeMap::new(),
                    packs: BTreeMap::new(),
                    profiles: BTreeMap::new(),
                    required_bindings: BTreeSet::new(),
                },
                &catalog,
                &crate::adoption::tests::capabilities(),
                SyncLimits::default(),
            )
            .unwrap_err();
            assert!(matches!(
                error.code(),
                "sync_merge.extension_shape_invalid" | "sync_merge.extension_provenance_invalid"
            ));
        }
    }
}
