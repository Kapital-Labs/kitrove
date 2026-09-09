use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_agent_skills::{
    CaptureLimits, CapturedTree, FileMode, NativeSkillObject, StoredSkillTree, capture_tree,
    hash_tree,
};
use kitrove_agents::{AgentLimits, StoredAgent, StoredNativeAgent};
use kitrove_instructions::{NativeInstructionRegion, StoredInstruction};
use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, HarnessId, NativeVariant,
    PortableContent, PortablePath, ValidationError,
};
use kitrove_prompt_commands::{StoredNativePromptCommand, StoredPromptCommand};

use crate::NativeExtensionObject;
use crate::materialization::MaterializationError;

const MAX_ENVELOPE_METADATA_BYTES: u64 = 4 * 1024 * 1024;

/// Loads one exact manifest-authorized portable MCP server object.
pub fn load_portable_mcp_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredMcpServer, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        MaterializationError::new(
            "object.portable_missing",
            "the selected asset has no portable object",
        )
    })?;
    if asset.kind != AssetKind::Mcp || portable.format != StoredMcpServer::format() {
        return Err(MaterializationError::new(
            "object.portable_format_unsupported",
            "the selected portable MCP format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(portable.root.as_str()),
        envelope_limits(limits),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.portable_unreadable",
            "the selected portable MCP object could not be read safely",
        )
    })?;
    let object = decode_portable_mcp_object(stored).map_err(|()| {
        MaterializationError::new(
            "object.portable_invalid",
            "the selected portable MCP envelope is invalid",
        )
    })?;
    if object.object_hash() != &portable.object_hash {
        return Err(MaterializationError::new(
            "object.portable_hash_mismatch",
            "the selected portable MCP object does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized origin-native MCP entry object.
pub fn load_native_mcp_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredNativeMcpEntry, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let native = asset.native_variants.get(harness).ok_or_else(|| {
        MaterializationError::new(
            "object.native_missing",
            "the selected asset has no native object for the requested harness",
        )
    })?;
    if asset.kind != AssetKind::Mcp || native.format != StoredNativeMcpEntry::format() {
        return Err(MaterializationError::new(
            "object.native_format_unsupported",
            "the selected native MCP format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(native.root.as_str()),
        envelope_limits(limits),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.native_unreadable",
            "the selected native MCP object could not be read safely",
        )
    })?;
    let object = decode_native_mcp_object(stored).map_err(|()| {
        MaterializationError::new(
            "object.native_invalid",
            "the selected native MCP envelope is invalid",
        )
    })?;
    if object.dialect().harness() != *harness || object.object_hash() != &native.object_hash {
        return Err(MaterializationError::new(
            "object.native_hash_mismatch",
            "the selected native MCP object does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized portable agent object.
pub fn load_portable_agent_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredAgent, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        MaterializationError::new(
            "object.portable_missing",
            "the selected asset has no portable object",
        )
    })?;
    if asset.kind != AssetKind::Agent || portable.format != StoredAgent::format() {
        return Err(MaterializationError::new(
            "object.portable_format_unsupported",
            "the selected portable agent format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(portable.root.as_str()),
        envelope_limits(limits),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.portable_unreadable",
            "the selected portable agent could not be read safely",
        )
    })?;
    let object = decode_portable_agent_object(stored, limits).map_err(|()| {
        MaterializationError::new(
            "object.portable_invalid",
            "the selected portable agent envelope is invalid",
        )
    })?;
    if object.object_hash() != &portable.object_hash {
        return Err(MaterializationError::new(
            "object.portable_hash_mismatch",
            "the selected portable agent does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized origin-native agent object.
pub fn load_native_agent_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredNativeAgent, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let native = asset.native_variants.get(harness).ok_or_else(|| {
        MaterializationError::new(
            "object.native_missing",
            "the selected asset has no native object for the requested harness",
        )
    })?;
    if asset.kind != AssetKind::Agent || native.format != StoredNativeAgent::format() {
        return Err(MaterializationError::new(
            "object.native_format_unsupported",
            "the selected native agent format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(native.root.as_str()),
        envelope_limits(limits),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.native_unreadable",
            "the selected native agent could not be read safely",
        )
    })?;
    let object = decode_native_agent_object(stored).map_err(|()| {
        MaterializationError::new(
            "object.native_invalid",
            "the selected native agent envelope is invalid",
        )
    })?;
    if object.object_hash() != &native.object_hash {
        return Err(MaterializationError::new(
            "object.native_hash_mismatch",
            "the selected native agent does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized portable prompt-command object.
pub fn load_portable_prompt_command_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredPromptCommand, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        MaterializationError::new(
            "object.portable_missing",
            "the selected asset has no portable object",
        )
    })?;
    if asset.kind != AssetKind::Command || portable.format != StoredPromptCommand::format() {
        return Err(MaterializationError::new(
            "object.portable_format_unsupported",
            "the selected portable prompt-command format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(portable.root.as_str()),
        envelope_limits(limits),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.portable_unreadable",
            "the selected portable prompt command could not be read safely",
        )
    })?;
    let object = decode_portable_prompt_command_object(stored, limits).map_err(|()| {
        MaterializationError::new(
            "object.portable_invalid",
            "the selected portable prompt-command envelope is invalid",
        )
    })?;
    if object.object_hash() != &portable.object_hash {
        return Err(MaterializationError::new(
            "object.portable_hash_mismatch",
            "the selected portable prompt command does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized origin-native prompt-command object.
pub fn load_native_prompt_command_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredNativePromptCommand, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let native = asset.native_variants.get(harness).ok_or_else(|| {
        MaterializationError::new(
            "object.native_missing",
            "the selected asset has no native object for the requested harness",
        )
    })?;
    if asset.kind != AssetKind::Command || native.format != StoredNativePromptCommand::format() {
        return Err(MaterializationError::new(
            "object.native_format_unsupported",
            "the selected native prompt-command format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(native.root.as_str()),
        envelope_limits(limits),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.native_unreadable",
            "the selected native prompt command could not be read safely",
        )
    })?;
    let object = decode_native_prompt_command_object(stored).map_err(|()| {
        MaterializationError::new(
            "object.native_invalid",
            "the selected native prompt-command envelope is invalid",
        )
    })?;
    if object.object_hash() != &native.object_hash {
        return Err(MaterializationError::new(
            "object.native_hash_mismatch",
            "the selected native prompt command does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized portable standing-instruction object.
pub fn load_portable_instruction_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredInstruction, MaterializationError> {
    load_portable_instruction_object_bounded(
        manifest,
        asset_id,
        environment_root,
        limits,
        envelope_limits(limits).max_total_bytes,
    )
}

/// Loads a portable instruction within one complete envelope allowance.
pub fn load_portable_instruction_object_bounded(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
    max_envelope_bytes: u64,
) -> Result<StoredInstruction, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        MaterializationError::new(
            "object.portable_missing",
            "the selected asset has no portable object",
        )
    })?;
    if asset.kind != AssetKind::Instruction || portable.format != StoredInstruction::format() {
        return Err(MaterializationError::new(
            "object.portable_format_unsupported",
            "the selected portable instruction format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(portable.root.as_str()),
        bounded_envelope_limits(limits, max_envelope_bytes),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.portable_unreadable",
            "the selected portable instruction could not be read safely",
        )
    })?;
    let object = decode_portable_instruction_object(stored, limits).map_err(|()| {
        MaterializationError::new(
            "object.portable_invalid",
            "the selected portable instruction envelope is invalid",
        )
    })?;
    if object.object_hash() != &portable.object_hash {
        return Err(MaterializationError::new(
            "object.portable_hash_mismatch",
            "the selected portable instruction does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized native standing-instruction region.
pub fn load_native_instruction_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<NativeInstructionRegion, MaterializationError> {
    load_native_instruction_object_bounded(
        manifest,
        asset_id,
        harness,
        environment_root,
        limits,
        envelope_limits(limits).max_total_bytes,
    )
}

/// Loads a native instruction region within one complete envelope allowance.
pub fn load_native_instruction_object_bounded(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
    max_envelope_bytes: u64,
) -> Result<NativeInstructionRegion, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let native = asset.native_variants.get(harness).ok_or_else(|| {
        MaterializationError::new(
            "object.native_missing",
            "the selected asset has no native object for the requested harness",
        )
    })?;
    if asset.kind != AssetKind::Instruction || native.format != NativeInstructionRegion::format() {
        return Err(MaterializationError::new(
            "object.native_format_unsupported",
            "the selected native instruction format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(native.root.as_str()),
        bounded_envelope_limits(limits, max_envelope_bytes),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.native_unreadable",
            "the selected native instruction could not be read safely",
        )
    })?;
    let object = decode_native_instruction_object(stored).map_err(|()| {
        MaterializationError::new(
            "object.native_invalid",
            "the selected native instruction envelope is invalid",
        )
    })?;
    if object.object_hash() != &native.object_hash {
        return Err(MaterializationError::new(
            "object.native_hash_mismatch",
            "the selected native instruction does not match manifest authority",
        ));
    }
    Ok(object)
}

/// The role of one independently referenced tree object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    /// Harness-neutral projected content.
    Portable,
    /// Exact content retained for one origin harness.
    Native,
}

/// Loads one exact manifest-authorized portable Agent Skills object.
pub fn load_portable_skill_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<StoredSkillTree, MaterializationError> {
    load_portable_skill_object_bounded(
        manifest,
        asset_id,
        environment_root,
        limits,
        envelope_limits(limits).max_total_bytes,
    )
}

/// Loads one exact manifest-authorized portable object within one complete envelope allowance.
pub fn load_portable_skill_object_bounded(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    environment_root: &Path,
    limits: CaptureLimits,
    max_envelope_bytes: u64,
) -> Result<StoredSkillTree, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    if asset.kind != AssetKind::Skill {
        return Err(MaterializationError::new(
            "object.portable_format_unsupported",
            "the selected portable object format is unsupported",
        ));
    }
    let portable = asset.portable.as_ref().ok_or_else(|| {
        MaterializationError::new(
            "object.portable_missing",
            "the selected asset has no portable object",
        )
    })?;
    if portable.format != "agent-skills/v1" {
        return Err(MaterializationError::new(
            "object.portable_format_unsupported",
            "the selected portable object format is unsupported",
        ));
    }
    let absolute_root = environment_root.join(portable.root.as_str());
    let expanded_limits = bounded_envelope_limits(limits, max_envelope_bytes);
    let stored = capture_tree(&absolute_root, expanded_limits).map_err(|_| {
        MaterializationError::new(
            "object.portable_unreadable",
            "the selected portable object could not be read safely",
        )
    })?;
    let object = decode_portable_object(stored, limits).map_err(|()| {
        MaterializationError::new(
            "object.portable_invalid",
            "the selected portable object envelope is invalid",
        )
    })?;
    if object.tree().hash != portable.object_hash {
        return Err(MaterializationError::new(
            "object.portable_hash_mismatch",
            "the selected portable object does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized native Agent Skills object.
pub fn load_native_skill_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<NativeSkillObject, MaterializationError> {
    load_native_skill_object_bounded(
        manifest,
        asset_id,
        harness,
        environment_root,
        limits,
        envelope_limits(limits).max_total_bytes,
    )
}

/// Loads one exact manifest-authorized native object within one complete envelope allowance.
pub fn load_native_skill_object_bounded(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
    max_envelope_bytes: u64,
) -> Result<NativeSkillObject, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let native = asset.native_variants.get(harness).ok_or_else(|| {
        MaterializationError::new(
            "object.native_missing",
            "the selected asset has no native object for the requested harness",
        )
    })?;
    if asset.kind != AssetKind::Skill || native.format != "kitrove-native-skill-object/v1" {
        return Err(MaterializationError::new(
            "object.native_format_unsupported",
            "the selected native object format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(native.root.as_str()),
        bounded_envelope_limits(limits, max_envelope_bytes),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.native_unreadable",
            "the selected native object could not be read safely",
        )
    })?;
    let object = decode_native_object(stored, limits).map_err(|()| {
        MaterializationError::new(
            "object.native_invalid",
            "the selected native object envelope is invalid",
        )
    })?;
    if object.hash() != &native.object_hash {
        return Err(MaterializationError::new(
            "object.native_hash_mismatch",
            "the selected native object does not match manifest authority",
        ));
    }
    Ok(object)
}

/// Loads one exact manifest-authorized native Pi extension object.
pub fn load_native_extension_object(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<NativeExtensionObject, MaterializationError> {
    load_native_extension_object_bounded(
        manifest,
        asset_id,
        harness,
        environment_root,
        limits,
        envelope_limits(limits).max_total_bytes,
    )
}

/// Loads one native extension object within one complete envelope allowance.
pub fn load_native_extension_object_bounded(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    harness: &HarnessId,
    environment_root: &Path,
    limits: CaptureLimits,
    max_envelope_bytes: u64,
) -> Result<NativeExtensionObject, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("object.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "object.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let native = asset.native_variants.get(harness).ok_or_else(|| {
        MaterializationError::new(
            "object.native_missing",
            "the selected asset has no native object for the requested harness",
        )
    })?;
    if asset.kind != AssetKind::Extension
        || native.format != "kitrove-native-pi-extension-object/v1"
    {
        return Err(MaterializationError::new(
            "object.native_format_unsupported",
            "the selected native extension object format is unsupported",
        ));
    }
    let stored = capture_tree(
        &environment_root.join(native.root.as_str()),
        bounded_envelope_limits(limits, max_envelope_bytes),
    )
    .map_err(|_| {
        MaterializationError::new(
            "object.native_unreadable",
            "the selected native extension object could not be read safely",
        )
    })?;
    let object = decode_native_extension_object(stored, limits).map_err(|()| {
        MaterializationError::new(
            "object.native_invalid",
            "the selected native extension object envelope is invalid",
        )
    })?;
    if object.hash() != &native.object_hash {
        return Err(MaterializationError::new(
            "object.native_hash_mismatch",
            "the selected native extension object does not match manifest authority",
        ));
    }
    Ok(object)
}

/// The verified state of one manifest object reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectState {
    /// The tree exists and has the referenced versioned hash.
    Verified,
    /// The referenced root does not exist.
    Missing,
    /// The tree exists but its versioned hash differs.
    HashMismatch,
    /// A link, reparse point, or special file made the root unsafe to inspect.
    Unsafe,
    /// The root was structurally invalid or exceeded the verification bounds.
    Invalid,
    /// The root could not be read safely.
    Unreadable,
}

/// One redacted result from independent object verification.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectFinding {
    asset_id: AssetId,
    harness: Option<HarnessId>,
    kind: ObjectKind,
    root: PortablePath,
    expected_hash: ContentHash,
    actual_hash: Option<ContentHash>,
    state: ObjectState,
}

impl ObjectFinding {
    /// Returns the asset owning this reference.
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    /// Returns the harness for a native reference.
    #[must_use]
    pub const fn harness(&self) -> Option<&HarnessId> {
        self.harness.as_ref()
    }

    /// Returns the role of this object.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Returns the portable environment-relative root.
    #[must_use]
    pub const fn root(&self) -> &PortablePath {
        &self.root
    }

    /// Returns the manifest-authorized object identity.
    #[must_use]
    pub const fn expected_hash(&self) -> &ContentHash {
        &self.expected_hash
    }

    /// Returns the observed tree identity when capture completed.
    #[must_use]
    pub const fn actual_hash(&self) -> Option<&ContentHash> {
        self.actual_hash.as_ref()
    }

    /// Returns the verification outcome.
    #[must_use]
    pub const fn state(&self) -> ObjectState {
        self.state
    }
}

impl Debug for ObjectFinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectFinding")
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("expected_hash", &self.expected_hash)
            .field("actual_hash", &self.actual_hash)
            .finish()
    }
}

/// Complete, deterministic verification of manifest-referenced tree objects.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectVerification {
    findings: Vec<ObjectFinding>,
}

impl ObjectVerification {
    /// Returns every reference in manifest order, including verified references.
    #[must_use]
    pub fn findings(&self) -> &[ObjectFinding] {
        &self.findings
    }

    /// Returns true only when every referenced object is present and exact.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings
            .iter()
            .all(|finding| finding.state == ObjectState::Verified)
    }
}

impl Debug for ObjectVerification {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let mut counts = [0_usize; 6];
        for finding in &self.findings {
            counts[object_state_index(finding.state)] += 1;
        }
        formatter
            .debug_struct("ObjectVerification")
            .field("total", &self.findings.len())
            .field("verified", &counts[0])
            .field("missing", &counts[1])
            .field("hash_mismatch", &counts[2])
            .field("unsafe", &counts[3])
            .field("invalid", &counts[4])
            .field("unreadable", &counts[5])
            .finish()
    }
}

/// Verifies every portable and native object referenced by manifest authority.
pub fn verify_referenced_objects(
    manifest: &EnvironmentManifest,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<ObjectVerification, ValidationError> {
    manifest.validate()?;
    let mut findings = Vec::new();

    for asset in manifest.assets.values() {
        if let Some(portable) = &asset.portable {
            findings.push(verify_portable_object(
                environment_root,
                limits,
                asset,
                portable,
            ));
        }
        for (harness, native) in &asset.native_variants {
            findings.push(verify_native_object(
                environment_root,
                limits,
                asset,
                harness,
                native,
            ));
        }
    }

    Ok(ObjectVerification { findings })
}

fn verify_native_object(
    environment_root: &Path,
    limits: CaptureLimits,
    asset: &Asset,
    harness: &HarnessId,
    native: &NativeVariant,
) -> ObjectFinding {
    if !matches!(
        (asset.kind, native.format.as_str()),
        (AssetKind::Skill, "kitrove-native-skill-object/v1")
            | (
                AssetKind::Extension,
                "kitrove-native-pi-extension-object/v1"
            )
            | (
                AssetKind::Instruction,
                "kitrove-native-instruction-region/v1"
            )
            | (AssetKind::Command, "kitrove-native-prompt-command/v1")
            | (AssetKind::Agent, "kitrove-native-agent/v1")
            | (AssetKind::Mcp, "kitrove-native-mcp-entry/v1")
    ) {
        return finding(
            &asset.id,
            Some(harness),
            ObjectKind::Native,
            &native.root,
            &native.object_hash,
            None,
            ObjectState::Invalid,
        );
    }

    let absolute_root = environment_root.join(native.root.as_str());
    let (state, actual_hash) = match native.format.as_str() {
        "kitrove-native-skill-object/v1" => {
            inspect_native_root(&absolute_root, limits, &native.object_hash)
        }
        "kitrove-native-pi-extension-object/v1" => {
            inspect_native_extension_root(&absolute_root, limits, &native.object_hash)
        }
        "kitrove-native-instruction-region/v1" => {
            inspect_native_instruction_root(&absolute_root, limits, &native.object_hash)
        }
        "kitrove-native-prompt-command/v1" => {
            inspect_native_prompt_command_root(&absolute_root, limits, &native.object_hash)
        }
        "kitrove-native-agent/v1" => {
            inspect_native_agent_root(&absolute_root, limits, &native.object_hash)
        }
        "kitrove-native-mcp-entry/v1" => {
            inspect_native_mcp_root(&absolute_root, limits, harness, &native.object_hash)
        }
        _ => unreachable!("format was checked above"),
    };
    finding(
        &asset.id,
        Some(harness),
        ObjectKind::Native,
        &native.root,
        &native.object_hash,
        actual_hash,
        state,
    )
}

pub(crate) fn inspect_native_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    let expanded_limits = envelope_limits(limits);
    match capture_tree(absolute_root, expanded_limits) {
        Ok(stored) => match decode_native_object(stored, limits) {
            Ok(object) if object.hash() == expected_hash => {
                (ObjectState::Verified, Some(object.hash().clone()))
            }
            Ok(object) => (ObjectState::HashMismatch, Some(object.hash().clone())),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn decode_native_object(
    mut stored: CapturedTree,
    limits: CaptureLimits,
) -> Result<NativeSkillObject, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    validate_payload_limits(&tree, limits)?;
    NativeSkillObject::from_stored(&metadata_json, tree).map_err(|_| ())
}

pub(crate) fn inspect_native_extension_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    let expanded_limits = envelope_limits(limits);
    match capture_tree(absolute_root, expanded_limits) {
        Ok(stored) => match decode_native_extension_object(stored, limits) {
            Ok(object) if object.hash() == expected_hash => {
                (ObjectState::Verified, Some(object.hash().clone()))
            }
            Ok(object) => (ObjectState::HashMismatch, Some(object.hash().clone())),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn decode_native_extension_object(
    mut stored: CapturedTree,
    limits: CaptureLimits,
) -> Result<NativeExtensionObject, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    validate_payload_limits(&tree, limits)?;
    NativeExtensionObject::from_stored(&metadata_json, tree).map_err(|_| ())
}

pub(crate) fn inspect_native_instruction_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_native_instruction_object(stored) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn decode_native_instruction_object(
    mut stored: CapturedTree,
) -> Result<NativeInstructionRegion, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    NativeInstructionRegion::from_json(&metadata_json).map_err(|_| ())
}

pub(crate) fn inspect_native_prompt_command_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_native_prompt_command_object(stored) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn decode_native_prompt_command_object(
    mut stored: CapturedTree,
) -> Result<StoredNativePromptCommand, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    StoredNativePromptCommand::from_json(&metadata_json).map_err(|_| ())
}

pub(crate) fn inspect_native_agent_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_native_agent_object(stored) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn decode_native_agent_object(
    mut stored: CapturedTree,
) -> Result<StoredNativeAgent, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    StoredNativeAgent::from_json(&metadata_json).map_err(|_| ())
}

pub(crate) fn inspect_native_mcp_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_harness: &HarnessId,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_native_mcp_object(stored) {
            Ok(object)
                if object.dialect().harness() == *expected_harness
                    && object.object_hash() == expected_hash =>
            {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn decode_native_mcp_object(
    mut stored: CapturedTree,
) -> Result<StoredNativeMcpEntry, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    StoredNativeMcpEntry::from_json(&metadata_json).map_err(|_| ())
}

pub(crate) fn decode_portable_instruction_object(
    mut stored: CapturedTree,
    limits: CaptureLimits,
) -> Result<StoredInstruction, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    StoredInstruction::from_json(&metadata_json, instruction_body_limit(limits)).map_err(|_| ())
}

pub(crate) fn decode_portable_prompt_command_object(
    mut stored: CapturedTree,
    limits: CaptureLimits,
) -> Result<StoredPromptCommand, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    let body_limit = usize::try_from(limits.max_file_bytes)
        .unwrap_or(usize::MAX)
        .min(kitrove_prompt_commands::DEFAULT_MAX_PROMPT_BODY_BYTES);
    StoredPromptCommand::from_json(&metadata_json, body_limit).map_err(|_| ())
}

pub(crate) fn decode_portable_agent_object(
    mut stored: CapturedTree,
    limits: CaptureLimits,
) -> Result<StoredAgent, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    let instruction_limit = usize::try_from(limits.max_file_bytes)
        .unwrap_or(usize::MAX)
        .min(AgentLimits::default().max_instructions_bytes);
    StoredAgent::from_json(&metadata_json, instruction_limit).map_err(|_| ())
}

pub(crate) fn decode_portable_mcp_object(mut stored: CapturedTree) -> Result<StoredMcpServer, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    if !tree.files.is_empty() {
        return Err(());
    }
    StoredMcpServer::from_json(&metadata_json).map_err(|_| ())
}

pub(crate) fn decode_portable_object(
    mut stored: CapturedTree,
    limits: CaptureLimits,
) -> Result<StoredSkillTree, ()> {
    let (metadata_json, tree) = decode_stored_root(&mut stored)?;
    validate_payload_limits(&tree, limits)?;
    StoredSkillTree::from_stored(&metadata_json, tree).map_err(|_| ())
}

fn decode_stored_root(stored: &mut CapturedTree) -> Result<(String, CapturedTree), ()> {
    let metadata_path = PortablePath::parse("metadata.json").expect("fixed portable path");
    let metadata = stored.files.remove(&metadata_path).ok_or(())?;
    if metadata.mode != FileMode::Regular {
        return Err(());
    }
    let metadata_json = std::str::from_utf8(&metadata.bytes)
        .map_err(|_| ())?
        .to_owned();
    let mut payload_files = std::collections::BTreeMap::new();
    for (path, file) in std::mem::take(&mut stored.files) {
        let relative = path.as_str().strip_prefix("payload/").ok_or(())?;
        let portable = PortablePath::parse(relative).map_err(|_| ())?;
        if payload_files.insert(portable, file).is_some() {
            return Err(());
        }
    }
    let tree = CapturedTree {
        hash: hash_tree(&payload_files),
        files: payload_files,
    };
    Ok((metadata_json, tree))
}

fn validate_payload_limits(tree: &CapturedTree, limits: CaptureLimits) -> Result<(), ()> {
    if tree.files.len() > limits.max_files {
        return Err(());
    }
    let mut total = 0_u64;
    for file in tree.files.values() {
        let size = u64::try_from(file.bytes.len()).map_err(|_| ())?;
        if size > limits.max_file_bytes {
            return Err(());
        }
        total = total.checked_add(size).ok_or(())?;
        if total > limits.max_total_bytes {
            return Err(());
        }
    }
    Ok(())
}

fn verify_portable_object(
    environment_root: &Path,
    limits: CaptureLimits,
    asset: &Asset,
    portable: &PortableContent,
) -> ObjectFinding {
    let absolute_root = environment_root.join(portable.root.as_str());
    let (state, actual_hash) = match (asset.kind, portable.format.as_str()) {
        (AssetKind::Skill, "agent-skills/v1") => {
            inspect_portable_root(&absolute_root, limits, &portable.object_hash)
        }
        (AssetKind::Instruction, "kitrove-instruction/v1") => {
            inspect_portable_instruction_root(&absolute_root, limits, &portable.object_hash)
        }
        (AssetKind::Command, "kitrove-prompt-command/v1") => {
            inspect_portable_prompt_command_root(&absolute_root, limits, &portable.object_hash)
        }
        (AssetKind::Agent, "kitrove-agent/v1") => {
            inspect_portable_agent_root(&absolute_root, limits, &portable.object_hash)
        }
        (AssetKind::Mcp, "kitrove-mcp-server/v1") => {
            inspect_portable_mcp_root(&absolute_root, limits, &portable.object_hash)
        }
        _ => (ObjectState::Invalid, None),
    };

    finding(
        &asset.id,
        None,
        ObjectKind::Portable,
        &portable.root,
        &portable.object_hash,
        actual_hash,
        state,
    )
}

pub(crate) fn inspect_portable_instruction_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_portable_instruction_object(stored, limits) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn inspect_portable_prompt_command_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_portable_prompt_command_object(stored, limits) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn inspect_portable_agent_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_portable_agent_object(stored, limits) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn inspect_portable_mcp_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    match capture_tree(absolute_root, envelope_limits(limits)) {
        Ok(stored) => match decode_portable_mcp_object(stored) {
            Ok(object) if object.object_hash() == expected_hash => {
                (ObjectState::Verified, Some(object.object_hash().clone()))
            }
            Ok(object) => (
                ObjectState::HashMismatch,
                Some(object.object_hash().clone()),
            ),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) fn inspect_portable_root(
    absolute_root: &Path,
    limits: CaptureLimits,
    expected_hash: &ContentHash,
) -> (ObjectState, Option<ContentHash>) {
    let expanded_limits = envelope_limits(limits);
    match capture_tree(absolute_root, expanded_limits) {
        Ok(stored) => match decode_portable_object(stored, limits) {
            Ok(object) if &object.tree().hash == expected_hash => {
                (ObjectState::Verified, Some(object.tree().hash.clone()))
            }
            Ok(object) => (ObjectState::HashMismatch, Some(object.tree().hash.clone())),
            Err(()) => (ObjectState::Invalid, None),
        },
        Err(error) => (classify_capture_error(absolute_root, error.code()), None),
    }
}

pub(crate) const fn envelope_limits(limits: CaptureLimits) -> CaptureLimits {
    CaptureLimits {
        max_files: limits.max_files.saturating_add(1),
        max_file_bytes: if limits.max_file_bytes > MAX_ENVELOPE_METADATA_BYTES {
            limits.max_file_bytes
        } else {
            MAX_ENVELOPE_METADATA_BYTES
        },
        max_total_bytes: limits
            .max_total_bytes
            .saturating_add(MAX_ENVELOPE_METADATA_BYTES),
    }
}

pub(crate) const fn bounded_envelope_limits(
    limits: CaptureLimits,
    max_envelope_bytes: u64,
) -> CaptureLimits {
    let expanded = envelope_limits(limits);
    CaptureLimits {
        max_files: expanded.max_files,
        max_file_bytes: if expanded.max_file_bytes < max_envelope_bytes {
            expanded.max_file_bytes
        } else {
            max_envelope_bytes
        },
        max_total_bytes: max_envelope_bytes,
    }
}

fn instruction_body_limit(limits: CaptureLimits) -> usize {
    usize::try_from(limits.max_file_bytes).unwrap_or(usize::MAX)
}

fn finding(
    asset_id: &AssetId,
    harness: Option<&HarnessId>,
    kind: ObjectKind,
    root: &PortablePath,
    expected_hash: &ContentHash,
    actual_hash: Option<ContentHash>,
    state: ObjectState,
) -> ObjectFinding {
    ObjectFinding {
        asset_id: asset_id.clone(),
        harness: harness.cloned(),
        kind,
        root: root.clone(),
        expected_hash: expected_hash.clone(),
        actual_hash,
        state,
    }
}

fn classify_capture_error(root: &Path, code: &str) -> ObjectState {
    match code {
        "capture.symlink" | "capture.reparse_point" | "capture.special_file" => ObjectState::Unsafe,
        "capture.root_not_directory"
        | "capture.invalid_root_path"
        | "capture.path_collision"
        | "capture.depth_limit"
        | "capture.file_count_limit"
        | "capture.file_size_limit"
        | "capture.total_size_limit"
        | "capture.request_budget_exhausted" => ObjectState::Invalid,
        "capture.io" if root_metadata_is_missing(root) => ObjectState::Missing,
        _ => ObjectState::Unreadable,
    }
}

fn root_metadata_is_missing(root: &Path) -> bool {
    std::fs::symlink_metadata(root).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

const fn object_state_index(state: ObjectState) -> usize {
    match state {
        ObjectState::Verified => 0,
        ObjectState::Missing => 1,
        ObjectState::HashMismatch => 2,
        ObjectState::Unsafe => 3,
        ObjectState::Invalid => 4,
        ObjectState::Unreadable => 5,
    }
}
