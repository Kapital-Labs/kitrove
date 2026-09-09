use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::{Component, Path};

use kitrove_adapter_api::TargetPolicy;
use kitrove_agent_skills::{
    CaptureLimits, CapturedTree, FileMode, SkillSource, SkillSourceLayout, StoredSkillTree,
    assess_portable_tree_risk, capture_skill_source, hash_skill_source, parse_skill_document,
};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, DeploymentReceipt, EnvironmentManifest,
    Fidelity, HarnessScope, LocalState, NormalizedDestination, PortablePath, ReceiptId, Revision,
};

use crate::derive_manifest_revision;
use crate::read_only_fs::RegularFileMode;

/// Stable redacted planning or rendering failure.
#[derive(Clone, Eq, PartialEq)]
pub struct MaterializationError {
    code: &'static str,
    message: &'static str,
}

impl MaterializationError {
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

impl Debug for MaterializationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for MaterializationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for MaterializationError {}

/// Refuses asset classes that have no authorized materialization workflow.
///
/// Native extensions use the separate exact-object trust and extension apply
/// workflow. Callers must run this guard before the portable-skill path reads
/// machine-local policy or resolves a destination.
pub fn guard_asset_materialization(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
) -> Result<(), MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("apply.manifest_invalid", "manifest authority is invalid")
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "apply.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    match asset.kind {
        AssetKind::Skill => Ok(()),
        AssetKind::Extension => Err(MaterializationError::new(
            "apply.executable_trust_required",
            "native extension materialization requires an explicit executable trust workflow",
        )),
        _ => Err(MaterializationError::new(
            "apply.asset_kind_unsupported",
            "the selected asset kind has no materialization workflow",
        )),
    }
}

/// Read-only exact state of one planned destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestinationObservation {
    Absent,
    Present {
        layout: SkillSourceLayout,
        rendered_hash: ContentHash,
    },
    Unsafe,
}

/// Ownership-safe apply behavior selected by planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyDisposition {
    Install,
    NoOp,
    Restore,
    ManagedUpdate,
    /// Remove one exact receipt-backed target while retaining portable authority.
    Remove,
}

impl ApplyDisposition {
    pub(crate) const fn requires_quarantine(self) -> bool {
        matches!(self, Self::ManagedUpdate | Self::Remove)
    }

    pub(crate) const fn materializes_target(self) -> bool {
        !matches!(self, Self::Remove)
    }
}

/// Complete non-mutating apply plan with every later commit precondition.
#[derive(Clone, Eq, PartialEq)]
pub struct ApplyPlan {
    policy: TargetPolicy,
    asset_id: AssetId,
    harness: kitrove_model::HarnessId,
    scope: HarnessScope,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    receipt_id: ReceiptId,
    manifest_revision: Revision,
    disposition: ApplyDisposition,
    observed_receipt: Option<DeploymentReceipt>,
    observed_destination: DestinationObservation,
    rendered: RenderedSkill,
    proposed_receipt: DeploymentReceipt,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

impl ApplyPlan {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn harness(&self) -> &kitrove_model::HarnessId {
        &self.harness
    }

    #[must_use]
    pub const fn scope(&self) -> HarnessScope {
        self.scope
    }

    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    #[must_use]
    pub const fn relative_destination(&self) -> &PortablePath {
        &self.relative_destination
    }

    #[must_use]
    pub const fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedSkill {
        &self.rendered
    }

    #[must_use]
    pub const fn proposed_receipt(&self) -> &DeploymentReceipt {
        &self.proposed_receipt
    }

    #[must_use]
    pub const fn proposed_local_state(&self) -> &LocalState {
        &self.proposed_local_state
    }

    pub(crate) fn observed_local_state_text(&self) -> &str {
        &self.observed_local_state_text
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    #[must_use]
    pub const fn observed_receipt(&self) -> Option<&DeploymentReceipt> {
        self.observed_receipt.as_ref()
    }

    #[must_use]
    pub const fn observed_destination(&self) -> &DestinationObservation {
        &self.observed_destination
    }

    /// Whether two plans differ only in machine-local state advanced by earlier batch items.
    #[must_use]
    pub fn same_confirmed_authority(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.asset_id == other.asset_id
            && self.harness == other.harness
            && self.scope == other.scope
            && self.destination == other.destination
            && self.relative_destination == other.relative_destination
            && self.receipt_id == other.receipt_id
            && self.manifest_revision == other.manifest_revision
            && self.disposition == other.disposition
            && self.observed_receipt == other.observed_receipt
            && self.observed_destination == other.observed_destination
            && self.rendered == other.rendered
            && self.proposed_receipt == other.proposed_receipt
    }
}

impl Debug for ApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplyPlan")
            .field("policy_line", &self.policy.policy_line)
            .field("harness", &self.harness)
            .field("scope", &self.scope)
            .field("disposition", &self.disposition)
            .field("manifest_revision", &self.manifest_revision)
            .field("rendered_hash", self.rendered.rendered_hash())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Complete pure render result before any destination staging occurs.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedSkill {
    layout: SkillSourceLayout,
    document_name: String,
    package_name: AssetId,
    tree: CapturedTree,
    rendered_hash: ContentHash,
}

impl RenderedSkill {
    #[must_use]
    pub const fn layout(&self) -> SkillSourceLayout {
        self.layout
    }

    #[must_use]
    pub fn document_name(&self) -> &str {
        &self.document_name
    }

    #[must_use]
    pub const fn package_name(&self) -> &AssetId {
        &self.package_name
    }

    #[must_use]
    pub const fn tree(&self) -> &CapturedTree {
        &self.tree
    }

    #[must_use]
    pub const fn rendered_hash(&self) -> &ContentHash {
        &self.rendered_hash
    }

    #[must_use]
    pub fn contains_executable_mode(&self) -> bool {
        self.tree
            .files
            .values()
            .any(|file| file.mode == FileMode::Executable)
    }
}

impl Debug for RenderedSkill {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedSkill")
            .field("layout", &self.layout)
            .field("file_count", &self.tree.files.len())
            .field("rendered_hash", &self.rendered_hash)
            .finish()
    }
}

/// Applies one pure adapter policy to a verified portable object.
pub fn render_portable_skill(
    object: &StoredSkillTree,
    policy: &TargetPolicy,
) -> Result<RenderedSkill, MaterializationError> {
    if policy.policy_line.harness() != policy.harness {
        return Err(MaterializationError::new(
            "materialization.policy_invalid",
            "the selected target policy line does not belong to its harness",
        ));
    }
    if policy.layout != SkillSourceLayout::Directory || policy.document_name.as_str() != "SKILL.md"
    {
        return Err(MaterializationError::new(
            "materialization.layout_unsupported",
            "the selected target layout is not supported for materialization",
        ));
    }
    let document_path = policy.document_name.clone();
    let document = object.tree().files.get(&document_path).ok_or_else(|| {
        MaterializationError::new(
            "materialization.document_missing",
            "the portable object has no target principal document",
        )
    })?;
    let parsed =
        parse_skill_document(Path::new("rendered/SKILL.md"), &document.bytes).map_err(|_| {
            MaterializationError::new(
                "materialization.document_invalid",
                "the portable principal document is invalid",
            )
        })?;
    let tree = object.tree().clone();
    let rendered_hash = hash_skill_source(policy.layout, policy.document_name.as_str(), &tree);
    Ok(RenderedSkill {
        layout: policy.layout,
        document_name: policy.document_name.as_str().to_owned(),
        package_name: parsed.manifest.name,
        tree,
        rendered_hash,
    })
}

/// Resolves a reviewed relative policy beneath one absolute trusted anchor.
pub fn resolve_target_destination(
    anchor: &Path,
    policy: &TargetPolicy,
    package_name: &AssetId,
) -> Result<NormalizedDestination, MaterializationError> {
    validate_target_anchor(anchor)?;
    let destination = anchor
        .join(policy.relative_root.as_str())
        .join(package_name.as_str());
    normalized_destination_from_path(&destination)
}

pub(crate) fn validate_target_anchor(anchor: &Path) -> Result<(), MaterializationError> {
    if !anchor.is_absolute()
        || raw_parent_component(anchor)
        || anchor
            .components()
            .any(|component| {
                matches!(component, Component::CurDir | Component::ParentDir)
                    || matches!(component, Component::Normal(value) if value == OsStr::new(".") || value == OsStr::new(".."))
            })
    {
        return Err(MaterializationError::new(
            "materialization.anchor_invalid",
            "the target anchor must be absolute without relative components",
        ));
    }
    Ok(())
}

pub(crate) fn normalized_destination_from_path(
    destination: &Path,
) -> Result<NormalizedDestination, MaterializationError> {
    let encoded = destination.to_str().ok_or_else(|| {
        MaterializationError::new(
            "materialization.destination_non_utf8",
            "the target destination must be valid UTF-8",
        )
    })?;
    let encoded = strip_lossless_verbatim_disk_prefix(encoded);
    NormalizedDestination::parse(encoded).map_err(|_| {
        MaterializationError::new(
            "materialization.destination_invalid",
            "the target destination is not a supported normalized absolute path",
        )
    })
}

fn strip_lossless_verbatim_disk_prefix(path: &str) -> &str {
    let Some(stripped) = path.strip_prefix(r"\\?\") else {
        return path;
    };
    let bytes = stripped.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
        && NormalizedDestination::parse(stripped).is_ok()
    {
        stripped
    } else {
        path
    }
}

#[cfg(windows)]
fn raw_parent_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|segment| segment == "..")
}

#[cfg(not(windows))]
const fn raw_parent_component(_path: &Path) -> bool {
    false
}

/// Captures the exact layout-aware identity of one destination without mutation.
pub fn observe_skill_destination(
    destination: &Path,
    limits: CaptureLimits,
) -> DestinationObservation {
    if !destination_ancestors_are_safe(destination) {
        return DestinationObservation::Unsafe;
    }
    let metadata = match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DestinationObservation::Absent;
        }
        Err(_) => return DestinationObservation::Unsafe,
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || metadata_is_windows_reparse(&metadata) {
        return DestinationObservation::Unsafe;
    }
    let source = if metadata.is_dir() {
        SkillSource::Directory {
            path: destination.to_path_buf(),
        }
    } else if metadata.is_file() {
        SkillSource::Standalone {
            path: destination.to_path_buf(),
        }
    } else {
        return DestinationObservation::Unsafe;
    };
    match capture_skill_source(&source, limits) {
        Ok(captured) => DestinationObservation::Present {
            layout: captured.layout,
            rendered_hash: captured.exact_source_hash,
        },
        Err(_) => DestinationObservation::Unsafe,
    }
}

pub(crate) fn destination_ancestors_are_safe(destination: &Path) -> bool {
    let mut current = destination.parent();
    while let Some(path) = current {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || metadata_is_windows_reparse(&metadata)
                    || !metadata.is_dir()
                {
                    return false;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
        current = path.parent();
    }
    true
}

#[cfg(windows)]
pub(crate) fn metadata_is_windows_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
pub(crate) fn metadata_is_windows_reparse(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Plans one receipt-backed apply without mutating the target or local state.
pub fn plan_skill_apply(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredSkillTree,
    policy: &TargetPolicy,
    anchor: &Path,
    local_state_text: &str,
    destination_observation: DestinationObservation,
) -> Result<ApplyPlan, MaterializationError> {
    manifest.validate().map_err(|_| {
        MaterializationError::new("apply.manifest_invalid", "manifest authority is invalid")
    })?;
    let local_state = LocalState::from_json(local_state_text).map_err(|_| {
        MaterializationError::new(
            "apply.local_state_invalid",
            "machine-local state is invalid",
        )
    })?;
    validate_local_receipts(&local_state)?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        MaterializationError::new(
            "apply.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let observed_class = assess_portable_tree_risk(object.tree()).map_err(|_| {
        MaterializationError::new(
            "apply.credential_blocked",
            "credential-like portable content cannot be materialized",
        )
    })?;
    if observed_class == ContentClass::Executable {
        return Err(MaterializationError::new(
            "apply.executable_blocked",
            "executable assets require a later trust workflow before materialization",
        ));
    }
    if asset.content_class == ContentClass::Executable {
        return Err(MaterializationError::new(
            "apply.executable_blocked",
            "executable assets require a later trust workflow before materialization",
        ));
    }
    if !asset.required_bindings.is_empty() {
        return Err(MaterializationError::new(
            "apply.bindings_unresolved",
            "the selected asset requires unresolved local bindings",
        ));
    }
    let compatibility = asset.compatibility.get(&policy.harness).ok_or_else(|| {
        MaterializationError::new(
            "apply.compatibility_missing",
            "the selected asset has no target compatibility result",
        )
    })?;
    if !matches!(
        compatibility.fidelity(),
        Fidelity::Native | Fidelity::Portable | Fidelity::Adapted
    ) {
        return Err(MaterializationError::new(
            "apply.compatibility_blocked",
            "the selected target fidelity does not permit materialization",
        ));
    }
    if compatibility.adapter_version() != policy.adapter_version {
        return Err(MaterializationError::new(
            "apply.adapter_version_mismatch",
            "the selected target policy differs from manifest compatibility authority",
        ));
    }
    let rendered = render_portable_skill(object, policy)?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        MaterializationError::new(
            "apply.portable_missing",
            "the selected asset has no portable object authority",
        )
    })?;
    if portable.format != "agent-skills/v1" || portable.object_hash != object.tree().hash {
        return Err(MaterializationError::new(
            "apply.portable_mismatch",
            "the supplied portable object does not match manifest authority",
        ));
    }
    let destination = resolve_target_destination(anchor, policy, rendered.package_name())?;
    let relative_destination = PortablePath::parse(format!(
        "{}/{}",
        policy.relative_root.as_str(),
        rendered.package_name().as_str()
    ))
    .map_err(|_| {
        MaterializationError::new(
            "apply.destination_invalid",
            "the selected relative destination is invalid",
        )
    })?;
    if rendered.contains_executable_mode() {
        return Err(MaterializationError::new(
            "apply.executable_mode_blocked",
            "portable output with executable mode requires a later trust workflow",
        ));
    }
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| {
        MaterializationError::new(
            "apply.manifest_revision_invalid",
            "manifest revision authority could not be derived",
        )
    })?;

    let matching =
        receipts_for_destination(&local_state, &policy.harness, policy.scope, &destination);
    if matching.len() > 1 {
        return Err(MaterializationError::new(
            "apply.receipt_ambiguous",
            "multiple receipts claim the selected destination",
        ));
    }
    let observed_receipt = matching.first().map(|(_, receipt)| (*receipt).clone());
    if observed_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.asset_id != *asset_id)
    {
        return Err(MaterializationError::new(
            "apply.destination_owned_by_other_asset",
            "the selected destination is owned by another asset",
        ));
    }

    let (disposition, prior_hash) = match (&observed_receipt, &destination_observation) {
        (None, DestinationObservation::Absent) => (ApplyDisposition::Install, None),
        (None, DestinationObservation::Present { .. }) => {
            return Err(MaterializationError::new(
                "apply.destination_unmanaged",
                "an unmanaged destination is never overwritten",
            ));
        }
        (_, DestinationObservation::Unsafe) => {
            return Err(MaterializationError::new(
                "apply.destination_unsafe",
                "the selected destination could not be inspected safely",
            ));
        }
        (Some(receipt), DestinationObservation::Absent) => {
            (ApplyDisposition::Restore, receipt.prior_hash.clone())
        }
        (
            Some(receipt),
            DestinationObservation::Present {
                layout,
                rendered_hash,
            },
        ) => {
            if *layout != rendered.layout {
                return Err(MaterializationError::new(
                    "apply.destination_layout_modified",
                    "the managed destination layout changed after materialization",
                ));
            }
            if rendered_hash != &receipt.rendered_hash {
                return Err(MaterializationError::new(
                    "apply.destination_modified",
                    "the managed destination changed after materialization",
                ));
            }
            let authority_unchanged = receipt.source_hash == asset.content_hash
                && receipt.rendered_hash == *rendered.rendered_hash()
                && receipt.adapter_version == policy.adapter_version
                && receipt.environment_revision == manifest_revision;
            if authority_unchanged {
                (ApplyDisposition::NoOp, receipt.prior_hash.clone())
            } else {
                (
                    ApplyDisposition::ManagedUpdate,
                    Some(receipt.rendered_hash.clone()),
                )
            }
        }
    };

    let proposed_receipt = DeploymentReceipt {
        asset_id: asset_id.clone(),
        harness: policy.harness.clone(),
        scope: policy.scope,
        destination: destination.clone(),
        target: Default::default(),
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: asset.content_hash.clone(),
        rendered_hash: rendered.rendered_hash().clone(),
        document_hash: None,
        prior_hash,
        adapter_version: policy.adapter_version.to_owned(),
        environment_revision: manifest_revision.clone(),
    };
    let receipt_id = proposed_receipt.receipt_id().map_err(|_| {
        MaterializationError::new("apply.receipt_invalid", "the proposed receipt is invalid")
    })?;
    let mut proposed_local_state = local_state;
    proposed_local_state
        .receipts
        .insert(receipt_id.clone(), proposed_receipt.clone());
    let proposed_local_state_text = proposed_local_state.to_json().map_err(|_| {
        MaterializationError::new(
            "apply.local_state_serialize",
            "the proposed machine-local state could not be serialized",
        )
    })?;
    let digest = apply_plan_digest(
        asset_id,
        policy,
        &destination,
        &manifest_revision,
        disposition,
        observed_receipt.as_ref(),
        &destination_observation,
        &proposed_receipt,
        local_state_text,
        &proposed_local_state_text,
    )?;
    Ok(ApplyPlan {
        policy: policy.clone(),
        asset_id: asset_id.clone(),
        harness: policy.harness.clone(),
        scope: policy.scope,
        destination,
        relative_destination,
        receipt_id,
        manifest_revision,
        disposition,
        observed_receipt,
        observed_destination: destination_observation,
        rendered,
        proposed_receipt,
        proposed_local_state,
        observed_local_state_text: local_state_text.to_owned(),
        digest,
    })
}

/// Plans removal of one exact receipt-backed skill projection while retaining portable authority.
pub fn plan_skill_removal(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredSkillTree,
    policy: &TargetPolicy,
    anchor: &Path,
    local_state_text: &str,
    destination_observation: DestinationObservation,
) -> Result<ApplyPlan, MaterializationError> {
    let mut plan = plan_skill_apply(
        manifest,
        asset_id,
        object,
        policy,
        anchor,
        local_state_text,
        destination_observation,
    )?;
    if !matches!(
        plan.disposition,
        ApplyDisposition::NoOp | ApplyDisposition::ManagedUpdate
    ) || !matches!(
        plan.observed_destination,
        DestinationObservation::Present { .. }
    ) {
        return Err(MaterializationError::new(
            "remove.skill_authority_unavailable",
            "skill removal requires one present exact receipt-backed destination",
        ));
    }
    let observed_receipt = plan.observed_receipt.clone().ok_or_else(|| {
        MaterializationError::new(
            "remove.skill_authority_unavailable",
            "skill removal requires one present exact receipt-backed destination",
        )
    })?;
    if observed_receipt.receipt_id().ok().as_ref() != Some(&plan.receipt_id)
        || plan
            .proposed_local_state
            .receipts
            .remove(&plan.receipt_id)
            .as_ref()
            != Some(&plan.proposed_receipt)
    {
        return Err(MaterializationError::new(
            "remove.skill_authority_unavailable",
            "skill removal requires one present exact receipt-backed destination",
        ));
    }
    plan.proposed_receipt = observed_receipt;
    let proposed_local_state_text = plan.proposed_local_state.to_json().map_err(|_| {
        MaterializationError::new(
            "apply.local_state_serialize",
            "the proposed machine-local state could not be serialized",
        )
    })?;
    plan.disposition = ApplyDisposition::Remove;
    plan.digest = apply_plan_digest(
        &plan.asset_id,
        &plan.policy,
        &plan.destination,
        &plan.manifest_revision,
        plan.disposition,
        plan.observed_receipt.as_ref(),
        &plan.observed_destination,
        &plan.proposed_receipt,
        &plan.observed_local_state_text,
        &proposed_local_state_text,
    )?;
    Ok(plan)
}

pub(crate) fn validate_local_receipts(
    local_state: &LocalState,
) -> Result<(), MaterializationError> {
    for (receipt_id, receipt) in &local_state.receipts {
        if receipt.receipt_id().ok().as_ref() != Some(receipt_id) {
            return Err(MaterializationError::new(
                "apply.local_state_invalid",
                "machine-local receipt authority is invalid",
            ));
        }
    }
    Ok(())
}

pub(crate) fn receipts_for_destination<'a>(
    local_state: &'a LocalState,
    harness: &kitrove_model::HarnessId,
    scope: HarnessScope,
    destination: &NormalizedDestination,
) -> Vec<(&'a ReceiptId, &'a DeploymentReceipt)> {
    local_state
        .receipts
        .iter()
        .filter(|(_, receipt)| {
            receipt.harness == *harness
                && receipt.scope == scope
                && receipt.destination == *destination
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn apply_plan_digest(
    asset_id: &AssetId,
    policy: &TargetPolicy,
    destination: &NormalizedDestination,
    manifest_revision: &Revision,
    disposition: ApplyDisposition,
    observed_receipt: Option<&DeploymentReceipt>,
    destination_observation: &DestinationObservation,
    proposed_receipt: &DeploymentReceipt,
    observed_local_state_text: &str,
    proposed_local_state_text: &str,
) -> Result<ContentHash, MaterializationError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-apply-plan-v1\0");
    for value in [
        asset_id.as_str(),
        policy.harness.as_str(),
        policy.scope.as_str(),
        policy.policy_line.as_str(),
        policy.relative_root.as_str(),
        policy.document_name.as_str(),
        policy.adapter_version,
        policy.evidence.as_str(),
        destination.as_str(),
        manifest_revision.as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    hasher.update(&[match disposition {
        ApplyDisposition::Install => 0,
        ApplyDisposition::NoOp => 1,
        ApplyDisposition::Restore => 2,
        ApplyDisposition::ManagedUpdate => 3,
        ApplyDisposition::Remove => 4,
    }]);
    match observed_receipt {
        Some(receipt) => {
            hasher.update(&[1]);
            let encoded = serde_json::to_vec(receipt).map_err(|_| {
                MaterializationError::new(
                    "apply.plan_digest_failed",
                    "the apply plan digest could not be derived",
                )
            })?;
            hasher.update(&(encoded.len() as u64).to_be_bytes());
            hasher.update(&encoded);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match destination_observation {
        DestinationObservation::Absent => {
            hasher.update(&[0]);
        }
        DestinationObservation::Unsafe => {
            hasher.update(&[1]);
        }
        DestinationObservation::Present {
            layout,
            rendered_hash,
        } => {
            hasher.update(&[2]);
            hasher.update(&[match layout {
                SkillSourceLayout::Directory => 0,
                SkillSourceLayout::Standalone => 1,
            }]);
            write_digest_record(&mut hasher, rendered_hash.as_str());
        }
    }
    let proposed = serde_json::to_vec(proposed_receipt).map_err(|_| {
        MaterializationError::new(
            "apply.plan_digest_failed",
            "the apply plan digest could not be derived",
        )
    })?;
    hasher.update(&(proposed.len() as u64).to_be_bytes());
    hasher.update(&proposed);
    write_digest_record(
        &mut hasher,
        ContentHash::digest(observed_local_state_text.as_bytes()).as_str(),
    );
    write_digest_record(
        &mut hasher,
        ContentHash::digest(proposed_local_state_text.as_bytes()).as_str(),
    );
    Ok(
        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("BLAKE3 digest is a valid content hash"),
    )
}

pub(crate) fn write_digest_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

pub(crate) fn hash_exact_file_target(
    domain: &[u8],
    bytes: &[u8],
    mode: RegularFileMode,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    if let Some(unix_mode) = mode.unix_mode() {
        hasher.update(&[1]);
        hasher.update(&unix_mode.to_be_bytes());
    } else {
        hasher.update(&[0, u8::from(mode.readonly())]);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_adapter_api::{EvidenceRef, TargetPolicy};
    use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, StoredSkillTree, hash_tree};
    use kitrove_model::{
        AssetId, BindingName, BindingResolver, HarnessId, HarnessScope, LocalState, MachineConfig,
        MachineId, PortablePath, ProfileId, SchemaVersion,
    };

    use super::*;
    use crate::adoption::tests::{capabilities, empty_manifest, make_candidate};
    use crate::{AdoptionPlanOutcome, AtomicApplyBatchPlan, AtomicApplyItem, plan_adoption};

    fn object() -> StoredSkillTree {
        let files = BTreeMap::from([(
            PortablePath::parse("SKILL.md").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"---\nname: review\ndescription: A reviewed portable skill.\n---\nBody.\n"
                    .to_vec(),
            },
        )]);
        StoredSkillTree::new(CapturedTree {
            hash: hash_tree(&files),
            files,
        })
        .unwrap()
    }

    fn policy() -> TargetPolicy {
        TargetPolicy {
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            policy_line: kitrove_adapter_api::PolicyLine::ClaudeCurrent,
            relative_root: PortablePath::parse(".claude/skills").unwrap(),
            layout: SkillSourceLayout::Directory,
            document_name: PortablePath::parse("SKILL.md").unwrap(),
            adapter_version: "test-agent-skills/1",
            evidence: EvidenceRef::parse("claude.target.skills").unwrap(),
        }
    }

    fn codex_policy() -> TargetPolicy {
        TargetPolicy {
            harness: HarnessId::Codex,
            scope: HarnessScope::User,
            policy_line: kitrove_adapter_api::PolicyLine::CodexCurrent,
            relative_root: PortablePath::parse(".codex/skills").unwrap(),
            layout: SkillSourceLayout::Directory,
            document_name: PortablePath::parse("SKILL.md").unwrap(),
            adapter_version: "test-agent-skills/1",
            evidence: EvidenceRef::parse("codex.target.skills").unwrap(),
        }
    }

    #[cfg(not(windows))]
    fn test_anchor() -> &'static Path {
        Path::new("/home/review")
    }

    #[cfg(windows)]
    fn test_anchor() -> &'static Path {
        Path::new(r"C:\home\review")
    }

    #[cfg(not(windows))]
    const TEST_DESTINATION: &str = "/home/review/.claude/skills/review";

    #[cfg(windows)]
    const TEST_DESTINATION: &str = "C:/home/review/.claude/skills/review";

    fn adopted() -> (EnvironmentManifest, StoredSkillTree, AssetId) {
        let candidate = make_candidate(FileMode::Regular, "review");
        let AdoptionPlanOutcome::Ready(plan) =
            plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap()
        else {
            panic!("portable candidate should be adoptable");
        };
        (
            plan.proposed_manifest().clone(),
            plan.portable_object().clone(),
            plan.asset().id.clone(),
        )
    }

    fn local_state() -> LocalState {
        LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("test-machine").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::<BindingName, BindingResolver>::new(),
            receipts: BTreeMap::new(),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: Vec::new(),
        }
    }

    fn local_state_text() -> String {
        local_state().to_json().unwrap()
    }

    #[test]
    fn portable_render_uses_layout_aware_target_identity() {
        let rendered = render_portable_skill(&object(), &policy()).unwrap();
        assert_eq!(rendered.layout(), SkillSourceLayout::Directory);
        assert_eq!(rendered.document_name(), "SKILL.md");
        assert_eq!(
            rendered.rendered_hash(),
            &hash_skill_source(SkillSourceLayout::Directory, "SKILL.md", object().tree())
        );
        assert_ne!(rendered.rendered_hash(), &object().tree().hash);
        assert!(!rendered.contains_executable_mode());
    }

    #[test]
    fn target_resolution_rejects_relative_or_parent_anchors() {
        let id = AssetId::parse("review").unwrap();
        assert_eq!(
            resolve_target_destination(Path::new("relative"), &policy(), &id)
                .unwrap_err()
                .code(),
            "materialization.anchor_invalid"
        );
        assert_eq!(
            resolve_target_destination(Path::new("/safe/../unsafe"), &policy(), &id)
                .unwrap_err()
                .code(),
            "materialization.anchor_invalid"
        );
        assert_eq!(
            resolve_target_destination(test_anchor(), &policy(), &id)
                .unwrap()
                .as_str(),
            TEST_DESTINATION
        );
    }

    #[test]
    fn only_lossless_verbatim_disk_paths_are_reduced_to_portable_destination_identity() {
        assert_eq!(
            strip_lossless_verbatim_disk_prefix(r"\\?\C:\Users\dev\skill"),
            r"C:\Users\dev\skill"
        );
        assert_eq!(
            strip_lossless_verbatim_disk_prefix(r"\\?\UNC\server\share"),
            r"\\?\UNC\server\share"
        );
        assert_eq!(
            strip_lossless_verbatim_disk_prefix("/home/dev/skill"),
            "/home/dev/skill"
        );
        for path in [
            r"\\?\C:\root.\skill",
            r"\\?\C:\root \skill",
            r"\\?\C:\root:stream\skill",
            r"\\?\C:\CON\skill",
            r"\\?\C:\com1.txt\skill",
        ] {
            assert_eq!(strip_lossless_verbatim_disk_prefix(path), path);
            assert_eq!(
                normalized_destination_from_path(Path::new(path))
                    .unwrap_err()
                    .code(),
                "materialization.destination_invalid"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_verbatim_disk_anchor_matches_safe_ordinary_identity_only() {
        let temporary = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(temporary.path()).unwrap();
        let normalized = normalized_destination_from_path(&canonical).unwrap();
        let ordinary = canonical
            .to_str()
            .unwrap()
            .strip_prefix(r"\\?\")
            .expect("Windows canonical disk path");
        assert_eq!(
            normalized,
            NormalizedDestination::parse(ordinary).expect("ordinary disk identity")
        );
    }

    #[test]
    fn ownership_planning_installs_then_becomes_an_exact_noop() {
        let (manifest, object, asset_id) = adopted();
        let initial = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Absent,
        )
        .unwrap();
        assert_eq!(initial.disposition(), ApplyDisposition::Install);
        assert_eq!(
            initial.proposed_receipt().source_hash,
            manifest.assets[&asset_id].content_hash
        );
        assert_eq!(
            initial.proposed_receipt().rendered_hash,
            *initial.rendered().rendered_hash()
        );
        assert_eq!(initial.proposed_receipt().prior_hash, None);

        let noop = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &initial.proposed_local_state().to_json().unwrap(),
            DestinationObservation::Present {
                layout: SkillSourceLayout::Directory,
                rendered_hash: initial.rendered().rendered_hash().clone(),
            },
        )
        .unwrap();
        assert_eq!(noop.disposition(), ApplyDisposition::NoOp);
        assert_eq!(noop.receipt_id(), initial.receipt_id());
    }

    #[test]
    fn atomic_batch_is_canonical_and_builds_one_final_profile_state() {
        let (manifest, object, asset_id) = adopted();
        let state = local_state_text();
        let claude = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &state,
            DestinationObservation::Absent,
        )
        .unwrap();
        let codex = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &codex_policy(),
            test_anchor(),
            &state,
            DestinationObservation::Absent,
        )
        .unwrap();
        let profile = ProfileId::parse("workstation").unwrap();

        let forward = AtomicApplyBatchPlan::new(
            vec![
                AtomicApplyItem::Skill(claude.clone()),
                AtomicApplyItem::Skill(codex.clone()),
            ],
            Some(profile.clone()),
        )
        .unwrap();
        let reverse = AtomicApplyBatchPlan::new(
            vec![
                AtomicApplyItem::Skill(codex),
                AtomicApplyItem::Skill(claude),
            ],
            Some(profile.clone()),
        )
        .unwrap();

        assert_eq!(forward.digest(), reverse.digest());
        assert_eq!(forward.items(), reverse.items());
        assert_eq!(
            forward.target_anchors(),
            &[normalized_destination_from_path(test_anchor()).unwrap()]
        );
        assert_eq!(forward.active_profile(), Some(&profile));
        assert_eq!(
            forward.proposed_local_state().machine.active_profile,
            Some(profile)
        );
        assert_eq!(forward.proposed_local_state().receipts.len(), 2);
        let debug = format!("{forward:?}");
        assert!(!debug.contains(".claude"));
        assert!(!debug.contains("test-machine"));
        assert!(!debug.contains("workstation"));
        assert!(!format!("{:?}", forward.items()[0]).contains("/home/review"));

        let absent_profile = AtomicApplyBatchPlan::new(forward.items().to_vec(), None).unwrap();
        let named_none = AtomicApplyBatchPlan::new(
            forward.items().to_vec(),
            Some(ProfileId::parse("none").unwrap()),
        )
        .unwrap();
        assert_ne!(absent_profile.digest(), named_none.digest());
    }

    #[test]
    fn atomic_batch_rejects_duplicate_destinations_and_unrelated_state_changes() {
        let (manifest, object, asset_id) = adopted();
        let plan = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Absent,
        )
        .unwrap();
        let duplicate = AtomicApplyBatchPlan::new(
            vec![
                AtomicApplyItem::Skill(plan.clone()),
                AtomicApplyItem::Skill(plan.clone()),
            ],
            None,
        )
        .unwrap_err();
        assert_eq!(duplicate.code(), "apply.batch_destination_duplicate");

        let mut unrelated = plan;
        unrelated.proposed_local_state.machine.active_profile =
            Some(ProfileId::parse("unrelated").unwrap());
        let error =
            AtomicApplyBatchPlan::new(vec![AtomicApplyItem::Skill(unrelated)], None).unwrap_err();
        assert_eq!(error.code(), "apply.batch_item_state_invalid");
    }

    #[test]
    fn atomic_batch_rejects_nested_destinations() {
        let (manifest, object, asset_id) = adopted();
        let state = local_state_text();
        let parent = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &state,
            DestinationObservation::Absent,
        )
        .unwrap();
        let mut nested_policy = policy();
        nested_policy.relative_root = PortablePath::parse(".claude/skills/review").unwrap();
        nested_policy.evidence = EvidenceRef::parse("claude.target.nested-test").unwrap();
        let child = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &nested_policy,
            test_anchor(),
            &state,
            DestinationObservation::Absent,
        )
        .unwrap();
        let mut competitor_policy = policy();
        competitor_policy.relative_root =
            PortablePath::parse(".claude/skills/review-competitor").unwrap();
        competitor_policy.evidence = EvidenceRef::parse("claude.target.competitor-test").unwrap();
        let competitor = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &competitor_policy,
            test_anchor(),
            &state,
            DestinationObservation::Absent,
        )
        .unwrap();

        let error = AtomicApplyBatchPlan::new(
            vec![
                AtomicApplyItem::Skill(child),
                AtomicApplyItem::Skill(competitor),
                AtomicApplyItem::Skill(parent),
            ],
            None,
        )
        .unwrap_err();

        assert_eq!(error.code(), "apply.batch_destination_overlap");
    }

    #[test]
    fn confirmed_authority_includes_complete_target_policy_evidence() {
        let (manifest, object, asset_id) = adopted();
        let plan = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Absent,
        )
        .unwrap();

        let mut changed_evidence = plan.clone();
        changed_evidence.policy.evidence = EvidenceRef::parse("claude.target.changed").unwrap();
        assert!(!plan.same_confirmed_authority(&changed_evidence));

        let mut changed_policy_line = plan.clone();
        changed_policy_line.policy.policy_line = kitrove_adapter_api::PolicyLine::CodexCurrent;
        assert!(!plan.same_confirmed_authority(&changed_policy_line));
    }

    #[test]
    fn ownership_planning_refuses_unmanaged_and_modified_destinations() {
        let (manifest, object, asset_id) = adopted();
        let rendered = render_portable_skill(&object, &policy()).unwrap();
        let unmanaged = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Present {
                layout: SkillSourceLayout::Directory,
                rendered_hash: rendered.rendered_hash().clone(),
            },
        )
        .unwrap_err();
        assert_eq!(unmanaged.code(), "apply.destination_unmanaged");

        let install = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Absent,
        )
        .unwrap();
        let modified = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &install.proposed_local_state().to_json().unwrap(),
            DestinationObservation::Present {
                layout: SkillSourceLayout::Directory,
                rendered_hash: ContentHash::digest(b"modified"),
            },
        )
        .unwrap_err();
        assert_eq!(modified.code(), "apply.destination_modified");

        let layout_substitution = plan_skill_apply(
            &manifest,
            &asset_id,
            &object,
            &policy(),
            test_anchor(),
            &install.proposed_local_state().to_json().unwrap(),
            DestinationObservation::Present {
                layout: SkillSourceLayout::Standalone,
                rendered_hash: install.rendered().rendered_hash().clone(),
            },
        )
        .unwrap_err();
        assert_eq!(
            layout_substitution.code(),
            "apply.destination_layout_modified"
        );
        assert_eq!(
            plan_skill_apply(
                &manifest,
                &asset_id,
                &object,
                &policy(),
                test_anchor(),
                &install.proposed_local_state().to_json().unwrap(),
                DestinationObservation::Unsafe,
            )
            .unwrap_err()
            .code(),
            "apply.destination_unsafe"
        );
    }

    #[test]
    fn executable_and_binding_dependent_assets_are_blocked_before_staging() {
        let (mut executable_manifest, object, asset_id) = adopted();
        let executable = executable_manifest.assets.get_mut(&asset_id).unwrap();
        executable.content_class = ContentClass::Executable;
        executable.refresh_content_hash();
        assert_eq!(
            plan_skill_apply(
                &executable_manifest,
                &asset_id,
                &object,
                &policy(),
                test_anchor(),
                &local_state_text(),
                DestinationObservation::Absent,
            )
            .unwrap_err()
            .code(),
            "apply.executable_blocked"
        );

        let (mut binding_manifest, object, asset_id) = adopted();
        let binding = BindingName::parse("review_token").unwrap();
        binding_manifest.required_bindings.insert(binding.clone());
        let asset = binding_manifest.assets.get_mut(&asset_id).unwrap();
        asset.required_bindings.insert(binding);
        asset.refresh_content_hash();
        assert_eq!(
            plan_skill_apply(
                &binding_manifest,
                &asset_id,
                &object,
                &policy(),
                test_anchor(),
                &local_state_text(),
                DestinationObservation::Absent,
            )
            .unwrap_err()
            .code(),
            "apply.bindings_unresolved"
        );
    }

    #[test]
    fn stored_tree_risk_is_recomputed_instead_of_trusting_manifest_labels() {
        for (path, bytes, expected_code) in [
            (
                ".env",
                b"TOKEN=credential-canary\n".as_slice(),
                "apply.credential_blocked",
            ),
            (
                "scripts/run.txt",
                b"harmless-looking regular mode\n".as_slice(),
                "apply.executable_blocked",
            ),
        ] {
            let (mut manifest, object, asset_id) = adopted();
            let mut files = object.tree().files.clone();
            files.insert(
                PortablePath::parse(path).unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: bytes.to_vec(),
                },
            );
            let hostile = StoredSkillTree::new(CapturedTree {
                hash: hash_tree(&files),
                files,
            })
            .unwrap();
            let asset = manifest.assets.get_mut(&asset_id).unwrap();
            asset.portable.as_mut().unwrap().object_hash = hostile.tree().hash.clone();
            asset.content_class = ContentClass::AgentActive;
            asset.refresh_content_hash();

            assert_eq!(
                plan_skill_apply(
                    &manifest,
                    &asset_id,
                    &hostile,
                    &policy(),
                    test_anchor(),
                    &local_state_text(),
                    DestinationObservation::Absent,
                )
                .unwrap_err()
                .code(),
                expected_code
            );
        }
    }

    #[test]
    fn explicit_portable_asset_id_does_not_break_target_package_identity() {
        let candidate = make_candidate(FileMode::Regular, "review");
        let explicit_id = AssetId::parse("portable-alias").unwrap();
        let AdoptionPlanOutcome::Ready(adoption) = plan_adoption(
            &candidate,
            Some(explicit_id.clone()),
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            panic!("explicit adoption should be ready");
        };
        let plan = plan_skill_apply(
            adoption.proposed_manifest(),
            &explicit_id,
            adoption.portable_object(),
            &policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Absent,
        )
        .unwrap();
        assert_eq!(plan.asset_id(), &explicit_id);
        assert_eq!(plan.rendered().package_name().as_str(), "review");
        assert_eq!(plan.destination().as_str(), TEST_DESTINATION);
    }

    #[cfg(unix)]
    #[test]
    fn destination_observation_rejects_a_symlinked_absent_parent() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temporary.path()).unwrap();
        let outside = root.join("outside");
        let anchor = root.join("anchor");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&anchor).unwrap();
        symlink(&outside, anchor.join(".claude")).unwrap();
        assert_eq!(
            observe_skill_destination(
                &anchor.join(".claude/skills/review"),
                CaptureLimits::default(),
            ),
            DestinationObservation::Unsafe
        );
        assert!(!outside.join("skills/review").exists());
    }
}
