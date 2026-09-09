use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_adapter_api::{ExtensionPackageLayout, ExtensionTargetPolicy, VersionObservationOwned};
use kitrove_agent_skills::{CaptureLimits, CapturedTree, FileMode};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, DeploymentReceipt, EnvironmentManifest,
    Fidelity, HarnessId, HarnessScope, LocalState, NormalizedDestination, PortablePath, Revision,
    TrustDecision,
};
use kitrove_version_probe::VerifiedPiVersion;

use crate::materialization::{
    destination_ancestors_are_safe, metadata_is_windows_reparse, normalized_destination_from_path,
    receipts_for_destination, validate_local_receipts, validate_target_anchor, write_digest_record,
};
use crate::{
    ApplyDisposition, MaterializationError, NativeExtensionLayout, NativeExtensionObject,
    NativeExtensionSource, PiProjectTrustEvidence, VerifiedSkillObjectCatalog,
    capture_pi_extension, derive_manifest_revision, merge::validate_extension_snapshot_asset,
};

/// Returns the fixed policy needed to identify an existing Pi extension for removal.
pub fn pi_extension_removal_policy(
    scope: HarnessScope,
) -> Result<ExtensionTargetPolicy, MaterializationError> {
    Ok(ExtensionTargetPolicy::pi_native_extensions(
        scope,
        VersionObservationOwned::Unknown,
    ))
}

/// Exact adapter-owned render result for one verified Pi extension object.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedExtension {
    layout: NativeExtensionLayout,
    native_id: AssetId,
    relative_name: PortablePath,
    tree: CapturedTree,
    rendered_hash: ContentHash,
}

impl RenderedExtension {
    #[must_use]
    pub const fn layout(&self) -> NativeExtensionLayout {
        self.layout
    }

    #[must_use]
    pub const fn native_id(&self) -> &AssetId {
        &self.native_id
    }

    #[must_use]
    pub const fn relative_name(&self) -> &PortablePath {
        &self.relative_name
    }

    #[must_use]
    pub const fn tree(&self) -> &CapturedTree {
        &self.tree
    }

    #[must_use]
    pub const fn rendered_hash(&self) -> &ContentHash {
        &self.rendered_hash
    }
}

impl Debug for RenderedExtension {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedExtension")
            .field("layout", &self.layout)
            .field("file_count", &self.tree.files.len())
            .field("rendered_hash", &self.rendered_hash)
            .finish()
    }
}

/// Read-only exact state of one native extension destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionDestinationObservation {
    Absent,
    Present {
        layout: NativeExtensionLayout,
        object_hash: ContentHash,
    },
    Unsafe,
}

/// Complete pure plan for one locally trusted Pi extension materialization.
#[derive(Clone, Eq, PartialEq)]
pub struct ExtensionApplyPlan {
    asset_id: AssetId,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    manifest_revision: Revision,
    disposition: ApplyDisposition,
    observed_receipt: Option<DeploymentReceipt>,
    observed_destination: ExtensionDestinationObservation,
    rendered: RenderedExtension,
    policy: ExtensionTargetPolicy,
    project_trust: Option<PiProjectTrustEvidence>,
    proposed_receipt: DeploymentReceipt,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

/// Machine-local authority required before an executable extension destination is inspected.
#[derive(Clone, Copy)]
pub struct ExtensionApplyAuthority<'a> {
    anchor: &'a Path,
    version: &'a VerifiedPiVersion,
    project_trust: Option<&'a PiProjectTrustEvidence>,
}

impl<'a> ExtensionApplyAuthority<'a> {
    #[must_use]
    pub const fn new(
        anchor: &'a Path,
        version: &'a VerifiedPiVersion,
        project_trust: Option<&'a PiProjectTrustEvidence>,
    ) -> Self {
        Self {
            anchor,
            version,
            project_trust,
        }
    }
}

impl ExtensionApplyPlan {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
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
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedExtension {
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
    pub const fn observed_receipt(&self) -> Option<&DeploymentReceipt> {
        self.observed_receipt.as_ref()
    }

    #[must_use]
    pub const fn observed_destination(&self) -> &ExtensionDestinationObservation {
        &self.observed_destination
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    pub(crate) fn revalidate_project_trust(&self) -> Result<bool, MaterializationError> {
        self.project_trust
            .as_ref()
            .map(PiProjectTrustEvidence::revalidate)
            .transpose()
            .map(|current| current.unwrap_or(true))
            .map_err(|_| {
                materialization_error(
                    "apply.project_trust_stale",
                    "Pi saved project trust changed before materialization",
                )
            })
    }

    /// Whether two plans differ only in machine-local state advanced by earlier batch items.
    #[must_use]
    pub fn same_confirmed_authority(&self, other: &Self) -> bool {
        self.asset_id == other.asset_id
            && self.destination == other.destination
            && self.relative_destination == other.relative_destination
            && self.manifest_revision == other.manifest_revision
            && self.disposition == other.disposition
            && self.observed_receipt == other.observed_receipt
            && self.observed_destination == other.observed_destination
            && self.rendered == other.rendered
            && self.policy == other.policy
            && self.project_trust == other.project_trust
            && self.proposed_receipt == other.proposed_receipt
    }
}

impl Debug for ExtensionApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExtensionApplyPlan")
            .field("disposition", &self.disposition)
            .field("manifest_revision", &self.manifest_revision)
            .field("rendered_hash", self.rendered.rendered_hash())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Applies only the compiled Pi extension policy without transforming any bytes.
pub fn render_native_extension(
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
) -> Result<RenderedExtension, MaterializationError> {
    if object.harness() != &policy.harness || policy.harness != HarnessId::Pi {
        return Err(materialization_error(
            "apply.extension_harness_mismatch",
            "the extension object does not match target policy authority",
        ));
    }
    let layout = match object.layout() {
        NativeExtensionLayout::Standalone => ExtensionPackageLayout::Standalone,
        NativeExtensionLayout::Directory => ExtensionPackageLayout::Directory,
    };
    if !policy.supported_layouts.contains(&layout) {
        return Err(materialization_error(
            "apply.extension_layout_unsupported",
            "the extension layout is not supported by target policy",
        ));
    }
    validate_extension_modes(object.tree(), cfg!(unix))?;
    let native_id = AssetId::parse(object.native_id()).map_err(|_| {
        materialization_error(
            "apply.extension_identity_invalid",
            "the extension identity is not a safe destination component",
        )
    })?;
    let relative_name = PortablePath::parse(match object.layout() {
        NativeExtensionLayout::Standalone => format!("{}.ts", native_id.as_str()),
        NativeExtensionLayout::Directory => native_id.as_str().to_owned(),
    })
    .map_err(|_| {
        materialization_error(
            "apply.extension_destination_invalid",
            "the extension destination is invalid",
        )
    })?;
    Ok(RenderedExtension {
        layout: object.layout(),
        native_id,
        relative_name,
        tree: object.tree().clone(),
        rendered_hash: object.hash().clone(),
    })
}

fn validate_extension_modes(
    tree: &CapturedTree,
    executable_modes_supported: bool,
) -> Result<(), MaterializationError> {
    if !executable_modes_supported
        && tree
            .files
            .values()
            .any(|file| file.mode == FileMode::Executable)
    {
        return Err(materialization_error(
            "apply.extension_mode_unsupported",
            "the current platform cannot preserve an executable extension file mode exactly",
        ));
    }
    Ok(())
}

pub fn resolve_extension_destination(
    anchor: &Path,
    policy: &ExtensionTargetPolicy,
    rendered: &RenderedExtension,
) -> Result<NormalizedDestination, MaterializationError> {
    validate_target_anchor(anchor)?;
    normalized_destination_from_path(
        &anchor
            .join(policy.relative_root.as_str())
            .join(rendered.relative_name.as_str()),
    )
}

fn extension_destination_authority(
    anchor: &Path,
    policy: &ExtensionTargetPolicy,
    object: &NativeExtensionObject,
) -> Result<(RenderedExtension, NormalizedDestination, PortablePath), MaterializationError> {
    let rendered = render_native_extension(object, policy)?;
    let destination = resolve_extension_destination(anchor, policy, &rendered)?;
    let relative_destination = PortablePath::parse(format!(
        "{}/{}",
        policy.relative_root.as_str(),
        rendered.relative_name.as_str()
    ))
    .map_err(|_| {
        materialization_error(
            "apply.extension_destination_invalid",
            "the extension destination is invalid",
        )
    })?;
    Ok((rendered, destination, relative_destination))
}

/// Reconstructs the exact destination object without following link-like entries.
pub fn observe_extension_destination(
    destination: &Path,
    expected: &NativeExtensionObject,
    limits: CaptureLimits,
) -> ExtensionDestinationObservation {
    match capture_extension_destination_object(
        destination,
        expected.layout(),
        expected.entrypoint(),
        expected.native_id(),
        limits,
    ) {
        Ok(None) => ExtensionDestinationObservation::Absent,
        Ok(Some(object)) => ExtensionDestinationObservation::Present {
            layout: object.layout(),
            object_hash: object.hash().clone(),
        },
        Err(()) => ExtensionDestinationObservation::Unsafe,
    }
}

pub(crate) fn capture_extension_destination_object(
    destination: &Path,
    layout: NativeExtensionLayout,
    entrypoint: &str,
    native_id: &str,
    limits: CaptureLimits,
) -> Result<Option<NativeExtensionObject>, ()> {
    if !destination_ancestors_are_safe(destination) {
        return Err(());
    }
    let metadata = match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || metadata_is_windows_reparse(&metadata) {
        return Err(());
    }
    let source = match layout {
        NativeExtensionLayout::Standalone if metadata.is_file() => {
            NativeExtensionSource::Standalone {
                path: destination.to_path_buf(),
            }
        }
        NativeExtensionLayout::Directory if metadata.is_dir() => NativeExtensionSource::Directory {
            path: destination.to_path_buf(),
        },
        _ => return Err(()),
    };
    let captured = capture_pi_extension(&source, limits).map_err(|_| ())?;
    NativeExtensionObject::new(
        HarnessId::Pi,
        captured.layout,
        entrypoint,
        native_id,
        captured.exact,
    )
    .map(Some)
    .map_err(|_| ())
}

pub fn plan_extension_apply(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    authority: ExtensionApplyAuthority<'_>,
    local_state_text: &str,
    destination_observation: ExtensionDestinationObservation,
) -> Result<ExtensionApplyPlan, MaterializationError> {
    authorize_extension_apply(
        manifest,
        asset_id,
        object,
        policy,
        authority,
        local_state_text,
    )?;
    let mut local_state = LocalState::from_json(local_state_text).map_err(|_| {
        materialization_error(
            "apply.local_state_invalid",
            "machine-local state is invalid",
        )
    })?;
    let asset = manifest
        .assets
        .get(asset_id)
        .expect("authorization proved the selected asset exists");
    let compatibility = asset
        .compatibility
        .get(&HarnessId::Pi)
        .expect("authorization proved Pi compatibility exists");
    let (rendered, destination, relative_destination) =
        extension_destination_authority(authority.anchor, policy, object)?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| {
        materialization_error(
            "apply.manifest_revision_invalid",
            "manifest revision authority could not be derived",
        )
    })?;
    let matching =
        receipts_for_destination(&local_state, &policy.harness, policy.scope, &destination);
    if matching.len() > 1 {
        return Err(materialization_error(
            "apply.receipt_ambiguous",
            "multiple receipts claim the selected destination",
        ));
    }
    let observed_receipt = matching.first().map(|(_, receipt)| (*receipt).clone());
    if observed_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.asset_id != *asset_id)
    {
        return Err(materialization_error(
            "apply.destination_owned_by_other_asset",
            "the selected destination is owned by another asset",
        ));
    }
    let (disposition, prior_hash) = extension_disposition(
        asset,
        policy,
        &manifest_revision,
        object,
        observed_receipt.as_ref(),
        &destination_observation,
    )?;
    let proposed_receipt = DeploymentReceipt {
        asset_id: asset_id.clone(),
        harness: HarnessId::Pi,
        scope: policy.scope,
        destination: destination.clone(),
        target: Default::default(),
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: asset.content_hash.clone(),
        rendered_hash: object.hash().clone(),
        document_hash: None,
        prior_hash,
        adapter_version: compatibility.adapter_version().to_owned(),
        environment_revision: manifest_revision.clone(),
    };
    let receipt_id = proposed_receipt.receipt_id().map_err(|_| {
        materialization_error("apply.receipt_invalid", "the proposed receipt is invalid")
    })?;
    local_state
        .receipts
        .insert(receipt_id, proposed_receipt.clone());
    let proposed_local_state_text = local_state.to_json().map_err(|_| {
        materialization_error(
            "apply.local_state_serialize",
            "the proposed machine-local state could not be serialized",
        )
    })?;
    let digest = extension_plan_digest(
        asset_id,
        policy,
        &destination,
        &manifest_revision,
        disposition,
        observed_receipt.as_ref(),
        &destination_observation,
        &proposed_receipt,
        authority.project_trust,
        local_state_text,
        &proposed_local_state_text,
    )?;
    Ok(ExtensionApplyPlan {
        asset_id: asset_id.clone(),
        destination,
        relative_destination,
        manifest_revision,
        disposition,
        observed_receipt,
        observed_destination: destination_observation,
        rendered,
        policy: policy.clone(),
        project_trust: authority.project_trust.cloned(),
        proposed_receipt,
        proposed_local_state: local_state,
        observed_local_state_text: local_state_text.to_owned(),
        digest,
    })
}

/// Plans exact receipt-backed removal of one native extension projection.
#[allow(clippy::too_many_arguments)]
pub fn plan_extension_removal(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    anchor: &Path,
    local_state_text: &str,
    destination_observation: ExtensionDestinationObservation,
) -> Result<ExtensionApplyPlan, MaterializationError> {
    plan_extension_claim_transition(
        manifest,
        asset_id,
        object,
        policy,
        anchor,
        local_state_text,
        destination_observation,
        false,
    )
}

/// Plans exact no-op retention when another pack continues to own the extension receipt.
#[allow(clippy::too_many_arguments)]
pub fn plan_extension_retention(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    anchor: &Path,
    local_state_text: &str,
    destination_observation: ExtensionDestinationObservation,
) -> Result<ExtensionApplyPlan, MaterializationError> {
    plan_extension_claim_transition(
        manifest,
        asset_id,
        object,
        policy,
        anchor,
        local_state_text,
        destination_observation,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_extension_claim_transition(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    anchor: &Path,
    local_state_text: &str,
    destination_observation: ExtensionDestinationObservation,
    retained: bool,
) -> Result<ExtensionApplyPlan, MaterializationError> {
    validate_extension_source(manifest, asset_id, object, policy, None, local_state_text)?;
    let mut local_state = LocalState::from_json(local_state_text).map_err(|_| {
        materialization_error(
            "apply.local_state_invalid",
            "machine-local state is invalid",
        )
    })?;
    let (rendered, destination, relative_destination) =
        extension_destination_authority(anchor, policy, object)?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| {
        materialization_error(
            "apply.manifest_revision_invalid",
            "manifest revision authority could not be derived",
        )
    })?;
    let matching =
        receipts_for_destination(&local_state, &policy.harness, policy.scope, &destination);
    let [(_, observed_receipt)] = matching.as_slice() else {
        return Err(materialization_error(
            "apply.receipt_ambiguous",
            "extension removal requires one exact receipt",
        ));
    };
    if observed_receipt.asset_id != *asset_id
        || !matches!(
            &destination_observation,
            ExtensionDestinationObservation::Present { object_hash, .. }
                if object_hash == &observed_receipt.rendered_hash
        )
    {
        return Err(materialization_error(
            "apply.extension_modified",
            "the receipt-backed extension projection is missing or modified",
        ));
    }
    let proposed_receipt = (*observed_receipt).clone();
    if retained && proposed_receipt.rendered_hash != *object.hash() {
        return Err(materialization_error(
            "apply.extension_source_stale",
            "retained extension authority differs from the current source object",
        ));
    }
    let receipt_id = proposed_receipt.receipt_id().map_err(|_| {
        materialization_error("apply.receipt_invalid", "the extension receipt is invalid")
    })?;
    if !retained && local_state.receipts.remove(&receipt_id).as_ref() != Some(&proposed_receipt) {
        return Err(materialization_error(
            "apply.local_state_invalid",
            "machine-local state is invalid",
        ));
    }
    let proposed_local_state_text = local_state.to_json().map_err(|_| {
        materialization_error(
            "apply.local_state_serialize",
            "the proposed machine-local state could not be serialized",
        )
    })?;
    let disposition = if retained {
        ApplyDisposition::NoOp
    } else {
        ApplyDisposition::Remove
    };
    let digest = extension_plan_digest(
        asset_id,
        policy,
        &destination,
        &manifest_revision,
        disposition,
        Some(&proposed_receipt),
        &destination_observation,
        &proposed_receipt,
        None,
        local_state_text,
        &proposed_local_state_text,
    )?;
    Ok(ExtensionApplyPlan {
        asset_id: asset_id.clone(),
        destination,
        relative_destination,
        manifest_revision,
        disposition,
        observed_receipt: Some(proposed_receipt.clone()),
        observed_destination: destination_observation,
        rendered,
        policy: policy.clone(),
        project_trust: None,
        proposed_receipt,
        proposed_local_state: local_state,
        observed_local_state_text: local_state_text.to_owned(),
        digest,
    })
}

/// Verifies exact-object and project trust before the target destination is inspected.
pub fn authorize_extension_apply(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    authority: ExtensionApplyAuthority<'_>,
    local_state_text: &str,
) -> Result<(), MaterializationError> {
    validate_extension_source(
        manifest,
        asset_id,
        object,
        policy,
        Some(authority),
        local_state_text,
    )
}

fn validate_extension_source(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    policy: &ExtensionTargetPolicy,
    authority: Option<ExtensionApplyAuthority<'_>>,
    local_state_text: &str,
) -> Result<(), MaterializationError> {
    manifest.validate().map_err(|_| {
        materialization_error("apply.manifest_invalid", "manifest authority is invalid")
    })?;
    let local_state = LocalState::from_json(local_state_text).map_err(|_| {
        materialization_error(
            "apply.local_state_invalid",
            "machine-local state is invalid",
        )
    })?;
    validate_local_receipts(&local_state)?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        materialization_error(
            "apply.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    if asset.kind != AssetKind::Extension || asset.content_class != ContentClass::Executable {
        return Err(materialization_error(
            "apply.extension_asset_invalid",
            "the selected asset is not an executable native extension",
        ));
    }
    let objects = VerifiedSkillObjectCatalog::new_with_extensions([], [], [object.clone()])
        .map_err(|_| {
            materialization_error(
                "apply.extension_object_invalid",
                "extension object authority is invalid",
            )
        })?;
    validate_extension_snapshot_asset(asset, &objects).map_err(|_| {
        materialization_error(
            "apply.extension_asset_invalid",
            "the selected asset is not a closed verified native extension",
        )
    })?;
    let selected = asset.native_variants.get(&HarnessId::Pi).ok_or_else(|| {
        materialization_error(
            "apply.extension_asset_invalid",
            "the selected asset is not a closed verified native extension",
        )
    })?;
    if selected.object_hash != *object.hash() {
        return Err(materialization_error(
            "apply.extension_object_mismatch",
            "the extension object does not match manifest authority",
        ));
    }
    if authority.is_some() {
        match local_state.trust.get(object.hash()) {
            Some(TrustDecision::Trusted { .. }) => {}
            Some(TrustDecision::Denied { .. }) => {
                return Err(materialization_error(
                    "apply.executable_trust_denied",
                    "the exact extension object is denied on this machine",
                ));
            }
            None => {
                return Err(materialization_error(
                    "apply.executable_trust_required",
                    "the exact extension object is not trusted on this machine",
                ));
            }
        }
    }
    if policy.harness != HarnessId::Pi
        || policy.policy_line != kitrove_adapter_api::PolicyLine::PiLatest
    {
        return Err(materialization_error(
            "apply.extension_policy_invalid",
            "the selected Pi extension policy is not the compiled target policy",
        ));
    }
    policy
        .validate_pi_native_extensions()
        .map_err(|error| materialization_error(error.code, error.message))?;
    if let Some(authority) = authority {
        validate_project_trust(policy.scope, authority.anchor, authority.project_trust)?;
        let verified = VersionObservationOwned::from(
            kitrove_adapter_api::VersionObservation::Verified(authority.version.evidence()),
        );
        if policy.version != verified
            || policy.policy_line != authority.version.evidence().policy_line()
        {
            return Err(materialization_error(
                "apply.harness_version_unverified",
                "extension materialization requires exact verified harness version evidence",
            ));
        }
    }
    let compatibility = asset.compatibility.get(&HarnessId::Pi).ok_or_else(|| {
        materialization_error(
            "apply.compatibility_missing",
            "the selected asset has no Pi compatibility result",
        )
    })?;
    if compatibility.fidelity() != Fidelity::Blocked
        || compatibility.adapter_version() != policy.adapter_version
    {
        return Err(materialization_error(
            "apply.adapter_version_mismatch",
            "the selected target policy differs from manifest compatibility authority",
        ));
    }
    Ok(())
}

fn extension_disposition(
    asset: &kitrove_model::Asset,
    policy: &ExtensionTargetPolicy,
    manifest_revision: &Revision,
    object: &NativeExtensionObject,
    receipt: Option<&DeploymentReceipt>,
    observation: &ExtensionDestinationObservation,
) -> Result<(ApplyDisposition, Option<ContentHash>), MaterializationError> {
    match (receipt, observation) {
        (None, ExtensionDestinationObservation::Absent) => Ok((ApplyDisposition::Install, None)),
        (None, ExtensionDestinationObservation::Present { .. }) => Err(materialization_error(
            "apply.destination_unmanaged",
            "an unmanaged destination is never overwritten",
        )),
        (_, ExtensionDestinationObservation::Unsafe) => Err(materialization_error(
            "apply.destination_unsafe",
            "the selected destination could not be inspected safely",
        )),
        (Some(receipt), ExtensionDestinationObservation::Absent) => {
            Ok((ApplyDisposition::Restore, receipt.prior_hash.clone()))
        }
        (
            Some(receipt),
            ExtensionDestinationObservation::Present {
                layout,
                object_hash,
            },
        ) => {
            if *layout != object.layout() || object_hash != &receipt.rendered_hash {
                return Err(materialization_error(
                    "apply.destination_modified",
                    "the managed extension destination changed after materialization",
                ));
            }
            if receipt.source_hash == asset.content_hash
                && receipt.rendered_hash == *object.hash()
                && receipt.adapter_version == policy.adapter_version
                && receipt.environment_revision == *manifest_revision
            {
                Ok((ApplyDisposition::NoOp, receipt.prior_hash.clone()))
            } else {
                Ok((
                    ApplyDisposition::ManagedUpdate,
                    Some(receipt.rendered_hash.clone()),
                ))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extension_plan_digest(
    asset_id: &AssetId,
    policy: &ExtensionTargetPolicy,
    destination: &NormalizedDestination,
    manifest_revision: &Revision,
    disposition: ApplyDisposition,
    observed_receipt: Option<&DeploymentReceipt>,
    observation: &ExtensionDestinationObservation,
    proposed_receipt: &DeploymentReceipt,
    project_trust: Option<&PiProjectTrustEvidence>,
    observed_local_state_text: &str,
    proposed_local_state_text: &str,
) -> Result<ContentHash, MaterializationError> {
    extension_plan_digest_from_authority(
        asset_id,
        &policy.harness,
        policy.scope,
        &policy.relative_root,
        policy.policy_line,
        &policy.version,
        policy.adapter_version,
        policy.evidence.as_str(),
        destination,
        manifest_revision,
        disposition,
        observed_receipt.map(|receipt| &receipt.rendered_hash),
        observation,
        project_trust,
        &proposed_receipt.source_hash,
        &proposed_receipt.rendered_hash,
        &ContentHash::digest(observed_local_state_text.as_bytes()),
        &ContentHash::digest(proposed_local_state_text.as_bytes()),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn extension_plan_digest_from_authority(
    asset_id: &AssetId,
    policy_harness: &HarnessId,
    policy_scope: HarnessScope,
    policy_relative_root: &PortablePath,
    policy_line: kitrove_adapter_api::PolicyLine,
    policy_version: &VersionObservationOwned,
    policy_adapter_version: &str,
    policy_evidence: &str,
    destination: &NormalizedDestination,
    manifest_revision: &Revision,
    disposition: ApplyDisposition,
    observed_receipt_hash: Option<&ContentHash>,
    observation: &ExtensionDestinationObservation,
    project_trust: Option<&PiProjectTrustEvidence>,
    proposed_source_hash: &ContentHash,
    proposed_rendered_hash: &ContentHash,
    observed_local_state_hash: &ContentHash,
    proposed_local_state_hash: &ContentHash,
) -> Result<ContentHash, MaterializationError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-extension-apply-plan-v1\0");
    for value in [
        asset_id.as_str(),
        policy_harness.as_str(),
        policy_scope.as_str(),
        policy_line.as_str(),
        policy_relative_root.as_str(),
        policy_adapter_version,
        policy_evidence,
        destination.as_str(),
        manifest_revision.as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    match policy_version {
        VersionObservationOwned::Verified {
            observed,
            policy_line,
            evidence,
        } => {
            hasher.update(&[1]);
            for value in [observed.as_str(), policy_line.as_str(), evidence.as_str()] {
                write_digest_record(&mut hasher, value);
            }
        }
        VersionObservationOwned::Unknown => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&[match disposition {
        ApplyDisposition::Install => 0,
        ApplyDisposition::NoOp => 1,
        ApplyDisposition::Restore => 2,
        ApplyDisposition::ManagedUpdate => 3,
        ApplyDisposition::Remove => 4,
    }]);
    write_digest_record(
        &mut hasher,
        observed_receipt_hash.map_or("none", ContentHash::as_str),
    );
    match observation {
        ExtensionDestinationObservation::Absent => {
            hasher.update(&[0]);
        }
        ExtensionDestinationObservation::Present {
            layout,
            object_hash,
        } => {
            hasher.update(&[
                1,
                match layout {
                    NativeExtensionLayout::Standalone => 0,
                    NativeExtensionLayout::Directory => 1,
                },
            ]);
            write_digest_record(&mut hasher, object_hash.as_str());
        }
        ExtensionDestinationObservation::Unsafe => {
            hasher.update(&[2]);
        }
    };
    match project_trust {
        Some(evidence) => {
            hasher.update(&[1]);
            for value in evidence.binding_values() {
                write_digest_record(&mut hasher, value);
            }
            write_digest_record(&mut hasher, evidence.trust_store_hash().as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    for value in [
        proposed_source_hash.as_str(),
        proposed_rendered_hash.as_str(),
        observed_local_state_hash.as_str(),
        proposed_local_state_hash.as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex())).map_err(|_| {
        materialization_error(
            "apply.plan_digest_failed",
            "the extension apply plan digest could not be derived",
        )
    })
}

const fn materialization_error(code: &'static str, message: &'static str) -> MaterializationError {
    MaterializationError::new(code, message)
}

fn validate_project_trust(
    scope: HarnessScope,
    anchor: &Path,
    project_trust: Option<&PiProjectTrustEvidence>,
) -> Result<(), MaterializationError> {
    match scope {
        HarnessScope::User if project_trust.is_none() => Ok(()),
        HarnessScope::Project => {
            let expected = normalized_destination_from_path(anchor).map_err(|_| {
                materialization_error(
                    "apply.project_trust_required",
                    "Pi project extension materialization requires verifiable project trust",
                )
            })?;
            if project_trust.is_some_and(|evidence| evidence.project_anchor() == &expected) {
                Ok(())
            } else {
                Err(materialization_error(
                    "apply.project_trust_required",
                    "Pi project extension materialization requires verifiable project trust",
                ))
            }
        }
        HarnessScope::User => Err(materialization_error(
            "apply.extension_policy_invalid",
            "user-scope extension materialization must not carry project trust authority",
        )),
    }
}
