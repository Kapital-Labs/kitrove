use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use std::collections::{BTreeMap, BTreeSet};

use kitrove_adapter_api::{ObservationId, RootTier};
use kitrove_agent_skills::{NativeSkillObject, StoredSkillTree};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, DeploymentReceipt, EnvironmentManifest, LocalState,
    Lockfile, NativeVariant, PortableContent, PortablePath, ProvenanceId, Revision, SyncLimits,
};

use crate::merge::rederive_skill_asset;
use crate::{
    AcceptedObservedCandidate, AdoptionBlockReason, AdoptionPlanOutcome, LockStatus,
    ObservedCandidate, ScanClassification, ScanReport, TierOneCapabilities,
    VerifiedSkillObjectCatalog, compare_lockfile, derive_lockfile, derive_manifest_revision,
    plan_adoption,
};

const PORTABLE_FORMAT: &str = "agent-skills/v1";
const NATIVE_FORMAT: &str = "kitrove-native-skill-object/v1";

/// The reviewed evidence category authorizing an explicit update proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateSourceAuthority {
    /// A valid deployment receipt proves that the selected destination is managed and modified.
    ManagedModified,
    /// The selected observation came from one exact caller-supplied explicit root.
    ExplicitRoot,
}

/// A classified accepted observation eligible for exact-prior update planning.
#[derive(Clone, Eq, PartialEq)]
pub struct UpdateSource {
    selected: AcceptedObservedCandidate,
    asset_id: AssetId,
    authority: UpdateSourceAuthority,
    receipt: Option<DeploymentReceipt>,
    observed_local_state_text: Option<String>,
}

impl UpdateSource {
    /// Returns the fresh accepted observation selected by exact identity.
    #[must_use]
    pub const fn selected(&self) -> &AcceptedObservedCandidate {
        &self.selected
    }

    /// Returns the existing asset identity the update is allowed to target.
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    /// Returns the typed review authority for this source.
    #[must_use]
    pub const fn authority(&self) -> UpdateSourceAuthority {
        self.authority
    }

    /// Returns the exact valid receipt only for managed-modified authority.
    #[must_use]
    pub const fn receipt(&self) -> Option<&DeploymentReceipt> {
        self.receipt.as_ref()
    }

    /// Returns the exact old local-state bytes bound by managed-modified authority.
    #[must_use]
    pub fn observed_local_state_text(&self) -> Option<&str> {
        self.observed_local_state_text.as_deref()
    }
}

impl Debug for UpdateSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateSource")
            .field("authority", &self.authority)
            .field("receipt_present", &self.receipt.is_some())
            .finish_non_exhaustive()
    }
}

/// A stable, authored-value-redacted update source selection failure.
#[derive(Clone, Eq, PartialEq)]
pub struct UpdateSelectionError {
    code: &'static str,
    message: &'static str,
}

impl UpdateSelectionError {
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

impl Debug for UpdateSelectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateSelectionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for UpdateSelectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for UpdateSelectionError {}

/// A complete deterministic update proposal that authorizes no writes.
#[derive(Clone, Eq, PartialEq)]
pub struct UpdatePlan {
    source: UpdateSource,
    expected_prior: ContentHash,
    prior_asset: Asset,
    asset: Asset,
    portable_object: StoredSkillTree,
    native_object: NativeSkillObject,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    observed_lock_text: String,
    base_manifest_hash: ContentHash,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    proposed_local_state_text: Option<String>,
    digest: ContentHash,
}

impl UpdatePlan {
    #[must_use]
    pub const fn source(&self) -> &UpdateSource {
        &self.source
    }

    #[must_use]
    pub const fn expected_prior(&self) -> &ContentHash {
        &self.expected_prior
    }

    #[must_use]
    pub const fn prior_asset(&self) -> &Asset {
        &self.prior_asset
    }

    #[must_use]
    pub const fn asset(&self) -> &Asset {
        &self.asset
    }

    #[must_use]
    pub const fn portable_object(&self) -> &StoredSkillTree {
        &self.portable_object
    }

    #[must_use]
    pub const fn native_object(&self) -> &NativeSkillObject {
        &self.native_object
    }

    #[must_use]
    pub const fn proposed_manifest(&self) -> &EnvironmentManifest {
        &self.proposed_manifest
    }

    #[must_use]
    pub const fn proposed_lock(&self) -> &Lockfile {
        &self.proposed_lock
    }

    #[must_use]
    pub const fn base_manifest_revision(&self) -> &Revision {
        &self.base_manifest_revision
    }

    #[must_use]
    pub const fn base_manifest_hash(&self) -> &ContentHash {
        &self.base_manifest_hash
    }

    #[must_use]
    pub const fn proposed_manifest_revision(&self) -> &Revision {
        &self.proposed_manifest_revision
    }

    #[must_use]
    pub fn proposed_local_state_text(&self) -> Option<&str> {
        self.proposed_local_state_text.as_deref()
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    /// Revalidates the complete captured observation immediately before mutation.
    pub fn ensure_observation_fresh(
        &self,
        reread: &AcceptedObservedCandidate,
    ) -> Result<(), UpdatePlanningError> {
        let destination_matches = match self.source.receipt() {
            Some(receipt) => {
                ObservedCandidate::Accepted(Box::new(reread.clone())).normalized_destination()
                    == Some(&receipt.destination)
            }
            None => true,
        };
        if self.source.selected() == reread && destination_matches {
            Ok(())
        } else {
            Err(planning_error("update.observation_stale"))
        }
    }

    /// Revalidates exact manifest and generated-lock authority immediately before mutation.
    pub fn ensure_portable_authority_fresh(
        &self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), UpdatePlanningError> {
        let revision = derive_manifest_revision(manifest)
            .map_err(|_| planning_error("update.manifest_stale"))?;
        if ContentHash::digest(manifest_text.as_bytes()) != self.base_manifest_hash
            || revision != self.base_manifest_revision
            || manifest
                .assets
                .get(self.source.asset_id())
                .map(|asset| &asset.content_hash)
                != Some(&self.expected_prior)
            || lock_text != Some(self.observed_lock_text.as_str())
            || compare_lockfile(manifest, lock_text).map(|comparison| comparison.status())
                != Ok(LockStatus::InSync)
        {
            return Err(planning_error("update.manifest_stale"));
        }
        Ok(())
    }

    /// Revalidates the exact machine-local bytes bound by managed update authority.
    pub fn ensure_local_state_fresh(
        &self,
        local_state_text: Option<&str>,
    ) -> Result<(), UpdatePlanningError> {
        if local_state_text == self.source.observed_local_state_text() {
            Ok(())
        } else {
            Err(planning_error("update.local_state_stale"))
        }
    }
}

impl Debug for UpdatePlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdatePlan")
            .field("authority", &self.source.authority)
            .field("asset_id", &self.asset.id)
            .field("expected_prior", &self.expected_prior)
            .field("proposed_revision", &self.asset.content_hash)
            .field("receipt_rebased", &self.proposed_local_state_text.is_some())
            .field("digest", &self.digest)
            .finish()
    }
}

/// A stable, authored-value-redacted update planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct UpdatePlanningError {
    code: &'static str,
    message: &'static str,
}

impl UpdatePlanningError {
    fn new(code: &'static str, message: &'static str) -> Self {
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

impl Debug for UpdatePlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdatePlanningError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for UpdatePlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for UpdatePlanningError {}

/// Produces a complete exact-prior update plan without mutating portable or local state.
#[allow(clippy::too_many_arguments)]
pub fn plan_update_adoption(
    source: &UpdateSource,
    expected_prior: &ContentHash,
    observed_manifest_text: &str,
    manifest: &EnvironmentManifest,
    current_lock_text: Option<&str>,
    retained_objects: &VerifiedSkillObjectCatalog,
    capabilities: &TierOneCapabilities,
    limits: SyncLimits,
) -> Result<UpdatePlan, UpdatePlanningError> {
    if EnvironmentManifest::from_toml(observed_manifest_text).as_ref() != Ok(manifest) {
        return Err(planning_error("update.manifest_invalid"));
    }
    manifest
        .validate()
        .map_err(|_| planning_error("update.manifest_invalid"))?;
    let lock = compare_lockfile(manifest, current_lock_text)
        .map_err(|_| planning_error("update.manifest_invalid"))?;
    if lock.status() != LockStatus::InSync {
        return Err(planning_error("update.lock_not_in_sync"));
    }
    let observed_lock_text = current_lock_text
        .ok_or_else(|| planning_error("update.lock_not_in_sync"))?
        .to_owned();
    let base_manifest_revision = derive_manifest_revision(manifest)
        .map_err(|_| planning_error("update.manifest_invalid"))?;
    let base_manifest_hash = ContentHash::digest(observed_manifest_text.as_bytes());
    let prior_asset = manifest
        .assets
        .get(source.asset_id())
        .ok_or_else(|| planning_error("update.asset_missing"))?;
    if prior_asset.kind != AssetKind::Skill {
        return Err(planning_error("update.asset_unsupported"));
    }
    if &prior_asset.content_hash != expected_prior {
        return Err(planning_error("update.expected_prior_mismatch"));
    }

    validate_receipt_authority(source, expected_prior, &base_manifest_revision)?;

    let empty_manifest = EnvironmentManifest {
        schema_version: manifest.schema_version,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let seed = match plan_adoption(
        source.selected(),
        Some(source.asset_id().clone()),
        &empty_manifest,
        capabilities,
    )
    .map_err(|_| planning_error("update.source_invalid"))?
    {
        AdoptionPlanOutcome::Ready(plan) => plan,
        AdoptionPlanOutcome::Blocked(block) => {
            return Err(planning_error(match block.reason() {
                AdoptionBlockReason::PortableProjectionUnavailable => {
                    "update.projection_unavailable"
                }
                AdoptionBlockReason::ExecutableTrustRequired => "update.executable_blocked",
                AdoptionBlockReason::CredentialShapedNativeIdentity => {
                    "update.credential_shaped_identity"
                }
                AdoptionBlockReason::AssetConflict => "update.source_invalid",
            }));
        }
    };
    let portable_object = seed.portable_object().clone();
    let native_object = seed.native_object().clone();
    let seed_asset = seed.asset();
    let new_provenance_id = seed_asset
        .portable
        .as_ref()
        .map(|component| component.provenance.clone())
        .ok_or_else(|| planning_error("update.projection_unavailable"))?;
    let new_provenance = seed_asset
        .provenance
        .get(&new_provenance_id)
        .cloned()
        .ok_or_else(|| planning_error("update.provenance_invalid"))?;

    let portable = PortableContent {
        format: PORTABLE_FORMAT.to_owned(),
        root: update_portable_root(source.asset_id(), portable_object.tree().hash.as_str())?,
        object_hash: portable_object.tree().hash.clone(),
        provenance: new_provenance_id.clone(),
    };
    let selected_harness = source.selected().location().harness.clone();
    let mut native_variants = prior_asset.native_variants.clone();
    native_variants.insert(
        selected_harness.clone(),
        NativeVariant {
            harness: selected_harness.clone(),
            format: NATIVE_FORMAT.to_owned(),
            root: update_native_root(
                source.asset_id(),
                &selected_harness,
                native_object.hash().as_str(),
            )?,
            object_hash: native_object.hash().clone(),
            content_class: source.selected().captured().content_class,
            provenance: new_provenance_id.clone(),
        },
    );

    let referenced_provenance: BTreeSet<ProvenanceId> = native_variants
        .values()
        .map(|component| component.provenance.clone())
        .chain([new_provenance_id.clone()])
        .collect();
    let mut provenance = BTreeMap::new();
    for id in referenced_provenance {
        let record = if id == new_provenance_id {
            new_provenance.clone()
        } else {
            prior_asset
                .provenance
                .get(&id)
                .cloned()
                .ok_or_else(|| planning_error("update.provenance_invalid"))?
        };
        provenance.insert(id, record);
    }

    let objects = retained_objects
        .with_additional(portable_object.clone(), native_object.clone(), limits)
        .map_err(|_| planning_error("update.object_catalog_invalid"))?;
    let asset = rederive_skill_asset(
        source.asset_id().clone(),
        provenance,
        portable,
        native_variants,
        &objects,
        capabilities,
    )
    .map_err(|error| {
        if error.code() == "sync_merge.object_missing" {
            planning_error("update.retained_object_invalid")
        } else {
            planning_error("update.derivation_failed")
        }
    })?;
    if &asset.content_hash == expected_prior {
        return Err(planning_error("update.revision_unchanged"));
    }

    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .assets
        .insert(source.asset_id().clone(), asset.clone());
    proposed_manifest
        .validate()
        .map_err(|_| planning_error("update.proposed_manifest_invalid"))?;
    let proposed_lock = derive_lockfile(&proposed_manifest)
        .map_err(|_| planning_error("update.proposed_lock_invalid"))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| planning_error("update.proposed_manifest_invalid"))?;
    let proposed_local_state_text =
        rebase_receipt(source, &asset, &proposed_manifest_revision, capabilities)?;
    let digest = update_plan_digest(
        source,
        expected_prior,
        &asset,
        (&base_manifest_revision, &proposed_manifest_revision),
        (&proposed_lock, &observed_lock_text),
        &base_manifest_hash,
        proposed_local_state_text.as_deref(),
    )?;

    Ok(UpdatePlan {
        source: source.clone(),
        expected_prior: expected_prior.clone(),
        prior_asset: prior_asset.clone(),
        asset,
        portable_object,
        native_object,
        proposed_manifest,
        proposed_lock,
        observed_lock_text,
        base_manifest_hash,
        base_manifest_revision,
        proposed_manifest_revision,
        proposed_local_state_text,
        digest,
    })
}

fn validate_receipt_authority(
    source: &UpdateSource,
    expected_prior: &ContentHash,
    base_manifest_revision: &Revision,
) -> Result<(), UpdatePlanningError> {
    match source.authority() {
        UpdateSourceAuthority::ExplicitRoot if source.receipt().is_none() => Ok(()),
        UpdateSourceAuthority::ManagedModified => {
            let receipt = source
                .receipt()
                .ok_or_else(|| planning_error("update.receipt_invalid"))?;
            if &receipt.source_hash != expected_prior
                || &receipt.environment_revision != base_manifest_revision
            {
                return Err(planning_error("update.receipt_stale"));
            }
            Ok(())
        }
        UpdateSourceAuthority::ExplicitRoot => Err(planning_error("update.receipt_invalid")),
    }
}

fn rebase_receipt(
    source: &UpdateSource,
    asset: &Asset,
    proposed_manifest_revision: &Revision,
    capabilities: &TierOneCapabilities,
) -> Result<Option<String>, UpdatePlanningError> {
    let Some(old_receipt) = source.receipt() else {
        return Ok(None);
    };
    let old_text = source
        .observed_local_state_text()
        .ok_or_else(|| planning_error("update.local_state_invalid"))?;
    let replacement = DeploymentReceipt {
        asset_id: old_receipt.asset_id.clone(),
        harness: old_receipt.harness.clone(),
        scope: old_receipt.scope,
        destination: old_receipt.destination.clone(),
        target: old_receipt.target,
        logical_key: old_receipt.logical_key.clone(),
        shared_with: old_receipt.shared_with.clone(),
        shared_adapter_versions: old_receipt.shared_adapter_versions.clone(),
        source_hash: asset.content_hash.clone(),
        rendered_hash: source.selected().captured().exact_source_hash.clone(),
        document_hash: old_receipt.document_hash.clone(),
        prior_hash: Some(old_receipt.rendered_hash.clone()),
        adapter_version: capabilities
            .skill(&old_receipt.harness)
            .result
            .adapter_version()
            .to_owned(),
        environment_revision: proposed_manifest_revision.clone(),
    };
    replace_receipt_in_local_state(old_text, old_receipt, replacement)
        .map(Some)
        .map_err(|()| planning_error("update.local_state_invalid"))
}

pub(crate) fn replace_receipt_in_local_state(
    state_text: &str,
    reviewed: &DeploymentReceipt,
    replacement: DeploymentReceipt,
) -> Result<String, ()> {
    let reviewed_id = reviewed.receipt_id().map_err(|_| ())?;
    if replacement.receipt_id().map_err(|_| ())? != reviewed_id {
        return Err(());
    }
    let mut state = LocalState::from_json(state_text).map_err(|_| ())?;
    if state.receipts.get(&reviewed_id) != Some(reviewed) {
        return Err(());
    }
    state.receipts.insert(reviewed_id, replacement);
    state.to_json().map_err(|_| ())
}

fn update_portable_root(
    asset_id: &AssetId,
    object_hash: &str,
) -> Result<PortablePath, UpdatePlanningError> {
    update_root(asset_id, None, object_hash)
}

fn update_native_root(
    asset_id: &AssetId,
    harness: &kitrove_model::HarnessId,
    object_hash: &str,
) -> Result<PortablePath, UpdatePlanningError> {
    update_root(asset_id, Some(harness), object_hash)
}

fn update_root(
    asset_id: &AssetId,
    harness: Option<&kitrove_model::HarnessId>,
    object_hash: &str,
) -> Result<PortablePath, UpdatePlanningError> {
    let digest = object_hash
        .strip_prefix("blake3:")
        .ok_or_else(|| planning_error("update.object_hash_invalid"))?;
    let path = match harness {
        Some(harness) => format!(
            "assets/{}/updates/native/{}/blake3-{digest}",
            asset_id.as_str(),
            harness.as_str()
        ),
        None => format!(
            "assets/{}/updates/portable/blake3-{digest}",
            asset_id.as_str()
        ),
    };
    PortablePath::parse(path).map_err(|_| planning_error("update.object_path_invalid"))
}

fn update_plan_digest(
    source: &UpdateSource,
    expected_prior: &ContentHash,
    asset: &Asset,
    revisions: (&Revision, &Revision),
    locks: (&Lockfile, &str),
    base_manifest_hash: &ContentHash,
    proposed_local_state_text: Option<&str>,
) -> Result<ContentHash, UpdatePlanningError> {
    let (base_manifest_revision, proposed_manifest_revision) = revisions;
    let (proposed_lock, observed_lock_text) = locks;
    let lock_text = proposed_lock
        .to_json()
        .map_err(|_| planning_error("update.plan_digest_failed"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-update-plan-v1\0");
    write_digest_record(&mut hasher, source.selected().observation_id().as_str());
    write_digest_record(&mut hasher, source.asset_id().as_str());
    hasher.update(&[match source.authority() {
        UpdateSourceAuthority::ManagedModified => 0,
        UpdateSourceAuthority::ExplicitRoot => 1,
    }]);
    for value in [
        expected_prior.as_str(),
        asset.content_hash.as_str(),
        base_manifest_revision.as_str(),
        proposed_manifest_revision.as_str(),
        base_manifest_hash.as_str(),
        ContentHash::digest(lock_text.as_bytes()).as_str(),
        ContentHash::digest(observed_lock_text.as_bytes()).as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    match proposed_local_state_text {
        Some(text) => {
            hasher.update(&[1]);
            write_digest_record(&mut hasher, ContentHash::digest(text.as_bytes()).as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| planning_error("update.plan_digest_failed"))
}

fn write_digest_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn planning_error(code: &'static str) -> UpdatePlanningError {
    let message = match code {
        "update.manifest_invalid" => "update planning requires valid manifest authority",
        "update.lock_not_in_sync" => "update planning requires generated lock state in sync",
        "update.asset_missing" => "the requested update asset does not exist",
        "update.asset_unsupported" => "the requested asset does not support update adoption",
        "update.expected_prior_mismatch" => "the expected prior asset revision is stale",
        "update.receipt_stale" => "the managed update receipt is stale",
        "update.projection_unavailable" => "the update has no portable projection",
        "update.executable_blocked" => "executable update content requires later trust authority",
        "update.credential_shaped_identity" => "the update native identity is credential-shaped",
        "update.retained_object_invalid" => "a retained update object is missing or invalid",
        "update.object_catalog_invalid" => "update objects exceed limits or have invalid aliases",
        "update.derivation_failed" => "the complete update asset could not be rederived",
        "update.revision_unchanged" => "the update does not produce a new asset revision",
        "update.receipt_invalid" => "the managed update receipt is invalid",
        "update.local_state_invalid" => "the managed update local state is invalid",
        "update.observation_stale" => "the selected update observation changed after planning",
        "update.manifest_stale" => "portable update authority changed after planning",
        "update.local_state_stale" => "machine-local update authority changed after planning",
        _ => "the explicit update proposal is invalid",
    };
    UpdatePlanningError::new(code, message)
}

impl ScanReport {
    /// Selects one exact classified observation without accepting caller-fabricated ownership.
    pub fn select_update_source(
        &self,
        observation_id: &ObservationId,
        asset_id: &AssetId,
        local_state_text: Option<&str>,
    ) -> Result<UpdateSource, UpdateSelectionError> {
        if self.mode != crate::ScanMode::Classified {
            return Err(selection_error(
                "update_source.classified_scan_required",
                "update selection requires a fresh classified scan",
            ));
        }
        let observations = self
            .observations()
            .iter()
            .filter(|observation| observation.observation_id() == Some(observation_id))
            .collect::<Vec<_>>();
        let [observation] = observations.as_slice() else {
            return Err(selection_error(
                "update_source.observation_unavailable",
                "update selection requires exactly one accepted observation",
            ));
        };
        let ObservedCandidate::Accepted(selected) = observation else {
            return Err(selection_error(
                "update_source.observation_unavailable",
                "update selection requires exactly one accepted observation",
            ));
        };
        let entries = self
            .entries
            .iter()
            .filter(|entry| entry.observation_id.as_ref() == Some(observation_id))
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return Err(selection_error(
                "update_source.classification_ambiguous",
                "update selection requires exactly one classified observation entry",
            ));
        };
        if entry.exact_source_hash.as_ref() != Some(&selected.captured().exact_source_hash)
            || entry.shadowed_by.is_some()
        {
            return Err(selection_error(
                "update_source.evidence_mismatch",
                "classified update evidence does not match the accepted observation",
            ));
        }

        match entry.classification {
            ScanClassification::ManagedModified => {
                select_managed_modified(observation, selected, entry, asset_id, local_state_text)
            }
            ScanClassification::Unmanaged
                if selected.location().root_tier == RootTier::Explicit
                    && entry.asset_id.is_none()
                    && entry.receipt_id.is_none() =>
            {
                Ok(UpdateSource {
                    selected: (**selected).clone(),
                    asset_id: asset_id.clone(),
                    authority: UpdateSourceAuthority::ExplicitRoot,
                    receipt: None,
                    observed_local_state_text: None,
                })
            }
            _ => Err(selection_error(
                "update_source.not_eligible",
                "the selected observation is not an eligible explicit update source",
            )),
        }
    }
}

fn select_managed_modified(
    observation: &ObservedCandidate,
    selected: &AcceptedObservedCandidate,
    entry: &crate::ScanEntry,
    asset_id: &AssetId,
    local_state_text: Option<&str>,
) -> Result<UpdateSource, UpdateSelectionError> {
    if entry
        .findings
        .iter()
        .any(|finding| finding.code == "scan.receipt_stale_desired_state")
    {
        return Err(selection_error(
            "update_source.receipt_stale",
            "the managed receipt does not match current portable authority",
        ));
    }
    let text = local_state_text.ok_or_else(|| {
        selection_error(
            "update_source.local_state_required",
            "managed update selection requires exact machine-local state",
        )
    })?;
    let state = LocalState::from_json(text).map_err(|_| {
        selection_error(
            "update_source.local_state_invalid",
            "managed update selection requires valid strict machine-local state",
        )
    })?;
    let receipt_id = entry.receipt_id.as_ref().ok_or_else(evidence_mismatch)?;
    let receipt = state
        .receipts
        .get(receipt_id)
        .ok_or_else(evidence_mismatch)?;
    if receipt.receipt_id().ok().as_ref() != Some(receipt_id)
        || entry.asset_id.as_ref() != Some(asset_id)
        || &receipt.asset_id != asset_id
        || entry.harness != receipt.harness
        || entry.scope != receipt.scope
        || receipt.harness != selected.location().harness
        || receipt.scope != selected.location().scope
        || entry.normalized_destination.as_deref() != Some(receipt.destination.as_str())
        || entry.receipt_rendered_hash.as_ref() != Some(&receipt.rendered_hash)
        || selected.captured().exact_source_hash == receipt.rendered_hash
        || observation.normalized_destination() != Some(&receipt.destination)
    {
        return Err(evidence_mismatch());
    }
    Ok(UpdateSource {
        selected: selected.clone(),
        asset_id: asset_id.clone(),
        authority: UpdateSourceAuthority::ManagedModified,
        receipt: Some(receipt.clone()),
        observed_local_state_text: Some(text.to_owned()),
    })
}

fn evidence_mismatch() -> UpdateSelectionError {
    selection_error(
        "update_source.evidence_mismatch",
        "classified update evidence does not match strict receipt ownership",
    )
}

fn selection_error(code: &'static str, message: &'static str) -> UpdateSelectionError {
    UpdateSelectionError::new(code, message)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_adapter_api::{
        CandidateDecision, NativeAcceptance, ObservationIdentity, PortablePolicyDecision,
    };
    use kitrove_agent_skills::CaptureUsage;
    use kitrove_agent_skills::{
        PortableProjection, hash_skill_source, hash_tree, project_skill_source,
    };
    use kitrove_model::{
        ContentHash, DeploymentReceipt, FidelityReason, HarnessId, HarnessScope, LocalState,
        MachineConfig, MachineId, NormalizedDestination, Revision, SchemaVersion,
    };

    use super::*;
    use crate::adoption::tests::make_candidate;
    use crate::adoption::tests::{capabilities, ready_plan, with_portable_decision};
    use crate::{ObservedCandidate, ScanEntry, ScanMode};

    fn managed_report() -> (ScanReport, LocalState, AssetId, ObservationId) {
        let destination =
            NormalizedDestination::parse("/Users/test/.claude/skills/review").unwrap();
        let candidate = make_candidate(kitrove_agent_skills::FileMode::Regular, "review")
            .with_test_destination(destination.clone());
        let asset_id = AssetId::parse("review").unwrap();
        let observation_id = candidate.observation_id().clone();
        let receipt = DeploymentReceipt {
            asset_id: asset_id.clone(),
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            destination: destination.clone(),
            target: Default::default(),
            logical_key: None,
            shared_with: Default::default(),
            shared_adapter_versions: Default::default(),
            source_hash: ContentHash::digest(b"prior asset"),
            rendered_hash: ContentHash::digest(b"prior target"),
            document_hash: None,
            prior_hash: None,
            adapter_version: "test/1".to_owned(),
            environment_revision: Revision::parse("manifest:prior").unwrap(),
        };
        let receipt_id = receipt.receipt_id().unwrap();
        let state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("machine-test").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: BTreeMap::from([(receipt_id.clone(), receipt.clone())]),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: vec![],
        };
        let entry = ScanEntry {
            observation_id: Some(observation_id.clone()),
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            root_tier: Some(RootTier::User),
            logical_root: None,
            policy_rank: Some(1),
            source_relative_path: None,
            layout: Some(candidate.location().layout),
            native_id: None,
            asset_id: Some(asset_id.clone()),
            receipt_id: Some(receipt_id),
            normalized_destination: Some(destination.as_str().to_owned()),
            receipt_rendered_hash: Some(receipt.rendered_hash),
            classification: ScanClassification::ManagedModified,
            exact_source_hash: Some(candidate.captured().exact_source_hash.clone()),
            portable_hash: candidate.portable_hash().cloned(),
            shadowed_by: None,
            findings: vec![],
        };
        let report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            vec![entry],
            vec![],
            vec![],
            vec![ObservedCandidate::Accepted(Box::new(candidate))],
            CaptureUsage::default(),
        );
        (report, state, asset_id, observation_id)
    }

    #[test]
    fn managed_modified_selection_binds_exact_receipt_and_local_state() {
        let (report, state, asset_id, observation_id) = managed_report();
        let state_text = state.to_json().unwrap();
        let source = report
            .select_update_source(&observation_id, &asset_id, Some(&state_text))
            .unwrap();

        assert_eq!(source.authority(), UpdateSourceAuthority::ManagedModified);
        assert_eq!(source.asset_id(), &asset_id);
        assert!(source.receipt().is_some());
        assert_eq!(
            source.observed_local_state_text(),
            Some(state_text.as_str())
        );
        assert!(!format!("{source:?}").contains(destination_canary()));
    }

    #[test]
    fn stale_or_fabricated_receipt_evidence_cannot_authorize_update() {
        let (mut report, state, asset_id, observation_id) = managed_report();
        report.entries[0]
            .findings
            .push(kitrove_adapter_api::ScanFinding::new(
                "scan.receipt_stale_desired_state",
                kitrove_adapter_api::FindingSeverity::Attention,
                kitrove_adapter_api::FindingSubject::Report,
                vec![],
                "review current desired state",
            ));
        assert_eq!(
            report
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.receipt_stale"
        );

        let (mut report, state, asset_id, observation_id) = managed_report();
        report.entries[0].receipt_rendered_hash = Some(ContentHash::digest(b"forged"));
        assert_eq!(
            report
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.evidence_mismatch"
        );

        let (mut report, mut state, asset_id, observation_id) = managed_report();
        let receipt_id = report.entries[0].receipt_id.clone().unwrap();
        let observed_hash = report.entries[0].exact_source_hash.clone().unwrap();
        state.receipts.get_mut(&receipt_id).unwrap().rendered_hash = observed_hash.clone();
        report.entries[0].receipt_rendered_hash = Some(observed_hash);
        assert_eq!(
            report
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.evidence_mismatch"
        );
    }

    #[test]
    fn public_report_labels_do_not_create_managed_authority() {
        let (mut report, state, asset_id, observation_id) = managed_report();
        report.entries[0].harness = HarnessId::Codex;

        assert_eq!(
            report
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.evidence_mismatch"
        );
    }

    #[test]
    fn ambiguous_or_ineligible_scan_evidence_cannot_authorize_update() {
        let (report, state, asset_id, observation_id) = managed_report();
        let mut duplicate_observations = report.observations().to_vec();
        duplicate_observations.push(duplicate_observations[0].clone());
        let ambiguous_observation = ScanReport::new(
            report.mode,
            report.versions.clone(),
            report.entries.clone(),
            report.related.clone(),
            report.findings.clone(),
            duplicate_observations,
            report.capture_usage().clone(),
        );
        assert_eq!(
            ambiguous_observation
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.observation_unavailable"
        );

        let (mut report, state, asset_id, observation_id) = managed_report();
        report.entries.push(report.entries[0].clone());
        assert_eq!(
            report
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.classification_ambiguous"
        );

        for classification in [
            ScanClassification::ManagedUnchanged,
            ScanClassification::MissingManaged,
            ScanClassification::ConflictingDuplicate,
            ScanClassification::Unknown,
        ] {
            let (mut report, state, asset_id, observation_id) = managed_report();
            report.entries[0].classification = classification;
            assert_eq!(
                report
                    .select_update_source(
                        &observation_id,
                        &asset_id,
                        Some(&state.to_json().unwrap()),
                    )
                    .unwrap_err()
                    .code(),
                "update_source.not_eligible"
            );
        }

        let (mut report, state, asset_id, observation_id) = managed_report();
        report.entries[0].classification = ScanClassification::Unmanaged;
        report.entries[0].asset_id = None;
        report.entries[0].receipt_id = None;
        assert_eq!(
            report
                .select_update_source(&observation_id, &asset_id, Some(&state.to_json().unwrap()))
                .unwrap_err()
                .code(),
            "update_source.not_eligible"
        );
    }

    fn destination_canary() -> &'static str {
        "/Users/test/.claude/skills/review"
    }

    pub(crate) const REDACTION_AUTHORED: &str = "KITROVE_D2_AUTHORED_CANARY_6f91";
    pub(crate) const REDACTION_NATIVE_ID: &str = "d2-native-canary-6f91";
    pub(crate) const REDACTION_PATH: &str = "KITROVE_D2_ABSOLUTE_PATH_CANARY_6f91";
    pub(crate) const REDACTION_DESTINATION: &str = "KITROVE_D2_DESTINATION_CANARY_6f91";
    pub(crate) const REDACTION_SECRET: &str = "KITROVE_D2_SECRET_VALUE_CANARY_6f91";

    pub(crate) fn redaction_update_fixture() -> (
        UpdateSource,
        EnvironmentManifest,
        String,
        ContentHash,
        TierOneCapabilities,
    ) {
        let (prior_plan, prior_candidate, _) = ready_plan();
        let manifest = prior_plan.proposed_manifest().clone();
        let mut captured = prior_candidate.captured().clone();
        captured.document.body = format!("{REDACTION_AUTHORED}\n{REDACTION_SECRET}\n");
        captured
            .exact
            .files
            .get_mut(&PortablePath::parse("SKILL.md").unwrap())
            .unwrap()
            .bytes = format!(
            "---\nname: review\ndescription: Review code carefully\n---\n{REDACTION_AUTHORED}\n{REDACTION_SECRET}\n"
        )
        .into_bytes();
        captured.exact.hash = hash_tree(&captured.exact.files);
        captured.exact_source_hash = hash_skill_source(
            captured.layout,
            &captured.original_document_name,
            &captured.exact,
        );
        let projection = project_skill_source(
            &captured,
            AssetId::parse("review").unwrap(),
            "Review code carefully".to_owned(),
            vec![],
        )
        .unwrap();
        let PortableProjection::Available { tree, .. } = projection else {
            panic!("redaction candidate must remain portable");
        };
        let decision = CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(REDACTION_NATIVE_ID.to_owned()),
            prior_candidate.decision().portable().clone(),
            vec![],
        )
        .unwrap();
        let mut location = prior_candidate.location().clone();
        location.root_tier = RootTier::Explicit;
        let observation_id = ObservationId::from_identity(&ObservationIdentity {
            harness: &location.harness,
            scope: location.scope,
            root_tier: location.root_tier,
            policy_rank: location.policy_rank,
            logical_root: &location.logical_root,
            source_relative_path: location.source_relative_path.as_ref().unwrap(),
            layout: location.layout,
            original_document_name: location.original_document_name.as_deref().unwrap(),
            native_id: Some(REDACTION_NATIVE_ID),
            exact_source_hash: Some(&captured.exact_source_hash),
        });
        let destination = NormalizedDestination::parse(format!(
            "/{REDACTION_PATH}/{REDACTION_DESTINATION}/review"
        ))
        .unwrap();
        let candidate = AcceptedObservedCandidate::from_test_parts(
            observation_id.clone(),
            location,
            captured,
            Some(tree.hash),
            decision,
        )
        .with_test_destination(destination);
        let asset_id = prior_plan.asset().id.clone();
        let entry = ScanEntry {
            observation_id: Some(observation_id.clone()),
            harness: candidate.location().harness.clone(),
            scope: candidate.location().scope,
            root_tier: Some(RootTier::Explicit),
            logical_root: None,
            policy_rank: Some(candidate.location().policy_rank),
            source_relative_path: None,
            layout: Some(candidate.location().layout),
            native_id: None,
            asset_id: None,
            receipt_id: None,
            normalized_destination: None,
            receipt_rendered_hash: None,
            classification: ScanClassification::Unmanaged,
            exact_source_hash: Some(candidate.captured().exact_source_hash.clone()),
            portable_hash: candidate.portable_hash().cloned(),
            shadowed_by: None,
            findings: vec![],
        };
        let report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            vec![entry],
            vec![],
            vec![],
            vec![ObservedCandidate::Accepted(Box::new(candidate))],
            CaptureUsage::default(),
        );
        let source = report
            .select_update_source(&observation_id, &asset_id, None)
            .unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        (
            source,
            manifest,
            lock_text,
            prior_plan.asset().content_hash.clone(),
            capabilities(),
        )
    }

    fn changed_candidate(
        prior: &AcceptedObservedCandidate,
        destination: NormalizedDestination,
    ) -> AcceptedObservedCandidate {
        let mut captured = prior.captured().clone();
        captured.document.body = "Inspect the newest change.\n".to_owned();
        captured.exact.files.get_mut(&PortablePath::parse("SKILL.md").unwrap()).unwrap().bytes =
            b"---\nname: review\ndescription: Review code carefully\n---\nInspect the newest change.\n"
                .to_vec();
        captured.exact.hash = hash_tree(&captured.exact.files);
        captured.exact_source_hash = hash_skill_source(
            captured.layout,
            &captured.original_document_name,
            &captured.exact,
        );
        let projection = project_skill_source(
            &captured,
            AssetId::parse("review").unwrap(),
            "Review code carefully".to_owned(),
            vec![],
        )
        .unwrap();
        let PortableProjection::Available { tree, .. } = projection else {
            panic!("changed candidate must remain portable");
        };
        let location = prior.location().clone();
        let relative = location.source_relative_path.as_ref().unwrap();
        let native_id = prior.decision().native_id().unwrap();
        let observation_id = ObservationId::from_identity(&ObservationIdentity {
            harness: &location.harness,
            scope: location.scope,
            root_tier: location.root_tier,
            policy_rank: location.policy_rank,
            logical_root: &location.logical_root,
            source_relative_path: relative,
            layout: location.layout,
            original_document_name: location.original_document_name.as_deref().unwrap(),
            native_id: Some(native_id),
            exact_source_hash: Some(&captured.exact_source_hash),
        });
        AcceptedObservedCandidate::from_test_parts(
            observation_id,
            location,
            captured,
            Some(tree.hash),
            prior.decision().clone(),
        )
        .with_test_destination(destination)
    }

    fn as_explicit_root(candidate: &AcceptedObservedCandidate) -> AcceptedObservedCandidate {
        let mut location = candidate.location().clone();
        location.root_tier = RootTier::Explicit;
        let relative = location.source_relative_path.as_ref().unwrap();
        let observation_id = ObservationId::from_identity(&ObservationIdentity {
            harness: &location.harness,
            scope: location.scope,
            root_tier: location.root_tier,
            policy_rank: location.policy_rank,
            logical_root: &location.logical_root,
            source_relative_path: relative,
            layout: location.layout,
            original_document_name: location.original_document_name.as_deref().unwrap(),
            native_id: candidate.decision().native_id(),
            exact_source_hash: Some(&candidate.captured().exact_source_hash),
        });
        AcceptedObservedCandidate::from_test_parts(
            observation_id,
            location,
            candidate.captured().clone(),
            candidate.portable_hash().cloned(),
            candidate.decision().clone(),
        )
    }

    fn managed_update_fixture() -> (
        UpdateSource,
        EnvironmentManifest,
        String,
        ContentHash,
        TierOneCapabilities,
    ) {
        managed_update_fixture_at(NormalizedDestination::parse(destination_canary()).unwrap())
    }

    pub(crate) fn managed_update_fixture_at(
        destination: NormalizedDestination,
    ) -> (
        UpdateSource,
        EnvironmentManifest,
        String,
        ContentHash,
        TierOneCapabilities,
    ) {
        let (prior_plan, prior_candidate, _) = ready_plan();
        let manifest = prior_plan.proposed_manifest().clone();
        let prior_hash = prior_plan.asset().content_hash.clone();
        let manifest_revision = derive_manifest_revision(&manifest).unwrap();
        let changed = changed_candidate(&prior_candidate, destination.clone());
        let asset_id = prior_plan.asset().id.clone();
        let receipt = DeploymentReceipt {
            asset_id: asset_id.clone(),
            harness: changed.location().harness.clone(),
            scope: changed.location().scope,
            destination: destination.clone(),
            target: Default::default(),
            logical_key: None,
            shared_with: Default::default(),
            shared_adapter_versions: Default::default(),
            source_hash: prior_hash.clone(),
            rendered_hash: prior_candidate.captured().exact_source_hash.clone(),
            document_hash: None,
            prior_hash: None,
            adapter_version: "test/1".to_owned(),
            environment_revision: manifest_revision,
        };
        let receipt_id = receipt.receipt_id().unwrap();
        let state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("machine-test").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: BTreeMap::from([(receipt_id.clone(), receipt.clone())]),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: vec![],
        };
        let state_text = state.to_json().unwrap();
        let observation_id = changed.observation_id().clone();
        let entry = ScanEntry {
            observation_id: Some(observation_id.clone()),
            harness: changed.location().harness.clone(),
            scope: changed.location().scope,
            root_tier: Some(changed.location().root_tier),
            logical_root: None,
            policy_rank: Some(changed.location().policy_rank),
            source_relative_path: None,
            layout: Some(changed.location().layout),
            native_id: None,
            asset_id: Some(asset_id.clone()),
            receipt_id: Some(receipt_id),
            normalized_destination: Some(destination.as_str().to_owned()),
            receipt_rendered_hash: Some(receipt.rendered_hash),
            classification: ScanClassification::ManagedModified,
            exact_source_hash: Some(changed.captured().exact_source_hash.clone()),
            portable_hash: changed.portable_hash().cloned(),
            shadowed_by: None,
            findings: vec![],
        };
        let report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            vec![entry],
            vec![],
            vec![],
            vec![ObservedCandidate::Accepted(Box::new(changed))],
            CaptureUsage::default(),
        );
        let source = report
            .select_update_source(&observation_id, &asset_id, Some(&state_text))
            .unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        (source, manifest, lock_text, prior_hash, capabilities())
    }

    pub(crate) fn explicit_update_fixture() -> (
        UpdateSource,
        EnvironmentManifest,
        String,
        ContentHash,
        TierOneCapabilities,
    ) {
        let (prior_plan, prior_candidate, _) = ready_plan();
        let manifest = prior_plan.proposed_manifest().clone();
        let candidate = as_explicit_root(&changed_candidate(
            &prior_candidate,
            NormalizedDestination::parse(destination_canary()).unwrap(),
        ));
        let observation_id = candidate.observation_id().clone();
        let asset_id = prior_plan.asset().id.clone();
        let entry = ScanEntry {
            observation_id: Some(observation_id.clone()),
            harness: candidate.location().harness.clone(),
            scope: candidate.location().scope,
            root_tier: Some(RootTier::Explicit),
            logical_root: None,
            policy_rank: Some(candidate.location().policy_rank),
            source_relative_path: None,
            layout: Some(candidate.location().layout),
            native_id: None,
            asset_id: None,
            receipt_id: None,
            normalized_destination: None,
            receipt_rendered_hash: None,
            classification: ScanClassification::Unmanaged,
            exact_source_hash: Some(candidate.captured().exact_source_hash.clone()),
            portable_hash: candidate.portable_hash().cloned(),
            shadowed_by: None,
            findings: vec![],
        };
        let report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            vec![entry],
            vec![],
            vec![],
            vec![ObservedCandidate::Accepted(Box::new(candidate))],
            CaptureUsage::default(),
        );
        let source = report
            .select_update_source(&observation_id, &asset_id, None)
            .unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        (
            source,
            manifest,
            lock_text,
            prior_plan.asset().content_hash.clone(),
            capabilities(),
        )
    }

    #[test]
    fn managed_update_plan_replaces_selected_components_and_rebases_receipt() {
        let (source, manifest, lock_text, prior_hash, capabilities) = managed_update_fixture();
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let plan = plan_update_adoption(
            &source,
            &prior_hash,
            &manifest.to_toml().unwrap(),
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();

        assert_ne!(plan.asset().content_hash, prior_hash);
        assert!(
            plan.asset()
                .portable
                .as_ref()
                .unwrap()
                .root
                .as_str()
                .starts_with("assets/review/updates/portable/blake3-")
        );
        assert!(
            plan.asset().native_variants[&HarnessId::Claude]
                .root
                .as_str()
                .starts_with("assets/review/updates/native/claude/blake3-")
        );
        assert_eq!(
            derive_lockfile(plan.proposed_manifest()).unwrap(),
            *plan.proposed_lock()
        );
        let rebased = LocalState::from_json(plan.proposed_local_state_text().unwrap()).unwrap();
        let receipt = rebased.receipts.values().next().unwrap();
        assert_eq!(receipt.source_hash, plan.asset().content_hash);
        assert_eq!(
            receipt.rendered_hash,
            source.selected().captured().exact_source_hash
        );
        assert_eq!(
            receipt.prior_hash.as_ref(),
            source.receipt().map(|r| &r.rendered_hash)
        );
        assert_eq!(
            receipt.environment_revision,
            *plan.proposed_manifest_revision()
        );
        assert!(!format!("{plan:?}").contains(destination_canary()));
        assert!(plan.ensure_observation_fresh(source.selected()).is_ok());
        assert!(
            plan.ensure_portable_authority_fresh(
                &manifest.to_toml().unwrap(),
                &manifest,
                Some(&lock_text),
            )
            .is_ok()
        );
        assert!(
            plan.ensure_local_state_fresh(source.observed_local_state_text())
                .is_ok()
        );
        let differently_encoded_manifest =
            format!("# concurrent comment\n{}", manifest.to_toml().unwrap());
        assert_eq!(
            plan.ensure_portable_authority_fresh(
                &differently_encoded_manifest,
                &manifest,
                Some(&lock_text),
            )
            .unwrap_err()
            .code(),
            "update.manifest_stale"
        );
        let differently_encoded_lock = format!("{lock_text}\n");
        assert_eq!(
            plan.ensure_portable_authority_fresh(
                &manifest.to_toml().unwrap(),
                &manifest,
                Some(&differently_encoded_lock),
            )
            .unwrap_err()
            .code(),
            "update.manifest_stale"
        );

        let repeated = plan_update_adoption(
            &source,
            &prior_hash,
            &manifest.to_toml().unwrap(),
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();
        assert_eq!(plan, repeated);
    }

    #[test]
    fn stale_prior_lock_and_receipt_refuse_update_planning() {
        let (source, manifest, lock_text, prior_hash, capabilities) = managed_update_fixture();
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        assert_eq!(
            plan_update_adoption(
                &source,
                &ContentHash::digest(b"stale"),
                &manifest.to_toml().unwrap(),
                &manifest,
                Some(&lock_text),
                &objects,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.expected_prior_mismatch"
        );
        assert_eq!(
            plan_update_adoption(
                &source,
                &prior_hash,
                &manifest.to_toml().unwrap(),
                &manifest,
                None,
                &objects,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.lock_not_in_sync"
        );
        let tiny_limits = SyncLimits::new(2, 1, 1, 1, 2, 1, 2, 2, 2, 1).unwrap();
        assert_eq!(
            plan_update_adoption(
                &source,
                &prior_hash,
                &manifest.to_toml().unwrap(),
                &manifest,
                Some(&lock_text),
                &objects,
                &capabilities,
                tiny_limits,
            )
            .unwrap_err()
            .code(),
            "update.object_catalog_invalid"
        );

        let mut stale_source = source.clone();
        stale_source.receipt.as_mut().unwrap().environment_revision =
            Revision::parse("manifest:stale").unwrap();
        assert_eq!(
            plan_update_adoption(
                &stale_source,
                &prior_hash,
                &manifest.to_toml().unwrap(),
                &manifest,
                Some(&lock_text),
                &objects,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.receipt_stale"
        );
    }

    #[test]
    fn update_planner_preserves_distinct_trust_refusal_codes() {
        let (base_source, manifest, lock_text, prior_hash, capabilities) =
            explicit_update_fixture();
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let manifest_text = manifest.to_toml().unwrap();

        let unavailable = with_portable_decision(
            base_source.selected(),
            PortablePolicyDecision::Unavailable {
                reasons: vec![FidelityReason::new(
                    "skill.portable_unavailable",
                    "the adapter cannot provide a portable projection",
                )],
            },
        );
        let mut unavailable_source = base_source.clone();
        unavailable_source.selected = unavailable;
        assert_eq!(
            plan_update_adoption(
                &unavailable_source,
                &prior_hash,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &objects,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.projection_unavailable"
        );

        for (mode, native_id, expected) in [
            (
                kitrove_agent_skills::FileMode::Executable,
                "review",
                "update.executable_blocked",
            ),
            (
                kitrove_agent_skills::FileMode::Regular,
                "sk-live-12345678901234567890",
                "update.credential_shaped_identity",
            ),
        ] {
            let candidate = as_explicit_root(&make_candidate(mode, native_id));
            let mut source = base_source.clone();
            source.selected = candidate;
            let error = plan_update_adoption(
                &source,
                &prior_hash,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &objects,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap_err();
            assert_eq!(error.code(), expected);
            assert!(!format!("{error:?}").contains("sk-live-"));
        }
    }

    #[test]
    fn update_plan_and_error_debug_display_redact_all_review_canaries() {
        let (source, manifest, lock_text, prior_hash, capabilities) = redaction_update_fixture();
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let manifest_text = manifest.to_toml().unwrap();
        let plan = plan_update_adoption(
            &source,
            &prior_hash,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();
        let error = plan_update_adoption(
            &source,
            &ContentHash::digest(b"wrong prior"),
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap_err();
        let rendered = format!("{plan:?}\n{error:?}\n{error}");
        for canary in [
            REDACTION_AUTHORED,
            REDACTION_NATIVE_ID,
            REDACTION_PATH,
            REDACTION_DESTINATION,
            REDACTION_SECRET,
        ] {
            assert!(!rendered.contains(canary), "surface disclosed {canary}");
        }
    }

    #[test]
    fn explicit_root_plan_never_changes_local_receipts() {
        let (prior_plan, prior_candidate, _) = ready_plan();
        let manifest = prior_plan.proposed_manifest().clone();
        let destination = NormalizedDestination::parse(destination_canary()).unwrap();
        let candidate = as_explicit_root(&changed_candidate(&prior_candidate, destination));
        let observation_id = candidate.observation_id().clone();
        let asset_id = prior_plan.asset().id.clone();
        let entry = ScanEntry {
            observation_id: Some(observation_id.clone()),
            harness: candidate.location().harness.clone(),
            scope: candidate.location().scope,
            root_tier: Some(RootTier::Explicit),
            logical_root: None,
            policy_rank: Some(candidate.location().policy_rank),
            source_relative_path: None,
            layout: Some(candidate.location().layout),
            native_id: None,
            asset_id: None,
            receipt_id: None,
            normalized_destination: None,
            receipt_rendered_hash: None,
            classification: ScanClassification::Unmanaged,
            exact_source_hash: Some(candidate.captured().exact_source_hash.clone()),
            portable_hash: candidate.portable_hash().cloned(),
            shadowed_by: None,
            findings: vec![],
        };
        let report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            vec![entry],
            vec![],
            vec![],
            vec![ObservedCandidate::Accepted(Box::new(candidate))],
            CaptureUsage::default(),
        );
        let source = report
            .select_update_source(&observation_id, &asset_id, None)
            .unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        let objects = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        let plan = plan_update_adoption(
            &source,
            &prior_plan.asset().content_hash,
            &manifest.to_toml().unwrap(),
            &manifest,
            Some(&lock_text),
            &objects,
            &capabilities(),
            SyncLimits::default(),
        )
        .unwrap();

        assert_eq!(source.authority(), UpdateSourceAuthority::ExplicitRoot);
        assert!(plan.proposed_local_state_text().is_none());
    }

    #[test]
    fn retained_native_variant_and_provenance_require_verified_object() {
        let (mut source, mut manifest, _, _, capabilities) = managed_update_fixture();
        let (prior_plan, _, _) = ready_plan();
        let retained_object = prior_plan.native_object().clone();
        let asset = manifest
            .assets
            .get_mut(&AssetId::parse("review").unwrap())
            .unwrap();
        let prior_claude = asset.native_variants[&HarnessId::Claude].clone();
        let retained_provenance = prior_claude.provenance.clone();
        let retained_variant = NativeVariant {
            harness: HarnessId::Codex,
            format: NATIVE_FORMAT.to_owned(),
            root: PortablePath::parse("assets/review/native/codex").unwrap(),
            object_hash: retained_object.hash().clone(),
            content_class: prior_claude.content_class,
            provenance: retained_provenance.clone(),
        };
        asset
            .native_variants
            .insert(HarnessId::Codex, retained_variant.clone());
        asset.refresh_content_hash();
        let expected_prior = asset.content_hash.clone();
        let base_revision = derive_manifest_revision(&manifest).unwrap();
        let old_state_text = source.observed_local_state_text().unwrap().to_owned();
        let replacement_receipt = {
            let receipt = source.receipt.as_mut().unwrap();
            receipt.source_hash = expected_prior.clone();
            receipt.environment_revision = base_revision;
            receipt.clone()
        };
        let mut state = LocalState::from_json(&old_state_text).unwrap();
        let receipt_id = replacement_receipt.receipt_id().unwrap();
        state.receipts.insert(receipt_id, replacement_receipt);
        source.observed_local_state_text = Some(state.to_json().unwrap());
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();

        let missing = VerifiedSkillObjectCatalog::new(
            Vec::<StoredSkillTree>::new(),
            Vec::<NativeSkillObject>::new(),
        )
        .unwrap();
        assert_eq!(
            plan_update_adoption(
                &source,
                &expected_prior,
                &manifest.to_toml().unwrap(),
                &manifest,
                Some(&lock_text),
                &missing,
                &capabilities,
                SyncLimits::default(),
            )
            .unwrap_err()
            .code(),
            "update.retained_object_invalid"
        );

        let retained =
            VerifiedSkillObjectCatalog::new(Vec::<StoredSkillTree>::new(), vec![retained_object])
                .unwrap();
        let plan = plan_update_adoption(
            &source,
            &expected_prior,
            &manifest.to_toml().unwrap(),
            &manifest,
            Some(&lock_text),
            &retained,
            &capabilities,
            SyncLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.asset().native_variants[&HarnessId::Codex],
            retained_variant
        );
        assert!(plan.asset().provenance.contains_key(&retained_provenance));
    }
}
