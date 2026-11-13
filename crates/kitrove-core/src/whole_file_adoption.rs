use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, HarnessId, HarnessScope, Lockfile,
    PortablePath, Revision, SchemaVersion,
};

use crate::adoption::{AdoptionDisposition, content_addressed_update_root};
use crate::{LockStatus, compare_lockfile, derive_lockfile, derive_manifest_revision};

pub(crate) struct BlockDigestInput<'a> {
    pub domain: &'static [u8],
    pub observation_identity: &'a ContentHash,
    pub asset_id: &'a AssetId,
    pub reason: &'static str,
    pub base_manifest_revision: &'a Revision,
    pub proposed_revision: Option<&'a ContentHash>,
    pub conflicting_revision: Option<&'a ContentHash>,
}

pub(crate) struct UpdateDigestInput<'a> {
    pub domain: &'static [u8],
    pub observation_identity: &'a ContentHash,
    pub asset_id: &'a AssetId,
    pub expected_prior: &'a ContentHash,
    pub asset: &'a Asset,
    pub base_manifest_hash: &'a ContentHash,
    pub base_revision: &'a Revision,
    pub proposed_revision: &'a Revision,
    pub observed_lock: &'a str,
    pub proposed_lock: &'a Lockfile,
}

pub(crate) fn observation_origin(
    identity: &ContentHash,
    harness: &HarnessId,
    scope: HarnessScope,
    capability_segment: &'static str,
) -> Result<PortablePath, ()> {
    let hash = identity.as_str().strip_prefix("blake3:").ok_or(())?;
    PortablePath::parse(format!(
        "observations/{}/{}/{capability_segment}/blake3-{hash}",
        harness.as_str(),
        scope.as_str(),
    ))
    .map_err(|_| ())
}

pub(crate) fn block_digest(input: BlockDigestInput<'_>) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(input.domain);
    for value in [
        input.observation_identity.as_str(),
        input.asset_id.as_str(),
        input.reason,
        input.base_manifest_revision.as_str(),
    ] {
        write_record(&mut hasher, value);
    }
    write_optional_record(
        &mut hasher,
        input.proposed_revision.map(ContentHash::as_str),
    );
    write_optional_record(
        &mut hasher,
        input.conflicting_revision.map(ContentHash::as_str),
    );
    digest(hasher)
}

pub(crate) fn plan_digest(
    domain: &'static [u8],
    observation_identity: &ContentHash,
    disposition: AdoptionDisposition,
    asset: &Asset,
    base_manifest_revision: &Revision,
    proposed_manifest_revision: &Revision,
    lockfile: &Lockfile,
) -> Result<ContentHash, ()> {
    let lock_json = lockfile.to_json().map_err(|_| ())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    write_record(&mut hasher, observation_identity.as_str());
    hasher.update(&[match disposition {
        AdoptionDisposition::First => 0,
        AdoptionDisposition::Idempotent => 1,
    }]);
    for value in [
        asset.id.as_str(),
        asset.content_hash.as_str(),
        base_manifest_revision.as_str(),
        proposed_manifest_revision.as_str(),
        ContentHash::digest(lock_json.as_bytes()).as_str(),
    ] {
        write_record(&mut hasher, value);
    }
    Ok(digest(hasher))
}

pub(crate) fn same_adopted_authority(prior: &Asset, candidate: &Asset) -> bool {
    let mut normalized = candidate.clone();
    if let (Some(prior), Some(candidate)) = (&prior.portable, &mut normalized.portable)
        && prior.object_hash == candidate.object_hash
    {
        candidate.root = prior.root.clone();
    }
    for (harness, candidate) in &mut normalized.native_variants {
        if let Some(root) = prior
            .native_variants
            .get(harness)
            .filter(|prior| prior.object_hash == candidate.object_hash)
            .map(|prior| prior.root.clone())
        {
            candidate.root = root;
        }
    }
    normalized.refresh_content_hash();
    &normalized == prior
}

pub(crate) fn update_digest(input: UpdateDigestInput<'_>) -> Result<ContentHash, ()> {
    let proposed_lock = input.proposed_lock.to_json().map_err(|_| ())?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(input.domain);
    for value in [
        input.asset_id.as_str(),
        input.observation_identity.as_str(),
        input.expected_prior.as_str(),
        input.asset.content_hash.as_str(),
        input.base_manifest_hash.as_str(),
        input.base_revision.as_str(),
        input.proposed_revision.as_str(),
        ContentHash::digest(input.observed_lock.as_bytes()).as_str(),
        ContentHash::digest(proposed_lock.as_bytes()).as_str(),
    ] {
        write_record(&mut hasher, value);
    }
    Ok(digest(hasher))
}

/// Why a whole-file update could not be planned, before a kind names its own code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpdateFailure {
    ManifestInvalid,
    LockNotInSync,
    AssetMissing,
    ExpectedPriorMismatch,
    DerivationFailed,
    RevisionUnchanged,
    ObjectPathInvalid,
    ProposedManifestInvalid,
    ProposedLockInvalid,
    PlanDigestFailed,
}

/// Exact portable authority an update replaces.
pub(crate) struct UpdateBase {
    pub prior_asset: Asset,
    pub manifest_hash: ContentHash,
    pub manifest_revision: Revision,
    pub observed_lock_text: String,
}

/// Replacement authority derived from one freshly adopted candidate.
pub(crate) struct UpdateProposal {
    pub asset: Asset,
    pub manifest: EnvironmentManifest,
    pub lock: Lockfile,
    pub manifest_revision: Revision,
    pub digest: ContentHash,
}

pub(crate) fn empty_manifest() -> EnvironmentManifest {
    EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    }
}

/// Binds an update to the exact manifest, in-sync lock, and prior revision of one asset.
pub(crate) fn update_base(
    kind: AssetKind,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    manifest_text: &str,
    manifest: &EnvironmentManifest,
    lock_text: Option<&str>,
) -> Result<UpdateBase, UpdateFailure> {
    manifest
        .validate()
        .map_err(|_| UpdateFailure::ManifestInvalid)?;
    if EnvironmentManifest::from_toml(manifest_text).as_ref() != Ok(manifest) {
        return Err(UpdateFailure::ManifestInvalid);
    }
    let manifest_hash = ContentHash::digest(manifest_text.as_bytes());
    let manifest_revision =
        derive_manifest_revision(manifest).map_err(|_| UpdateFailure::ManifestInvalid)?;
    let observed_lock_text = lock_text
        .filter(|text| {
            compare_lockfile(manifest, Some(text)).map(|comparison| comparison.status())
                == Ok(LockStatus::InSync)
        })
        .ok_or(UpdateFailure::LockNotInSync)?
        .to_owned();
    let prior_asset = manifest
        .assets
        .get(asset_id)
        .filter(|asset| asset.kind == kind)
        .ok_or(UpdateFailure::AssetMissing)?;
    if &prior_asset.content_hash != expected_prior {
        return Err(UpdateFailure::ExpectedPriorMismatch);
    }
    Ok(UpdateBase {
        prior_asset: prior_asset.clone(),
        manifest_hash,
        manifest_revision,
        observed_lock_text,
    })
}

/// Rehomes a candidate under content-addressed update roots and derives the proposed authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn propose_update(
    domain: &'static [u8],
    observation_identity: &ContentHash,
    harness: &HarnessId,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    base: &UpdateBase,
    candidate: &Asset,
    manifest: &EnvironmentManifest,
    carry_required_bindings: bool,
) -> Result<UpdateProposal, UpdateFailure> {
    if same_adopted_authority(&base.prior_asset, candidate) {
        return Err(UpdateFailure::RevisionUnchanged);
    }
    let mut asset = candidate.clone();
    let portable = asset
        .portable
        .as_mut()
        .ok_or(UpdateFailure::DerivationFailed)?;
    portable.root = content_addressed_update_root(asset_id, None, &portable.object_hash)
        .map_err(|_| UpdateFailure::ObjectPathInvalid)?;
    let native = asset
        .native_variants
        .get_mut(harness)
        .ok_or(UpdateFailure::DerivationFailed)?;
    native.root = content_addressed_update_root(asset_id, Some(harness), &native.object_hash)
        .map_err(|_| UpdateFailure::ObjectPathInvalid)?;
    asset.refresh_content_hash();

    let mut proposed = manifest.clone();
    if carry_required_bindings {
        proposed
            .required_bindings
            .extend(asset.required_bindings.iter().cloned());
    }
    proposed.assets.insert(asset_id.clone(), asset.clone());
    proposed
        .refresh_pack_revisions()
        .map_err(|_| UpdateFailure::ProposedManifestInvalid)?;
    let lock = derive_lockfile(&proposed).map_err(|_| UpdateFailure::ProposedLockInvalid)?;
    let manifest_revision =
        derive_manifest_revision(&proposed).map_err(|_| UpdateFailure::ProposedManifestInvalid)?;
    let digest = update_digest(UpdateDigestInput {
        domain,
        observation_identity,
        asset_id,
        expected_prior,
        asset: &asset,
        base_manifest_hash: &base.manifest_hash,
        base_revision: &base.manifest_revision,
        proposed_revision: &manifest_revision,
        observed_lock: &base.observed_lock_text,
        proposed_lock: &lock,
    })
    .map_err(|()| UpdateFailure::PlanDigestFailed)?;
    Ok(UpdateProposal {
        asset,
        manifest: proposed,
        lock,
        manifest_revision,
        digest,
    })
}

/// Returns whether portable authority still matches what an update plan was bound to.
#[allow(clippy::too_many_arguments)]
pub(crate) fn update_authority_is_current(
    manifest_text: &str,
    manifest: &EnvironmentManifest,
    lock_text: Option<&str>,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    base_manifest_hash: &ContentHash,
    base_manifest_revision: &Revision,
    observed_lock_text: &str,
) -> bool {
    derive_manifest_revision(manifest).as_ref() == Ok(base_manifest_revision)
        && &ContentHash::digest(manifest_text.as_bytes()) == base_manifest_hash
        && manifest
            .assets
            .get(asset_id)
            .map(|asset| &asset.content_hash)
            == Some(expected_prior)
        && lock_text == Some(observed_lock_text)
        && compare_lockfile(manifest, lock_text).map(|comparison| comparison.status())
            == Ok(LockStatus::InSync)
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn write_optional_record(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            write_record(hasher, value);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn digest(hasher: blake3::Hasher) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}
