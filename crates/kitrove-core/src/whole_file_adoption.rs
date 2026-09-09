use kitrove_model::{
    Asset, AssetId, ContentHash, HarnessId, HarnessScope, Lockfile, PortablePath, Revision,
};

use crate::adoption::AdoptionDisposition;

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
    if let (Some(prior), Some(candidate)) = (&prior.portable, &mut normalized.portable) {
        if prior.object_hash == candidate.object_hash {
            candidate.root = prior.root.clone();
        }
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
