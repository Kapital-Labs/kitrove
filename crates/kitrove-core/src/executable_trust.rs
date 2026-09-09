use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{
    AssetId, ContentHash, EnvironmentManifest, HarnessId, LocalState, Revision, TrustDecision,
};
use serde::{Deserialize, Serialize};

use crate::{
    NativeExtensionObject, VerifiedSkillObjectCatalog, derive_manifest_revision,
    merge::validate_extension_snapshot_asset,
};

const TRUST_RATIONALE: &str = "explicit_exact_content_review";

/// A requested machine-local decision about one exact executable object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableTrustDecision {
    Trusted,
    Denied,
}

impl ExecutableTrustDecision {
    const fn tag(self) -> u8 {
        match self {
            Self::Trusted => 0,
            Self::Denied => 1,
        }
    }
}

/// Relationship between the requested decision and current local authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableTrustDisposition {
    First,
    Replace,
    NoOp,
}

/// Current machine-local review state for one exact executable object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableTrustStatus {
    Trusted,
    Denied,
    Unreviewed,
}

/// Redacted read-only view of the authority governing one executable object.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableTrustInspection {
    asset_id: AssetId,
    harness: HarnessId,
    object_hash: ContentHash,
    status: ExecutableTrustStatus,
}

impl ExecutableTrustInspection {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn harness(&self) -> &HarnessId {
        &self.harness
    }

    #[must_use]
    pub const fn object_hash(&self) -> &ContentHash {
        &self.object_hash
    }

    #[must_use]
    pub const fn status(&self) -> ExecutableTrustStatus {
        self.status
    }
}

impl Debug for ExecutableTrustInspection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustInspection")
            .field("harness", &self.harness)
            .field("object_hash", &self.object_hash)
            .field("status", &self.status)
            .finish()
    }
}

impl ExecutableTrustDisposition {
    const fn tag(self) -> u8 {
        match self {
            Self::First => 0,
            Self::Replace => 1,
            Self::NoOp => 2,
        }
    }
}

/// Stable redacted executable-trust planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableTrustError {
    code: &'static str,
    message: &'static str,
}

impl ExecutableTrustError {
    const fn new(code: &'static str, message: &'static str) -> Self {
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

impl Debug for ExecutableTrustError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for ExecutableTrustError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for ExecutableTrustError {}

/// Complete non-mutating authority for one exact local trust-state transition.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableTrustPlan {
    asset_id: AssetId,
    object_hash: ContentHash,
    decision: ExecutableTrustDecision,
    disposition: ExecutableTrustDisposition,
    manifest_revision: Revision,
    proposed_local_state: LocalState,
    digest: ContentHash,
}

impl ExecutableTrustPlan {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn object_hash(&self) -> &ContentHash {
        &self.object_hash
    }

    #[must_use]
    pub const fn decision(&self) -> ExecutableTrustDecision {
        self.decision
    }

    #[must_use]
    pub const fn disposition(&self) -> ExecutableTrustDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub const fn proposed_local_state(&self) -> &LocalState {
        &self.proposed_local_state
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for ExecutableTrustPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustPlan")
            .field("decision", &self.decision)
            .field("disposition", &self.disposition)
            .field("manifest_revision", &self.manifest_revision)
            .field("object_hash", &self.object_hash)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Plans one exact-content executable trust decision without mutating either authority root.
pub fn plan_executable_trust(
    manifest_text: &str,
    local_state_text: &str,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    decision: ExecutableTrustDecision,
) -> Result<ExecutableTrustPlan, ExecutableTrustError> {
    let (manifest_revision, mut proposed_local_state) =
        validate_trust_authority(manifest_text, local_state_text, asset_id, object)?;
    let current = proposed_local_state.trust.get(object.hash());
    let disposition = match (current, decision) {
        (None, _) => ExecutableTrustDisposition::First,
        (Some(TrustDecision::Trusted { .. }), ExecutableTrustDecision::Trusted)
        | (Some(TrustDecision::Denied { .. }), ExecutableTrustDecision::Denied) => {
            ExecutableTrustDisposition::NoOp
        }
        (Some(_), _) => ExecutableTrustDisposition::Replace,
    };
    if disposition != ExecutableTrustDisposition::NoOp {
        let value = match decision {
            ExecutableTrustDecision::Trusted => TrustDecision::Trusted {
                rationale: TRUST_RATIONALE.to_owned(),
            },
            ExecutableTrustDecision::Denied => TrustDecision::Denied {
                rationale: TRUST_RATIONALE.to_owned(),
            },
        };
        proposed_local_state
            .trust
            .insert(object.hash().clone(), value);
    }
    let proposed_local_state_text = proposed_local_state.to_json().map_err(|_| {
        trust_error(
            "trust.local_state_invalid",
            "machine-local state authority is invalid",
        )
    })?;
    let digest = trust_plan_digest(
        asset_id,
        object.hash(),
        decision,
        disposition,
        &manifest_revision,
        local_state_text,
        &proposed_local_state_text,
    )?;
    Ok(ExecutableTrustPlan {
        asset_id: asset_id.clone(),
        object_hash: object.hash().clone(),
        decision,
        disposition,
        manifest_revision,
        proposed_local_state,
        digest,
    })
}

/// Inspects the local decision for one exact manifest-authorized executable object.
pub fn inspect_executable_trust(
    manifest_text: &str,
    local_state_text: &str,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
) -> Result<ExecutableTrustInspection, ExecutableTrustError> {
    let (_, local_state) =
        validate_trust_authority(manifest_text, local_state_text, asset_id, object)?;
    let status = match local_state.trust.get(object.hash()) {
        Some(TrustDecision::Trusted { .. }) => ExecutableTrustStatus::Trusted,
        Some(TrustDecision::Denied { .. }) => ExecutableTrustStatus::Denied,
        None => ExecutableTrustStatus::Unreviewed,
    };
    Ok(ExecutableTrustInspection {
        asset_id: asset_id.clone(),
        harness: HarnessId::Pi,
        object_hash: object.hash().clone(),
        status,
    })
}

fn validate_trust_authority(
    manifest_text: &str,
    local_state_text: &str,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
) -> Result<(Revision, LocalState), ExecutableTrustError> {
    let manifest = EnvironmentManifest::from_toml(manifest_text).map_err(|_| {
        trust_error(
            "trust.manifest_invalid",
            "portable manifest authority is invalid",
        )
    })?;
    let manifest_revision = derive_manifest_revision(&manifest).map_err(|_| {
        trust_error(
            "trust.manifest_invalid",
            "portable manifest authority is invalid",
        )
    })?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        trust_error(
            "trust.asset_missing",
            "the selected asset is not present in manifest authority",
        )
    })?;
    let objects = VerifiedSkillObjectCatalog::new_with_extensions([], [], [object.clone()])
        .map_err(|_| {
            trust_error(
                "trust.object_invalid",
                "executable object authority is invalid",
            )
        })?;
    validate_extension_snapshot_asset(asset, &objects).map_err(|_| {
        trust_error(
            "trust.asset_invalid",
            "the selected asset is not a closed verified native extension",
        )
    })?;
    let selected = asset.native_variants.get(&HarnessId::Pi).ok_or_else(|| {
        trust_error(
            "trust.asset_invalid",
            "the selected asset is not a closed verified native extension",
        )
    })?;
    if selected.object_hash != *object.hash() {
        return Err(trust_error(
            "trust.object_mismatch",
            "the supplied executable object does not match manifest authority",
        ));
    }

    let local_state = LocalState::from_json(local_state_text).map_err(|_| {
        trust_error(
            "trust.local_state_invalid",
            "machine-local state authority is invalid",
        )
    })?;
    Ok((manifest_revision, local_state))
}

fn trust_plan_digest(
    asset_id: &AssetId,
    object_hash: &ContentHash,
    decision: ExecutableTrustDecision,
    disposition: ExecutableTrustDisposition,
    manifest_revision: &Revision,
    observed_local_state_text: &str,
    proposed_local_state_text: &str,
) -> Result<ContentHash, ExecutableTrustError> {
    trust_plan_digest_from_hashes(
        asset_id,
        object_hash,
        decision,
        disposition,
        manifest_revision,
        &ContentHash::digest(observed_local_state_text.as_bytes()),
        &ContentHash::digest(proposed_local_state_text.as_bytes()),
    )
}

pub(crate) fn trust_plan_digest_from_hashes(
    asset_id: &AssetId,
    object_hash: &ContentHash,
    decision: ExecutableTrustDecision,
    disposition: ExecutableTrustDisposition,
    manifest_revision: &Revision,
    observed_local_state_hash: &ContentHash,
    proposed_local_state_hash: &ContentHash,
) -> Result<ContentHash, ExecutableTrustError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-executable-trust-plan-v1\0");
    write_record(&mut hasher, asset_id.as_str());
    write_record(&mut hasher, object_hash.as_str());
    hasher.update(&[decision.tag(), disposition.tag()]);
    write_record(&mut hasher, manifest_revision.as_str());
    write_record(&mut hasher, observed_local_state_hash.as_str());
    write_record(&mut hasher, proposed_local_state_hash.as_str());
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex())).map_err(|_| {
        trust_error(
            "trust.plan_digest_failed",
            "the executable trust plan digest could not be derived",
        )
    })
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn trust_error(code: &'static str, message: &'static str) -> ExecutableTrustError {
    ExecutableTrustError::new(code, message)
}
