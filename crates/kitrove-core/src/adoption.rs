use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::{
    CapabilityMatrix, CapabilitySupport, NativeAcceptance, ObservationId, PortablePolicyDecision,
};
use kitrove_agent_skills::{
    NativeSkillObject, PortableProjection, StoredSkillTree, project_skill_source,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, Fidelity,
    FidelityEvidence, FidelityResult, HarnessId, Lockfile, NativeVariant, PortableContent,
    PortablePath, Revision, Source,
};

use crate::{AcceptedObservedCandidate, derive_lockfile, derive_manifest_revision};

const PORTABLE_FORMAT: &str = "agent-skills/v1";
const NATIVE_FORMAT: &str = "kitrove-native-skill-object/v1";

/// The fixed, complete target capability catalog required by adoption planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierOneCapabilities {
    skills: BTreeMap<HarnessId, CapabilitySupport>,
}

impl TierOneCapabilities {
    /// Validates that all and only the four tier-one adapters declare portable Agent Skills.
    pub fn new(matrices: BTreeMap<HarnessId, CapabilityMatrix>) -> Result<Self, AdoptionError> {
        let skills = validate_tier_one_portable_capabilities(&matrices, AssetKind::Skill).map_err(
            |failure| match failure {
                CapabilityCatalogFailure::Incomplete => AdoptionError::new(
                    "adoption.incomplete_target_catalog",
                    "adoption requires exactly one capability matrix for every tier-one harness",
                ),
                CapabilityCatalogFailure::Missing => AdoptionError::new(
                    "adoption.skill_capability_missing",
                    "a tier-one adapter does not declare Agent Skills support",
                ),
                CapabilityCatalogFailure::Invalid => AdoptionError::new(
                    "adoption.skill_capability_invalid",
                    "tier-one Agent Skills support must be portable and evidence-backed",
                ),
            },
        )?;
        Ok(Self { skills })
    }

    pub(crate) fn skill(&self, harness: &HarnessId) -> &CapabilitySupport {
        &self.skills[harness]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityCatalogFailure {
    Incomplete,
    Missing,
    Invalid,
}

pub(crate) fn validate_tier_one_portable_capabilities(
    matrices: &BTreeMap<HarnessId, CapabilityMatrix>,
    kind: AssetKind,
) -> Result<BTreeMap<HarnessId, CapabilitySupport>, CapabilityCatalogFailure> {
    let capabilities = validate_tier_one_capabilities(matrices, kind)?;
    if capabilities
        .values()
        .any(|support| support.result.fidelity() != Fidelity::Portable)
    {
        return Err(CapabilityCatalogFailure::Invalid);
    }
    Ok(capabilities)
}

pub(crate) fn validate_tier_one_capabilities(
    matrices: &BTreeMap<HarnessId, CapabilityMatrix>,
    kind: AssetKind,
) -> Result<BTreeMap<HarnessId, CapabilitySupport>, CapabilityCatalogFailure> {
    let required = tier_one_harnesses();
    if matrices.len() != required.len() || !matrices.keys().eq(required.iter()) {
        return Err(CapabilityCatalogFailure::Incomplete);
    }

    required
        .into_iter()
        .map(|harness| {
            let support = matrices[&harness]
                .capabilities
                .get(&kind)
                .ok_or(CapabilityCatalogFailure::Missing)?;
            if support.result.evidence().is_empty()
                || !portable_version(support.result.adapter_version())
                || support
                    .result
                    .harness_version()
                    .is_some_and(|version| !portable_version(version))
                || support.result.evidence().iter().any(|evidence| {
                    !portable_evidence_kind(&evidence.kind)
                        || !portable_evidence_detail(&evidence.detail)
                })
                || support.result.reasons().iter().any(|reason| {
                    !portable_evidence_kind(&reason.code)
                        || !portable_evidence_detail(&reason.message)
                })
            {
                return Err(CapabilityCatalogFailure::Invalid);
            }
            Ok((harness, support.clone()))
        })
        .collect()
}

fn portable_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b'+')
        })
}

fn portable_evidence_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn portable_evidence_detail(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 2_048
        || value.chars().any(char::is_control)
        || value.contains('\\')
        || ["~/", "$HOME", "${HOME}", "%USERPROFILE%", "file://"]
            .into_iter()
            .any(|marker| value.contains(marker))
    {
        return false;
    }
    !value.split_ascii_whitespace().any(|word| {
        let word = word.trim_matches(['(', ')', '[', ']', '{', '}', '"', '\'', ',', ';']);
        word.starts_with('/')
            || word.as_bytes().get(0..3).is_some_and(|prefix| {
                prefix[0].is_ascii_alphabetic() && prefix[1] == b':' && prefix[2] == b'/'
            })
    })
}

/// Whether the proposed asset identifier came from policy or an explicit user choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionIdChoice {
    PolicyDefault,
    Explicit,
}

/// A nonblocking plan's relationship to current manifest authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionDisposition {
    First,
    Idempotent,
}

/// The recovery-safe authority action represented by a ready plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionRecoveryAction {
    CommitNewAsset,
    RepairReferencedState,
}

pub(crate) const fn adoption_state(exists: bool) -> (AdoptionDisposition, AdoptionRecoveryAction) {
    if exists {
        (
            AdoptionDisposition::Idempotent,
            AdoptionRecoveryAction::RepairReferencedState,
        )
    } else {
        (
            AdoptionDisposition::First,
            AdoptionRecoveryAction::CommitNewAsset,
        )
    }
}

pub(crate) fn portable_asset_root(
    id: &AssetId,
) -> Result<PortablePath, kitrove_model::ValidationError> {
    PortablePath::parse(format!("assets/{}/portable", id.as_str()))
}

pub(crate) fn native_asset_root(
    id: &AssetId,
    harness: &HarnessId,
) -> Result<PortablePath, kitrove_model::ValidationError> {
    PortablePath::parse(format!(
        "assets/{}/native/{}",
        id.as_str(),
        harness.as_str()
    ))
}

pub(crate) fn content_addressed_update_root(
    asset_id: &AssetId,
    harness: Option<&HarnessId>,
    object_hash: &ContentHash,
) -> Result<PortablePath, kitrove_model::ValidationError> {
    let digest = object_hash
        .as_str()
        .strip_prefix("blake3:")
        .expect("validated content hashes use the BLAKE3 qualifier");
    let path = harness.map_or_else(
        || {
            format!(
                "assets/{}/updates/portable/blake3-{digest}",
                asset_id.as_str()
            )
        },
        |harness| {
            format!(
                "assets/{}/updates/native/{}/blake3-{digest}",
                asset_id.as_str(),
                harness.as_str()
            )
        },
    );
    PortablePath::parse(path)
}

/// A reason that makes an adoption plan non-mutating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionBlockReason {
    PortableProjectionUnavailable,
    ExecutableTrustRequired,
    CredentialShapedNativeIdentity,
    AssetConflict,
}

impl AdoptionBlockReason {
    const fn tag(self) -> &'static str {
        match self {
            Self::PortableProjectionUnavailable => "portable_projection_unavailable",
            Self::ExecutableTrustRequired => "executable_trust_required",
            Self::CredentialShapedNativeIdentity => "credential_shaped_native_identity",
            Self::AssetConflict => "asset_conflict",
        }
    }
}

/// A deterministic plan that authorizes no writes.
#[derive(Clone, Eq, PartialEq)]
pub struct AdoptionBlock {
    observation_id: ObservationId,
    asset_id: Option<AssetId>,
    reason: AdoptionBlockReason,
    digest: ContentHash,
}

impl AdoptionBlock {
    #[must_use]
    pub const fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    #[must_use]
    pub const fn asset_id(&self) -> Option<&AssetId> {
        self.asset_id.as_ref()
    }

    #[must_use]
    pub const fn reason(&self) -> AdoptionBlockReason {
        self.reason
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for AdoptionBlock {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdoptionBlock")
            .field("observation_id", &self.observation_id)
            .field("asset_id", &self.asset_id)
            .field("reason", &self.reason)
            .field("digest", &self.digest)
            .finish()
    }
}

/// A complete, deterministic, still non-mutating adoption proposal.
#[derive(Clone, Eq, PartialEq)]
pub struct AdoptionPlan {
    selected: AcceptedObservedCandidate,
    id_choice: AdoptionIdChoice,
    disposition: AdoptionDisposition,
    recovery_action: AdoptionRecoveryAction,
    asset: Asset,
    portable_object: StoredSkillTree,
    native_object: NativeSkillObject,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl AdoptionPlan {
    #[must_use]
    pub fn observation_id(&self) -> &ObservationId {
        self.selected.observation_id()
    }

    #[must_use]
    pub fn origin_harness(&self) -> &HarnessId {
        &self.selected.location().harness
    }

    #[must_use]
    pub const fn id_choice(&self) -> AdoptionIdChoice {
        self.id_choice
    }

    #[must_use]
    pub const fn disposition(&self) -> AdoptionDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn recovery_action(&self) -> AdoptionRecoveryAction {
        self.recovery_action
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
    pub const fn proposed_manifest_revision(&self) -> &Revision {
        &self.proposed_manifest_revision
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    /// Revalidates every retained C2 identity input immediately before mutation.
    pub fn ensure_observation_fresh(
        &self,
        reread: &AcceptedObservedCandidate,
    ) -> Result<(), AdoptionError> {
        if &self.selected == reread {
            Ok(())
        } else {
            Err(AdoptionError::new(
                "adoption.observation_stale",
                "the selected observation changed after planning",
            ))
        }
    }

    /// Revalidates current manifest authority immediately before mutation.
    pub fn ensure_manifest_fresh(&self, reread: &EnvironmentManifest) -> Result<(), AdoptionError> {
        let revision = manifest_revision(reread)?;
        if revision == self.base_manifest_revision {
            Ok(())
        } else {
            Err(AdoptionError::new(
                "adoption.manifest_stale",
                "the authoritative manifest changed after planning",
            ))
        }
    }
}

impl Debug for AdoptionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdoptionPlan")
            .field("observation_id", &self.selected.observation_id())
            .field("asset_id", &self.asset.id)
            .field("id_choice", &self.id_choice)
            .field("disposition", &self.disposition)
            .field("recovery_action", &self.recovery_action)
            .field("asset_revision", &self.asset.content_hash)
            .field("portable_object_hash", &self.portable_object.tree().hash)
            .field("native_object_hash", &self.native_object.hash())
            .field("digest", &self.digest)
            .finish()
    }
}

/// The complete result of adoption planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdoptionPlanOutcome {
    Ready(Box<AdoptionPlan>),
    Blocked(AdoptionBlock),
}

/// A stable, content-redacted adoption planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct AdoptionError {
    code: &'static str,
    message: &'static str,
}

impl AdoptionError {
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

impl Debug for AdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdoptionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for AdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AdoptionError {}

/// Produces a complete plan from one accepted observation without mutating any state.
pub fn plan_adoption(
    candidate: &AcceptedObservedCandidate,
    requested_id: Option<AssetId>,
    manifest: &EnvironmentManifest,
    capabilities: &TierOneCapabilities,
) -> Result<AdoptionPlanOutcome, AdoptionError> {
    manifest.validate().map_err(|_| {
        AdoptionError::new(
            "adoption.manifest_invalid",
            "the authoritative manifest is invalid",
        )
    })?;
    if candidate.decision().acceptance() != NativeAcceptance::Accepted {
        return Err(AdoptionError::new(
            "adoption.candidate_not_accepted",
            "adoption requires an accepted observation",
        ));
    }
    let base_manifest_revision = manifest_revision(manifest)?;

    let id_choice = if requested_id.is_some() {
        AdoptionIdChoice::Explicit
    } else {
        AdoptionIdChoice::PolicyDefault
    };
    let (projected_name, description, reasons) = match candidate.decision().portable() {
        PortablePolicyDecision::Project {
            name,
            description,
            reasons,
        } => (name.clone(), description.clone(), reasons.clone()),
        PortablePolicyDecision::Unavailable { .. } => {
            return Ok(blocked(
                candidate,
                requested_id,
                id_choice,
                AdoptionBlockReason::PortableProjectionUnavailable,
                &base_manifest_revision,
            ));
        }
    };
    let asset_id = requested_id.unwrap_or_else(|| projected_name.clone());

    if candidate.captured().content_class == ContentClass::Executable {
        return Ok(blocked(
            candidate,
            Some(asset_id),
            id_choice,
            AdoptionBlockReason::ExecutableTrustRequired,
            &base_manifest_revision,
        ));
    }
    let Some(native_id) = candidate.decision().native_id() else {
        return Err(AdoptionError::new(
            "adoption.native_identity_missing",
            "an accepted observation is missing its native identity",
        ));
    };
    let inspected =
        native_id.trim_start_matches(|character: char| !character.is_ascii_alphanumeric());
    if kitrove_risk::is_credential_shaped(inspected) {
        return Ok(blocked(
            candidate,
            Some(asset_id),
            id_choice,
            AdoptionBlockReason::CredentialShapedNativeIdentity,
            &base_manifest_revision,
        ));
    }

    let projection = project_skill_source(
        candidate.captured(),
        projected_name,
        description,
        reasons.clone(),
    )
    .map_err(|_| {
        AdoptionError::new(
            "adoption.projection_failed",
            "the policy-authorized portable projection could not be reproduced",
        )
    })?;
    let PortableProjection::Available { tree, .. } = projection else {
        return Err(AdoptionError::new(
            "adoption.projection_inconsistent",
            "an available policy projection became unavailable",
        ));
    };
    if candidate.portable_hash() != Some(&tree.hash) {
        return Err(AdoptionError::new(
            "adoption.projection_stale",
            "the reproduced portable projection differs from the scanned observation",
        ));
    }
    let portable_object = StoredSkillTree::new(tree).map_err(|_| {
        AdoptionError::new(
            "adoption.portable_object_invalid",
            "the portable projection cannot form a canonical stored object",
        )
    })?;
    let native_object = NativeSkillObject::new(
        candidate.captured().layout,
        candidate.captured().original_document_name.clone(),
        native_id,
        candidate.captured().exact.clone(),
    )
    .map_err(|_| {
        AdoptionError::new(
            "adoption.native_object_invalid",
            "the exact source cannot form a canonical native object",
        )
    })?;

    let portable_root = portable_root(&asset_id)?;
    let native_root = native_root(&asset_id, &candidate.location().harness)?;
    let compatibility = compatibility(
        candidate,
        capabilities,
        &portable_object.tree().hash,
        native_object.hash(),
        &reasons,
    )?;
    let source = Source::Harness {
        harness: candidate.location().harness.clone(),
        origin: logical_origin(candidate)?,
    };
    let revision = Revision::parse(candidate.observation_id().as_str()).map_err(|_| {
        AdoptionError::new(
            "adoption.revision_invalid",
            "the observation identity cannot form an immutable revision",
        )
    })?;
    let provenance = kitrove_model::ComponentProvenance::new(
        source,
        revision,
        candidate.captured().exact_source_hash.clone(),
        Some(candidate.location().scope),
    )
    .map_err(|_| {
        AdoptionError::new(
            "adoption.provenance_invalid",
            "the observation cannot form bounded component provenance",
        )
    })?;
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: asset_id.clone(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"pending-asset-revision"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: PORTABLE_FORMAT.to_owned(),
            root: portable_root,
            object_hash: portable_object.tree().hash.clone(),
            provenance: provenance_id.clone(),
        }),
        native_variants: BTreeMap::from([(
            candidate.location().harness.clone(),
            NativeVariant {
                harness: candidate.location().harness.clone(),
                format: NATIVE_FORMAT.to_owned(),
                root: native_root,
                object_hash: native_object.hash().clone(),
                content_class: candidate.captured().content_class,
                provenance: provenance_id,
            },
        )]),
        compatibility,
        content_class: candidate.captured().content_class,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();

    let existing_asset = manifest.assets.get(&asset_id);
    let existing_pack = manifest.packs.get(&asset_id);
    if existing_asset.is_some_and(|existing| existing != &asset) || existing_pack.is_some() {
        let conflicting_revision = existing_asset
            .map(|existing| &existing.content_hash)
            .or_else(|| existing_pack.map(|existing| &existing.content_hash));
        return Ok(blocked_with_revision(
            candidate,
            Some(asset_id),
            id_choice,
            AdoptionBlockReason::AssetConflict,
            &base_manifest_revision,
            Some(&asset.content_hash),
            conflicting_revision,
        ));
    }
    let (disposition, recovery_action) = adoption_state(existing_asset.is_some());
    let mut proposed_manifest = manifest.clone();
    proposed_manifest.assets.insert(asset_id, asset.clone());
    proposed_manifest.validate().map_err(|_| {
        AdoptionError::new(
            "adoption.proposed_manifest_invalid",
            "the proposed manifest failed validation",
        )
    })?;
    let proposed_lock = derive_lockfile(&proposed_manifest).map_err(|_| {
        AdoptionError::new(
            "adoption.proposed_lock_invalid",
            "the manifest-derived lockfile failed validation",
        )
    })?;
    let proposed_manifest_revision = manifest_revision(&proposed_manifest)?;
    let digest = plan_digest(
        candidate,
        id_choice,
        disposition,
        &asset,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
    )?;

    Ok(AdoptionPlanOutcome::Ready(Box::new(AdoptionPlan {
        selected: candidate.clone(),
        id_choice,
        disposition,
        recovery_action,
        asset,
        portable_object,
        native_object,
        proposed_manifest,
        proposed_lock,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })))
}

fn compatibility(
    candidate: &AcceptedObservedCandidate,
    capabilities: &TierOneCapabilities,
    portable_hash: &ContentHash,
    native_hash: &ContentHash,
    reasons: &[kitrove_model::FidelityReason],
) -> Result<BTreeMap<HarnessId, FidelityResult>, AdoptionError> {
    let mut results = BTreeMap::new();
    for harness in tier_one_harnesses() {
        let support = capabilities.skill(&harness);
        let mut evidence = support.result.evidence().to_vec();
        if harness == candidate.location().harness {
            evidence.push(FidelityEvidence::new(
                "observation.native_policy",
                "the compiled origin policy accepted the exact source layout and native identity",
            ));
            evidence.push(FidelityEvidence::new(
                "native.object_hash",
                native_hash.as_str(),
            ));
            results.insert(
                harness,
                FidelityResult::exact(
                    Fidelity::Native,
                    evidence,
                    support.result.adapter_version(),
                    support.result.harness_version().map(str::to_owned),
                )
                .map_err(|_| invalid_fidelity())?,
            );
        } else if reasons.is_empty() {
            evidence.push(FidelityEvidence::new(
                "portable.object_hash",
                portable_hash.as_str(),
            ));
            results.insert(
                harness,
                FidelityResult::exact(
                    Fidelity::Portable,
                    evidence,
                    support.result.adapter_version(),
                    support.result.harness_version().map(str::to_owned),
                )
                .map_err(|_| invalid_fidelity())?,
            );
        } else {
            evidence.push(FidelityEvidence::new(
                "portable.object_hash",
                portable_hash.as_str(),
            ));
            results.insert(
                harness,
                FidelityResult::new(
                    Fidelity::Partial,
                    reasons.to_vec(),
                    evidence,
                    vec![],
                    support.result.adapter_version(),
                    support.result.harness_version().map(str::to_owned),
                )
                .map_err(|_| invalid_fidelity())?,
            );
        }
    }
    Ok(results)
}

fn invalid_fidelity() -> AdoptionError {
    AdoptionError::new(
        "adoption.fidelity_invalid",
        "the evidence-backed target fidelity result is invalid",
    )
}

fn portable_root(id: &AssetId) -> Result<PortablePath, AdoptionError> {
    portable_asset_root(id).map_err(|_| invalid_path())
}

fn native_root(id: &AssetId, harness: &HarnessId) -> Result<PortablePath, AdoptionError> {
    native_asset_root(id, harness).map_err(|_| invalid_path())
}

fn logical_origin(candidate: &AcceptedObservedCandidate) -> Result<PortablePath, AdoptionError> {
    PortablePath::parse(format!(
        "observations/{}/{}/{}",
        candidate.location().harness.as_str(),
        candidate.location().scope.as_str(),
        candidate.observation_id().as_str()
    ))
    .map_err(|_| invalid_path())
}

fn invalid_path() -> AdoptionError {
    AdoptionError::new(
        "adoption.portable_path_invalid",
        "the adoption identity cannot form a portable object path",
    )
}

fn manifest_revision(manifest: &EnvironmentManifest) -> Result<Revision, AdoptionError> {
    derive_manifest_revision(manifest).map_err(|_| {
        AdoptionError::new(
            "adoption.manifest_invalid",
            "the authoritative manifest is invalid",
        )
    })
}

fn blocked(
    candidate: &AcceptedObservedCandidate,
    asset_id: Option<AssetId>,
    id_choice: AdoptionIdChoice,
    reason: AdoptionBlockReason,
    base_manifest_revision: &Revision,
) -> AdoptionPlanOutcome {
    blocked_with_revision(
        candidate,
        asset_id,
        id_choice,
        reason,
        base_manifest_revision,
        None,
        None,
    )
}

fn blocked_with_revision(
    candidate: &AcceptedObservedCandidate,
    asset_id: Option<AssetId>,
    id_choice: AdoptionIdChoice,
    reason: AdoptionBlockReason,
    base_manifest_revision: &Revision,
    proposed_revision: Option<&ContentHash>,
    conflicting_revision: Option<&ContentHash>,
) -> AdoptionPlanOutcome {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-adoption-block-v1\0");
    write_record(&mut hasher, candidate.observation_id().as_str());
    write_optional_record(&mut hasher, asset_id.as_ref().map(AssetId::as_str));
    hasher.update(&[match id_choice {
        AdoptionIdChoice::PolicyDefault => 0,
        AdoptionIdChoice::Explicit => 1,
    }]);
    write_record(&mut hasher, reason.tag());
    write_record(&mut hasher, base_manifest_revision.as_str());
    write_optional_record(&mut hasher, proposed_revision.map(ContentHash::as_str));
    write_optional_record(&mut hasher, conflicting_revision.map(ContentHash::as_str));
    let digest = ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("BLAKE3 output is a valid content hash");
    AdoptionPlanOutcome::Blocked(AdoptionBlock {
        observation_id: candidate.observation_id().clone(),
        asset_id,
        reason,
        digest,
    })
}

fn plan_digest(
    candidate: &AcceptedObservedCandidate,
    id_choice: AdoptionIdChoice,
    disposition: AdoptionDisposition,
    asset: &Asset,
    base_manifest_revision: &Revision,
    proposed_manifest_revision: &Revision,
    lockfile: &Lockfile,
) -> Result<ContentHash, AdoptionError> {
    let lock_json = lockfile.to_json().map_err(|_| {
        AdoptionError::new(
            "adoption.plan_digest_failed",
            "the proposed lockfile cannot be encoded for the plan digest",
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-adoption-plan-v1\0");
    write_record(&mut hasher, candidate.observation_id().as_str());
    hasher.update(&[match id_choice {
        AdoptionIdChoice::PolicyDefault => 0,
        AdoptionIdChoice::Explicit => 1,
    }]);
    hasher.update(&[match disposition {
        AdoptionDisposition::First => 0,
        AdoptionDisposition::Idempotent => 1,
    }]);
    write_record(&mut hasher, asset.id.as_str());
    write_record(&mut hasher, asset.content_hash.as_str());
    let portable = asset.portable.as_ref().ok_or_else(|| {
        AdoptionError::new(
            "adoption.plan_digest_failed",
            "a ready adoption plan is missing its portable object",
        )
    })?;
    write_record(&mut hasher, portable.root.as_str());
    write_record(&mut hasher, portable.object_hash.as_str());
    let native = asset
        .native_variants
        .get(&candidate.location().harness)
        .ok_or_else(|| {
            AdoptionError::new(
                "adoption.plan_digest_failed",
                "a ready adoption plan is missing its origin-native object",
            )
        })?;
    write_record(&mut hasher, native.root.as_str());
    write_record(&mut hasher, native.object_hash.as_str());
    write_record(&mut hasher, base_manifest_revision.as_str());
    write_record(&mut hasher, proposed_manifest_revision.as_str());
    write_record(
        &mut hasher,
        ContentHash::digest(lock_json.as_bytes()).as_str(),
    );
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex())).map_err(|_| {
        AdoptionError::new(
            "adoption.plan_digest_failed",
            "the proposed adoption plan cannot form a canonical digest",
        )
    })
}

pub(crate) fn tier_one_harnesses() -> [HarnessId; 4] {
    [
        HarnessId::Claude,
        HarnessId::Codex,
        HarnessId::Pi,
        HarnessId::OpenCode,
    ]
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

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_adapter_api::{
        CandidateDecision, NativeAcceptance, ObservationId, ObservationIdentity,
        PortablePolicyDecision, RootId, RootTier, SourceRelativePath,
    };
    use kitrove_agent_skills::{
        CapturedFile, CapturedSkillSource, CapturedTree, FileMode, ObservedSkillDocument,
        SkillSourceLayout, hash_skill_source, hash_tree,
    };
    use kitrove_model::{
        AssetId, AssetKind, ContentClass, Fidelity, FidelityEvidence, FidelityReason,
        FidelityResult, HarnessId, HarnessScope, SchemaVersion,
    };

    use super::*;
    use crate::ObservationLocation;

    pub(crate) fn capabilities() -> TierOneCapabilities {
        TierOneCapabilities::new(
            tier_one_harnesses()
                .into_iter()
                .map(|harness| {
                    (
                        harness,
                        CapabilityMatrix::portable_agent_skills(
                            "test-agent-skills/1",
                            "test adapter accepts canonical Agent Skills packages",
                        ),
                    )
                })
                .collect(),
        )
        .unwrap()
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

    pub(crate) fn make_candidate(mode: FileMode, native_id: &str) -> AcceptedObservedCandidate {
        let document_name = "SKILL.md".to_owned();
        let document = ObservedSkillDocument {
            frontmatter: BTreeMap::new(),
            declared_name: Some("review".to_owned()),
            description: Some("Review code carefully".to_owned()),
            license: None,
            compatibility: None,
            metadata: None,
            allowed_tools: None,
            body: "Inspect the change.\n".to_owned(),
            native_fields: BTreeSet::new(),
        };
        let files = BTreeMap::from([(
            PortablePath::parse("SKILL.md").unwrap(),
            CapturedFile {
                mode,
                bytes: b"---\nname: review\ndescription: Review code carefully\n---\nInspect the change.\n"
                    .to_vec(),
            },
        )]);
        let exact = CapturedTree {
            hash: hash_tree(&files),
            files,
        };
        let captured = CapturedSkillSource {
            layout: SkillSourceLayout::Directory,
            original_document_name: document_name.clone(),
            document,
            exact,
            exact_source_hash: ContentHash::digest(b"placeholder"),
            content_class: if mode == FileMode::Executable {
                ContentClass::Executable
            } else {
                ContentClass::AgentActive
            },
        };
        let captured = CapturedSkillSource {
            exact_source_hash: hash_skill_source(
                captured.layout,
                &captured.original_document_name,
                &captured.exact,
            ),
            ..captured
        };
        let decision = CandidateDecision::new(
            NativeAcceptance::Accepted,
            Some(native_id.to_owned()),
            PortablePolicyDecision::Project {
                name: AssetId::parse("review").unwrap(),
                description: "Review code carefully".to_owned(),
                reasons: vec![],
            },
            vec![],
        )
        .unwrap();
        let projection = project_skill_source(
            &captured,
            AssetId::parse("review").unwrap(),
            "Review code carefully".to_owned(),
            vec![],
        )
        .unwrap();
        let PortableProjection::Available { tree, .. } = projection else {
            panic!("test projection must be available");
        };
        let location = ObservationLocation {
            harness: HarnessId::Claude,
            scope: HarnessScope::User,
            root_tier: RootTier::User,
            logical_root: RootId::parse("claude.user.skills").unwrap(),
            policy_rank: 10,
            source_relative_path: Some(SourceRelativePath::parse("review").unwrap()),
            layout: SkillSourceLayout::Directory,
            original_document_name: Some(document_name),
        };
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
            native_id: Some(native_id),
            exact_source_hash: Some(&captured.exact_source_hash),
        });
        AcceptedObservedCandidate::from_test_parts(
            observation_id,
            location,
            captured,
            Some(tree.hash),
            decision,
        )
    }

    pub(crate) fn ready_plan() -> (AdoptionPlan, AcceptedObservedCandidate, EnvironmentManifest) {
        let candidate = make_candidate(FileMode::Regular, "review");
        let manifest = empty_manifest();
        let outcome = plan_adoption(&candidate, None, &manifest, &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(plan) = outcome else {
            panic!("test candidate must produce a ready plan");
        };
        (*plan, candidate, manifest)
    }

    pub(crate) fn with_portable_decision(
        candidate: &AcceptedObservedCandidate,
        portable: PortablePolicyDecision,
    ) -> AcceptedObservedCandidate {
        let decision = CandidateDecision::new(
            NativeAcceptance::Accepted,
            candidate.decision().native_id().map(str::to_owned),
            portable.clone(),
            vec![],
        )
        .unwrap();
        let portable_hash = match portable {
            PortablePolicyDecision::Project {
                name,
                description,
                reasons,
            } => {
                let projection =
                    project_skill_source(candidate.captured(), name, description, reasons).unwrap();
                let PortableProjection::Available { tree, .. } = projection else {
                    panic!("test projection must be available");
                };
                Some(tree.hash)
            }
            PortablePolicyDecision::Unavailable { .. } => None,
        };
        AcceptedObservedCandidate::from_test_parts(
            candidate.observation_id().clone(),
            candidate.location().clone(),
            candidate.captured().clone(),
            portable_hash,
            decision,
        )
    }

    pub(crate) fn with_changed_document_bytes(
        candidate: &AcceptedObservedCandidate,
    ) -> AcceptedObservedCandidate {
        let mut captured = candidate.captured().clone();
        captured.document.body = "Inspect the changed source.\n".to_owned();
        captured
            .exact
            .files
            .get_mut(&PortablePath::parse("SKILL.md").unwrap())
            .unwrap()
            .bytes = b"---\nname: review\ndescription: Review code carefully\n---\nInspect the changed source.\n"
            .to_vec();
        captured.exact.hash = hash_tree(&captured.exact.files);
        captured.exact_source_hash = hash_skill_source(
            captured.layout,
            &captured.original_document_name,
            &captured.exact,
        );
        let PortablePolicyDecision::Project {
            name,
            description,
            reasons,
        } = candidate.decision().portable().clone()
        else {
            panic!("base test candidate has a portable projection");
        };
        let projection = project_skill_source(&captured, name, description, reasons).unwrap();
        let PortableProjection::Available { tree, .. } = projection else {
            panic!("changed test projection must be available");
        };
        let location = candidate.location().clone();
        let observation_id = ObservationId::from_identity(&ObservationIdentity {
            harness: &location.harness,
            scope: location.scope,
            root_tier: location.root_tier,
            policy_rank: location.policy_rank,
            logical_root: &location.logical_root,
            source_relative_path: location.source_relative_path.as_ref().unwrap(),
            layout: location.layout,
            original_document_name: location.original_document_name.as_deref().unwrap(),
            native_id: candidate.decision().native_id(),
            exact_source_hash: Some(&captured.exact_source_hash),
        });
        AcceptedObservedCandidate::from_test_parts(
            observation_id,
            location,
            captured,
            Some(tree.hash),
            candidate.decision().clone(),
        )
    }

    #[test]
    fn first_plan_contains_two_objects_four_results_and_derived_authority() {
        let candidate = make_candidate(FileMode::Regular, "review");
        let outcome = plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(plan) = outcome else {
            panic!("valid candidate must produce a ready plan");
        };

        assert_eq!(plan.disposition(), AdoptionDisposition::First);
        assert_eq!(
            plan.recovery_action(),
            AdoptionRecoveryAction::CommitNewAsset
        );
        assert_eq!(plan.id_choice(), AdoptionIdChoice::PolicyDefault);
        assert_eq!(plan.asset().compatibility.len(), 4);
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Claude].fidelity(),
            Fidelity::Native
        );
        assert!(
            [HarnessId::Codex, HarnessId::OpenCode, HarnessId::Pi]
                .into_iter()
                .all(
                    |harness| plan.asset().compatibility[&harness].fidelity() == Fidelity::Portable
                )
        );
        assert_eq!(
            plan.proposed_lock().assets[&plan.asset().id].content_hash,
            plan.asset().content_hash
        );
        assert!(plan.ensure_observation_fresh(&candidate).is_ok());
        assert!(plan.ensure_manifest_fresh(&empty_manifest()).is_ok());
    }

    #[test]
    fn explicit_identity_changes_the_asset_revision_and_plan_digest() {
        let candidate = make_candidate(FileMode::Regular, "review");
        let default = plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap();
        let explicit = plan_adoption(
            &candidate,
            Some(AssetId::parse("review-copy").unwrap()),
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap();
        let (AdoptionPlanOutcome::Ready(default), AdoptionPlanOutcome::Ready(explicit)) =
            (default, explicit)
        else {
            panic!("both plans must be ready");
        };
        assert_ne!(default.asset().content_hash, explicit.asset().content_hash);
        assert_ne!(default.digest(), explicit.digest());
        assert_eq!(explicit.id_choice(), AdoptionIdChoice::Explicit);
    }

    #[test]
    fn equivalent_existing_asset_is_idempotent_and_different_asset_blocks() {
        let candidate = make_candidate(FileMode::Regular, "review");
        let first = plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(first) = first else {
            panic!("first plan must be ready");
        };
        let manifest = first.proposed_manifest().clone();
        let again = plan_adoption(&candidate, None, &manifest, &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(again) = again else {
            panic!("equivalent plan must remain ready");
        };
        assert_eq!(again.disposition(), AdoptionDisposition::Idempotent);
        assert_eq!(
            again.recovery_action(),
            AdoptionRecoveryAction::RepairReferencedState
        );

        let other = make_candidate(FileMode::Regular, "other-native-id");
        let conflict = plan_adoption(&other, None, &manifest, &capabilities()).unwrap();
        let AdoptionPlanOutcome::Blocked(conflict) = conflict else {
            panic!("different complete revision must block");
        };
        assert_eq!(conflict.reason(), AdoptionBlockReason::AssetConflict);
    }

    #[test]
    fn executable_and_secret_shaped_native_identity_are_non_mutating_blocks() {
        let executable = plan_adoption(
            &make_candidate(FileMode::Executable, "review"),
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap();
        assert!(matches!(
            executable,
            AdoptionPlanOutcome::Blocked(AdoptionBlock {
                reason: AdoptionBlockReason::ExecutableTrustRequired,
                ..
            })
        ));

        let secret = plan_adoption(
            &make_candidate(FileMode::Regular, "sk-live-12345678901234567890"),
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap();
        assert!(matches!(
            secret,
            AdoptionPlanOutcome::Blocked(AdoptionBlock {
                reason: AdoptionBlockReason::CredentialShapedNativeIdentity,
                ..
            })
        ));
        assert!(!format!("{secret:?}").contains("sk-live-"));
    }

    #[test]
    fn complete_candidate_comparison_rejects_stale_native_identity_and_bytes() {
        let candidate = make_candidate(FileMode::Regular, "review");
        let outcome = plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(plan) = outcome else {
            panic!("valid candidate must produce a ready plan");
        };
        let changed_identity = make_candidate(FileMode::Regular, "changed");
        let changed_mode = make_candidate(FileMode::Executable, "review");
        let changed_bytes = with_changed_document_bytes(&candidate);
        assert_eq!(
            plan.ensure_observation_fresh(&changed_identity)
                .unwrap_err()
                .code(),
            "adoption.observation_stale"
        );
        assert_eq!(
            plan.ensure_observation_fresh(&changed_mode)
                .unwrap_err()
                .code(),
            "adoption.observation_stale"
        );
        assert_eq!(
            plan.ensure_observation_fresh(&changed_bytes)
                .unwrap_err()
                .code(),
            "adoption.observation_stale"
        );
        assert_eq!(
            plan.ensure_manifest_fresh(plan.proposed_manifest())
                .unwrap_err()
                .code(),
            "adoption.manifest_stale"
        );
    }

    #[test]
    fn unavailable_projection_blocks_and_loss_reasons_make_other_targets_partial() {
        let candidate = make_candidate(FileMode::Regular, "review");
        let unavailable = with_portable_decision(
            &candidate,
            PortablePolicyDecision::Unavailable {
                reasons: vec![FidelityReason::new(
                    "skill.portable_unavailable",
                    "the adapter cannot provide a standards-valid portable identity",
                )],
            },
        );
        let outcome =
            plan_adoption(&unavailable, None, &empty_manifest(), &capabilities()).unwrap();
        assert!(matches!(
            outcome,
            AdoptionPlanOutcome::Blocked(AdoptionBlock {
                reason: AdoptionBlockReason::PortableProjectionUnavailable,
                ..
            })
        ));

        let partial = with_portable_decision(
            &candidate,
            PortablePolicyDecision::Project {
                name: AssetId::parse("review").unwrap(),
                description: "Review code carefully".to_owned(),
                reasons: vec![FidelityReason::new(
                    "skill.native_field_omitted",
                    "one origin-native field is retained only in native evidence",
                )],
            },
        );
        let outcome = plan_adoption(&partial, None, &empty_manifest(), &capabilities()).unwrap();
        let AdoptionPlanOutcome::Ready(plan) = outcome else {
            panic!("loss-aware portable projection must remain adoptable");
        };
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Claude].fidelity(),
            Fidelity::Native
        );
        assert!(
            [HarnessId::Codex, HarnessId::Pi, HarnessId::OpenCode]
                .into_iter()
                .all(|harness| plan.asset().compatibility[&harness].fidelity()
                    == Fidelity::Partial)
        );
    }

    #[test]
    fn incomplete_capability_catalog_is_rejected() {
        let matrices = BTreeMap::from([(
            HarnessId::Claude,
            CapabilityMatrix::portable_agent_skills(
                "test-agent-skills/1",
                "test adapter accepts canonical Agent Skills packages",
            ),
        )]);
        assert_eq!(
            TierOneCapabilities::new(matrices).unwrap_err().code(),
            "adoption.incomplete_target_catalog"
        );
    }

    #[test]
    fn machine_local_capability_evidence_is_rejected_before_persistence() {
        let result = FidelityResult::exact(
            Fidelity::Portable,
            vec![FidelityEvidence::new(
                "adapter.capability_matrix",
                "loaded from /Users/example/.config/skills",
            )],
            "test-agent-skills/1",
            None,
        )
        .unwrap();
        let forged = CapabilityMatrix {
            capabilities: BTreeMap::from([(
                AssetKind::Skill,
                CapabilitySupport {
                    result,
                    notes: vec![],
                },
            )]),
        };
        let matrices = tier_one_harnesses()
            .into_iter()
            .map(|harness| (harness, forged.clone()))
            .collect();
        assert_eq!(
            TierOneCapabilities::new(matrices).unwrap_err().code(),
            "adoption.skill_capability_invalid"
        );
    }
}
