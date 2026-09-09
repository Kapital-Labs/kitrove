use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::{CapabilityMatrix, CapabilitySupport};
use kitrove_instructions::{InstructionBody, NativeInstructionRegion, StoredInstruction};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, Fidelity,
    FidelityEvidence, FidelityResult, HarnessId, Lockfile, NativeVariant, PortableContent,
    PortablePath, Revision, Source,
};

use crate::adoption::{
    AdoptionDisposition, AdoptionRecoveryAction, CapabilityCatalogFailure, adoption_state,
    native_asset_root, portable_asset_root, tier_one_harnesses,
    validate_tier_one_portable_capabilities,
};
use crate::{
    InstructionDocumentObservation, ObservedInstructionRegion, derive_lockfile,
    derive_manifest_revision,
};

/// The complete tier-one instruction capability catalog required by adoption planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierOneInstructionCapabilities {
    instructions: BTreeMap<HarnessId, CapabilitySupport>,
}

impl TierOneInstructionCapabilities {
    /// Validates that all and only the tier-one adapters declare portable instructions.
    pub fn new(
        matrices: BTreeMap<HarnessId, CapabilityMatrix>,
    ) -> Result<Self, InstructionAdoptionError> {
        let instructions =
            validate_tier_one_portable_capabilities(&matrices, AssetKind::Instruction).map_err(
                |failure| match failure {
                    CapabilityCatalogFailure::Incomplete => instruction_error(
                        "instruction_adoption.incomplete_target_catalog",
                        "instruction adoption requires every tier-one capability matrix",
                    ),
                    CapabilityCatalogFailure::Missing => instruction_error(
                        "instruction_adoption.capability_missing",
                        "a tier-one adapter does not declare standing-instruction support",
                    ),
                    CapabilityCatalogFailure::Invalid => instruction_error(
                        "instruction_adoption.capability_invalid",
                        "tier-one instruction support must be portable and evidence-backed",
                    ),
                },
            )?;
        Ok(Self { instructions })
    }

    fn instruction(&self, harness: &HarnessId) -> &CapabilitySupport {
        &self.instructions[harness]
    }
}

/// A reason an instruction adoption proposal remains non-mutating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionAdoptionBlockReason {
    CredentialShapedBody,
    AssetConflict,
}

impl InstructionAdoptionBlockReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialShapedBody => "credential_shaped_body",
            Self::AssetConflict => "asset_conflict",
        }
    }
}

/// A deterministic non-mutating instruction adoption result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstructionAdoptionBlock {
    asset_id: AssetId,
    observation_revision: ContentHash,
    reason: InstructionAdoptionBlockReason,
    digest: ContentHash,
}

impl InstructionAdoptionBlock {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn observation_revision(&self) -> &ContentHash {
        &self.observation_revision
    }

    #[must_use]
    pub const fn reason(&self) -> InstructionAdoptionBlockReason {
        self.reason
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

/// A complete, deterministic, still non-mutating instruction adoption proposal.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionAdoptionPlan {
    observation: InstructionDocumentObservation,
    asset_id: AssetId,
    disposition: AdoptionDisposition,
    recovery_action: AdoptionRecoveryAction,
    asset: Asset,
    portable_object: StoredInstruction,
    native_object: NativeInstructionRegion,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl InstructionAdoptionPlan {
    #[must_use]
    pub fn origin_harness(&self) -> &HarnessId {
        self.observation.harness()
    }

    #[must_use]
    pub fn observation_revision(&self) -> &ContentHash {
        self.selected_region().observation_revision()
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
    pub const fn portable_object(&self) -> &StoredInstruction {
        &self.portable_object
    }

    #[must_use]
    pub const fn native_object(&self) -> &NativeInstructionRegion {
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

    /// Revalidates the complete document observation immediately before mutation.
    pub fn ensure_observation_fresh(
        &self,
        reread: &InstructionDocumentObservation,
    ) -> Result<(), InstructionAdoptionError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(instruction_error(
                "instruction_adoption.observation_stale",
                "the instruction document changed after planning",
            ))
        }
    }

    /// Revalidates manifest authority immediately before mutation.
    pub fn ensure_manifest_fresh(
        &self,
        reread: &EnvironmentManifest,
    ) -> Result<(), InstructionAdoptionError> {
        if manifest_revision(reread)? == self.base_manifest_revision {
            Ok(())
        } else {
            Err(instruction_error(
                "instruction_adoption.manifest_stale",
                "the authoritative manifest changed after planning",
            ))
        }
    }

    fn selected_region(&self) -> &ObservedInstructionRegion {
        self.observation
            .region(&self.asset_id)
            .expect("a ready plan retains its selected region")
    }
}

impl Debug for InstructionAdoptionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionAdoptionPlan")
            .field("asset_id", &self.asset_id)
            .field("origin_harness", &self.origin_harness())
            .field("observation_revision", &self.observation_revision())
            .field("disposition", &self.disposition)
            .field("recovery_action", &self.recovery_action)
            .field("asset_revision", &self.asset.content_hash)
            .field("portable_object_hash", &self.portable_object.object_hash())
            .field("native_object_hash", &self.native_object.object_hash())
            .field("digest", &self.digest)
            .finish()
    }
}

/// Complete instruction adoption planning result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstructionAdoptionOutcome {
    Ready(Box<InstructionAdoptionPlan>),
    Blocked(InstructionAdoptionBlock),
}

/// Stable, content-redacted instruction adoption failure.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionAdoptionError {
    code: &'static str,
    message: &'static str,
}

impl InstructionAdoptionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for InstructionAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionAdoptionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for InstructionAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for InstructionAdoptionError {}

/// Plans adoption of one already-observed managed region without writing state.
pub fn plan_instruction_adoption(
    observation: &InstructionDocumentObservation,
    asset_id: &AssetId,
    manifest: &EnvironmentManifest,
    capabilities: &TierOneInstructionCapabilities,
) -> Result<InstructionAdoptionOutcome, InstructionAdoptionError> {
    manifest.validate().map_err(|_| {
        instruction_error(
            "instruction_adoption.manifest_invalid",
            "the authoritative manifest is invalid",
        )
    })?;
    let base_manifest_revision = manifest_revision(manifest)?;
    let region = observation.region(asset_id).ok_or_else(|| {
        instruction_error(
            "instruction_adoption.region_missing",
            "the selected managed instruction region was not observed",
        )
    })?;
    let body_text = std::str::from_utf8(region.body()).map_err(|_| {
        instruction_error(
            "instruction_adoption.body_invalid",
            "the selected instruction body is not valid UTF-8",
        )
    })?;
    if crate::instruction_risk::contains_credential_shaped_value(body_text) {
        return Ok(blocked(
            region,
            asset_id.clone(),
            InstructionAdoptionBlockReason::CredentialShapedBody,
            &base_manifest_revision,
            None,
            None,
        ));
    }

    let body =
        InstructionBody::parse(body_text, region.body().len().saturating_add(1)).map_err(|_| {
            instruction_error(
                "instruction_adoption.body_invalid",
                "the selected instruction body cannot form a canonical portable instruction",
            )
        })?;
    let portable_object = StoredInstruction::new(body);
    let native_object =
        NativeInstructionRegion::new(asset_id.clone(), region.exact_region().to_vec()).map_err(
            |_| {
                instruction_error(
                    "instruction_adoption.native_object_invalid",
                    "the exact source region cannot form a native instruction object",
                )
            },
        )?;

    let source = Source::Harness {
        harness: observation.harness().clone(),
        origin: logical_origin(observation, region)?,
    };
    let provenance = kitrove_model::ComponentProvenance::new(
        source,
        Revision::parse(region.observation_revision().as_str()).map_err(|_| invalid_path())?,
        region.exact_region_hash().clone(),
        Some(observation.scope()),
    )
    .map_err(|_| {
        instruction_error(
            "instruction_adoption.provenance_invalid",
            "the instruction observation cannot form component provenance",
        )
    })?;
    let provenance_id = provenance.provenance_id();
    let compatibility = compatibility(
        observation.harness(),
        capabilities,
        portable_object.object_hash(),
        native_object.object_hash(),
    )?;
    let mut asset = Asset {
        id: asset_id.clone(),
        kind: AssetKind::Instruction,
        content_hash: ContentHash::digest(b"pending-instruction-revision"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: StoredInstruction::format().to_owned(),
            root: portable_root(asset_id)?,
            object_hash: portable_object.object_hash().clone(),
            provenance: provenance_id.clone(),
        }),
        native_variants: BTreeMap::from([(
            observation.harness().clone(),
            NativeVariant {
                harness: observation.harness().clone(),
                format: NativeInstructionRegion::format().to_owned(),
                root: native_root(asset_id, observation.harness())?,
                object_hash: native_object.object_hash().clone(),
                content_class: ContentClass::AgentActive,
                provenance: provenance_id,
            },
        )]),
        compatibility,
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();

    let existing_asset = manifest.assets.get(asset_id);
    let existing_pack = manifest.packs.get(asset_id);
    if existing_asset.is_some_and(|existing| existing != &asset) || existing_pack.is_some() {
        let conflicting_revision = existing_asset
            .map(|existing| &existing.content_hash)
            .or_else(|| existing_pack.map(|existing| &existing.content_hash));
        return Ok(blocked(
            region,
            asset_id.clone(),
            InstructionAdoptionBlockReason::AssetConflict,
            &base_manifest_revision,
            Some(&asset.content_hash),
            conflicting_revision,
        ));
    }
    let (disposition, recovery_action) = adoption_state(existing_asset.is_some());
    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .assets
        .insert(asset_id.clone(), asset.clone());
    proposed_manifest.validate().map_err(|_| {
        instruction_error(
            "instruction_adoption.proposed_manifest_invalid",
            "the proposed instruction manifest failed validation",
        )
    })?;
    let proposed_lock = derive_lockfile(&proposed_manifest).map_err(|_| {
        instruction_error(
            "instruction_adoption.proposed_lock_invalid",
            "the manifest-derived lockfile failed validation",
        )
    })?;
    let proposed_manifest_revision = manifest_revision(&proposed_manifest)?;
    let digest = plan_digest(
        region,
        disposition,
        &asset,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
    )?;

    Ok(InstructionAdoptionOutcome::Ready(Box::new(
        InstructionAdoptionPlan {
            observation: observation.clone(),
            asset_id: asset_id.clone(),
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
        },
    )))
}

fn compatibility(
    origin: &HarnessId,
    capabilities: &TierOneInstructionCapabilities,
    portable_hash: &ContentHash,
    native_hash: &ContentHash,
) -> Result<BTreeMap<HarnessId, FidelityResult>, InstructionAdoptionError> {
    tier_one_harnesses()
        .into_iter()
        .map(|harness| {
            let support = capabilities.instruction(&harness);
            let mut evidence = support.result.evidence().to_vec();
            let (fidelity, object_hash, kind) = if &harness == origin {
                (Fidelity::Native, native_hash, "native.object_hash")
            } else {
                (Fidelity::Portable, portable_hash, "portable.object_hash")
            };
            evidence.push(FidelityEvidence::new(kind, object_hash.as_str()));
            let result = FidelityResult::exact(
                fidelity,
                evidence,
                support.result.adapter_version(),
                support.result.harness_version().map(str::to_owned),
            )
            .map_err(|_| {
                instruction_error(
                    "instruction_adoption.fidelity_invalid",
                    "the evidence-backed instruction fidelity result is invalid",
                )
            })?;
            Ok((harness, result))
        })
        .collect()
}

fn portable_root(asset_id: &AssetId) -> Result<PortablePath, InstructionAdoptionError> {
    portable_asset_root(asset_id).map_err(|_| invalid_path())
}

fn native_root(
    asset_id: &AssetId,
    harness: &HarnessId,
) -> Result<PortablePath, InstructionAdoptionError> {
    native_asset_root(asset_id, harness).map_err(|_| invalid_path())
}

fn logical_origin(
    observation: &InstructionDocumentObservation,
    region: &ObservedInstructionRegion,
) -> Result<PortablePath, InstructionAdoptionError> {
    let revision = region
        .observation_revision()
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(invalid_path)?;
    PortablePath::parse(format!(
        "observations/{}/{}/instructions/blake3-{}",
        observation.harness().as_str(),
        observation.scope().as_str(),
        revision
    ))
    .map_err(|_| invalid_path())
}

fn invalid_path() -> InstructionAdoptionError {
    instruction_error(
        "instruction_adoption.portable_path_invalid",
        "the instruction observation cannot form a portable authority path",
    )
}

fn manifest_revision(manifest: &EnvironmentManifest) -> Result<Revision, InstructionAdoptionError> {
    derive_manifest_revision(manifest).map_err(|_| {
        instruction_error(
            "instruction_adoption.manifest_invalid",
            "the authoritative manifest is invalid",
        )
    })
}

fn blocked(
    region: &ObservedInstructionRegion,
    asset_id: AssetId,
    reason: InstructionAdoptionBlockReason,
    base_manifest_revision: &Revision,
    proposed_revision: Option<&ContentHash>,
    conflicting_revision: Option<&ContentHash>,
) -> InstructionAdoptionOutcome {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-adoption-block-v1\0");
    for value in [
        region.observation_revision().as_str(),
        asset_id.as_str(),
        reason.as_str(),
        base_manifest_revision.as_str(),
    ] {
        write_record(&mut hasher, value);
    }
    write_optional_record(&mut hasher, proposed_revision.map(ContentHash::as_str));
    write_optional_record(&mut hasher, conflicting_revision.map(ContentHash::as_str));
    InstructionAdoptionOutcome::Blocked(InstructionAdoptionBlock {
        asset_id,
        observation_revision: region.observation_revision().clone(),
        reason,
        digest: ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("a lowercase BLAKE3 digest is a valid content hash"),
    })
}

fn plan_digest(
    region: &ObservedInstructionRegion,
    disposition: AdoptionDisposition,
    asset: &Asset,
    base_manifest_revision: &Revision,
    proposed_manifest_revision: &Revision,
    lockfile: &Lockfile,
) -> Result<ContentHash, InstructionAdoptionError> {
    let lock_json = lockfile.to_json().map_err(|_| {
        instruction_error(
            "instruction_adoption.plan_digest_failed",
            "the proposed lockfile cannot be encoded for the plan digest",
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-adoption-plan-v1\0");
    write_record(&mut hasher, region.observation_revision().as_str());
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
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex())).map_err(|_| {
        instruction_error(
            "instruction_adoption.plan_digest_failed",
            "the instruction adoption plan cannot form a canonical digest",
        )
    })
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

const fn instruction_error(code: &'static str, message: &'static str) -> InstructionAdoptionError {
    InstructionAdoptionError { code, message }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kitrove_adapter_api::{InstructionTargetAnchor, InstructionTargetPolicy, PolicyLine};
    use kitrove_instructions::InstructionLimits;
    use kitrove_model::{HarnessScope, SchemaVersion};

    use super::*;
    use crate::observe_instruction_document;

    fn capabilities() -> TierOneInstructionCapabilities {
        TierOneInstructionCapabilities::new(
            tier_one_harnesses()
                .into_iter()
                .map(|harness| {
                    (
                        harness,
                        CapabilityMatrix::empty().with_portable_instructions(
                            "test-instructions/1",
                            "test adapter accepts canonical standing instructions",
                        ),
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    fn empty_manifest() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    fn policy() -> InstructionTargetPolicy {
        InstructionTargetPolicy::new(
            HarnessId::Claude,
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            InstructionTargetAnchor::Scope,
            "CLAUDE.md",
            "test-claude/1",
            "claude.instructions.current",
        )
        .unwrap()
    }

    fn observed_document(body: &str) -> (tempfile::TempDir, InstructionDocumentObservation) {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("CLAUDE.md"),
            format!(
                "User preface.\n<!-- kitrove:instruction review begin -->\n{body}\n<!-- kitrove:instruction review end -->\n"
            ),
        )
        .unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        let observed =
            observe_instruction_document(&anchor, &policy(), InstructionLimits::default()).unwrap();
        (directory, observed)
    }

    #[test]
    fn ready_plan_retains_lossless_origin_and_portable_body() {
        let (_directory, observation) = observed_document("Review carefully.  ");
        let asset_id = AssetId::parse("review").unwrap();
        let outcome =
            plan_instruction_adoption(&observation, &asset_id, &empty_manifest(), &capabilities())
                .unwrap();
        let InstructionAdoptionOutcome::Ready(plan) = outcome else {
            panic!("valid instruction must produce a ready plan");
        };

        assert_eq!(plan.asset().kind, AssetKind::Instruction);
        assert_eq!(plan.disposition(), AdoptionDisposition::First);
        assert_eq!(
            plan.recovery_action(),
            AdoptionRecoveryAction::CommitNewAsset
        );
        assert_eq!(plan.asset().compatibility.len(), 4);
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Claude].fidelity(),
            Fidelity::Native
        );
        assert!(
            [HarnessId::Codex, HarnessId::OpenCode, HarnessId::Pi]
                .into_iter()
                .all(|harness| {
                    plan.asset().compatibility[&harness].fidelity() == Fidelity::Portable
                })
        );
        assert_eq!(
            plan.portable_object().body().as_str(),
            "Review carefully.  \n"
        );
        assert!(
            plan.native_object()
                .exact_region()
                .windows(3)
                .any(|bytes| bytes == b".  ")
        );
        assert!(plan.ensure_observation_fresh(&observation).is_ok());
        assert!(plan.ensure_manifest_fresh(&empty_manifest()).is_ok());
        assert!(!format!("{plan:?}").contains("Review carefully"));
    }

    #[test]
    fn logical_observation_revision_excludes_machine_anchor() {
        let (_first_directory, first) = observed_document("Same body.");
        let (_second_directory, second) = observed_document("Same body.");
        let asset_id = AssetId::parse("review").unwrap();
        assert_ne!(first.destination(), second.destination());
        assert_eq!(
            first.region(&asset_id).unwrap().observation_revision(),
            second.region(&asset_id).unwrap().observation_revision()
        );
    }

    #[test]
    fn equivalent_asset_is_idempotent_and_changed_source_conflicts() {
        let (_directory, observation) = observed_document("Review carefully.");
        let asset_id = AssetId::parse("review").unwrap();
        let first =
            plan_instruction_adoption(&observation, &asset_id, &empty_manifest(), &capabilities())
                .unwrap();
        let InstructionAdoptionOutcome::Ready(first) = first else {
            panic!("first plan must be ready");
        };
        let manifest = first.proposed_manifest().clone();
        let again =
            plan_instruction_adoption(&observation, &asset_id, &manifest, &capabilities()).unwrap();
        let InstructionAdoptionOutcome::Ready(again) = again else {
            panic!("equivalent plan must remain ready");
        };
        assert_eq!(again.disposition(), AdoptionDisposition::Idempotent);

        let (_changed_directory, changed) = observed_document("Changed review policy.");
        let conflict =
            plan_instruction_adoption(&changed, &asset_id, &manifest, &capabilities()).unwrap();
        let InstructionAdoptionOutcome::Blocked(conflict) = conflict else {
            panic!("a different complete revision must block");
        };
        assert_eq!(
            conflict.reason(),
            InstructionAdoptionBlockReason::AssetConflict
        );
        assert_eq!(
            first.ensure_observation_fresh(&changed).unwrap_err().code(),
            "instruction_adoption.observation_stale"
        );
    }

    #[test]
    fn credential_shaped_body_blocks_without_disclosure() {
        let (_directory, observation) =
            observed_document("Use sk-live-12345678901234567890 for authentication.");
        let outcome = plan_instruction_adoption(
            &observation,
            &AssetId::parse("review").unwrap(),
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap();
        let InstructionAdoptionOutcome::Blocked(block) = outcome else {
            panic!("credential-shaped instructions must block");
        };
        assert_eq!(
            block.reason(),
            InstructionAdoptionBlockReason::CredentialShapedBody
        );
        assert!(!format!("{block:?}").contains("sk-live"));
    }

    #[test]
    fn capability_catalog_is_exact_and_instruction_specific() {
        let skills_only: BTreeMap<_, _> = tier_one_harnesses()
            .into_iter()
            .map(|harness| {
                (
                    harness,
                    CapabilityMatrix::portable_agent_skills(
                        "test-skills/1",
                        "test adapter accepts canonical Agent Skills packages",
                    ),
                )
            })
            .collect();
        assert_eq!(
            TierOneInstructionCapabilities::new(skills_only)
                .unwrap_err()
                .code(),
            "instruction_adoption.capability_missing"
        );
    }

    #[test]
    fn planned_instruction_objects_round_trip_through_manifest_verification() {
        let (_source_directory, observation) = observed_document("Review carefully.");
        let asset_id = AssetId::parse("review").unwrap();
        let outcome =
            plan_instruction_adoption(&observation, &asset_id, &empty_manifest(), &capabilities())
                .unwrap();
        let InstructionAdoptionOutcome::Ready(plan) = outcome else {
            panic!("valid instruction must produce a ready plan");
        };
        let environment = tempfile::tempdir().unwrap();
        let environment_root = environment.path().canonicalize().unwrap();
        let store = crate::ObjectStore::open(&environment_root).unwrap();
        let portable_stage = PortablePath::parse("staging/portable").unwrap();
        let native_stage = PortablePath::parse("staging/native").unwrap();
        let portable = plan.asset().portable.as_ref().unwrap();
        let native = &plan.asset().native_variants[&HarnessId::Claude];
        let limits = kitrove_agent_skills::CaptureLimits::default();

        store
            .stage_portable_instruction(&portable_stage, plan.portable_object(), limits)
            .unwrap();
        store
            .stage_native_instruction(&native_stage, plan.native_object(), limits)
            .unwrap();
        store
            .install_portable_instruction(
                &portable_stage,
                &portable.root,
                &portable.object_hash,
                limits,
            )
            .unwrap();
        store
            .install_native_instruction(&native_stage, &native.root, &native.object_hash, limits)
            .unwrap();

        assert_eq!(
            crate::load_portable_instruction_object(
                plan.proposed_manifest(),
                &asset_id,
                &environment_root,
                limits,
            )
            .unwrap(),
            *plan.portable_object()
        );
        assert_eq!(
            crate::load_native_instruction_object(
                plan.proposed_manifest(),
                &asset_id,
                &HarnessId::Claude,
                &environment_root,
                limits,
            )
            .unwrap(),
            *plan.native_object()
        );
        assert!(
            crate::verify_referenced_objects(plan.proposed_manifest(), &environment_root, limits,)
                .unwrap()
                .is_clean()
        );

        let mut cross_kind = plan.proposed_manifest().clone();
        let substituted = cross_kind.assets.get_mut(&asset_id).unwrap();
        substituted.kind = AssetKind::Skill;
        substituted.refresh_content_hash();
        cross_kind.validate().unwrap();
        assert_eq!(
            crate::load_portable_instruction_object(
                &cross_kind,
                &asset_id,
                &environment_root,
                limits,
            )
            .unwrap_err()
            .code(),
            "object.portable_format_unsupported"
        );
        assert!(
            !crate::verify_referenced_objects(&cross_kind, &environment_root, limits)
                .unwrap()
                .is_clean()
        );
    }
}
