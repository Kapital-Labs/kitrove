use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::{CapabilityMatrix, CapabilitySupport};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, Fidelity, FidelityEvidence,
    FidelityReason, FidelityResult, HarnessId, Lockfile, NativeVariant, PortableContent,
    PortablePath, Revision, Source,
};
use kitrove_prompt_commands::{
    NativePromptDialect, PromptArgumentMode, PromptCommandPortability,
    StoredNativePromptCommand as StoredNativePromptObject,
    StoredPromptCommand as StoredPromptObject,
};

use crate::adoption::{
    AdoptionDisposition, AdoptionRecoveryAction, CapabilityCatalogFailure, adoption_state,
    native_asset_root, portable_asset_root, tier_one_harnesses, validate_tier_one_capabilities,
};
use crate::prompt_command_observation::prompt_command_dialect;
use crate::whole_file_adoption::{self, BlockDigestInput};
use crate::{PromptCommandObservation, derive_lockfile, derive_manifest_revision};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierOnePromptCommandCapabilities {
    commands: BTreeMap<HarnessId, CapabilitySupport>,
}

impl TierOnePromptCommandCapabilities {
    pub fn new(
        matrices: BTreeMap<HarnessId, CapabilityMatrix>,
    ) -> Result<Self, PromptCommandAdoptionError> {
        let commands =
            validate_tier_one_capabilities(&matrices, AssetKind::Command).map_err(|failure| {
                match failure {
                    CapabilityCatalogFailure::Incomplete => command_error(
                        "prompt_command_adoption.incomplete_target_catalog",
                        "prompt-command adoption requires every tier-one capability matrix",
                    ),
                    CapabilityCatalogFailure::Missing => command_error(
                        "prompt_command_adoption.capability_missing",
                        "a tier-one adapter does not declare prompt-command support",
                    ),
                    CapabilityCatalogFailure::Invalid => command_error(
                        "prompt_command_adoption.capability_invalid",
                        "tier-one prompt-command support must be bounded and evidence-backed",
                    ),
                }
            })?;
        let expected = [
            (HarnessId::Claude, Fidelity::Adapted),
            (HarnessId::Codex, Fidelity::Unsupported),
            (HarnessId::Pi, Fidelity::Portable),
            (HarnessId::OpenCode, Fidelity::Portable),
        ];
        if expected
            .iter()
            .any(|(harness, fidelity)| commands[harness].result.fidelity() != *fidelity)
        {
            return Err(command_error(
                "prompt_command_adoption.capability_invalid",
                "tier-one prompt-command fidelity does not match the portable-v1 support contract",
            ));
        }
        Ok(Self { commands })
    }

    fn command(&self, harness: &HarnessId) -> &CapabilitySupport {
        &self.commands[harness]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptCommandAdoptionBlockReason {
    PortableProjectionUnavailable,
    CredentialShapedBody,
    AssetConflict,
}

impl PromptCommandAdoptionBlockReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PortableProjectionUnavailable => "portable_projection_unavailable",
            Self::CredentialShapedBody => "credential_shaped_body",
            Self::AssetConflict => "asset_conflict",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptCommandAdoptionBlock {
    asset_id: AssetId,
    exact_source_hash: ContentHash,
    reason: PromptCommandAdoptionBlockReason,
    digest: ContentHash,
}

impl PromptCommandAdoptionBlock {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn exact_source_hash(&self) -> &ContentHash {
        &self.exact_source_hash
    }

    #[must_use]
    pub const fn reason(&self) -> PromptCommandAdoptionBlockReason {
        self.reason
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandAdoptionPlan {
    observation: PromptCommandObservation,
    disposition: AdoptionDisposition,
    recovery_action: AdoptionRecoveryAction,
    asset: Asset,
    portable_object: StoredPromptObject,
    native_object: StoredNativePromptObject,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl PromptCommandAdoptionPlan {
    #[must_use]
    pub const fn observation(&self) -> &PromptCommandObservation {
        &self.observation
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
    pub const fn portable_object(&self) -> &StoredPromptObject {
        &self.portable_object
    }

    #[must_use]
    pub const fn native_object(&self) -> &StoredNativePromptObject {
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

    pub fn ensure_observation_fresh(
        &self,
        reread: &PromptCommandObservation,
    ) -> Result<(), PromptCommandAdoptionError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(command_error(
                "prompt_command_adoption.observation_stale",
                "the prompt command changed after planning",
            ))
        }
    }

    pub fn ensure_manifest_fresh(
        &self,
        reread: &EnvironmentManifest,
    ) -> Result<(), PromptCommandAdoptionError> {
        if manifest_revision(reread)? == self.base_manifest_revision {
            Ok(())
        } else {
            Err(command_error(
                "prompt_command_adoption.manifest_stale",
                "the authoritative manifest changed after planning",
            ))
        }
    }
}

impl Debug for PromptCommandAdoptionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandAdoptionPlan")
            .field("asset_id", &self.asset.id)
            .field("origin_harness", &self.observation.harness())
            .field(
                "exact_source_hash",
                &self.observation.observed().exact_hash(),
            )
            .field("disposition", &self.disposition)
            .field("recovery_action", &self.recovery_action)
            .field("asset_revision", &self.asset.content_hash)
            .field("portable_object_hash", &self.portable_object.object_hash())
            .field("native_object_hash", &self.native_object.object_hash())
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptCommandAdoptionOutcome {
    Ready(Box<PromptCommandAdoptionPlan>),
    Blocked(PromptCommandAdoptionBlock),
}

#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandAdoptionError {
    code: &'static str,
    message: &'static str,
}

impl PromptCommandAdoptionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PromptCommandAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandAdoptionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PromptCommandAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PromptCommandAdoptionError {}

/// Plans first adoption or idempotent repair of one already-observed portable command.
pub fn plan_prompt_command_adoption(
    observation: &PromptCommandObservation,
    asset_id: &AssetId,
    manifest: &EnvironmentManifest,
    capabilities: &TierOnePromptCommandCapabilities,
) -> Result<PromptCommandAdoptionOutcome, PromptCommandAdoptionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    let base_manifest_revision = manifest_revision(manifest)?;
    let observed = observation.observed();
    let PromptCommandPortability::Portable(command) = observed.portability() else {
        return Ok(blocked(
            observation,
            asset_id.clone(),
            PromptCommandAdoptionBlockReason::PortableProjectionUnavailable,
            &base_manifest_revision,
            None,
            None,
        ));
    };
    let exact_source = std::str::from_utf8(observed.exact_bytes()).map_err(|_| {
        command_error(
            "prompt_command_adoption.source_invalid",
            "the observed prompt command is not valid UTF-8",
        )
    })?;
    if crate::instruction_risk::contains_credential_shaped_value(exact_source) {
        return Ok(blocked(
            observation,
            asset_id.clone(),
            PromptCommandAdoptionBlockReason::CredentialShapedBody,
            &base_manifest_revision,
            None,
            None,
        ));
    }

    let portable_object = StoredPromptObject::new(command.clone());
    let native_object = StoredNativePromptObject::new(observed.clone()).map_err(|_| {
        command_error(
            "prompt_command_adoption.native_object_invalid",
            "the exact prompt command cannot form a native storage object",
        )
    })?;
    let provenance = kitrove_model::ComponentProvenance::new(
        Source::Harness {
            harness: observation.harness().clone(),
            origin: logical_origin(observation)?,
        },
        Revision::parse(observation.identity().as_str()).map_err(|_| invalid_path())?,
        observed.exact_hash().clone(),
        Some(observation.scope()),
    )
    .map_err(|_| {
        command_error(
            "prompt_command_adoption.provenance_invalid",
            "the prompt-command observation cannot form component provenance",
        )
    })?;
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: asset_id.clone(),
        kind: AssetKind::Command,
        content_hash: ContentHash::digest(b"pending-prompt-command-revision"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: StoredPromptObject::format().to_owned(),
            root: portable_root(asset_id)?,
            object_hash: portable_object.object_hash().clone(),
            provenance: provenance_id.clone(),
        }),
        native_variants: BTreeMap::from([(
            observation.harness().clone(),
            NativeVariant {
                harness: observation.harness().clone(),
                format: StoredNativePromptObject::format().to_owned(),
                root: native_root(asset_id, observation.harness())?,
                object_hash: native_object.object_hash().clone(),
                content_class: observed.content_class(),
                provenance: provenance_id,
            },
        )]),
        compatibility: compatibility(
            observation.harness(),
            capabilities,
            command.argument_mode(),
            portable_object.object_hash(),
            native_object.object_hash(),
        )?,
        content_class: observed.content_class(),
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
            observation,
            asset_id.clone(),
            PromptCommandAdoptionBlockReason::AssetConflict,
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
        command_error(
            "prompt_command_adoption.proposed_manifest_invalid",
            "the proposed prompt-command manifest failed validation",
        )
    })?;
    let proposed_lock = derive_lockfile(&proposed_manifest).map_err(|_| {
        command_error(
            "prompt_command_adoption.proposed_lock_invalid",
            "the manifest-derived lockfile failed validation",
        )
    })?;
    let proposed_manifest_revision = manifest_revision(&proposed_manifest)?;
    let digest = plan_digest(
        observation,
        disposition,
        &asset,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
    )?;

    Ok(PromptCommandAdoptionOutcome::Ready(Box::new(
        PromptCommandAdoptionPlan {
            observation: observation.clone(),
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
    capabilities: &TierOnePromptCommandCapabilities,
    argument_mode: PromptArgumentMode,
    portable_hash: &ContentHash,
    native_hash: &ContentHash,
) -> Result<BTreeMap<HarnessId, FidelityResult>, PromptCommandAdoptionError> {
    tier_one_harnesses()
        .into_iter()
        .map(|harness| {
            let support = capabilities.command(&harness);
            let mut evidence = support.result.evidence().to_vec();
            let (fidelity, reasons, blocked_requirements) = if &harness == origin {
                evidence.push(FidelityEvidence::new(
                    "native.object_hash",
                    native_hash.as_str(),
                ));
                (Fidelity::Native, vec![], vec![])
            } else if prompt_command_dialect(&harness)
                .is_some_and(NativePromptDialect::appends_implicit_arguments)
                && argument_mode == PromptArgumentMode::None
            {
                evidence.push(FidelityEvidence::new(
                    "portable.object_hash",
                    portable_hash.as_str(),
                ));
                (
                    Fidelity::Partial,
                    vec![FidelityReason::new(
                        "command.implicit_arguments",
                        "OpenCode appends invocation arguments when no placeholder is present",
                    )],
                    vec![],
                )
            } else {
                if support.result.fidelity() != Fidelity::Unsupported {
                    evidence.push(FidelityEvidence::new(
                        "portable.object_hash",
                        portable_hash.as_str(),
                    ));
                }
                (
                    support.result.fidelity(),
                    support.result.reasons().to_vec(),
                    support.result.blocked_requirements().to_vec(),
                )
            };
            let result = FidelityResult::new(
                fidelity,
                reasons,
                evidence,
                blocked_requirements,
                support.result.adapter_version(),
                support.result.harness_version().map(str::to_owned),
            )
            .map_err(|_| {
                command_error(
                    "prompt_command_adoption.fidelity_invalid",
                    "the evidence-backed prompt-command fidelity result is invalid",
                )
            })?;
            Ok((harness, result))
        })
        .collect()
}

fn portable_root(asset_id: &AssetId) -> Result<PortablePath, PromptCommandAdoptionError> {
    portable_asset_root(asset_id).map_err(|_| invalid_path())
}

fn native_root(
    asset_id: &AssetId,
    harness: &HarnessId,
) -> Result<PortablePath, PromptCommandAdoptionError> {
    native_asset_root(asset_id, harness).map_err(|_| invalid_path())
}

fn logical_origin(
    observation: &PromptCommandObservation,
) -> Result<PortablePath, PromptCommandAdoptionError> {
    whole_file_adoption::observation_origin(
        observation.identity(),
        observation.harness(),
        observation.scope(),
        "commands",
    )
    .map_err(|()| invalid_path())
}

fn invalid_path() -> PromptCommandAdoptionError {
    command_error(
        "prompt_command_adoption.portable_path_invalid",
        "the prompt-command observation cannot form a portable authority path",
    )
}

fn invalid_manifest() -> PromptCommandAdoptionError {
    command_error(
        "prompt_command_adoption.manifest_invalid",
        "the authoritative manifest is invalid",
    )
}

fn manifest_revision(
    manifest: &EnvironmentManifest,
) -> Result<Revision, PromptCommandAdoptionError> {
    derive_manifest_revision(manifest).map_err(|_| invalid_manifest())
}

fn blocked(
    observation: &PromptCommandObservation,
    asset_id: AssetId,
    reason: PromptCommandAdoptionBlockReason,
    base_manifest_revision: &Revision,
    proposed_revision: Option<&ContentHash>,
    conflicting_revision: Option<&ContentHash>,
) -> PromptCommandAdoptionOutcome {
    let digest = whole_file_adoption::block_digest(BlockDigestInput {
        domain: b"kitrove-prompt-command-adoption-block-v1\0",
        observation_identity: observation.identity(),
        asset_id: &asset_id,
        reason: reason.as_str(),
        base_manifest_revision,
        proposed_revision,
        conflicting_revision,
    });
    PromptCommandAdoptionOutcome::Blocked(PromptCommandAdoptionBlock {
        asset_id,
        exact_source_hash: observation.observed().exact_hash().clone(),
        reason,
        digest,
    })
}

fn plan_digest(
    observation: &PromptCommandObservation,
    disposition: AdoptionDisposition,
    asset: &Asset,
    base_manifest_revision: &Revision,
    proposed_manifest_revision: &Revision,
    lockfile: &Lockfile,
) -> Result<ContentHash, PromptCommandAdoptionError> {
    whole_file_adoption::plan_digest(
        b"kitrove-prompt-command-adoption-plan-v1\0",
        observation.identity(),
        disposition,
        asset,
        base_manifest_revision,
        proposed_manifest_revision,
        lockfile,
    )
    .map_err(|()| {
        command_error(
            "prompt_command_adoption.plan_digest_failed",
            "the proposed lockfile cannot be encoded for the plan digest",
        )
    })
}

const fn command_error(code: &'static str, message: &'static str) -> PromptCommandAdoptionError {
    PromptCommandAdoptionError { code, message }
}

#[cfg(test)]
pub(crate) mod tests {
    use kitrove_adapter_api::{RootId, RootTier};
    use kitrove_model::{FidelityReason, HarnessScope, SchemaVersion};
    use kitrove_prompt_commands::{
        NativePromptDialect, PromptCommandLimits, parse_native_prompt_command,
    };

    use super::*;

    fn capability(fidelity: Fidelity, adapter_version: &'static str) -> CapabilityMatrix {
        let evidence = vec![FidelityEvidence::new(
            "adapter.capability_matrix",
            "test adapter prompt-command contract",
        )];
        let result = if fidelity == Fidelity::Unsupported {
            FidelityResult::new(
                fidelity,
                vec![FidelityReason::new(
                    "command.unsupported",
                    "the target does not load prompt commands",
                )],
                evidence,
                vec![],
                adapter_version,
                None,
            )
        } else {
            FidelityResult::exact(fidelity, evidence, adapter_version, None)
        }
        .unwrap();
        CapabilityMatrix::empty().with_capability(AssetKind::Command, result, vec![])
    }

    pub(crate) fn capabilities() -> TierOnePromptCommandCapabilities {
        TierOnePromptCommandCapabilities::new(BTreeMap::from([
            (
                HarnessId::Claude,
                capability(Fidelity::Adapted, "claude-commands/1"),
            ),
            (
                HarnessId::Codex,
                capability(Fidelity::Unsupported, "codex-commands/1"),
            ),
            (
                HarnessId::Pi,
                capability(Fidelity::Portable, "pi-commands/1"),
            ),
            (
                HarnessId::OpenCode,
                capability(Fidelity::Portable, "opencode-commands/1"),
            ),
        ]))
        .unwrap()
    }

    pub(crate) fn manifest() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    pub(crate) fn observation(source: &str) -> PromptCommandObservation {
        observation_document("review.md", source)
    }

    fn observation_document(document_name: &str, source: &str) -> PromptCommandObservation {
        PromptCommandObservation::new(
            HarnessId::Pi,
            HarnessScope::User,
            RootTier::User,
            RootId::parse("pi.user.prompts").unwrap(),
            10,
            parse_native_prompt_command(
                NativePromptDialect::PiLatest,
                document_name,
                source.as_bytes(),
                PromptCommandLimits::default(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn ready_plan_retains_exact_origin_and_target_fidelity() {
        let observed =
            observation("---\ndescription: Review changes\n---\nReview $ARGUMENTS carefully.\n");
        let asset_id = AssetId::parse("review").unwrap();
        let PromptCommandAdoptionOutcome::Ready(plan) =
            plan_prompt_command_adoption(&observed, &asset_id, &manifest(), &capabilities())
                .unwrap()
        else {
            panic!("portable prompt command must produce a ready plan");
        };

        assert_eq!(plan.asset().kind, AssetKind::Command);
        assert_eq!(plan.disposition(), AdoptionDisposition::First);
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Pi].fidelity(),
            Fidelity::Native
        );
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Claude].fidelity(),
            Fidelity::Adapted
        );
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Codex].fidelity(),
            Fidelity::Unsupported
        );
        assert_eq!(
            plan.asset().compatibility[&HarnessId::OpenCode].fidelity(),
            Fidelity::Portable
        );
        assert_eq!(
            plan.native_object().observed().exact_bytes(),
            observed.observed().exact_bytes()
        );
        assert!(plan.ensure_observation_fresh(&observed).is_ok());
        assert!(plan.ensure_manifest_fresh(&manifest()).is_ok());
        assert!(!format!("{plan:?}").contains("Review changes"));
    }

    #[test]
    fn no_argument_command_reports_opencode_semantic_loss() {
        let observed = observation("Review carefully.\n");
        let asset_id = AssetId::parse("review").unwrap();
        let PromptCommandAdoptionOutcome::Ready(plan) =
            plan_prompt_command_adoption(&observed, &asset_id, &manifest(), &capabilities())
                .unwrap()
        else {
            panic!("portable prompt command must produce a ready plan");
        };

        let compatibility = &plan.asset().compatibility[&HarnessId::OpenCode];
        assert_eq!(compatibility.fidelity(), Fidelity::Partial);
        assert_eq!(
            compatibility.reasons()[0].code,
            "command.implicit_arguments"
        );
    }

    #[test]
    fn equivalent_asset_is_idempotent_and_changed_source_conflicts() {
        let observed = observation("Review $ARGUMENTS.\n");
        let asset_id = AssetId::parse("review").unwrap();
        let PromptCommandAdoptionOutcome::Ready(first) =
            plan_prompt_command_adoption(&observed, &asset_id, &manifest(), &capabilities())
                .unwrap()
        else {
            panic!("first adoption must be ready");
        };
        let adopted = first.proposed_manifest().clone();
        let PromptCommandAdoptionOutcome::Ready(repeated) =
            plan_prompt_command_adoption(&observed, &asset_id, &adopted, &capabilities()).unwrap()
        else {
            panic!("equivalent adoption must be ready");
        };
        assert_eq!(repeated.disposition(), AdoptionDisposition::Idempotent);
        assert_eq!(
            repeated.recovery_action(),
            AdoptionRecoveryAction::RepairReferencedState
        );

        let changed = observation("Review all files $ARGUMENTS.\n");
        let PromptCommandAdoptionOutcome::Blocked(block) =
            plan_prompt_command_adoption(&changed, &asset_id, &adopted, &capabilities()).unwrap()
        else {
            panic!("changed source requires explicit update");
        };
        assert_eq!(
            block.reason(),
            PromptCommandAdoptionBlockReason::AssetConflict
        );
    }

    #[test]
    fn nonportable_and_credential_shaped_commands_fail_closed() {
        let asset_id = AssetId::parse("review").unwrap();
        let executable = observation_document("nested/review.md", "Review $ARGUMENTS.\n");
        let PromptCommandAdoptionOutcome::Blocked(block) =
            plan_prompt_command_adoption(&executable, &asset_id, &manifest(), &capabilities())
                .unwrap()
        else {
            panic!("executable command must remain native");
        };
        assert_eq!(
            block.reason(),
            PromptCommandAdoptionBlockReason::PortableProjectionUnavailable
        );

        let credential = observation(
            "---\ndescription: Use sk-live-12345678901234567890\n---\nReview carefully.\n",
        );
        let PromptCommandAdoptionOutcome::Blocked(block) =
            plan_prompt_command_adoption(&credential, &asset_id, &manifest(), &capabilities())
                .unwrap()
        else {
            panic!("credential-shaped command must be blocked");
        };
        assert_eq!(
            block.reason(),
            PromptCommandAdoptionBlockReason::CredentialShapedBody
        );
    }

    #[test]
    fn catalog_rejects_an_incorrect_support_shape() {
        let mut matrices = BTreeMap::from([
            (
                HarnessId::Claude,
                capability(Fidelity::Adapted, "claude-commands/1"),
            ),
            (
                HarnessId::Codex,
                capability(Fidelity::Unsupported, "codex-commands/1"),
            ),
            (
                HarnessId::Pi,
                capability(Fidelity::Portable, "pi-commands/1"),
            ),
            (
                HarnessId::OpenCode,
                capability(Fidelity::Portable, "opencode-commands/1"),
            ),
        ]);
        matrices.insert(
            HarnessId::Codex,
            capability(Fidelity::Portable, "codex-commands/1"),
        );
        assert_eq!(
            TierOnePromptCommandCapabilities::new(matrices)
                .unwrap_err()
                .code(),
            "prompt_command_adoption.capability_invalid"
        );
    }
}
