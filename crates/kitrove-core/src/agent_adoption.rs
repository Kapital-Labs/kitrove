use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::{CapabilityMatrix, CapabilitySupport};
use kitrove_agents::{AgentPortability, StoredAgent, StoredNativeAgent};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, Fidelity, FidelityEvidence,
    FidelityResult, HarnessId, Lockfile, NativeVariant, PortableContent, PortablePath, Revision,
    Source,
};

use crate::adoption::{
    AdoptionDisposition, AdoptionRecoveryAction, CapabilityCatalogFailure, adoption_state,
    native_asset_root, portable_asset_root, tier_one_harnesses, validate_tier_one_capabilities,
};
use crate::whole_file_adoption::{self, BlockDigestInput};
use crate::{AgentObservation, derive_lockfile, derive_manifest_revision};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierOneAgentCapabilities {
    agents: BTreeMap<HarnessId, CapabilitySupport>,
}

impl TierOneAgentCapabilities {
    pub fn new(
        matrices: BTreeMap<HarnessId, CapabilityMatrix>,
    ) -> Result<Self, AgentAdoptionError> {
        let agents =
            validate_tier_one_capabilities(&matrices, AssetKind::Agent).map_err(|failure| {
                match failure {
                    CapabilityCatalogFailure::Incomplete => adoption_error(
                        "agent_adoption.incomplete_target_catalog",
                        "agent adoption requires every tier-one capability matrix",
                    ),
                    CapabilityCatalogFailure::Missing => adoption_error(
                        "agent_adoption.capability_missing",
                        "a tier-one adapter does not declare agent support",
                    ),
                    CapabilityCatalogFailure::Invalid => adoption_error(
                        "agent_adoption.capability_invalid",
                        "tier-one agent support must be bounded and evidence-backed",
                    ),
                }
            })?;
        let expected = [
            (HarnessId::Claude, Fidelity::Portable),
            (HarnessId::Codex, Fidelity::Portable),
            (HarnessId::Pi, Fidelity::Unsupported),
            (HarnessId::OpenCode, Fidelity::Portable),
        ];
        if expected
            .iter()
            .any(|(harness, fidelity)| agents[harness].result.fidelity() != *fidelity)
        {
            return Err(adoption_error(
                "agent_adoption.capability_invalid",
                "tier-one agent fidelity does not match the portable-v1 support contract",
            ));
        }
        Ok(Self { agents })
    }

    fn agent(&self, harness: &HarnessId) -> &CapabilitySupport {
        &self.agents[harness]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentAdoptionBlockReason {
    PortableProjectionUnavailable,
    CredentialShapedBody,
    AssetConflict,
}

impl AgentAdoptionBlockReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PortableProjectionUnavailable => "portable_projection_unavailable",
            Self::CredentialShapedBody => "credential_shaped_body",
            Self::AssetConflict => "asset_conflict",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentAdoptionBlock {
    asset_id: AssetId,
    exact_source_hash: ContentHash,
    reason: AgentAdoptionBlockReason,
    digest: ContentHash,
}

impl AgentAdoptionBlock {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn exact_source_hash(&self) -> &ContentHash {
        &self.exact_source_hash
    }

    #[must_use]
    pub const fn reason(&self) -> AgentAdoptionBlockReason {
        self.reason
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentAdoptionPlan {
    observation: AgentObservation,
    disposition: AdoptionDisposition,
    recovery_action: AdoptionRecoveryAction,
    asset: Asset,
    portable_object: StoredAgent,
    native_object: StoredNativeAgent,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl AgentAdoptionPlan {
    #[must_use]
    pub const fn observation(&self) -> &AgentObservation {
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
    pub const fn portable_object(&self) -> &StoredAgent {
        &self.portable_object
    }
    #[must_use]
    pub const fn native_object(&self) -> &StoredNativeAgent {
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
        reread: &AgentObservation,
    ) -> Result<(), AgentAdoptionError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(adoption_error(
                "agent_adoption.observation_stale",
                "the agent changed after planning",
            ))
        }
    }

    pub fn ensure_manifest_fresh(
        &self,
        reread: &EnvironmentManifest,
    ) -> Result<(), AgentAdoptionError> {
        if manifest_revision(reread)? == self.base_manifest_revision {
            Ok(())
        } else {
            Err(adoption_error(
                "agent_adoption.manifest_stale",
                "the authoritative manifest changed after planning",
            ))
        }
    }
}

impl Debug for AgentAdoptionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAdoptionPlan")
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
pub enum AgentAdoptionOutcome {
    Ready(Box<AgentAdoptionPlan>),
    Blocked(AgentAdoptionBlock),
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentAdoptionError {
    code: &'static str,
    message: &'static str,
}

impl AgentAdoptionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for AgentAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAdoptionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for AgentAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AgentAdoptionError {}

/// Plans first adoption or idempotent repair of one already-observed portable agent.
pub fn plan_agent_adoption(
    observation: &AgentObservation,
    asset_id: &AssetId,
    manifest: &EnvironmentManifest,
    capabilities: &TierOneAgentCapabilities,
) -> Result<AgentAdoptionOutcome, AgentAdoptionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    let base_manifest_revision = manifest_revision(manifest)?;
    let observed = observation.observed();
    let AgentPortability::Portable(agent) = observed.portability() else {
        return Ok(blocked(
            observation,
            asset_id.clone(),
            AgentAdoptionBlockReason::PortableProjectionUnavailable,
            &base_manifest_revision,
            None,
            None,
        ));
    };
    let exact_source = std::str::from_utf8(observed.exact_bytes()).map_err(|_| {
        adoption_error(
            "agent_adoption.source_invalid",
            "the observed agent is not valid UTF-8",
        )
    })?;
    if crate::instruction_risk::contains_credential_shaped_value(exact_source) {
        return Ok(blocked(
            observation,
            asset_id.clone(),
            AgentAdoptionBlockReason::CredentialShapedBody,
            &base_manifest_revision,
            None,
            None,
        ));
    }

    let portable_object = StoredAgent::new(agent.clone());
    let native_object = StoredNativeAgent::new(observed.clone()).map_err(|_| {
        adoption_error(
            "agent_adoption.native_object_invalid",
            "the exact agent cannot form a native storage object",
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
        adoption_error(
            "agent_adoption.provenance_invalid",
            "the agent observation cannot form component provenance",
        )
    })?;
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: asset_id.clone(),
        kind: AssetKind::Agent,
        content_hash: ContentHash::digest(b"pending-agent-revision"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: StoredAgent::format().to_owned(),
            root: portable_asset_root(asset_id).map_err(|_| invalid_path())?,
            object_hash: portable_object.object_hash().clone(),
            provenance: provenance_id.clone(),
        }),
        native_variants: BTreeMap::from([(
            observation.harness().clone(),
            NativeVariant {
                harness: observation.harness().clone(),
                format: StoredNativeAgent::format().to_owned(),
                root: native_asset_root(asset_id, observation.harness())
                    .map_err(|_| invalid_path())?,
                object_hash: native_object.object_hash().clone(),
                content_class: observed.content_class(),
                provenance: provenance_id,
            },
        )]),
        compatibility: compatibility(
            observation.harness(),
            capabilities,
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
            AgentAdoptionBlockReason::AssetConflict,
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
        adoption_error(
            "agent_adoption.proposed_manifest_invalid",
            "the proposed agent manifest failed validation",
        )
    })?;
    let proposed_lock = derive_lockfile(&proposed_manifest).map_err(|_| {
        adoption_error(
            "agent_adoption.proposed_lock_invalid",
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

    Ok(AgentAdoptionOutcome::Ready(Box::new(AgentAdoptionPlan {
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
    })))
}

fn compatibility(
    origin: &HarnessId,
    capabilities: &TierOneAgentCapabilities,
    portable_hash: &ContentHash,
    native_hash: &ContentHash,
) -> Result<BTreeMap<HarnessId, FidelityResult>, AgentAdoptionError> {
    tier_one_harnesses()
        .into_iter()
        .map(|harness| {
            let support = capabilities.agent(&harness);
            let mut evidence = support.result.evidence().to_vec();
            let (fidelity, reasons, blocked_requirements) = if &harness == origin {
                evidence.push(FidelityEvidence::new(
                    "native.object_hash",
                    native_hash.as_str(),
                ));
                (Fidelity::Native, vec![], vec![])
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
            FidelityResult::new(
                fidelity,
                reasons,
                evidence,
                blocked_requirements,
                support.result.adapter_version(),
                support.result.harness_version().map(str::to_owned),
            )
            .map(|result| (harness, result))
            .map_err(|_| {
                adoption_error(
                    "agent_adoption.fidelity_invalid",
                    "the evidence-backed agent fidelity result is invalid",
                )
            })
        })
        .collect()
}

fn logical_origin(observation: &AgentObservation) -> Result<PortablePath, AgentAdoptionError> {
    whole_file_adoption::observation_origin(
        observation.identity(),
        observation.harness(),
        observation.scope(),
        "agents",
    )
    .map_err(|()| invalid_path())
}

fn invalid_path() -> AgentAdoptionError {
    adoption_error(
        "agent_adoption.portable_path_invalid",
        "the agent observation cannot form a portable authority path",
    )
}

fn invalid_manifest() -> AgentAdoptionError {
    adoption_error(
        "agent_adoption.manifest_invalid",
        "the authoritative manifest is invalid",
    )
}

fn manifest_revision(manifest: &EnvironmentManifest) -> Result<Revision, AgentAdoptionError> {
    derive_manifest_revision(manifest).map_err(|_| invalid_manifest())
}

fn blocked(
    observation: &AgentObservation,
    asset_id: AssetId,
    reason: AgentAdoptionBlockReason,
    base_manifest_revision: &Revision,
    proposed_revision: Option<&ContentHash>,
    conflicting_revision: Option<&ContentHash>,
) -> AgentAdoptionOutcome {
    let digest = whole_file_adoption::block_digest(BlockDigestInput {
        domain: b"kitrove-agent-adoption-block-v1\0",
        observation_identity: observation.identity(),
        asset_id: &asset_id,
        reason: reason.as_str(),
        base_manifest_revision,
        proposed_revision,
        conflicting_revision,
    });
    AgentAdoptionOutcome::Blocked(AgentAdoptionBlock {
        asset_id,
        exact_source_hash: observation.observed().exact_hash().clone(),
        reason,
        digest,
    })
}

fn plan_digest(
    observation: &AgentObservation,
    disposition: AdoptionDisposition,
    asset: &Asset,
    base_manifest_revision: &Revision,
    proposed_manifest_revision: &Revision,
    lockfile: &Lockfile,
) -> Result<ContentHash, AgentAdoptionError> {
    whole_file_adoption::plan_digest(
        b"kitrove-agent-adoption-plan-v1\0",
        observation.identity(),
        disposition,
        asset,
        base_manifest_revision,
        proposed_manifest_revision,
        lockfile,
    )
    .map_err(|()| {
        adoption_error(
            "agent_adoption.plan_digest_failed",
            "the proposed lockfile cannot be encoded for the plan digest",
        )
    })
}

const fn adoption_error(code: &'static str, message: &'static str) -> AgentAdoptionError {
    AgentAdoptionError { code, message }
}

#[cfg(test)]
pub(crate) mod tests {
    use kitrove_adapter_api::{CapabilityMatrix, RootId, RootTier};
    use kitrove_agents::{AgentLimits, NativeAgentDialect, parse_native_agent};
    use kitrove_model::{FidelityReason, HarnessScope, SchemaVersion};

    use super::*;

    fn capability(fidelity: Fidelity, version: &'static str) -> CapabilityMatrix {
        let evidence = vec![FidelityEvidence::new(
            "adapter.capability_matrix",
            "test adapter agent contract",
        )];
        let result = if fidelity == Fidelity::Unsupported {
            FidelityResult::new(
                fidelity,
                vec![FidelityReason::new(
                    "agent.unsupported",
                    "the target does not load built-in agents",
                )],
                evidence,
                vec![],
                version,
                None,
            )
        } else {
            FidelityResult::exact(fidelity, evidence, version, None)
        }
        .unwrap();
        CapabilityMatrix::empty().with_capability(AssetKind::Agent, result, vec![])
    }

    pub(crate) fn capabilities() -> TierOneAgentCapabilities {
        TierOneAgentCapabilities::new(BTreeMap::from([
            (
                HarnessId::Claude,
                capability(Fidelity::Portable, "claude-agents/1"),
            ),
            (
                HarnessId::Codex,
                capability(Fidelity::Portable, "codex-agents/1"),
            ),
            (
                HarnessId::Pi,
                capability(Fidelity::Unsupported, "pi-agents/1"),
            ),
            (
                HarnessId::OpenCode,
                capability(Fidelity::Portable, "opencode-agents/1"),
            ),
        ]))
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

    fn observation(source: &str) -> AgentObservation {
        AgentObservation::new(
            HarnessId::Claude,
            HarnessScope::User,
            RootTier::User,
            RootId::parse("claude.user.agents").unwrap(),
            20,
            parse_native_agent(
                NativeAgentDialect::ClaudeCurrent,
                "review.md",
                source.as_bytes(),
                AgentLimits::default(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn portable_observation(body: &str) -> AgentObservation {
        observation(&format!(
            "---\nname: review\ndescription: Review changes.\n---\n{body}\n"
        ))
    }

    #[test]
    fn first_plan_is_content_addressed_receipt_ready_and_idempotent() {
        let asset_id = AssetId::parse("review").unwrap();
        let observed = portable_observation("Review carefully.");
        let AgentAdoptionOutcome::Ready(first) =
            plan_agent_adoption(&observed, &asset_id, &empty_manifest(), &capabilities()).unwrap()
        else {
            panic!("portable agent must be adoptable")
        };
        assert_eq!(first.asset().kind, AssetKind::Agent);
        assert_eq!(
            first.asset().content_class,
            kitrove_model::ContentClass::AgentActive
        );
        assert_eq!(
            first.asset().compatibility[&HarnessId::Claude].fidelity(),
            Fidelity::Native
        );
        assert_eq!(
            first.asset().compatibility[&HarnessId::Codex].fidelity(),
            Fidelity::Portable
        );
        assert_eq!(
            first.asset().compatibility[&HarnessId::Pi].fidelity(),
            Fidelity::Unsupported
        );
        assert!(first.ensure_observation_fresh(&observed).is_ok());
        assert!(first.ensure_manifest_fresh(&empty_manifest()).is_ok());
        assert!(!format!("{first:?}").contains("Review carefully"));

        let AgentAdoptionOutcome::Ready(repeated) = plan_agent_adoption(
            &observed,
            &asset_id,
            first.proposed_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            panic!("equivalent adoption must be idempotent")
        };
        assert_eq!(repeated.disposition(), AdoptionDisposition::Idempotent);
    }

    #[test]
    fn native_authority_credentials_and_conflicts_block_without_disclosure() {
        let asset_id = AssetId::parse("review").unwrap();
        let configured = observation(
            "---\nname: review\ndescription: Review changes.\nhooks: enabled\n---\nReview.\n",
        );
        let AgentAdoptionOutcome::Blocked(blocked) =
            plan_agent_adoption(&configured, &asset_id, &empty_manifest(), &capabilities())
                .unwrap()
        else {
            panic!("native authority must block portable adoption")
        };
        assert_eq!(
            blocked.reason(),
            AgentAdoptionBlockReason::PortableProjectionUnavailable
        );

        let credential = portable_observation("Use ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.");
        let AgentAdoptionOutcome::Blocked(blocked) =
            plan_agent_adoption(&credential, &asset_id, &empty_manifest(), &capabilities())
                .unwrap()
        else {
            panic!("credential-shaped agent instructions must block")
        };
        assert_eq!(
            blocked.reason(),
            AgentAdoptionBlockReason::CredentialShapedBody
        );
        assert!(!format!("{blocked:?}").contains("ghp_"));

        let first = portable_observation("Review carefully.");
        let AgentAdoptionOutcome::Ready(plan) =
            plan_agent_adoption(&first, &asset_id, &empty_manifest(), &capabilities()).unwrap()
        else {
            unreachable!()
        };
        let changed = portable_observation("Review differently.");
        let AgentAdoptionOutcome::Blocked(blocked) = plan_agent_adoption(
            &changed,
            &asset_id,
            plan.proposed_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            panic!("changed authority requires explicit update")
        };
        assert_eq!(blocked.reason(), AgentAdoptionBlockReason::AssetConflict);
    }

    #[test]
    fn capability_catalog_and_freshness_fail_closed() {
        let mut matrices = BTreeMap::new();
        matrices.insert(
            HarnessId::Claude,
            capability(Fidelity::Portable, "claude-agents/1"),
        );
        assert_eq!(
            TierOneAgentCapabilities::new(matrices).unwrap_err().code(),
            "agent_adoption.incomplete_target_catalog"
        );

        let asset_id = AssetId::parse("review").unwrap();
        let observed = portable_observation("Review carefully.");
        let AgentAdoptionOutcome::Ready(plan) =
            plan_agent_adoption(&observed, &asset_id, &empty_manifest(), &capabilities()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(
            plan.ensure_observation_fresh(&portable_observation("Review differently."))
                .unwrap_err()
                .code(),
            "agent_adoption.observation_stale"
        );
    }
}
