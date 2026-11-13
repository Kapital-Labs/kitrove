use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_agents::{StoredAgent, StoredNativeAgent};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, Lockfile, Revision,
};

use crate::whole_file_adoption::{self, UpdateFailure};
use crate::{
    AgentAdoptionOutcome, AgentObservation, TierOneAgentCapabilities, plan_agent_adoption,
};

#[derive(Clone, Eq, PartialEq)]
pub struct AgentUpdatePlan {
    observation: AgentObservation,
    expected_prior: ContentHash,
    prior_asset: Asset,
    asset: Asset,
    portable_object: StoredAgent,
    native_object: StoredNativeAgent,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    observed_lock_text: String,
    base_manifest_hash: ContentHash,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl AgentUpdatePlan {
    #[must_use]
    pub const fn observation(&self) -> &AgentObservation {
        &self.observation
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
    pub const fn base_manifest_hash(&self) -> &ContentHash {
        &self.base_manifest_hash
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
    ) -> Result<(), AgentUpdateError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(update_error("agent_update.observation_stale"))
        }
    }

    pub fn ensure_portable_authority_fresh(
        &self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), AgentUpdateError> {
        if !whole_file_adoption::update_authority_is_current(
            manifest_text,
            manifest,
            lock_text,
            &self.asset.id,
            &self.expected_prior,
            &self.base_manifest_hash,
            &self.base_manifest_revision,
            &self.observed_lock_text,
        ) {
            return Err(update_error("agent_update.manifest_stale"));
        }
        Ok(())
    }
}

impl Debug for AgentUpdatePlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentUpdatePlan")
            .field("asset_id", &self.asset.id)
            .field("observation_identity", &self.observation.identity())
            .field("expected_prior", &self.expected_prior)
            .field("proposed_revision", &self.asset.content_hash)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AgentUpdateError {
    code: &'static str,
    message: &'static str,
}

impl AgentUpdateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for AgentUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentUpdateError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for AgentUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for AgentUpdateError {}

/// Plans replacement of exactly one adopted agent without mutating state.
#[allow(clippy::too_many_arguments)]
pub fn plan_agent_update(
    observation: &AgentObservation,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    manifest_text: &str,
    manifest: &EnvironmentManifest,
    lock_text: Option<&str>,
    capabilities: &TierOneAgentCapabilities,
) -> Result<AgentUpdatePlan, AgentUpdateError> {
    let base = whole_file_adoption::update_base(
        AssetKind::Agent,
        asset_id,
        expected_prior,
        manifest_text,
        manifest,
        lock_text,
    )
    .map_err(planning_error)?;
    let AgentAdoptionOutcome::Ready(candidate) = plan_agent_adoption(
        observation,
        asset_id,
        &whole_file_adoption::empty_manifest(),
        capabilities,
    )
    .map_err(|_| update_error("agent_update.derivation_failed"))?
    else {
        return Err(update_error("agent_update.content_blocked"));
    };
    let proposal = whole_file_adoption::propose_update(
        b"kitrove-agent-update-plan-v1\0",
        observation.identity(),
        observation.harness(),
        asset_id,
        expected_prior,
        &base,
        candidate.asset(),
        manifest,
        false,
    )
    .map_err(planning_error)?;

    Ok(AgentUpdatePlan {
        observation: observation.clone(),
        expected_prior: expected_prior.clone(),
        prior_asset: base.prior_asset,
        asset: proposal.asset,
        portable_object: candidate.portable_object().clone(),
        native_object: candidate.native_object().clone(),
        proposed_manifest: proposal.manifest,
        proposed_lock: proposal.lock,
        observed_lock_text: base.observed_lock_text,
        base_manifest_hash: base.manifest_hash,
        base_manifest_revision: base.manifest_revision,
        proposed_manifest_revision: proposal.manifest_revision,
        digest: proposal.digest,
    })
}

fn planning_error(failure: UpdateFailure) -> AgentUpdateError {
    update_error(match failure {
        UpdateFailure::ManifestInvalid => "agent_update.manifest_invalid",
        UpdateFailure::LockNotInSync => "agent_update.lock_not_in_sync",
        UpdateFailure::AssetMissing => "agent_update.asset_missing",
        UpdateFailure::ExpectedPriorMismatch => "agent_update.expected_prior_mismatch",
        UpdateFailure::DerivationFailed => "agent_update.derivation_failed",
        UpdateFailure::RevisionUnchanged => "agent_update.revision_unchanged",
        UpdateFailure::ObjectPathInvalid => "agent_update.object_path_invalid",
        UpdateFailure::ProposedManifestInvalid => "agent_update.proposed_manifest_invalid",
        UpdateFailure::ProposedLockInvalid => "agent_update.proposed_lock_invalid",
        UpdateFailure::PlanDigestFailed => "agent_update.plan_digest_failed",
    })
}

fn update_error(code: &'static str) -> AgentUpdateError {
    let message = match code {
        "agent_update.manifest_invalid" => "agent update planning requires a valid exact manifest",
        "agent_update.lock_not_in_sync" => {
            "agent update planning requires generated lock state in sync"
        }
        "agent_update.asset_missing" => "the agent asset does not exist",
        "agent_update.expected_prior_mismatch" => "the expected prior agent revision is stale",
        "agent_update.content_blocked" => "the agent update content requires review",
        "agent_update.derivation_failed" => "the agent update could not be derived",
        "agent_update.revision_unchanged" => "the agent update does not change stored content",
        "agent_update.object_path_invalid" => "the agent update object path is invalid",
        "agent_update.proposed_manifest_invalid" => "the proposed agent manifest is invalid",
        "agent_update.proposed_lock_invalid" => "the proposed agent lock is invalid",
        "agent_update.plan_digest_failed" => "the agent update plan digest could not be derived",
        "agent_update.observation_stale" => "the agent observation changed after planning",
        "agent_update.manifest_stale" => "portable agent authority changed after planning",
        _ => "agent update planning failed",
    };
    AgentUpdateError { code, message }
}

#[cfg(test)]
mod tests {
    use kitrove_adapter_api::{CapabilityMatrix, RootId, RootTier};
    use kitrove_agents::{AgentLimits, NativeAgentDialect, parse_native_agent};
    use kitrove_model::{
        Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId, HarnessScope,
    };

    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::SchemaVersion;

    use super::*;
    use crate::derive_lockfile;

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

    fn capabilities() -> TierOneAgentCapabilities {
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

    fn observation(body: &str) -> AgentObservation {
        AgentObservation::new(
            HarnessId::Claude,
            HarnessScope::User,
            RootTier::User,
            RootId::parse("claude.user.agents").unwrap(),
            20,
            parse_native_agent(
                NativeAgentDialect::ClaudeCurrent,
                "review.md",
                format!("---\nname: review\ndescription: Review changes.\n---\n{body}\n")
                    .as_bytes(),
                AgentLimits::default(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn adopted() -> (AssetId, EnvironmentManifest, String, String) {
        let asset_id = AssetId::parse("review").unwrap();
        let empty = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };
        let AgentAdoptionOutcome::Ready(plan) = plan_agent_adoption(
            &observation("Review carefully."),
            &asset_id,
            &empty,
            &capabilities(),
        )
        .unwrap() else {
            unreachable!()
        };
        let manifest = plan.proposed_manifest().clone();
        let manifest_text = manifest.to_toml().unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        (asset_id, manifest, manifest_text, lock_text)
    }

    #[test]
    fn plans_exact_prior_content_addressed_replacement() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let changed = observation("Review every file carefully.");
        let plan = plan_agent_update(
            &changed,
            &asset_id,
            &expected,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &capabilities(),
        )
        .unwrap();

        assert_ne!(plan.asset().content_hash, expected);
        assert!(
            plan.asset()
                .portable
                .as_ref()
                .unwrap()
                .root
                .as_str()
                .contains("updates/portable/blake3-")
        );
        assert!(
            plan.asset().native_variants[&HarnessId::Claude]
                .root
                .as_str()
                .contains("updates/native/claude/blake3-")
        );
        assert!(plan.ensure_observation_fresh(&changed).is_ok());
        assert!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, Some(&lock_text))
                .is_ok()
        );
        assert!(!format!("{plan:?}").contains("Review every file"));
    }

    #[test]
    fn unchanged_stale_and_nonportable_updates_fail_closed() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        assert_eq!(
            plan_agent_update(
                &observation("Review carefully."),
                &asset_id,
                &expected,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities(),
            )
            .unwrap_err()
            .code(),
            "agent_update.revision_unchanged"
        );
        assert_eq!(
            plan_agent_update(
                &observation("Review differently."),
                &asset_id,
                &ContentHash::digest(b"stale"),
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities(),
            )
            .unwrap_err()
            .code(),
            "agent_update.expected_prior_mismatch"
        );
        let configured = AgentObservation::new(
            HarnessId::Claude,
            HarnessScope::User,
            RootTier::User,
            RootId::parse("claude.user.agents").unwrap(),
            20,
            parse_native_agent(
                NativeAgentDialect::ClaudeCurrent,
                "review.md",
                b"---\nname: review\ndescription: Review changes.\nhooks: enabled\n---\nReview.\n",
                AgentLimits::default(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            plan_agent_update(
                &configured,
                &asset_id,
                &expected,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities(),
            )
            .unwrap_err()
            .code(),
            "agent_update.content_blocked"
        );
    }

    #[test]
    fn update_failures_keep_their_exact_codes_messages_and_plan_identity() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let changed = observation("Review every file carefully.");
        let plan_with = |id: &AssetId, text: &str, lock: Option<&str>| {
            plan_agent_update(
                &changed,
                id,
                &expected,
                text,
                &manifest,
                lock,
                &capabilities(),
            )
        };
        let failure = |id: &AssetId, text: &str, lock: Option<&str>| {
            plan_with(id, text, lock).unwrap_err().to_string()
        };

        assert_eq!(
            failure(&asset_id, "", Some(&lock_text)),
            "agent_update.manifest_invalid: agent update planning requires a valid exact manifest"
        );
        assert_eq!(
            failure(&asset_id, &manifest_text, None),
            "agent_update.lock_not_in_sync: agent update planning requires generated lock state in sync"
        );
        assert_eq!(
            failure(&asset_id, &manifest_text, Some("{}")),
            "agent_update.lock_not_in_sync: agent update planning requires generated lock state in sync"
        );
        assert_eq!(
            failure(
                &AssetId::parse("absent").unwrap(),
                &manifest_text,
                Some(&lock_text)
            ),
            "agent_update.asset_missing: the agent asset does not exist"
        );
        // An invalid manifest is reported before a missing lock or asset.
        assert!(
            failure(&AssetId::parse("absent").unwrap(), "", None)
                .starts_with("agent_update.manifest_invalid")
        );
        // A missing lock is reported before a missing asset.
        assert!(
            failure(&AssetId::parse("absent").unwrap(), &manifest_text, None)
                .starts_with("agent_update.lock_not_in_sync")
        );

        let plan = plan_with(&asset_id, &manifest_text, Some(&lock_text)).unwrap();
        assert_eq!(
            plan.ensure_observation_fresh(&observation("Review something else."))
                .unwrap_err()
                .to_string(),
            "agent_update.observation_stale: the agent observation changed after planning"
        );
        assert_eq!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, None)
                .unwrap_err()
                .to_string(),
            "agent_update.manifest_stale: portable agent authority changed after planning"
        );
        assert_eq!(
            format!("{:?}", plan_with(&asset_id, "", None).unwrap_err()),
            "AgentUpdateError { code: \"agent_update.manifest_invalid\" }"
        );
        assert_eq!(
            plan.digest().as_str(),
            "blake3:c36b8a12f1d1f17df9fd093a3d334a5be6e43aa68761f7795f9c14f071a60095"
        );
        assert_eq!(
            plan.asset().content_hash.as_str(),
            "blake3:d19b1289031a7b74958b2e8a01236e78dbf7ac26c1022675b4f4a46e7c22244f"
        );
        assert_eq!(
            plan.proposed_manifest_revision().as_str(),
            "manifest:blake3:62737a435161218975f46d09ccf4811819fa1c37405d14f0c8d14ad93ac630d4"
        );
        assert!(format!("{plan:?}").starts_with("AgentUpdatePlan { asset_id: "));
    }
}
