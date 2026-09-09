use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_agents::{StoredAgent, StoredNativeAgent};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, Lockfile, Revision, SchemaVersion,
};

use crate::adoption::content_addressed_update_root;
use crate::whole_file_adoption::{self, UpdateDigestInput};
use crate::{
    AgentAdoptionOutcome, AgentObservation, LockStatus, TierOneAgentCapabilities, compare_lockfile,
    derive_lockfile, derive_manifest_revision, plan_agent_adoption,
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
        let revision = derive_manifest_revision(manifest)
            .map_err(|_| update_error("agent_update.manifest_stale"))?;
        if ContentHash::digest(manifest_text.as_bytes()) != self.base_manifest_hash
            || revision != self.base_manifest_revision
            || manifest
                .assets
                .get(&self.asset.id)
                .map(|asset| &asset.content_hash)
                != Some(&self.expected_prior)
            || lock_text != Some(self.observed_lock_text.as_str())
            || compare_lockfile(manifest, lock_text).map(|comparison| comparison.status())
                != Ok(LockStatus::InSync)
        {
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
    manifest
        .validate()
        .map_err(|_| update_error("agent_update.manifest_invalid"))?;
    if EnvironmentManifest::from_toml(manifest_text).as_ref() != Ok(manifest) {
        return Err(update_error("agent_update.manifest_invalid"));
    }
    let base_manifest_hash = ContentHash::digest(manifest_text.as_bytes());
    let base_manifest_revision = derive_manifest_revision(manifest)
        .map_err(|_| update_error("agent_update.manifest_invalid"))?;
    let observed_lock_text = lock_text
        .filter(|text| {
            compare_lockfile(manifest, Some(text)).map(|comparison| comparison.status())
                == Ok(LockStatus::InSync)
        })
        .ok_or_else(|| update_error("agent_update.lock_not_in_sync"))?
        .to_owned();
    let prior_asset = manifest
        .assets
        .get(asset_id)
        .filter(|asset| asset.kind == AssetKind::Agent)
        .ok_or_else(|| update_error("agent_update.asset_missing"))?;
    if &prior_asset.content_hash != expected_prior {
        return Err(update_error("agent_update.expected_prior_mismatch"));
    }

    let empty = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let AgentAdoptionOutcome::Ready(candidate) =
        plan_agent_adoption(observation, asset_id, &empty, capabilities)
            .map_err(|_| update_error("agent_update.derivation_failed"))?
    else {
        return Err(update_error("agent_update.content_blocked"));
    };
    let portable_object = candidate.portable_object().clone();
    let native_object = candidate.native_object().clone();
    if whole_file_adoption::same_adopted_authority(prior_asset, candidate.asset()) {
        return Err(update_error("agent_update.revision_unchanged"));
    }
    let mut asset = candidate.asset().clone();
    let portable = asset
        .portable
        .as_mut()
        .ok_or_else(|| update_error("agent_update.derivation_failed"))?;
    portable.root = content_addressed_update_root(asset_id, None, &portable.object_hash)
        .map_err(|_| update_error("agent_update.object_path_invalid"))?;
    let native = asset
        .native_variants
        .get_mut(observation.harness())
        .ok_or_else(|| update_error("agent_update.derivation_failed"))?;
    native.root =
        content_addressed_update_root(asset_id, Some(observation.harness()), &native.object_hash)
            .map_err(|_| update_error("agent_update.object_path_invalid"))?;
    asset.refresh_content_hash();

    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .assets
        .insert(asset_id.clone(), asset.clone());
    proposed_manifest
        .validate()
        .map_err(|_| update_error("agent_update.proposed_manifest_invalid"))?;
    let proposed_lock = derive_lockfile(&proposed_manifest)
        .map_err(|_| update_error("agent_update.proposed_lock_invalid"))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| update_error("agent_update.proposed_manifest_invalid"))?;
    let digest = plan_digest(
        observation,
        asset_id,
        expected_prior,
        &asset,
        &base_manifest_hash,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &observed_lock_text,
        &proposed_lock,
    )?;

    Ok(AgentUpdatePlan {
        observation: observation.clone(),
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
        digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn plan_digest(
    observation: &AgentObservation,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    asset: &Asset,
    base_manifest_hash: &ContentHash,
    base_revision: &Revision,
    proposed_revision: &Revision,
    observed_lock: &str,
    proposed_lock: &Lockfile,
) -> Result<ContentHash, AgentUpdateError> {
    whole_file_adoption::update_digest(UpdateDigestInput {
        domain: b"kitrove-agent-update-plan-v1\0",
        observation_identity: observation.identity(),
        asset_id,
        expected_prior,
        asset,
        base_manifest_hash,
        base_revision,
        proposed_revision,
        observed_lock,
        proposed_lock,
    })
    .map_err(|()| update_error("agent_update.plan_digest_failed"))
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
}
