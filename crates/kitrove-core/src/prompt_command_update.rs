use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, Lockfile, Revision, SchemaVersion,
};
use kitrove_prompt_commands::{
    StoredNativePromptCommand as StoredNativePromptObject,
    StoredPromptCommand as StoredPromptObject,
};

use crate::adoption::content_addressed_update_root;
use crate::whole_file_adoption::{self, UpdateDigestInput};
use crate::{
    LockStatus, PromptCommandAdoptionOutcome, PromptCommandObservation,
    TierOnePromptCommandCapabilities, compare_lockfile, derive_lockfile, derive_manifest_revision,
    plan_prompt_command_adoption,
};

/// Complete deterministic prompt-command replacement authority that performs no writes.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandUpdatePlan {
    observation: PromptCommandObservation,
    expected_prior: ContentHash,
    prior_asset: Asset,
    asset: Asset,
    portable_object: StoredPromptObject,
    native_object: StoredNativePromptObject,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    observed_lock_text: String,
    base_manifest_hash: ContentHash,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl PromptCommandUpdatePlan {
    #[must_use]
    pub const fn observation(&self) -> &PromptCommandObservation {
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
        reread: &PromptCommandObservation,
    ) -> Result<(), PromptCommandUpdateError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(update_error("prompt_command_update.observation_stale"))
        }
    }

    pub fn ensure_portable_authority_fresh(
        &self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), PromptCommandUpdateError> {
        let revision = derive_manifest_revision(manifest)
            .map_err(|_| update_error("prompt_command_update.manifest_stale"))?;
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
            return Err(update_error("prompt_command_update.manifest_stale"));
        }
        Ok(())
    }
}

impl Debug for PromptCommandUpdatePlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandUpdatePlan")
            .field("asset_id", &self.asset.id)
            .field("observation_identity", &self.observation.identity())
            .field("expected_prior", &self.expected_prior)
            .field("proposed_revision", &self.asset.content_hash)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Stable, authored-value-redacted prompt-command update failure.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandUpdateError {
    code: &'static str,
    message: &'static str,
}

impl PromptCommandUpdateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PromptCommandUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandUpdateError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for PromptCommandUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for PromptCommandUpdateError {}

/// Plans replacement of exactly one adopted prompt command without mutating state.
#[allow(clippy::too_many_arguments)]
pub fn plan_prompt_command_update(
    observation: &PromptCommandObservation,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    manifest_text: &str,
    manifest: &EnvironmentManifest,
    lock_text: Option<&str>,
    capabilities: &TierOnePromptCommandCapabilities,
) -> Result<PromptCommandUpdatePlan, PromptCommandUpdateError> {
    manifest
        .validate()
        .map_err(|_| update_error("prompt_command_update.manifest_invalid"))?;
    if EnvironmentManifest::from_toml(manifest_text).as_ref() != Ok(manifest) {
        return Err(update_error("prompt_command_update.manifest_invalid"));
    }
    let base_manifest_hash = ContentHash::digest(manifest_text.as_bytes());
    let base_manifest_revision = derive_manifest_revision(manifest)
        .map_err(|_| update_error("prompt_command_update.manifest_invalid"))?;
    let observed_lock_text = lock_text
        .filter(|text| {
            compare_lockfile(manifest, Some(text)).map(|comparison| comparison.status())
                == Ok(LockStatus::InSync)
        })
        .ok_or_else(|| update_error("prompt_command_update.lock_not_in_sync"))?
        .to_owned();
    let prior_asset = manifest
        .assets
        .get(asset_id)
        .filter(|asset| asset.kind == AssetKind::Command)
        .ok_or_else(|| update_error("prompt_command_update.asset_missing"))?;
    if &prior_asset.content_hash != expected_prior {
        return Err(update_error(
            "prompt_command_update.expected_prior_mismatch",
        ));
    }

    let empty = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let PromptCommandAdoptionOutcome::Ready(candidate) =
        plan_prompt_command_adoption(observation, asset_id, &empty, capabilities)
            .map_err(|_| update_error("prompt_command_update.derivation_failed"))?
    else {
        return Err(update_error("prompt_command_update.content_blocked"));
    };
    let portable_object = candidate.portable_object().clone();
    let native_object = candidate.native_object().clone();
    if whole_file_adoption::same_adopted_authority(prior_asset, candidate.asset()) {
        return Err(update_error("prompt_command_update.revision_unchanged"));
    }
    let mut asset = candidate.asset().clone();
    let portable = asset
        .portable
        .as_mut()
        .ok_or_else(|| update_error("prompt_command_update.derivation_failed"))?;
    portable.root = content_addressed_update_root(asset_id, None, &portable.object_hash)
        .map_err(|_| update_error("prompt_command_update.object_path_invalid"))?;
    let native = asset
        .native_variants
        .get_mut(observation.harness())
        .ok_or_else(|| update_error("prompt_command_update.derivation_failed"))?;
    native.root =
        content_addressed_update_root(asset_id, Some(observation.harness()), &native.object_hash)
            .map_err(|_| update_error("prompt_command_update.object_path_invalid"))?;
    asset.refresh_content_hash();

    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .assets
        .insert(asset_id.clone(), asset.clone());
    proposed_manifest
        .validate()
        .map_err(|_| update_error("prompt_command_update.proposed_manifest_invalid"))?;
    let proposed_lock = derive_lockfile(&proposed_manifest)
        .map_err(|_| update_error("prompt_command_update.proposed_lock_invalid"))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| update_error("prompt_command_update.proposed_manifest_invalid"))?;
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

    Ok(PromptCommandUpdatePlan {
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
    observation: &PromptCommandObservation,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    asset: &Asset,
    base_manifest_hash: &ContentHash,
    base_revision: &Revision,
    proposed_revision: &Revision,
    observed_lock: &str,
    proposed_lock: &Lockfile,
) -> Result<ContentHash, PromptCommandUpdateError> {
    whole_file_adoption::update_digest(UpdateDigestInput {
        domain: b"kitrove-prompt-command-update-plan-v1\0",
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
    .map_err(|()| update_error("prompt_command_update.plan_digest_failed"))
}

fn update_error(code: &'static str) -> PromptCommandUpdateError {
    let message = match code {
        "prompt_command_update.manifest_invalid" => {
            "prompt-command update planning requires a valid exact manifest"
        }
        "prompt_command_update.lock_not_in_sync" => {
            "prompt-command update planning requires generated lock state in sync"
        }
        "prompt_command_update.asset_missing" => "the prompt-command asset does not exist",
        "prompt_command_update.expected_prior_mismatch" => {
            "the expected prior prompt-command revision is stale"
        }
        "prompt_command_update.content_blocked" => {
            "the prompt-command update content requires review"
        }
        "prompt_command_update.derivation_failed" => {
            "the prompt-command update could not be derived"
        }
        "prompt_command_update.revision_unchanged" => {
            "the prompt-command update does not change stored content"
        }
        "prompt_command_update.object_path_invalid" => {
            "the prompt-command update object path is invalid"
        }
        "prompt_command_update.proposed_manifest_invalid" => {
            "the proposed prompt-command manifest is invalid"
        }
        "prompt_command_update.proposed_lock_invalid" => {
            "the proposed prompt-command lock is invalid"
        }
        "prompt_command_update.plan_digest_failed" => {
            "the prompt-command update plan digest could not be derived"
        }
        "prompt_command_update.observation_stale" => {
            "the prompt-command observation changed after planning"
        }
        "prompt_command_update.manifest_stale" => {
            "portable prompt-command authority changed after planning"
        }
        _ => "prompt-command update planning failed",
    };
    PromptCommandUpdateError { code, message }
}

#[cfg(test)]
mod tests {
    use kitrove_adapter_api::{CapabilityMatrix, RootId, RootTier};
    use kitrove_model::{
        Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId, HarnessScope,
    };
    use kitrove_prompt_commands::{
        NativePromptDialect, PromptCommandLimits, parse_native_prompt_command,
    };

    use super::*;

    fn capability(fidelity: Fidelity, version: &'static str) -> CapabilityMatrix {
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
                version,
                None,
            )
        } else {
            FidelityResult::exact(fidelity, evidence, version, None)
        }
        .unwrap();
        CapabilityMatrix::empty().with_capability(AssetKind::Command, result, vec![])
    }

    fn capabilities() -> TierOnePromptCommandCapabilities {
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

    fn observation(body: &str) -> PromptCommandObservation {
        scoped_observation(
            HarnessScope::Project,
            RootTier::Project,
            "pi.project.prompts",
            body,
        )
    }

    fn scoped_observation(
        scope: HarnessScope,
        root_tier: RootTier,
        logical_root: &str,
        body: &str,
    ) -> PromptCommandObservation {
        PromptCommandObservation::new(
            HarnessId::Pi,
            scope,
            root_tier,
            RootId::parse(logical_root).unwrap(),
            30,
            parse_native_prompt_command(
                NativePromptDialect::PiLatest,
                "review.md",
                body.as_bytes(),
                PromptCommandLimits::default(),
            )
            .unwrap(),
        )
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
        let PromptCommandAdoptionOutcome::Ready(plan) = plan_prompt_command_adoption(
            &observation("Review $ARGUMENTS.\n"),
            &asset_id,
            &empty,
            &capabilities(),
        )
        .unwrap() else {
            panic!("first adoption must be ready");
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
        let changed = observation("Review all files in $ARGUMENTS.\n");
        let plan = plan_prompt_command_update(
            &changed,
            &asset_id,
            &expected,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &capabilities(),
        )
        .unwrap();

        assert_eq!(plan.expected_prior(), &expected);
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
            plan.asset().native_variants[&HarnessId::Pi]
                .root
                .as_str()
                .contains("updates/native/pi/blake3-")
        );
        assert!(plan.ensure_observation_fresh(&changed).is_ok());
        assert!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, Some(&lock_text))
                .is_ok()
        );
        assert!(!format!("{plan:?}").contains("Review all files"));
    }

    #[test]
    fn unchanged_content_and_stale_authority_are_rejected() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        assert_eq!(
            plan_prompt_command_update(
                &observation("Review $ARGUMENTS.\n"),
                &asset_id,
                &expected,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities(),
            )
            .unwrap_err()
            .code(),
            "prompt_command_update.revision_unchanged"
        );

        let stale = ContentHash::digest(b"stale prior");
        assert_eq!(
            plan_prompt_command_update(
                &observation("Review changed $ARGUMENTS.\n"),
                &asset_id,
                &stale,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities(),
            )
            .unwrap_err()
            .code(),
            "prompt_command_update.expected_prior_mismatch"
        );
    }

    #[test]
    fn planned_freshness_binds_exact_manifest_lock_and_observation() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let changed = observation("Review changed $ARGUMENTS.\n");
        let plan = plan_prompt_command_update(
            &changed,
            &asset_id,
            &expected,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &capabilities(),
        )
        .unwrap();

        assert_eq!(
            plan.ensure_observation_fresh(&observation("Different $ARGUMENTS.\n"))
                .unwrap_err()
                .code(),
            "prompt_command_update.observation_stale"
        );
        assert_eq!(
            plan.ensure_portable_authority_fresh(
                &format!("{manifest_text}\n"),
                &manifest,
                Some(&lock_text),
            )
            .unwrap_err()
            .code(),
            "prompt_command_update.manifest_stale"
        );
        assert_eq!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, None)
                .unwrap_err()
                .code(),
            "prompt_command_update.manifest_stale"
        );
    }

    #[test]
    fn an_origin_authority_change_is_not_mistaken_for_unchanged_content() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let moved = scoped_observation(
            HarnessScope::User,
            RootTier::User,
            "pi.user.prompts",
            "Review $ARGUMENTS.\n",
        );
        let plan = plan_prompt_command_update(
            &moved,
            &asset_id,
            &expected,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &capabilities(),
        )
        .unwrap();

        assert_ne!(plan.asset().provenance, plan.prior_asset().provenance);
        assert_ne!(plan.asset().content_hash, expected);
    }
}
