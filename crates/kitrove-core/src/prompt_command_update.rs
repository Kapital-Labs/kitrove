use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, EnvironmentManifest, Lockfile, Revision,
};
use kitrove_prompt_commands::{
    StoredNativePromptCommand as StoredNativePromptObject,
    StoredPromptCommand as StoredPromptObject,
};

use crate::whole_file_adoption::{self, UpdateFailure};
use crate::{
    PromptCommandAdoptionOutcome, PromptCommandObservation, TierOnePromptCommandCapabilities,
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
    let base = whole_file_adoption::update_base(
        AssetKind::Command,
        asset_id,
        expected_prior,
        manifest_text,
        manifest,
        lock_text,
    )
    .map_err(planning_error)?;
    let PromptCommandAdoptionOutcome::Ready(candidate) = plan_prompt_command_adoption(
        observation,
        asset_id,
        &whole_file_adoption::empty_manifest(),
        capabilities,
    )
    .map_err(|_| update_error("prompt_command_update.derivation_failed"))?
    else {
        return Err(update_error("prompt_command_update.content_blocked"));
    };
    let proposal = whole_file_adoption::propose_update(
        b"kitrove-prompt-command-update-plan-v1\0",
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

    Ok(PromptCommandUpdatePlan {
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

fn planning_error(failure: UpdateFailure) -> PromptCommandUpdateError {
    update_error(match failure {
        UpdateFailure::ManifestInvalid => "prompt_command_update.manifest_invalid",
        UpdateFailure::LockNotInSync => "prompt_command_update.lock_not_in_sync",
        UpdateFailure::AssetMissing => "prompt_command_update.asset_missing",
        UpdateFailure::ExpectedPriorMismatch => "prompt_command_update.expected_prior_mismatch",
        UpdateFailure::DerivationFailed => "prompt_command_update.derivation_failed",
        UpdateFailure::RevisionUnchanged => "prompt_command_update.revision_unchanged",
        UpdateFailure::ObjectPathInvalid => "prompt_command_update.object_path_invalid",
        UpdateFailure::ProposedManifestInvalid => "prompt_command_update.proposed_manifest_invalid",
        UpdateFailure::ProposedLockInvalid => "prompt_command_update.proposed_lock_invalid",
        UpdateFailure::PlanDigestFailed => "prompt_command_update.plan_digest_failed",
    })
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

    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::SchemaVersion;

    use super::*;
    use crate::derive_lockfile;

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

    #[test]
    fn update_failures_keep_their_exact_codes_messages_and_plan_identity() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let changed = observation("Review all files in $ARGUMENTS.\n");
        let plan_with = |id: &AssetId, text: &str, lock: Option<&str>| {
            plan_prompt_command_update(
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
            "prompt_command_update.manifest_invalid: prompt-command update planning requires a valid exact manifest"
        );
        assert_eq!(
            failure(&asset_id, &manifest_text, None),
            "prompt_command_update.lock_not_in_sync: prompt-command update planning requires generated lock state in sync"
        );
        assert_eq!(
            failure(&asset_id, &manifest_text, Some("{}")),
            "prompt_command_update.lock_not_in_sync: prompt-command update planning requires generated lock state in sync"
        );
        assert_eq!(
            failure(
                &AssetId::parse("absent").unwrap(),
                &manifest_text,
                Some(&lock_text)
            ),
            "prompt_command_update.asset_missing: the prompt-command asset does not exist"
        );
        // An invalid manifest is reported before a missing lock or asset.
        assert!(
            failure(&AssetId::parse("absent").unwrap(), "", None)
                .starts_with("prompt_command_update.manifest_invalid")
        );
        // A missing lock is reported before a missing asset.
        assert!(
            failure(&AssetId::parse("absent").unwrap(), &manifest_text, None)
                .starts_with("prompt_command_update.lock_not_in_sync")
        );

        let plan = plan_with(&asset_id, &manifest_text, Some(&lock_text)).unwrap();
        assert_eq!(
            plan.ensure_observation_fresh(&observation("Different $ARGUMENTS.\n"))
                .unwrap_err()
                .to_string(),
            "prompt_command_update.observation_stale: the prompt-command observation changed after planning"
        );
        assert_eq!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, None)
                .unwrap_err()
                .to_string(),
            "prompt_command_update.manifest_stale: portable prompt-command authority changed after planning"
        );
        assert_eq!(
            format!("{:?}", plan_with(&asset_id, "", None).unwrap_err()),
            "PromptCommandUpdateError { code: \"prompt_command_update.manifest_invalid\" }"
        );
        assert_eq!(
            plan.digest().as_str(),
            "blake3:591f8ec26eb162c1371b5995598dfe6370faff3b06b6b04be2a4bf16ef6628f3"
        );
        assert_eq!(
            plan.asset().content_hash.as_str(),
            "blake3:88dedb91945418ec38d830f098469d4c335d1db25b0a0ae42f3d9c121147ed6f"
        );
        assert_eq!(
            plan.proposed_manifest_revision().as_str(),
            "manifest:blake3:afb58888cf1a72513d06b240abceb84f18eddb1e633bae382347372bfa5f21ed"
        );
        assert!(format!("{plan:?}").starts_with("PromptCommandUpdatePlan { asset_id: "));
    }
}
