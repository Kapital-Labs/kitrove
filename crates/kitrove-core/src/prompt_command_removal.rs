use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_adapter_api::PromptCommandTargetPolicy;
use kitrove_model::{
    AssetId, AssetKind, ContentHash, DeploymentReceipt, EnvironmentManifest, LocalState,
    NormalizedDestination, PortablePath, ReceiptId, ReceiptTarget, Revision,
};
use kitrove_prompt_commands::{PromptCommandLimits, PromptCommandName, StoredPromptCommand};

use crate::authority::derive_manifest_revision;
use crate::materialization::{
    MaterializationError, ReceiptClaimFailure, claim_whole_target_receipt, finish_digest,
    whole_file_removal_hasher,
};
use crate::prompt_command_materialization::{
    PromptCommandDestinationObservation, observe_prompt_command_destination,
};

/// Complete non-mutating authority for removing one exact receipt-backed command file.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandRemovalPlan {
    policy: PromptCommandTargetPolicy,
    asset_id: AssetId,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    manifest_revision: Revision,
    observation: PromptCommandDestinationObservation,
    observed_receipt: DeploymentReceipt,
    receipt_id: ReceiptId,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

impl PromptCommandRemovalPlan {
    #[must_use]
    pub const fn policy(&self) -> &PromptCommandTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    #[must_use]
    pub const fn relative_destination(&self) -> &PortablePath {
        &self.relative_destination
    }

    #[must_use]
    pub const fn manifest_revision(&self) -> &Revision {
        &self.manifest_revision
    }

    #[must_use]
    pub const fn observation(&self) -> &PromptCommandDestinationObservation {
        &self.observation
    }

    #[must_use]
    pub const fn observed_receipt(&self) -> &DeploymentReceipt {
        &self.observed_receipt
    }

    #[must_use]
    pub const fn receipt_id(&self) -> &ReceiptId {
        &self.receipt_id
    }

    #[must_use]
    pub const fn proposed_local_state(&self) -> &LocalState {
        &self.proposed_local_state
    }

    pub(crate) fn observed_local_state_text(&self) -> &str {
        &self.observed_local_state_text
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    pub fn ensure_observation_fresh(
        &self,
        reread: &PromptCommandDestinationObservation,
    ) -> Result<(), MaterializationError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(removal_error(
                "command_remove.observation_stale",
                "the prompt-command destination changed after removal planning",
            ))
        }
    }

    pub fn ensure_manifest_fresh(
        &self,
        manifest: &EnvironmentManifest,
    ) -> Result<(), MaterializationError> {
        if derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?
            == self.manifest_revision
        {
            Ok(())
        } else {
            Err(removal_error(
                "command_remove.manifest_stale",
                "manifest authority changed after prompt-command removal planning",
            ))
        }
    }

    pub fn ensure_local_state_fresh(
        &self,
        local_state_text: &str,
    ) -> Result<(), MaterializationError> {
        if local_state_text == self.observed_local_state_text {
            Ok(())
        } else {
            Err(removal_error(
                "command_remove.local_state_stale",
                "machine-local receipt authority changed after prompt-command removal planning",
            ))
        }
    }
}

impl Debug for PromptCommandRemovalPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandRemovalPlan")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("asset_id", &self.asset_id)
            .field("manifest_revision", &self.manifest_revision)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Reads the exact whole-file destination named by a receipt after proving its policy-relative path.
pub fn observe_prompt_command_receipt_destination(
    anchor: &Path,
    policy: &PromptCommandTargetPolicy,
    receipt: &DeploymentReceipt,
    limits: PromptCommandLimits,
) -> Result<PromptCommandDestinationObservation, MaterializationError> {
    if receipt.harness != policy.harness
        || receipt.scope != policy.scope
        || receipt.target != ReceiptTarget::WholeTarget
        || !receipt.shared_with.is_empty()
    {
        return Err(removal_error(
            "command_remove.receipt_mismatch",
            "the prompt-command receipt does not match selected removal authority",
        ));
    }
    let name = Path::new(receipt.destination.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".md"))
        .and_then(|name| PromptCommandName::parse(name).ok())
        .ok_or_else(|| {
            removal_error(
                "command_remove.destination_invalid",
                "the prompt-command receipt destination is invalid",
            )
        })?;
    let observation = observe_prompt_command_destination(anchor, policy, &name, limits)?;
    if observation.destination() != &receipt.destination {
        return Err(removal_error(
            "command_remove.destination_invalid",
            "the prompt-command receipt destination is outside selected policy authority",
        ));
    }
    Ok(observation)
}

/// Plans exact whole-file removal from machine-local receipt authority.
pub fn plan_prompt_command_removal(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredPromptCommand,
    policy: &PromptCommandTargetPolicy,
    observation: &PromptCommandDestinationObservation,
    local_state_text: &str,
) -> Result<PromptCommandRemovalPlan, MaterializationError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    policy.validate().map_err(|_| invalid_policy())?;
    if observation.policy() != policy {
        return Err(removal_error(
            "command_remove.observation_mismatch",
            "the destination observation does not match command removal authority",
        ));
    }
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        removal_error(
            "command_remove.asset_missing",
            "the selected prompt-command asset is not present",
        )
    })?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        removal_error(
            "command_remove.portable_missing",
            "the selected asset has no portable prompt-command authority",
        )
    })?;
    if asset.kind != AssetKind::Command
        || portable.format != StoredPromptCommand::format()
        || portable.object_hash != *object.object_hash()
    {
        return Err(removal_error(
            "command_remove.asset_unsupported",
            "the selected asset cannot authorize prompt-command removal",
        ));
    }
    let observed_hash = observation.content_hash().ok_or_else(|| {
        removal_error(
            "command_remove.destination_missing",
            "the receipt-backed prompt-command file is missing",
        )
    })?;
    let claim = claim_whole_target_receipt(
        local_state_text,
        observation.destination(),
        asset_id,
        &policy.harness,
        policy.scope,
        observed_hash,
    )
    .map_err(|failure| match failure {
        ReceiptClaimFailure::StateInvalid => invalid_state(),
        ReceiptClaimFailure::Unavailable => removal_error(
            "command_remove.receipt_unavailable",
            "the destination does not have one exact managed prompt-command receipt",
        ),
        ReceiptClaimFailure::Mismatch => removal_error(
            "command_remove.receipt_mismatch",
            "the prompt-command receipt does not match selected removal authority",
        ),
        ReceiptClaimFailure::Modified => removal_error(
            "command_remove.destination_modified",
            "the managed prompt-command file changed after materialization",
        ),
    })?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?;
    let relative_destination = PortablePath::parse(format!(
        "{}/{}.md",
        policy.relative_root.as_str(),
        observation.command_name().as_str()
    ))
    .map_err(|_| {
        removal_error(
            "command_remove.destination_invalid",
            "the prompt-command removal destination is invalid",
        )
    })?;
    let digest = finish_digest(&whole_file_removal_hasher(
        b"kitrove-prompt-command-removal-plan-v1\0",
        &[
            asset_id.as_str(),
            policy.harness.as_str(),
            policy.scope.as_str(),
            policy.policy_line.as_str(),
            policy.relative_root.as_str(),
            policy.adapter_version,
            policy.evidence.as_str(),
            observation.destination().as_str(),
            observation.command_name().as_str(),
            observed_hash.as_str(),
            claim.receipt_id.as_str(),
            manifest_revision.as_str(),
            ContentHash::digest(local_state_text.as_bytes()).as_str(),
            ContentHash::digest(claim.proposed_state_text.as_bytes()).as_str(),
        ],
        policy.anchor,
    ));
    Ok(PromptCommandRemovalPlan {
        policy: policy.clone(),
        asset_id: asset_id.clone(),
        destination: observation.destination().clone(),
        relative_destination,
        manifest_revision,
        observation: observation.clone(),
        observed_receipt: claim.receipt,
        receipt_id: claim.receipt_id,
        proposed_local_state: claim.proposed_state,
        observed_local_state_text: local_state_text.to_owned(),
        digest,
    })
}

const fn removal_error(code: &'static str, message: &'static str) -> MaterializationError {
    MaterializationError::new(code, message)
}

const fn invalid_policy() -> MaterializationError {
    removal_error(
        "command_remove.policy_invalid",
        "prompt-command removal policy is invalid",
    )
}

const fn invalid_manifest() -> MaterializationError {
    removal_error(
        "command_remove.manifest_invalid",
        "manifest authority is invalid for prompt-command removal",
    )
}

const fn invalid_state() -> MaterializationError {
    removal_error(
        "command_remove.local_state_invalid",
        "machine-local receipt authority is invalid for prompt-command removal",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kitrove_adapter_api::TargetAnchor;
    use kitrove_agent_skills::CaptureLimits;
    use kitrove_model::HarnessId;

    use super::*;
    use crate::prompt_command_materialization::AtomicPromptCommandFixture;

    #[test]
    fn removal_planning_keeps_exact_failures_order_and_plan_identity() {
        let fixture = AtomicPromptCommandFixture::new();
        let observe = || {
            observe_prompt_command_destination(
                &fixture.target,
                &fixture.policy,
                fixture.object.command().name(),
                PromptCommandLimits::default(),
            )
            .unwrap()
        };
        let read_state = || fs::read_to_string(fixture.state.join("state.json")).unwrap();
        let plan_with =
            |asset_id: &AssetId, observation: &PromptCommandDestinationObservation, state: &str| {
                plan_prompt_command_removal(
                    &fixture.manifest,
                    asset_id,
                    &fixture.object,
                    &fixture.policy,
                    observation,
                    state,
                )
            };
        let failure =
            |asset_id: &AssetId, observation: &PromptCommandDestinationObservation, state: &str| {
                let error = plan_with(asset_id, observation, state).unwrap_err();
                format!("{}: {}", error.code(), error.message())
            };
        let absent_asset = AssetId::parse("absent").unwrap();
        let unreceipted_state = read_state();

        // Before installation nothing is at the destination.
        let missing = observe();
        assert_eq!(
            failure(&fixture.asset_id, &missing, &unreceipted_state),
            "command_remove.destination_missing: the receipt-backed prompt-command file is missing"
        );
        // A missing asset is reported before a missing destination.
        assert_eq!(
            failure(&absent_asset, &missing, &unreceipted_state),
            "command_remove.asset_missing: the selected prompt-command asset is not present"
        );

        crate::commit_atomic_apply_batch(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        let installed = observe();
        let state = read_state();

        // Invalid local state is reported before any receipt lookup.
        assert_eq!(
            failure(&fixture.asset_id, &installed, "{"),
            "command_remove.local_state_invalid: machine-local receipt authority is invalid for prompt-command removal"
        );
        assert_eq!(
            failure(&fixture.asset_id, &installed, &unreceipted_state),
            "command_remove.receipt_unavailable: the destination does not have one exact managed prompt-command receipt"
        );

        // Receipt validation rejects a shared whole-target receipt before lookup.
        let mut foreign = LocalState::from_json(&state).unwrap();
        for receipt in foreign.receipts.values_mut() {
            receipt.shared_with.insert(HarnessId::Pi);
        }
        assert_eq!(
            failure(&fixture.asset_id, &installed, &foreign.to_json().unwrap()),
            "command_remove.local_state_invalid: machine-local receipt authority is invalid for prompt-command removal"
        );

        let mut reassigned = LocalState::from_json(&state).unwrap();
        for receipt in reassigned.receipts.values_mut() {
            receipt.asset_id = absent_asset.clone();
            receipt.rendered_hash = ContentHash::digest(b"another rendering");
        }
        // A receipt for another asset is reported before changed bytes.
        assert_eq!(
            failure(
                &fixture.asset_id,
                &installed,
                &reassigned.to_json().unwrap()
            ),
            "command_remove.local_state_invalid: machine-local receipt authority is invalid for prompt-command removal"
        );

        let mut restamped = LocalState::from_json(&state).unwrap();
        for receipt in restamped.receipts.values_mut() {
            receipt.rendered_hash = ContentHash::digest(b"another rendering");
        }
        assert_eq!(
            failure(&fixture.asset_id, &installed, &restamped.to_json().unwrap()),
            "command_remove.destination_modified: the managed prompt-command file changed after materialization"
        );

        let plan = plan_with(&fixture.asset_id, &installed, &state).unwrap();
        let observed = LocalState::from_json(&state).unwrap();
        let (receipt_id, receipt) = observed.receipts.iter().next().unwrap();
        assert_eq!(observed.receipts.len(), 1);
        assert_eq!(plan.receipt_id(), receipt_id);
        assert_eq!(plan.observed_receipt(), receipt);
        assert!(plan.proposed_local_state().receipts.is_empty());
        assert_eq!(plan.destination(), installed.destination());
        assert_eq!(plan.asset_id(), &fixture.asset_id);
        assert_eq!(
            plan.manifest_revision(),
            &derive_manifest_revision(&fixture.manifest).unwrap()
        );

        let policy = &fixture.policy;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-prompt-command-removal-plan-v1\0");
        for value in [
            fixture.asset_id.as_str(),
            policy.harness.as_str(),
            policy.scope.as_str(),
            policy.policy_line.as_str(),
            policy.relative_root.as_str(),
            policy.adapter_version,
            policy.evidence.as_str(),
            installed.destination().as_str(),
            installed.command_name().as_str(),
            installed.content_hash().unwrap().as_str(),
            receipt_id.as_str(),
            plan.manifest_revision().as_str(),
            ContentHash::digest(state.as_bytes()).as_str(),
            ContentHash::digest(plan.proposed_local_state().to_json().unwrap().as_bytes()).as_str(),
        ] {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update(&[match policy.anchor {
            TargetAnchor::Scope => 0,
            TargetAnchor::HarnessConfiguration => 1,
        }]);
        assert_eq!(
            plan.digest().as_str(),
            format!("blake3:{}", hasher.finalize().to_hex())
        );

        let stale = |error: MaterializationError| format!("{}: {}", error.code(), error.message());
        assert_eq!(
            stale(plan.ensure_observation_fresh(&missing).unwrap_err()),
            "command_remove.observation_stale: the prompt-command destination changed after removal planning"
        );
        assert_eq!(
            stale(
                plan.ensure_local_state_fresh(&unreceipted_state)
                    .unwrap_err()
            ),
            "command_remove.local_state_stale: machine-local receipt authority changed after prompt-command removal planning"
        );
        assert!(plan.ensure_observation_fresh(&installed).is_ok());
        assert!(plan.ensure_local_state_fresh(&state).is_ok());
        assert!(plan.ensure_manifest_fresh(&fixture.manifest).is_ok());
    }
}
