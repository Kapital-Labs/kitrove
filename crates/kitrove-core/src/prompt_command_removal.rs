use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_adapter_api::{PromptCommandTargetPolicy, TargetAnchor};
use kitrove_model::{
    AssetId, AssetKind, ContentHash, DeploymentReceipt, EnvironmentManifest, LocalState,
    NormalizedDestination, PortablePath, ReceiptId, ReceiptTarget, Revision,
};
use kitrove_prompt_commands::{PromptCommandLimits, PromptCommandName, StoredPromptCommand};

use crate::authority::derive_manifest_revision;
use crate::materialization::{MaterializationError, validate_local_receipts, write_digest_record};
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
    let mut local_state = LocalState::from_json(local_state_text).map_err(|_| invalid_state())?;
    validate_local_receipts(&local_state).map_err(|_| invalid_state())?;
    let matching = local_state
        .receipts
        .iter()
        .filter(|(_, receipt)| receipt.destination == *observation.destination())
        .collect::<Vec<_>>();
    let [(receipt_id, receipt)] = matching.as_slice() else {
        return Err(removal_error(
            "command_remove.receipt_unavailable",
            "the destination does not have one exact managed prompt-command receipt",
        ));
    };
    if receipt.asset_id != *asset_id
        || receipt.harness != policy.harness
        || receipt.scope != policy.scope
        || receipt.target != ReceiptTarget::WholeTarget
        || !receipt.shared_with.is_empty()
    {
        return Err(removal_error(
            "command_remove.receipt_mismatch",
            "the prompt-command receipt does not match selected removal authority",
        ));
    }
    if &receipt.rendered_hash != observed_hash {
        return Err(removal_error(
            "command_remove.destination_modified",
            "the managed prompt-command file changed after materialization",
        ));
    }
    let receipt_id = (*receipt_id).clone();
    let observed_receipt = (*receipt).clone();
    local_state.receipts.remove(&receipt_id);
    let proposed_local_state_text = local_state.to_json().map_err(|_| invalid_state())?;
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
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-prompt-command-removal-plan-v1\0");
    for value in [
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
        receipt_id.as_str(),
        manifest_revision.as_str(),
        ContentHash::digest(local_state_text.as_bytes()).as_str(),
        ContentHash::digest(proposed_local_state_text.as_bytes()).as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    hasher.update(&[match policy.anchor {
        TargetAnchor::Scope => 0,
        TargetAnchor::HarnessConfiguration => 1,
    }]);
    let digest = ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash");
    Ok(PromptCommandRemovalPlan {
        policy: policy.clone(),
        asset_id: asset_id.clone(),
        destination: observation.destination().clone(),
        relative_destination,
        manifest_revision,
        observation: observation.clone(),
        observed_receipt,
        receipt_id,
        proposed_local_state: local_state,
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
