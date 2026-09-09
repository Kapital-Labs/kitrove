use std::fmt::{self, Debug, Formatter};
use std::path::Path;

use kitrove_adapter_api::{AgentDiscovery, AgentTargetPolicy, TargetAnchor};
use kitrove_agents::{AgentLimits, AgentName, NativeAgentDialect, StoredAgent};
use kitrove_model::{
    AssetId, AssetKind, ContentHash, DeploymentReceipt, EnvironmentManifest, LocalState,
    NormalizedDestination, PortablePath, ReceiptId, ReceiptTarget, Revision,
};

use crate::agent_materialization::{agent_document_extension, agent_relative_destination};
use crate::authority::derive_manifest_revision;
use crate::materialization::{MaterializationError, validate_local_receipts, write_digest_record};
use crate::{AgentDestinationObservation, observe_agent_destination};

/// Complete non-mutating authority for removing one exact receipt-backed agent file.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentRemovalPlan {
    policy: AgentTargetPolicy,
    asset_id: AssetId,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    manifest_revision: Revision,
    observation: AgentDestinationObservation,
    observed_receipt: DeploymentReceipt,
    receipt_id: ReceiptId,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

impl AgentRemovalPlan {
    #[must_use]
    pub const fn policy(&self) -> &AgentTargetPolicy {
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
    pub const fn observation(&self) -> &AgentDestinationObservation {
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
        reread: &AgentDestinationObservation,
    ) -> Result<(), MaterializationError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(removal_error(
                "agent_remove.observation_stale",
                "the agent destination changed after removal planning",
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
                "agent_remove.manifest_stale",
                "manifest authority changed after agent removal planning",
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
                "agent_remove.local_state_stale",
                "machine-local receipt authority changed after agent removal planning",
            ))
        }
    }
}

impl Debug for AgentRemovalPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRemovalPlan")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("asset_id", &self.asset_id)
            .field("manifest_revision", &self.manifest_revision)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Reads a receipt-named agent destination after proving its exact policy-relative path.
pub fn observe_agent_receipt_destination(
    anchor: &Path,
    policy: &AgentTargetPolicy,
    receipt: &DeploymentReceipt,
    limits: AgentLimits,
) -> Result<AgentDestinationObservation, MaterializationError> {
    if receipt.harness != policy.harness
        || receipt.scope != policy.scope
        || receipt.target != ReceiptTarget::WholeTarget
        || !receipt.shared_with.is_empty()
    {
        return Err(removal_error(
            "agent_remove.receipt_mismatch",
            "the agent receipt does not match selected removal authority",
        ));
    }
    let extension = format!(".{}", agent_document_extension(policy.dialect));
    let name = Path::new(receipt.destination.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(&extension))
        .and_then(|name| AgentName::parse(name).ok())
        .ok_or_else(|| {
            removal_error(
                "agent_remove.destination_invalid",
                "the agent receipt destination is invalid",
            )
        })?;
    let observation = observe_agent_destination(anchor, policy, &name, limits)?;
    if observation.destination() != &receipt.destination {
        return Err(removal_error(
            "agent_remove.destination_invalid",
            "the agent receipt destination is outside selected policy authority",
        ));
    }
    Ok(observation)
}

/// Plans exact whole-file agent removal from machine-local receipt authority.
pub fn plan_agent_removal(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredAgent,
    policy: &AgentTargetPolicy,
    observation: &AgentDestinationObservation,
    local_state_text: &str,
) -> Result<AgentRemovalPlan, MaterializationError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    policy.validate().map_err(|_| invalid_policy())?;
    if observation.policy() != policy || observation.agent_name() != object.agent().name() {
        return Err(removal_error(
            "agent_remove.observation_mismatch",
            "the destination observation does not match agent removal authority",
        ));
    }
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        removal_error(
            "agent_remove.asset_missing",
            "the selected agent asset is not present",
        )
    })?;
    let portable = asset.portable.as_ref().ok_or_else(|| {
        removal_error(
            "agent_remove.portable_missing",
            "the selected asset has no portable agent authority",
        )
    })?;
    if asset.kind != AssetKind::Agent
        || portable.format != StoredAgent::format()
        || portable.object_hash != *object.object_hash()
    {
        return Err(removal_error(
            "agent_remove.asset_unsupported",
            "the selected asset cannot authorize agent removal",
        ));
    }
    let observed_hash = observation.content_hash().ok_or_else(|| {
        removal_error(
            "agent_remove.destination_missing",
            "the receipt-backed agent file is missing",
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
            "agent_remove.receipt_unavailable",
            "the destination does not have one exact managed agent receipt",
        ));
    };
    if receipt.asset_id != *asset_id
        || receipt.harness != policy.harness
        || receipt.scope != policy.scope
        || receipt.target != ReceiptTarget::WholeTarget
        || !receipt.shared_with.is_empty()
    {
        return Err(removal_error(
            "agent_remove.receipt_mismatch",
            "the agent receipt does not match selected removal authority",
        ));
    }
    if &receipt.rendered_hash != observed_hash {
        return Err(removal_error(
            "agent_remove.destination_modified",
            "the managed agent file changed after materialization",
        ));
    }
    let receipt_id = (*receipt_id).clone();
    let observed_receipt = (*receipt).clone();
    local_state.receipts.remove(&receipt_id);
    let proposed_local_state_text = local_state.to_json().map_err(|_| invalid_state())?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?;
    let relative_destination = agent_relative_destination(policy, observation.agent_name())?;
    let digest = removal_digest(
        asset_id,
        policy,
        observation,
        observed_hash,
        &receipt_id,
        &manifest_revision,
        local_state_text,
        &proposed_local_state_text,
    );
    Ok(AgentRemovalPlan {
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

#[allow(clippy::too_many_arguments)]
fn removal_digest(
    asset_id: &AssetId,
    policy: &AgentTargetPolicy,
    observation: &AgentDestinationObservation,
    observed_hash: &ContentHash,
    receipt_id: &ReceiptId,
    manifest_revision: &Revision,
    observed_state: &str,
    proposed_state: &str,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-agent-removal-plan-v1\0");
    for value in [
        asset_id.as_str(),
        policy.harness.as_str(),
        policy.scope.as_str(),
        policy.policy_line.as_str(),
        policy.relative_root.as_str(),
        policy.adapter_version,
        policy.evidence.as_str(),
        observation.destination().as_str(),
        observation.agent_name().as_str(),
        observed_hash.as_str(),
        receipt_id.as_str(),
        manifest_revision.as_str(),
        ContentHash::digest(observed_state.as_bytes()).as_str(),
        ContentHash::digest(proposed_state.as_bytes()).as_str(),
    ] {
        write_digest_record(&mut hasher, value);
    }
    hasher.update(&[match policy.anchor {
        TargetAnchor::Scope => 0,
        TargetAnchor::HarnessConfiguration => 1,
    }]);
    hasher.update(&[match policy.discovery {
        AgentDiscovery::DirectFiles => 0,
        AgentDiscovery::Recursive => 1,
    }]);
    hasher.update(&[match policy.dialect {
        NativeAgentDialect::ClaudeCurrent => 0,
        NativeAgentDialect::CodexCurrent => 1,
        NativeAgentDialect::OpenCodeCurrent => 2,
    }]);
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

const fn removal_error(code: &'static str, message: &'static str) -> MaterializationError {
    MaterializationError::new(code, message)
}

const fn invalid_policy() -> MaterializationError {
    removal_error(
        "agent_remove.policy_invalid",
        "agent target policy is invalid",
    )
}

const fn invalid_manifest() -> MaterializationError {
    removal_error(
        "agent_remove.manifest_invalid",
        "manifest authority is invalid",
    )
}

const fn invalid_state() -> MaterializationError {
    removal_error(
        "agent_remove.local_state_invalid",
        "machine-local receipt authority is invalid",
    )
}
