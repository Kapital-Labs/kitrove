use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Formatter};

use serde::{Deserialize, Serialize};

use crate::{
    AssetId, BindingName, ContentHash, EnvironmentVariableName, HarnessId, HarnessScope, MachineId,
    NormalizedDestination, PackApplicationId, ProfileId, ReceiptId, Revision, SchemaVersion,
    ValidationError, is_portable_mcp_server_name,
};

const MAX_ADDITIONAL_RECEIPT_CONSUMERS: usize = 3;

/// A machine-local symbolic mechanism for resolving a binding later.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingResolver {
    Environment {
        variable: EnvironmentVariableName,
    },
    Command {
        program: String,
        arguments: Vec<String>,
    },
}

/// Machine identity, active profile, enabled targets, and observed roots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    pub id: MachineId,
    pub active_profile: Option<ProfileId>,
    #[serde(default)]
    pub enabled_targets: BTreeSet<HarnessId>,
    #[serde(default)]
    pub harness_roots: BTreeMap<HarnessId, String>,
}

/// Local evidence that Kitrove owns one materialized destination.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReceipt {
    pub asset_id: AssetId,
    pub harness: HarnessId,
    pub scope: HarnessScope,
    pub destination: NormalizedDestination,
    #[serde(default, skip_serializing_if = "ReceiptTarget::is_whole_target")]
    pub target: ReceiptTarget,
    /// Logical key owned inside a structured shared document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_key: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub shared_with: BTreeSet<HarnessId>,
    /// Exact adapter-policy versions for every additional harness consumer.
    ///
    /// The primary harness continues to use `adapter_version`. Keeping secondary policy evidence
    /// keyed by harness lets one physical managed region be revalidated independently for every
    /// consumer without changing legacy, non-shared receipt JSON.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shared_adapter_versions: BTreeMap<HarnessId, String>,
    pub source_hash: ContentHash,
    pub rendered_hash: ContentHash,
    /// Exact whole-document identity after a structured-entry mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_hash: Option<ContentHash>,
    pub prior_hash: Option<ContentHash>,
    pub adapter_version: String,
    pub environment_revision: Revision,
}

/// Logical ownership unit within a physical materialization destination.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptTarget {
    /// The receipt owns the complete file or directory at `destination`.
    #[default]
    WholeTarget,
    /// The receipt owns only the asset-keyed managed instruction region in a co-owned file.
    ManagedInstructionRegion,
    /// The receipt owns one exact logical MCP entry in a co-owned configuration document.
    ManagedMcpEntry,
}

impl ReceiptTarget {
    fn is_whole_target(&self) -> bool {
        *self == Self::WholeTarget
    }
}

impl DeploymentReceipt {
    /// Derives the stable identity for this exact materialized destination.
    pub fn receipt_id(&self) -> Result<ReceiptId, ValidationError> {
        let is_mcp_entry = self.target == ReceiptTarget::ManagedMcpEntry;
        let has_structured_authority = self.logical_key.is_some() || self.document_hash.is_some();
        if (is_mcp_entry && (self.logical_key.is_none() || self.document_hash.is_none()))
            || (!is_mcp_entry && has_structured_authority)
        {
            return Err(ValidationError::new(
                "receipt.structured_authority_invalid",
                "only managed MCP entry receipts require a logical key and document identity",
            ));
        }
        if let Some(key) = self.logical_key.as_deref() {
            if !is_portable_mcp_server_name(key) {
                return Err(ValidationError::new(
                    "receipt.logical_key_invalid",
                    "structured receipt key is not a conservative MCP identifier",
                ));
            }
        }
        if is_mcp_entry
            && (!self.shared_with.is_empty() || !self.shared_adapter_versions.is_empty())
        {
            return Err(ValidationError::new(
                "receipt.mcp_consumers_invalid",
                "one managed MCP entry receipt has exactly one harness consumer",
            ));
        }
        if self.target == ReceiptTarget::WholeTarget
            && (!self.shared_with.is_empty() || !self.shared_adapter_versions.is_empty())
        {
            return Err(ValidationError::new(
                "receipt.shared_whole_target",
                "whole-target receipts cannot declare additional harness consumers",
            ));
        }
        if self.shared_with.len() > MAX_ADDITIONAL_RECEIPT_CONSUMERS {
            return Err(ValidationError::new(
                "receipt.consumer_limit",
                "receipt declares too many additional harness consumers",
            ));
        }
        if self
            .shared_adapter_versions
            .keys()
            .ne(self.shared_with.iter())
            || self.shared_adapter_versions.values().any(String::is_empty)
        {
            return Err(ValidationError::new(
                "receipt.consumer_versions_invalid",
                "shared receipt consumers require exact adapter-policy version evidence",
            ));
        }
        if self.shared_with.contains(&self.harness)
            || self
                .shared_with
                .first()
                .is_some_and(|consumer| consumer < &self.harness)
        {
            return Err(ValidationError::new(
                "receipt.consumers_noncanonical",
                "additional receipt consumers must be unique and ordered after the primary harness",
            ));
        }

        if self.target == ReceiptTarget::WholeTarget {
            return self.whole_target_receipt_id();
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-receipt-id-v2\0");
        for field in [
            self.asset_id.as_str(),
            self.harness.as_str(),
            self.scope.as_str(),
            self.destination.as_str(),
        ] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        match self.target {
            ReceiptTarget::ManagedInstructionRegion => {
                hasher.update(b"managed_instruction_region\0");
            }
            ReceiptTarget::ManagedMcpEntry => {
                hasher.update(b"managed_mcp_entry\0");
                let key = self
                    .logical_key
                    .as_deref()
                    .expect("validated MCP receipt has a logical key");
                hasher.update(&(key.len() as u64).to_be_bytes());
                hasher.update(key.as_bytes());
            }
            ReceiptTarget::WholeTarget => unreachable!("whole target returned above"),
        }
        hasher.update(&(self.shared_with.len() as u64).to_be_bytes());
        for consumer in &self.shared_with {
            let value = consumer.as_str();
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        ReceiptId::parse(format!("receipt-{}", hasher.finalize().to_hex()))
    }

    /// Returns every harness served by this one physical materialization.
    pub fn consumers(&self) -> impl Iterator<Item = &HarnessId> {
        std::iter::once(&self.harness).chain(self.shared_with.iter())
    }

    /// Returns the adapter-policy version recorded for one served harness.
    #[must_use]
    pub fn adapter_version_for(&self, harness: &HarnessId) -> Option<&str> {
        if harness == &self.harness {
            Some(&self.adapter_version)
        } else {
            self.shared_adapter_versions
                .get(harness)
                .map(String::as_str)
        }
    }

    fn whole_target_receipt_id(&self) -> Result<ReceiptId, ValidationError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-receipt-id-v1\0");
        for field in [
            self.asset_id.as_str(),
            self.harness.as_str(),
            self.scope.as_str(),
            self.destination.as_str(),
        ] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        ReceiptId::parse(format!("receipt-{}", hasher.finalize().to_hex()))
    }
}

/// A local decision about one exact content identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustDecision {
    Trusted { rationale: String },
    Denied { rationale: String },
}

/// A non-secret summary of one read-only harness scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRecord {
    pub harness: HarnessId,
    pub observed_at: String,
    pub discovered_assets: u32,
}

/// Machine-local evidence that one exact pack application owns a set of deployment receipts.
///
/// Multiple claims may own the same receipt. A later direct or profile application removes
/// overlapping pack ownership so uninstalling a pack cannot erase independently requested work.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackApplicationClaim {
    pub pack_id: AssetId,
    pub pack_revision: ContentHash,
    pub scope: HarnessScope,
    pub target_anchor: NormalizedDestination,
    pub targets: BTreeSet<HarnessId>,
    pub receipts: BTreeSet<ReceiptId>,
}

impl fmt::Debug for PackApplicationClaim {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackApplicationClaim")
            .field("scope", &self.scope)
            .field("target_count", &self.targets.len())
            .field("receipt_count", &self.receipts.len())
            .finish_non_exhaustive()
    }
}

impl PackApplicationClaim {
    /// Derives the stable identity of this pack, scope, root, and target-set application.
    pub fn application_id(&self) -> Result<PackApplicationId, ValidationError> {
        if self.targets.is_empty() {
            return Err(ValidationError::new(
                "pack_application.empty",
                "a pack application requires at least one target",
            ));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-pack-application-id-v1\0");
        for field in [
            self.pack_id.as_str(),
            self.scope.as_str(),
            self.target_anchor.as_str(),
        ] {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update(&(self.targets.len() as u64).to_be_bytes());
        for target in &self.targets {
            let value = target.as_str();
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        PackApplicationId::parse(format!("pack-application-{}", hasher.finalize().to_hex()))
    }
}

/// The complete machine-local root, intentionally separate from portable state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalState {
    pub schema_version: SchemaVersion,
    pub machine: MachineConfig,
    #[serde(default)]
    pub bindings: BTreeMap<BindingName, BindingResolver>,
    #[serde(default)]
    pub receipts: BTreeMap<ReceiptId, DeploymentReceipt>,
    #[serde(default)]
    pub pack_applications: BTreeMap<PackApplicationId, PackApplicationClaim>,
    #[serde(default)]
    pub trust: BTreeMap<ContentHash, TrustDecision>,
    #[serde(default)]
    pub scans: Vec<ScanRecord>,
}

impl LocalState {
    /// Parses a strict machine-local JSON document.
    pub fn from_json(input: &str) -> Result<Self, ValidationError> {
        serde_json::from_str(input)
            .map_err(|error| ValidationError::new("local_state.invalid_json", error.to_string()))
    }

    /// Deterministically serializes machine-local state.
    pub fn to_json(&self) -> Result<String, ValidationError> {
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|error| ValidationError::new("local_state.serialize", error.to_string()))?;
        encoded.push('\n');
        Ok(encoded)
    }
}
