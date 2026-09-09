use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{AgentDiscovery, AgentTargetPolicy, TargetAnchor};
use kitrove_agents::{
    AgentLimits, AgentName, NativeAgentDialect, StoredAgent, render_native_agent,
};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, DeploymentReceipt, EnvironmentManifest,
    Fidelity, LocalState, NormalizedDestination, PortablePath, ReceiptTarget, Revision,
};

use crate::derive_manifest_revision;
use crate::instruction_risk::contains_credential_shaped_value;
use crate::materialization::{
    ApplyDisposition, MaterializationError, hash_exact_file_target,
    normalized_destination_from_path, validate_local_receipts, validate_target_anchor,
    write_digest_record,
};
use crate::read_only_fs::{
    ReadOnlyFileError, RegularFileMode, read_bounded_regular_file_with_mode,
};

/// Exact read-only state of one whole-file agent destination.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentDestinationObservation {
    policy: AgentTargetPolicy,
    agent_name: AgentName,
    destination: NormalizedDestination,
    content: Option<Vec<u8>>,
    content_hash: Option<ContentHash>,
    byte_count: Option<usize>,
    mode: RegularFileMode,
}

impl AgentDestinationObservation {
    #[must_use]
    pub const fn policy(&self) -> &AgentTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn agent_name(&self) -> &AgentName {
        &self.agent_name
    }

    #[must_use]
    pub const fn destination(&self) -> &NormalizedDestination {
        &self.destination
    }

    #[must_use]
    pub const fn content_hash(&self) -> Option<&ContentHash> {
        self.content_hash.as_ref()
    }

    #[must_use]
    pub const fn byte_count(&self) -> Option<usize> {
        self.byte_count
    }

    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.content.is_some()
    }

    pub(crate) fn content_text(&self) -> Option<&str> {
        self.content
            .as_deref()
            .and_then(|content| std::str::from_utf8(content).ok())
    }

    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }
}

impl Debug for AgentDestinationObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentDestinationObservation")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("policy_line", &self.policy.policy_line)
            .field("agent_name", &self.agent_name)
            .field("present", &self.is_present())
            .field("content_hash", &self.content_hash)
            .field("byte_count", &self.byte_count)
            .finish()
    }
}

/// Exact inert native output produced by pure agent rendering.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedAgent {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    mode: RegularFileMode,
}

impl RenderedAgent {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn content_hash(&self) -> &ContentHash {
        &self.content_hash
    }

    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }
}

impl Debug for RenderedAgent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedAgent")
            .field("byte_count", &self.bytes.len())
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

/// Complete non-mutating plan for one receipt-backed agent file.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentApplyPlan {
    policy: AgentTargetPolicy,
    asset_id: AssetId,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    manifest_revision: Revision,
    disposition: ApplyDisposition,
    observation: AgentDestinationObservation,
    rendered: RenderedAgent,
    observed_receipt: Option<DeploymentReceipt>,
    proposed_receipt: DeploymentReceipt,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

impl AgentApplyPlan {
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
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn observation(&self) -> &AgentDestinationObservation {
        &self.observation
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedAgent {
        &self.rendered
    }

    #[must_use]
    pub const fn observed_receipt(&self) -> Option<&DeploymentReceipt> {
        self.observed_receipt.as_ref()
    }

    #[must_use]
    pub const fn proposed_receipt(&self) -> &DeploymentReceipt {
        &self.proposed_receipt
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
            Err(agent_apply_error(
                "agent_apply.observation_stale",
                "the agent destination changed after planning",
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
            Err(agent_apply_error(
                "agent_apply.manifest_stale",
                "manifest authority changed after agent planning",
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
            Err(agent_apply_error(
                "agent_apply.local_state_stale",
                "machine-local receipt authority changed after agent planning",
            ))
        }
    }
}

impl Debug for AgentApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentApplyPlan")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("policy_line", &self.policy.policy_line)
            .field("asset_id", &self.asset_id)
            .field("disposition", &self.disposition)
            .field("manifest_revision", &self.manifest_revision)
            .field("rendered", &self.rendered)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Resolves one reviewed agent policy beneath an absolute trusted anchor.
pub fn resolve_agent_destination(
    anchor: &Path,
    policy: &AgentTargetPolicy,
    agent_name: &AgentName,
) -> Result<NormalizedDestination, MaterializationError> {
    policy.validate().map_err(|_| invalid_policy())?;
    validate_target_anchor(anchor)?;
    normalized_destination_from_path(&agent_path(anchor, policy, agent_name)?)
}

/// Reads one exact agent file without following links or mutating the destination.
pub fn observe_agent_destination(
    anchor: &Path,
    policy: &AgentTargetPolicy,
    agent_name: &AgentName,
    limits: AgentLimits,
) -> Result<AgentDestinationObservation, MaterializationError> {
    let destination = resolve_agent_destination(anchor, policy, agent_name)?;
    let observed = match read_bounded_regular_file_with_mode(
        Path::new(destination.as_str()),
        limits.max_document_bytes,
    ) {
        Ok(file) => Some(file),
        Err(ReadOnlyFileError::Missing) => None,
        Err(ReadOnlyFileError::Unsafe) => {
            return Err(agent_apply_error(
                "agent_apply.destination_unsafe",
                "the agent destination could not be inspected safely",
            ));
        }
        Err(ReadOnlyFileError::Limit) => {
            return Err(agent_apply_error(
                "agent_apply.destination_limit",
                "the agent destination exceeds the configured byte limit",
            ));
        }
    };
    Ok(match observed {
        Some(file) => AgentDestinationObservation {
            policy: policy.clone(),
            agent_name: agent_name.clone(),
            destination,
            content_hash: Some(hash_agent_target(&file.bytes, file.mode)),
            byte_count: Some(file.bytes.len()),
            mode: file.mode,
            content: Some(file.bytes),
        },
        None => AgentDestinationObservation {
            policy: policy.clone(),
            agent_name: agent_name.clone(),
            destination,
            content: None,
            content_hash: None,
            byte_count: None,
            mode: RegularFileMode::conservative(),
        },
    })
}

/// Plans one ownership-safe whole-file agent apply without mutating any state.
pub fn plan_agent_apply(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredAgent,
    policy: &AgentTargetPolicy,
    observation: &AgentDestinationObservation,
    local_state_text: &str,
) -> Result<AgentApplyPlan, MaterializationError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    policy.validate().map_err(|_| invalid_policy())?;
    if observation.policy != *policy || observation.agent_name != *object.agent().name() {
        return Err(agent_apply_error(
            "agent_apply.observation_mismatch",
            "the destination observation does not match agent target authority",
        ));
    }
    let mut local_state = LocalState::from_json(local_state_text).map_err(|_| invalid_state())?;
    validate_local_receipts(&local_state)?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        agent_apply_error(
            "agent_apply.asset_missing",
            "the selected agent asset is not present",
        )
    })?;
    if asset.kind != AssetKind::Agent
        || asset.content_class != ContentClass::AgentActive
        || !asset.required_bindings.is_empty()
    {
        return Err(agent_apply_error(
            "agent_apply.asset_unsupported",
            "the selected asset cannot be materialized as an agent",
        ));
    }
    let compatibility = asset.compatibility.get(&policy.harness).ok_or_else(|| {
        agent_apply_error(
            "agent_apply.compatibility_missing",
            "the selected asset has no target compatibility result",
        )
    })?;
    if !matches!(
        compatibility.fidelity(),
        Fidelity::Native | Fidelity::Portable | Fidelity::Adapted
    ) || compatibility.adapter_version() != policy.adapter_version
    {
        return Err(agent_apply_error(
            "agent_apply.compatibility_blocked",
            "target compatibility does not authorize this agent policy",
        ));
    }
    let portable = asset.portable.as_ref().ok_or_else(|| {
        agent_apply_error(
            "agent_apply.portable_missing",
            "the selected asset has no portable agent authority",
        )
    })?;
    if portable.format != StoredAgent::format() || portable.object_hash != *object.object_hash() {
        return Err(agent_apply_error(
            "agent_apply.portable_mismatch",
            "the supplied agent object does not match manifest authority",
        ));
    }
    if contains_credential_shaped_value(object.agent().description().as_str())
        || contains_credential_shaped_value(object.agent().instructions().as_str())
    {
        return Err(agent_apply_error(
            "agent_apply.credential_shaped_content",
            "credential-shaped agent authority cannot be materialized",
        ));
    }
    let rendered_bytes = render_native_agent(policy.dialect, object.agent())
        .map_err(|_| {
            agent_apply_error(
                "agent_apply.render_failed",
                "the agent could not be rendered without semantic loss",
            )
        })?
        .into_bytes();
    let rendered = RenderedAgent {
        content_hash: hash_agent_target(&rendered_bytes, observation.mode()),
        mode: observation.mode(),
        bytes: rendered_bytes,
    };
    let destination = observation.destination.clone();
    let relative_destination = agent_relative_destination(policy, object.agent().name())?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?;

    let matching = local_state
        .receipts
        .values()
        .filter(|receipt| receipt.destination == destination)
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err(agent_apply_error(
            "agent_apply.receipt_ambiguous",
            "multiple receipts claim the selected agent destination",
        ));
    }
    let observed_receipt = matching.first().map(|receipt| (*receipt).clone());
    if observed_receipt.as_ref().is_some_and(|receipt| {
        receipt.asset_id != *asset_id
            || receipt.harness != policy.harness
            || receipt.scope != policy.scope
            || receipt.target != ReceiptTarget::WholeTarget
            || !receipt.shared_with.is_empty()
    }) {
        return Err(agent_apply_error(
            "agent_apply.destination_owned_by_other_asset",
            "the selected agent destination is owned by other authority",
        ));
    }

    let (disposition, prior_hash) = match (&observed_receipt, observation.content_hash()) {
        (None, None) => (ApplyDisposition::Install, None),
        (None, Some(_)) => {
            return Err(agent_apply_error(
                "agent_apply.destination_unmanaged",
                "an unmanaged agent file is never overwritten",
            ));
        }
        (Some(receipt), None) => (ApplyDisposition::Restore, receipt.prior_hash.clone()),
        (Some(receipt), Some(observed_hash)) => {
            if observed_hash != &receipt.rendered_hash {
                return Err(agent_apply_error(
                    "agent_apply.destination_modified",
                    "the managed agent file changed after materialization",
                ));
            }
            if receipt.source_hash == asset.content_hash
                && receipt.rendered_hash == rendered.content_hash
                && receipt.adapter_version_for(&policy.harness) == Some(policy.adapter_version)
                && receipt.environment_revision == manifest_revision
            {
                (ApplyDisposition::NoOp, receipt.prior_hash.clone())
            } else {
                (
                    ApplyDisposition::ManagedUpdate,
                    Some(receipt.rendered_hash.clone()),
                )
            }
        }
    };
    let proposed_receipt = DeploymentReceipt {
        asset_id: asset_id.clone(),
        harness: policy.harness.clone(),
        scope: policy.scope,
        destination: destination.clone(),
        target: ReceiptTarget::WholeTarget,
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: asset.content_hash.clone(),
        rendered_hash: rendered.content_hash.clone(),
        document_hash: None,
        prior_hash,
        adapter_version: policy.adapter_version.to_owned(),
        environment_revision: manifest_revision.clone(),
    };
    if let Some(receipt) = &observed_receipt {
        local_state
            .receipts
            .remove(&receipt.receipt_id().map_err(|_| invalid_state())?);
    }
    let receipt_id = proposed_receipt.receipt_id().map_err(|_| invalid_state())?;
    local_state
        .receipts
        .insert(receipt_id.clone(), proposed_receipt.clone());
    let proposed_local_state_text = local_state.to_json().map_err(|_| invalid_state())?;
    let digest = agent_apply_digest(
        asset_id,
        policy,
        &destination,
        &manifest_revision,
        disposition,
        observation,
        &rendered,
        &receipt_id,
        local_state_text,
        &proposed_local_state_text,
    );
    Ok(AgentApplyPlan {
        policy: policy.clone(),
        asset_id: asset_id.clone(),
        destination,
        relative_destination,
        manifest_revision,
        disposition,
        observation: observation.clone(),
        rendered,
        observed_receipt,
        proposed_receipt,
        proposed_local_state: local_state,
        observed_local_state_text: local_state_text.to_owned(),
        digest,
    })
}

fn agent_path(
    anchor: &Path,
    policy: &AgentTargetPolicy,
    agent_name: &AgentName,
) -> Result<PathBuf, MaterializationError> {
    Ok(anchor.join(agent_relative_destination(policy, agent_name)?.as_str()))
}

pub(crate) fn agent_relative_destination(
    policy: &AgentTargetPolicy,
    agent_name: &AgentName,
) -> Result<PortablePath, MaterializationError> {
    PortablePath::parse(format!(
        "{}/{}.{}",
        policy.relative_root.as_str(),
        agent_name.as_str(),
        agent_document_extension(policy.dialect)
    ))
    .map_err(|_| {
        agent_apply_error(
            "agent_apply.destination_invalid",
            "the agent destination is invalid",
        )
    })
}

pub(crate) const fn agent_document_extension(dialect: NativeAgentDialect) -> &'static str {
    match dialect {
        NativeAgentDialect::ClaudeCurrent | NativeAgentDialect::OpenCodeCurrent => "md",
        NativeAgentDialect::CodexCurrent => "toml",
    }
}

pub(crate) fn hash_agent_target(bytes: &[u8], mode: RegularFileMode) -> ContentHash {
    hash_exact_file_target(b"kitrove-agent-target-v1\0", bytes, mode)
}

#[allow(clippy::too_many_arguments)]
fn agent_apply_digest(
    asset_id: &AssetId,
    policy: &AgentTargetPolicy,
    destination: &NormalizedDestination,
    manifest_revision: &Revision,
    disposition: ApplyDisposition,
    observation: &AgentDestinationObservation,
    rendered: &RenderedAgent,
    receipt_id: &kitrove_model::ReceiptId,
    observed_state: &str,
    proposed_state: &str,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-agent-apply-plan-v1\0");
    for value in [
        asset_id.as_str(),
        policy.harness.as_str(),
        policy.scope.as_str(),
        policy.policy_line.as_str(),
        policy.relative_root.as_str(),
        policy.adapter_version,
        policy.evidence.as_str(),
        observation.agent_name.as_str(),
        destination.as_str(),
        manifest_revision.as_str(),
        rendered.content_hash.as_str(),
        receipt_id.as_str(),
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
    hasher.update(&[match disposition {
        ApplyDisposition::Install => 0,
        ApplyDisposition::NoOp => 1,
        ApplyDisposition::Restore => 2,
        ApplyDisposition::ManagedUpdate => 3,
        ApplyDisposition::Remove => 4,
    }]);
    match observation.content_hash() {
        Some(hash) => {
            hasher.update(&[1]);
            write_digest_record(&mut hasher, hash.as_str());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    if let Some(mode) = rendered.mode().unix_mode() {
        hasher.update(&[1]);
        hasher.update(&mode.to_be_bytes());
    } else {
        hasher.update(&[0, u8::from(rendered.mode().readonly())]);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

const fn agent_apply_error(code: &'static str, message: &'static str) -> MaterializationError {
    MaterializationError::new(code, message)
}

const fn invalid_policy() -> MaterializationError {
    agent_apply_error(
        "agent_apply.policy_invalid",
        "agent target policy is invalid",
    )
}

const fn invalid_manifest() -> MaterializationError {
    agent_apply_error(
        "agent_apply.manifest_invalid",
        "manifest authority is invalid",
    )
}

const fn invalid_state() -> MaterializationError {
    agent_apply_error(
        "agent_apply.local_state_invalid",
        "machine-local receipt authority is invalid",
    )
}

#[cfg(test)]
pub(crate) use tests::AtomicAgentFixture;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use kitrove_adapter_api::{PolicyLine, RootId, RootTier};
    use kitrove_agent_skills::CaptureLimits;
    use kitrove_agents::{AgentLimits, NativeAgentDialect, parse_native_agent};
    use kitrove_model::{
        BindingName, BindingResolver, HarnessId, HarnessScope, MachineConfig, MachineId,
        SchemaVersion,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::agent_adoption::tests::{capabilities, empty_manifest};
    use crate::{AgentAdoptionOutcome, AgentObservation, plan_agent_adoption};

    fn adopted() -> (EnvironmentManifest, StoredAgent, AssetId) {
        let source = "---\nname: review\ndescription: Review changes.\n---\nReview carefully.\n";
        let observed = AgentObservation::new(
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
        .unwrap();
        let asset_id = AssetId::parse("review").unwrap();
        let AgentAdoptionOutcome::Ready(plan) =
            plan_agent_adoption(&observed, &asset_id, &empty_manifest(), &capabilities()).unwrap()
        else {
            panic!("portable agent must be adoptable")
        };
        (
            plan.proposed_manifest().clone(),
            plan.portable_object().clone(),
            asset_id,
        )
    }

    fn policy(dialect: NativeAgentDialect) -> AgentTargetPolicy {
        let (line, root, version) = match dialect {
            NativeAgentDialect::ClaudeCurrent => (
                PolicyLine::ClaudeCurrent,
                ".claude/agents",
                "claude-agents/1",
            ),
            NativeAgentDialect::CodexCurrent => {
                (PolicyLine::CodexCurrent, ".codex/agents", "codex-agents/1")
            }
            NativeAgentDialect::OpenCodeCurrent => (
                PolicyLine::OpenCodeV2,
                ".opencode/agents",
                "opencode-agents/1",
            ),
        };
        AgentTargetPolicy::new(
            HarnessScope::Project,
            line,
            TargetAnchor::Scope,
            root,
            dialect,
            version,
            "test.agent.target",
        )
        .unwrap()
    }

    fn local_state() -> LocalState {
        LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("test-machine").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::<BindingName, BindingResolver>::new(),
            receipts: BTreeMap::new(),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: Vec::new(),
        }
    }

    pub(crate) struct AtomicAgentFixture {
        _root: tempfile::TempDir,
        pub(crate) environment: PathBuf,
        pub(crate) state: PathBuf,
        pub(crate) batch: crate::AtomicApplyBatchPlan,
        pub(crate) destination: String,
        pub(crate) expected: Vec<u8>,
        pub(crate) target: PathBuf,
        pub(crate) manifest: EnvironmentManifest,
        pub(crate) object: StoredAgent,
        pub(crate) asset_id: AssetId,
        pub(crate) policy: AgentTargetPolicy,
    }

    impl AtomicAgentFixture {
        pub(crate) fn new() -> Self {
            let root = tempdir().unwrap();
            let canonical = root.path().canonicalize().unwrap();
            let environment = canonical.join("environment");
            let state = canonical.join("state");
            let target = canonical.join("target");
            for directory in [&environment, &target] {
                fs::create_dir(directory).unwrap();
            }
            let (manifest, object, asset_id) = adopted();
            fs::write(
                environment.join("kitrove.toml"),
                manifest.to_toml().unwrap(),
            )
            .unwrap();
            let portable = manifest.assets[&asset_id].portable.as_ref().unwrap();
            let store = crate::ObjectStore::open(&environment).unwrap();
            let environment_lock = store.try_lock_environment().unwrap();
            let staging = PortablePath::parse(".kitrove/test-agent").unwrap();
            store
                .stage_portable_agent(&staging, &object, CaptureLimits::default())
                .unwrap();
            store
                .install_portable_agent(
                    &staging,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
            drop(environment_lock);
            let local = local_state();
            let initial_state = local.to_json().unwrap();
            crate::test_authority::initialize_private_state(&state, &local).unwrap();
            let policy = policy(NativeAgentDialect::ClaudeCurrent);
            let absent = observe_agent_destination(
                &target,
                &policy,
                object.agent().name(),
                AgentLimits::default(),
            )
            .unwrap();
            let plan = plan_agent_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &absent,
                &initial_state,
            )
            .unwrap();
            let expected = plan.rendered().bytes().to_vec();
            let destination = plan.destination().as_str().to_owned();
            let batch =
                crate::AtomicApplyBatchPlan::new(vec![crate::AtomicApplyItem::Agent(plan)], None)
                    .unwrap();
            Self {
                _root: root,
                environment,
                state,
                batch,
                destination,
                expected,
                target,
                manifest,
                object,
                asset_id,
                policy,
            }
        }

        pub(crate) fn removal_batch(&self) -> crate::AtomicApplyBatchPlan {
            let state_text = fs::read_to_string(self.state.join("state.json")).unwrap();
            let observation = observe_agent_destination(
                &self.target,
                &self.policy,
                self.object.agent().name(),
                AgentLimits::default(),
            )
            .unwrap();
            let removal = crate::plan_agent_removal(
                &self.manifest,
                &self.asset_id,
                &self.object,
                &self.policy,
                &observation,
                &state_text,
            )
            .unwrap();
            crate::AtomicApplyBatchPlan::new(
                vec![crate::AtomicApplyItem::AgentRemoval(removal)],
                None,
            )
            .unwrap()
        }
    }

    #[test]
    fn dialects_resolve_exact_native_extensions_and_render_round_trips() {
        let root = tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        let (manifest, object, asset_id) = adopted();
        for (dialect, suffix) in [
            (
                NativeAgentDialect::ClaudeCurrent,
                ".claude/agents/review.md",
            ),
            (
                NativeAgentDialect::CodexCurrent,
                ".codex/agents/review.toml",
            ),
            (
                NativeAgentDialect::OpenCodeCurrent,
                ".opencode/agents/review.md",
            ),
        ] {
            let policy = policy(dialect);
            let observed = observe_agent_destination(
                &anchor,
                &policy,
                object.agent().name(),
                AgentLimits::default(),
            )
            .unwrap();
            assert!(observed.destination().as_str().ends_with(suffix));
            let plan = plan_agent_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &observed,
                &local_state().to_json().unwrap(),
            )
            .unwrap();
            assert_eq!(plan.disposition(), ApplyDisposition::Install);
            assert_eq!(
                plan.rendered().bytes(),
                render_native_agent(dialect, object.agent())
                    .unwrap()
                    .as_bytes()
            );
        }
    }

    #[test]
    fn receipt_classifies_noop_restore_update_and_refuses_unmanaged_or_modified() {
        let root = tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        let (manifest, object, asset_id) = adopted();
        let policy = policy(NativeAgentDialect::ClaudeCurrent);
        let state_text = local_state().to_json().unwrap();
        let absent = observe_agent_destination(
            &anchor,
            &policy,
            object.agent().name(),
            AgentLimits::default(),
        )
        .unwrap();
        let install =
            plan_agent_apply(&manifest, &asset_id, &object, &policy, &absent, &state_text).unwrap();
        let destination = Path::new(install.destination().as_str());
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, install.rendered().bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let managed_state = install.proposed_local_state().to_json().unwrap();
        let present = observe_agent_destination(
            &anchor,
            &policy,
            object.agent().name(),
            AgentLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan_agent_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &present,
                &managed_state,
            )
            .unwrap()
            .disposition(),
            ApplyDisposition::NoOp
        );

        fs::write(destination, "changed\n").unwrap();
        let changed = observe_agent_destination(
            &anchor,
            &policy,
            object.agent().name(),
            AgentLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan_agent_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &changed,
                &managed_state,
            )
            .unwrap_err()
            .code(),
            "agent_apply.destination_modified"
        );
        assert_eq!(
            plan_agent_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &changed,
                &state_text,
            )
            .unwrap_err()
            .code(),
            "agent_apply.destination_unmanaged"
        );

        fs::remove_file(destination).unwrap();
        let missing = observe_agent_destination(
            &anchor,
            &policy,
            object.agent().name(),
            AgentLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan_agent_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &missing,
                &managed_state,
            )
            .unwrap()
            .disposition(),
            ApplyDisposition::Restore
        );
    }

    #[test]
    fn atomic_coordinator_commits_agent_file_and_receipt_together() {
        let fixture = AtomicAgentFixture::new();

        assert_eq!(
            crate::commit_atomic_apply_batch(
                &fixture.batch,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            crate::AtomicApplyBatchCommitOutcome::Committed
        );
        assert_eq!(fs::read(&fixture.destination).unwrap(), fixture.expected);
        assert_eq!(
            LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
                .unwrap()
                .receipts
                .len(),
            1
        );
    }
}
