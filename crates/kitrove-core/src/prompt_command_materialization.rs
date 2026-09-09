use std::fmt::{self, Debug, Formatter};
use std::path::{Path, PathBuf};

use kitrove_adapter_api::{PromptCommandTargetPolicy, TargetAnchor};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, DeploymentReceipt, EnvironmentManifest,
    Fidelity, LocalState, NormalizedDestination, PortablePath, ReceiptTarget, Revision,
};
use kitrove_prompt_commands::{
    PromptCommandLimits, PromptCommandName, StoredPromptCommand, render_native_prompt_command,
};

use crate::derive_manifest_revision;
use crate::instruction_risk::contains_credential_shaped_value;
use crate::materialization::{
    ApplyDisposition, MaterializationError, hash_exact_file_target,
    normalized_destination_from_path, validate_local_receipts, validate_target_anchor,
    write_digest_record,
};
use crate::prompt_command_observation::prompt_command_dialect;
use crate::read_only_fs::{
    ReadOnlyFileError, RegularFileMode, read_bounded_regular_file_with_mode,
};

/// Exact read-only state of one whole-file prompt-command destination.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandDestinationObservation {
    policy: PromptCommandTargetPolicy,
    command_name: PromptCommandName,
    destination: NormalizedDestination,
    content: Option<Vec<u8>>,
    content_hash: Option<ContentHash>,
    byte_count: Option<usize>,
    mode: RegularFileMode,
}

impl PromptCommandDestinationObservation {
    #[must_use]
    pub const fn policy(&self) -> &PromptCommandTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn command_name(&self) -> &PromptCommandName {
        &self.command_name
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

impl Debug for PromptCommandDestinationObservation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandDestinationObservation")
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("policy_line", &self.policy.policy_line)
            .field("command_name", &self.command_name)
            .field("present", &self.is_present())
            .field("content_hash", &self.content_hash)
            .field("byte_count", &self.byte_count)
            .finish()
    }
}

/// Exact inert Markdown output produced by pure prompt-command rendering.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedPromptCommand {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    mode: RegularFileMode,
}

impl RenderedPromptCommand {
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

impl Debug for RenderedPromptCommand {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedPromptCommand")
            .field("byte_count", &self.bytes.len())
            .field("content_hash", &self.content_hash)
            .finish()
    }
}

/// Complete non-mutating plan for one receipt-backed prompt-command file.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptCommandApplyPlan {
    policy: PromptCommandTargetPolicy,
    asset_id: AssetId,
    destination: NormalizedDestination,
    relative_destination: PortablePath,
    manifest_revision: Revision,
    disposition: ApplyDisposition,
    observation: PromptCommandDestinationObservation,
    rendered: RenderedPromptCommand,
    observed_receipt: Option<DeploymentReceipt>,
    proposed_receipt: DeploymentReceipt,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

impl PromptCommandApplyPlan {
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
    pub const fn disposition(&self) -> ApplyDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn observation(&self) -> &PromptCommandDestinationObservation {
        &self.observation
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedPromptCommand {
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
        reread: &PromptCommandDestinationObservation,
    ) -> Result<(), MaterializationError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(command_apply_error(
                "command_apply.observation_stale",
                "the prompt-command destination changed after planning",
            ))
        }
    }

    pub fn ensure_manifest_fresh(
        &self,
        manifest: &EnvironmentManifest,
    ) -> Result<(), MaterializationError> {
        let revision = derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?;
        if revision == self.manifest_revision {
            Ok(())
        } else {
            Err(command_apply_error(
                "command_apply.manifest_stale",
                "manifest authority changed after prompt-command planning",
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
            Err(command_apply_error(
                "command_apply.local_state_stale",
                "machine-local receipt authority changed after prompt-command planning",
            ))
        }
    }
}

impl Debug for PromptCommandApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptCommandApplyPlan")
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

/// Resolves one reviewed prompt-command policy beneath an absolute trusted anchor.
pub fn resolve_prompt_command_destination(
    anchor: &Path,
    policy: &PromptCommandTargetPolicy,
    command_name: &PromptCommandName,
) -> Result<NormalizedDestination, MaterializationError> {
    policy.validate().map_err(|_| invalid_policy())?;
    validate_target_anchor(anchor)?;
    normalized_destination_from_path(&prompt_command_path(anchor, policy, command_name))
}

/// Reads one exact command file without following links or mutating the destination.
pub fn observe_prompt_command_destination(
    anchor: &Path,
    policy: &PromptCommandTargetPolicy,
    command_name: &PromptCommandName,
    limits: PromptCommandLimits,
) -> Result<PromptCommandDestinationObservation, MaterializationError> {
    let destination = resolve_prompt_command_destination(anchor, policy, command_name)?;
    let path = Path::new(destination.as_str());
    let observed = match read_bounded_regular_file_with_mode(path, limits.max_document_bytes) {
        Ok(file) => Some(file),
        Err(ReadOnlyFileError::Missing) => None,
        Err(ReadOnlyFileError::Unsafe) => {
            return Err(command_apply_error(
                "command_apply.destination_unsafe",
                "the prompt-command destination could not be inspected safely",
            ));
        }
        Err(ReadOnlyFileError::Limit) => {
            return Err(command_apply_error(
                "command_apply.destination_limit",
                "the prompt-command destination exceeds the configured byte limit",
            ));
        }
    };
    Ok(match observed {
        Some(file) => PromptCommandDestinationObservation {
            policy: policy.clone(),
            command_name: command_name.clone(),
            destination,
            content_hash: Some(hash_prompt_command_target(&file.bytes, file.mode)),
            byte_count: Some(file.bytes.len()),
            mode: file.mode,
            content: Some(file.bytes),
        },
        None => PromptCommandDestinationObservation {
            policy: policy.clone(),
            command_name: command_name.clone(),
            destination,
            content: None,
            content_hash: None,
            byte_count: None,
            mode: RegularFileMode::conservative(),
        },
    })
}

/// Plans one ownership-safe whole-file command apply without mutating any state.
pub fn plan_prompt_command_apply(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredPromptCommand,
    policy: &PromptCommandTargetPolicy,
    observation: &PromptCommandDestinationObservation,
    local_state_text: &str,
) -> Result<PromptCommandApplyPlan, MaterializationError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    policy.validate().map_err(|_| invalid_policy())?;
    if observation.policy != *policy || observation.command_name != *object.command().name() {
        return Err(command_apply_error(
            "command_apply.observation_mismatch",
            "the destination observation does not match command target authority",
        ));
    }
    let mut local_state = LocalState::from_json(local_state_text).map_err(|_| invalid_state())?;
    validate_local_receipts(&local_state)?;
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        command_apply_error(
            "command_apply.asset_missing",
            "the selected prompt-command asset is not present",
        )
    })?;
    if asset.kind != AssetKind::Command
        || asset.content_class != ContentClass::AgentActive
        || !asset.required_bindings.is_empty()
    {
        return Err(command_apply_error(
            "command_apply.asset_unsupported",
            "the selected asset cannot be materialized as a prompt command",
        ));
    }
    let compatibility = asset.compatibility.get(&policy.harness).ok_or_else(|| {
        command_apply_error(
            "command_apply.compatibility_missing",
            "the selected asset has no target compatibility result",
        )
    })?;
    if !matches!(
        compatibility.fidelity(),
        Fidelity::Native | Fidelity::Portable | Fidelity::Adapted
    ) || compatibility.adapter_version() != policy.adapter_version
    {
        return Err(command_apply_error(
            "command_apply.compatibility_blocked",
            "target compatibility does not authorize this prompt-command policy",
        ));
    }
    let portable = asset.portable.as_ref().ok_or_else(|| {
        command_apply_error(
            "command_apply.portable_missing",
            "the selected asset has no portable prompt-command authority",
        )
    })?;
    if portable.format != StoredPromptCommand::format()
        || portable.object_hash != *object.object_hash()
    {
        return Err(command_apply_error(
            "command_apply.portable_mismatch",
            "the supplied prompt-command object does not match manifest authority",
        ));
    }
    if contains_credential_shaped_value(object.command().body().as_str())
        || object
            .command()
            .description()
            .is_some_and(|description| contains_credential_shaped_value(description.as_str()))
    {
        return Err(command_apply_error(
            "command_apply.credential_shaped_content",
            "credential-shaped prompt-command authority cannot be materialized",
        ));
    }
    let dialect = prompt_command_dialect(&policy.harness).ok_or_else(|| {
        command_apply_error(
            "command_apply.dialect_unsupported",
            "the target has no supported prompt-command dialect",
        )
    })?;
    let rendered_bytes = render_native_prompt_command(dialect, object.command())
        .map_err(|_| {
            command_apply_error(
                "command_apply.render_failed",
                "the prompt command could not be rendered without semantic loss",
            )
        })?
        .into_bytes();
    let rendered = RenderedPromptCommand {
        content_hash: hash_prompt_command_target(&rendered_bytes, observation.mode()),
        mode: observation.mode(),
        bytes: rendered_bytes,
    };
    let destination = observation.destination.clone();
    let relative_destination = PortablePath::parse(format!(
        "{}/{}.md",
        policy.relative_root.as_str(),
        object.command().name().as_str()
    ))
    .map_err(|_| {
        command_apply_error(
            "command_apply.destination_invalid",
            "the prompt-command destination is invalid",
        )
    })?;
    let manifest_revision = derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?;

    let matching: Vec<_> = local_state
        .receipts
        .values()
        .filter(|receipt| receipt.destination == destination)
        .collect();
    if matching.len() > 1 {
        return Err(command_apply_error(
            "command_apply.receipt_ambiguous",
            "multiple receipts claim the selected prompt-command destination",
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
        return Err(command_apply_error(
            "command_apply.destination_owned_by_other_asset",
            "the selected prompt-command destination is owned by other authority",
        ));
    }

    let (disposition, prior_hash) = match (&observed_receipt, observation.content_hash()) {
        (None, None) => (ApplyDisposition::Install, None),
        (None, Some(_)) => {
            return Err(command_apply_error(
                "command_apply.destination_unmanaged",
                "an unmanaged prompt-command file is never overwritten",
            ));
        }
        (Some(receipt), None) => (ApplyDisposition::Restore, receipt.prior_hash.clone()),
        (Some(receipt), Some(observed_hash)) => {
            if observed_hash != &receipt.rendered_hash {
                return Err(command_apply_error(
                    "command_apply.destination_modified",
                    "the managed prompt-command file changed after materialization",
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
        let receipt_id = receipt.receipt_id().map_err(|_| invalid_state())?;
        local_state.receipts.remove(&receipt_id);
    }
    let receipt_id = proposed_receipt.receipt_id().map_err(|_| invalid_state())?;
    local_state
        .receipts
        .insert(receipt_id.clone(), proposed_receipt.clone());
    let proposed_local_state_text = local_state.to_json().map_err(|_| invalid_state())?;
    let digest = command_apply_digest(
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
    Ok(PromptCommandApplyPlan {
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

fn prompt_command_path(
    anchor: &Path,
    policy: &PromptCommandTargetPolicy,
    command_name: &PromptCommandName,
) -> PathBuf {
    anchor
        .join(policy.relative_root.as_str())
        .join(format!("{}.md", command_name.as_str()))
}

pub(crate) fn hash_prompt_command_target(bytes: &[u8], mode: RegularFileMode) -> ContentHash {
    hash_exact_file_target(b"kitrove-prompt-command-target-v1\0", bytes, mode)
}

#[allow(clippy::too_many_arguments)]
fn command_apply_digest(
    asset_id: &AssetId,
    policy: &PromptCommandTargetPolicy,
    destination: &NormalizedDestination,
    manifest_revision: &Revision,
    disposition: ApplyDisposition,
    observation: &PromptCommandDestinationObservation,
    rendered: &RenderedPromptCommand,
    receipt_id: &kitrove_model::ReceiptId,
    observed_state: &str,
    proposed_state: &str,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-prompt-command-apply-plan-v1\0");
    for value in [
        asset_id.as_str(),
        policy.harness.as_str(),
        policy.scope.as_str(),
        policy.policy_line.as_str(),
        policy.relative_root.as_str(),
        policy.adapter_version,
        policy.evidence.as_str(),
        observation.command_name.as_str(),
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

const fn command_apply_error(code: &'static str, message: &'static str) -> MaterializationError {
    MaterializationError::new(code, message)
}

const fn invalid_policy() -> MaterializationError {
    command_apply_error(
        "command_apply.policy_invalid",
        "prompt-command target policy is invalid",
    )
}

const fn invalid_manifest() -> MaterializationError {
    command_apply_error(
        "command_apply.manifest_invalid",
        "manifest authority is invalid",
    )
}

const fn invalid_state() -> MaterializationError {
    command_apply_error(
        "command_apply.local_state_invalid",
        "machine-local receipt authority is invalid",
    )
}

#[cfg(test)]
pub(crate) use tests::AtomicPromptCommandFixture;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use super::*;
    use crate::prompt_command_adoption::tests::{capabilities, manifest, observation};
    use crate::{
        PromptCommandAdoptionOutcome, plan_prompt_command_adoption, plan_prompt_command_removal,
    };
    use kitrove_adapter_api::{PolicyLine, PromptCommandTargetPolicy};
    use kitrove_agent_skills::CaptureLimits;
    use kitrove_model::{
        BindingName, BindingResolver, HarnessId, HarnessScope, MachineConfig, MachineId,
        SchemaVersion,
    };

    fn adopted(source: &str) -> (EnvironmentManifest, StoredPromptCommand, AssetId) {
        let observed = observation(source);
        let asset_id = AssetId::parse("review").unwrap();
        let PromptCommandAdoptionOutcome::Ready(plan) =
            plan_prompt_command_adoption(&observed, &asset_id, &manifest(), &capabilities())
                .unwrap()
        else {
            panic!("portable prompt command must be adoptable");
        };
        (
            plan.proposed_manifest().clone(),
            plan.portable_object().clone(),
            asset_id,
        )
    }

    fn target_policy(harness: HarnessId) -> PromptCommandTargetPolicy {
        let (line, root, adapter_version) = match harness {
            HarnessId::Pi => (PolicyLine::PiLatest, ".pi/prompts", "pi-commands/1"),
            HarnessId::OpenCode => (
                PolicyLine::OpenCodeV2,
                ".opencode/commands",
                "opencode-commands/1",
            ),
            _ => panic!("test policy supports Pi and OpenCode only"),
        };
        PromptCommandTargetPolicy::new(
            harness,
            HarnessScope::Project,
            line,
            TargetAnchor::Scope,
            root,
            adapter_version,
            "test.prompt_command.target",
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

    pub(crate) struct AtomicPromptCommandFixture {
        _root: tempfile::TempDir,
        pub(crate) environment: PathBuf,
        pub(crate) state: PathBuf,
        pub(crate) batch: crate::AtomicApplyBatchPlan,
        pub(crate) destination: String,
        pub(crate) expected: Vec<u8>,
        pub(crate) target: PathBuf,
        pub(crate) manifest: EnvironmentManifest,
        pub(crate) object: StoredPromptCommand,
        pub(crate) asset_id: AssetId,
        pub(crate) policy: PromptCommandTargetPolicy,
    }

    impl AtomicPromptCommandFixture {
        pub(crate) fn new() -> Self {
            let root = crate::test_authority::trusted_tempdir(".kitrove-prompt-command-");
            let canonical_root = root.path().canonicalize().unwrap();
            let environment = canonical_root.join("environment");
            let state = canonical_root.join("state");
            let target = canonical_root.join("target");
            for directory in [&environment, &target] {
                fs::create_dir(directory).unwrap();
            }
            let initial_state = local_state();
            crate::object_mutation::initialize_empty_authority_for_tests(
                &canonical_root.join("state-bootstrap-environment"),
                &state,
                &manifest(),
                &initial_state,
            )
            .unwrap();
            let (manifest, object, asset_id) = adopted("Review $ARGUMENTS carefully.\n");
            fs::write(
                environment.join("kitrove.toml"),
                manifest.to_toml().unwrap(),
            )
            .unwrap();
            let portable = manifest.assets[&asset_id].portable.as_ref().unwrap();
            let store = crate::ObjectStore::open(&environment).unwrap();
            let environment_lock = store.try_lock_environment().unwrap();
            let staging = PortablePath::parse(".kitrove/test-command").unwrap();
            store
                .stage_portable_prompt_command(&staging, &object, CaptureLimits::default())
                .unwrap();
            store
                .install_portable_prompt_command(
                    &staging,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
            drop(environment_lock);
            let initial_state = initial_state.to_json().unwrap();
            let policy = target_policy(HarnessId::Pi);
            let absent = observe_prompt_command_destination(
                &target,
                &policy,
                object.command().name(),
                PromptCommandLimits::default(),
            )
            .unwrap();
            let plan = plan_prompt_command_apply(
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
            let batch = crate::AtomicApplyBatchPlan::new(
                vec![crate::AtomicApplyItem::PromptCommand(plan)],
                None,
            )
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
            let observation = observe_prompt_command_destination(
                &self.target,
                &self.policy,
                self.object.command().name(),
                PromptCommandLimits::default(),
            )
            .unwrap();
            let plan = plan_prompt_command_removal(
                &self.manifest,
                &self.asset_id,
                &self.object,
                &self.policy,
                &observation,
                &state_text,
            )
            .unwrap();
            crate::AtomicApplyBatchPlan::new(
                vec![crate::AtomicApplyItem::PromptCommandRemoval(plan)],
                None,
            )
            .unwrap()
        }
    }

    #[test]
    fn install_noop_and_modified_destination_are_distinguished() {
        let root = crate::test_authority::trusted_tempdir(".kitrove-prompt-command-");
        let anchor = root.path().canonicalize().unwrap();
        let (manifest, object, asset_id) = adopted("Review $ARGUMENTS carefully.\n");
        let policy = target_policy(HarnessId::Pi);
        let absent = observe_prompt_command_destination(
            &anchor,
            &policy,
            object.command().name(),
            PromptCommandLimits::default(),
        )
        .unwrap();
        let state = local_state().to_json().unwrap();
        let install =
            plan_prompt_command_apply(&manifest, &asset_id, &object, &policy, &absent, &state)
                .unwrap();
        assert_eq!(install.disposition(), ApplyDisposition::Install);
        assert!(install.rendered().bytes().ends_with(b"\n"));
        assert!(!format!("{install:?}").contains("Review"));

        let destination = Path::new(install.destination().as_str());
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, install.rendered().bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let present = observe_prompt_command_destination(
            &anchor,
            &policy,
            object.command().name(),
            PromptCommandLimits::default(),
        )
        .unwrap();
        let advanced = install.proposed_local_state().to_json().unwrap();
        let no_op =
            plan_prompt_command_apply(&manifest, &asset_id, &object, &policy, &present, &advanced)
                .unwrap();
        assert_eq!(no_op.disposition(), ApplyDisposition::NoOp);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mode_changed = observe_prompt_command_destination(
                &anchor,
                &policy,
                object.command().name(),
                PromptCommandLimits::default(),
            )
            .unwrap();
            assert_eq!(
                plan_prompt_command_apply(
                    &manifest,
                    &asset_id,
                    &object,
                    &policy,
                    &mode_changed,
                    &advanced,
                )
                .unwrap_err()
                .code(),
                "command_apply.destination_modified"
            );
            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::fs::write(destination, "locally changed\n").unwrap();
        let changed = observe_prompt_command_destination(
            &anchor,
            &policy,
            object.command().name(),
            PromptCommandLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan_prompt_command_apply(&manifest, &asset_id, &object, &policy, &changed, &advanced,)
                .unwrap_err()
                .code(),
            "command_apply.destination_modified"
        );
    }

    #[test]
    fn partial_fidelity_and_unmanaged_files_fail_closed() {
        let root = crate::test_authority::trusted_tempdir(".kitrove-prompt-command-");
        let anchor = root.path().canonicalize().unwrap();
        let (manifest, object, asset_id) = adopted("Review carefully.\n");
        let policy = target_policy(HarnessId::OpenCode);
        let absent = observe_prompt_command_destination(
            &anchor,
            &policy,
            object.command().name(),
            PromptCommandLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan_prompt_command_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &absent,
                &local_state().to_json().unwrap(),
            )
            .unwrap_err()
            .code(),
            "command_apply.compatibility_blocked"
        );

        let (manifest, object, asset_id) = adopted("Review $ARGUMENTS carefully.\n");
        let policy = target_policy(HarnessId::Pi);
        let destination =
            resolve_prompt_command_destination(&anchor, &policy, object.command().name()).unwrap();
        let path = Path::new(destination.as_str());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "owned by the user\n").unwrap();
        let present = observe_prompt_command_destination(
            &anchor,
            &policy,
            object.command().name(),
            PromptCommandLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan_prompt_command_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &present,
                &local_state().to_json().unwrap(),
            )
            .unwrap_err()
            .code(),
            "command_apply.destination_unmanaged"
        );
    }

    #[test]
    fn physical_destination_receipts_cannot_cross_scope_boundaries() {
        let root = crate::test_authority::trusted_tempdir(".kitrove-prompt-command-");
        let anchor = root.path().canonicalize().unwrap();
        let (manifest, object, asset_id) = adopted("Review $ARGUMENTS carefully.\n");
        let policy = target_policy(HarnessId::Pi);
        let absent = observe_prompt_command_destination(
            &anchor,
            &policy,
            object.command().name(),
            PromptCommandLimits::default(),
        )
        .unwrap();
        let install = plan_prompt_command_apply(
            &manifest,
            &asset_id,
            &object,
            &policy,
            &absent,
            &local_state().to_json().unwrap(),
        )
        .unwrap();
        let mut foreign = install.proposed_receipt().clone();
        foreign.scope = HarnessScope::User;
        let mut state = local_state();
        state
            .receipts
            .insert(foreign.receipt_id().unwrap(), foreign);

        assert_eq!(
            plan_prompt_command_apply(
                &manifest,
                &asset_id,
                &object,
                &policy,
                &absent,
                &state.to_json().unwrap(),
            )
            .unwrap_err()
            .code(),
            "command_apply.destination_owned_by_other_asset"
        );
    }

    #[cfg(unix)]
    #[test]
    fn observation_rejects_linked_target_ancestors() {
        use std::os::unix::fs::symlink;

        let root = crate::test_authority::trusted_tempdir(".kitrove-prompt-command-");
        let anchor = root.path().canonicalize().unwrap();
        let outside = crate::test_authority::trusted_tempdir(".kitrove-prompt-command-");
        symlink(outside.path(), anchor.join(".pi")).unwrap();
        let policy = target_policy(HarnessId::Pi);
        let name = PromptCommandName::parse("review").unwrap();

        assert_eq!(
            observe_prompt_command_destination(
                &anchor,
                &policy,
                &name,
                PromptCommandLimits::default(),
            )
            .unwrap_err()
            .code(),
            "command_apply.destination_unsafe"
        );
    }

    #[test]
    fn atomic_coordinator_commits_command_and_receipt_together() {
        let fixture = AtomicPromptCommandFixture::new();

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
            fs::read_to_string(fixture.state.join("state.json")).unwrap(),
            fixture.batch.proposed_local_state_text()
        );
    }
}
