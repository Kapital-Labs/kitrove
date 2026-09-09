use kitrove_adapter_api::{InstructionTargetAnchor, InstructionTargetPolicy};
use kitrove_instructions::{
    InstructionLimits, StoredInstruction, hash_instruction_document, render_managed_region,
    upsert_managed_region,
};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, DeploymentReceipt, EnvironmentManifest,
    Fidelity, LocalState, ReceiptId, ReceiptTarget, Revision,
};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use crate::materialization::ApplyDisposition;
use crate::read_only_fs::RegularFileMode;
use crate::{InstructionDocumentObservation, ReceiptIndex, derive_manifest_revision};

pub(crate) struct ValidatedInstructionSource<'a> {
    pub(crate) asset: &'a kitrove_model::Asset,
    pub(crate) manifest_revision: Revision,
}

/// Stable, content- and path-redacted instruction materialization failure.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionMaterializationError {
    code: &'static str,
    message: &'static str,
}

impl InstructionMaterializationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for InstructionMaterializationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionMaterializationError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for InstructionMaterializationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for InstructionMaterializationError {}

/// Exact document output and region identity produced by pure planning.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedInstructionDocument {
    bytes: Vec<u8>,
    document_hash: ContentHash,
    region_hash: ContentHash,
    mode: RegularFileMode,
}

impl RenderedInstructionDocument {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn document_hash(&self) -> &ContentHash {
        &self.document_hash
    }

    #[must_use]
    pub const fn region_hash(&self) -> &ContentHash {
        &self.region_hash
    }

    pub(crate) const fn mode(&self) -> RegularFileMode {
        self.mode
    }
}

impl Debug for RenderedInstructionDocument {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedInstructionDocument")
            .field("byte_count", &self.bytes.len())
            .field("document_hash", &self.document_hash)
            .field("region_hash", &self.region_hash)
            .finish()
    }
}

/// Complete non-mutating plan for one managed instruction region.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionApplyPlan {
    policy: InstructionTargetPolicy,
    asset_id: AssetId,
    manifest_revision: Revision,
    disposition: ApplyDisposition,
    observation: InstructionDocumentObservation,
    rendered: RenderedInstructionDocument,
    observed_receipt: Option<DeploymentReceipt>,
    proposed_receipt: DeploymentReceipt,
    proposed_local_state: LocalState,
    observed_local_state_text: String,
    digest: ContentHash,
}

impl InstructionApplyPlan {
    #[must_use]
    pub const fn policy(&self) -> &InstructionTargetPolicy {
        &self.policy
    }

    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
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
    pub const fn observation(&self) -> &InstructionDocumentObservation {
        &self.observation
    }

    #[must_use]
    pub const fn rendered(&self) -> &RenderedInstructionDocument {
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

    /// Revalidates the complete co-owned document observation before mutation.
    pub fn ensure_observation_fresh(
        &self,
        reread: &InstructionDocumentObservation,
    ) -> Result<(), InstructionMaterializationError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(materialization_error(
                "instruction_apply.observation_stale",
                "the co-owned instruction document changed after planning",
            ))
        }
    }

    /// Revalidates portable manifest authority before mutation.
    pub fn ensure_manifest_fresh(
        &self,
        manifest: &EnvironmentManifest,
    ) -> Result<(), InstructionMaterializationError> {
        let revision = derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?;
        if revision == self.manifest_revision {
            Ok(())
        } else {
            Err(materialization_error(
                "instruction_apply.manifest_stale",
                "manifest authority changed after instruction planning",
            ))
        }
    }

    /// Revalidates exact machine-local receipt authority before mutation.
    pub fn ensure_local_state_fresh(
        &self,
        local_state_text: &str,
    ) -> Result<(), InstructionMaterializationError> {
        if local_state_text == self.observed_local_state_text {
            Ok(())
        } else {
            Err(materialization_error(
                "instruction_apply.local_state_stale",
                "machine-local receipt authority changed after instruction planning",
            ))
        }
    }
}

impl Debug for InstructionApplyPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionApplyPlan")
            .field("policy_line", &self.policy.policy_line)
            .field("harness", &self.policy.harness)
            .field("scope", &self.policy.scope)
            .field("asset_id", &self.asset_id)
            .field("disposition", &self.disposition)
            .field("manifest_revision", &self.manifest_revision)
            .field("rendered", &self.rendered)
            .field("digest", &self.digest)
            .finish()
    }
}

/// Plans one receipt-backed managed-region apply without mutating any state.
pub fn plan_instruction_apply(
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredInstruction,
    policy: &InstructionTargetPolicy,
    observation: &InstructionDocumentObservation,
    local_state_text: &str,
    limits: InstructionLimits,
) -> Result<InstructionApplyPlan, InstructionMaterializationError> {
    let validated = validate_instruction_source(manifest, asset_id, object, policy, observation)?;
    let inspection = ReceiptIndex::inspect_json(local_state_text).map_err(|_| invalid_state())?;
    if !inspection.invalid.is_empty() {
        return Err(invalid_state());
    }
    let mut local_state = LocalState::from_json(local_state_text).map_err(|_| invalid_state())?;
    let asset = validated.asset;
    let manifest_revision = validated.manifest_revision;
    let matching = matching_region_receipts(&local_state, asset_id, policy, observation)?;
    let observed_receipt = matching.into_iter().next().cloned();
    if observed_receipt
        .as_ref()
        .is_some_and(|receipt| !receipt.shared_with.is_empty())
    {
        return Err(materialization_error(
            "instruction_apply.shared_batch_required",
            "a shared instruction receipt requires atomic multi-target planning",
        ));
    }

    let (_, region_hash) =
        render_managed_region(asset_id, object.body()).map_err(|_| render_failed())?;
    let original = observation.document_bytes().unwrap_or_default();
    let rendered_bytes = upsert_managed_region(original, asset_id, object.body(), limits)
        .map_err(|_| render_failed())?;
    let rendered = RenderedInstructionDocument {
        document_hash: hash_instruction_document(&rendered_bytes),
        region_hash,
        mode: observation.mode(),
        bytes: rendered_bytes,
    };
    let observed_region = observation.region(asset_id);
    let (disposition, prior_hash) = match (&observed_receipt, observed_region) {
        (None, None) => (ApplyDisposition::Install, None),
        (None, Some(_)) => {
            return Err(materialization_error(
                "instruction_apply.region_unmanaged",
                "an unmanaged instruction region is never claimed or overwritten",
            ));
        }
        (Some(receipt), None) => (ApplyDisposition::Restore, receipt.prior_hash.clone()),
        (Some(receipt), Some(region)) => {
            if region.exact_region_hash() != &receipt.rendered_hash {
                return Err(materialization_error(
                    "instruction_apply.region_modified",
                    "the managed instruction region changed after materialization",
                ));
            }
            if receipt.source_hash == asset.content_hash
                && receipt.rendered_hash == rendered.region_hash
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
        destination: observation.destination().clone(),
        target: ReceiptTarget::ManagedInstructionRegion,
        logical_key: None,
        shared_with: Default::default(),
        shared_adapter_versions: Default::default(),
        source_hash: asset.content_hash.clone(),
        rendered_hash: rendered.region_hash.clone(),
        document_hash: None,
        prior_hash,
        adapter_version: policy.adapter_version.to_owned(),
        environment_revision: manifest_revision.clone(),
    };
    let receipt_id = proposed_receipt.receipt_id().map_err(|_| invalid_state())?;
    if let Some(receipt) = &observed_receipt {
        let old_id = receipt.receipt_id().map_err(|_| invalid_state())?;
        local_state.receipts.remove(&old_id);
    }
    local_state
        .receipts
        .insert(receipt_id.clone(), proposed_receipt.clone());
    let proposed_local_state_text = local_state.to_json().map_err(|_| invalid_state())?;
    let digest = apply_digest(
        asset_id,
        policy,
        observation,
        &manifest_revision,
        disposition,
        &rendered,
        &receipt_id,
        local_state_text,
        &proposed_local_state_text,
    );
    Ok(InstructionApplyPlan {
        policy: policy.clone(),
        asset_id: asset_id.clone(),
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

pub(crate) fn validate_instruction_source<'a>(
    manifest: &'a EnvironmentManifest,
    asset_id: &AssetId,
    object: &StoredInstruction,
    policy: &InstructionTargetPolicy,
    observation: &InstructionDocumentObservation,
) -> Result<ValidatedInstructionSource<'a>, InstructionMaterializationError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    policy.validate().map_err(|_| {
        materialization_error(
            "instruction_apply.policy_invalid",
            "instruction target policy is invalid",
        )
    })?;
    if observation.policy() != policy {
        return Err(materialization_error(
            "instruction_apply.policy_mismatch",
            "the observation was produced by another instruction target policy",
        ));
    }
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        materialization_error(
            "instruction_apply.asset_missing",
            "the selected instruction asset is not present",
        )
    })?;
    if asset.kind != AssetKind::Instruction
        || asset.content_class != ContentClass::AgentActive
        || !asset.required_bindings.is_empty()
    {
        return Err(materialization_error(
            "instruction_apply.asset_unsupported",
            "the selected asset cannot be materialized as a standing instruction",
        ));
    }
    let compatibility = asset.compatibility.get(&policy.harness).ok_or_else(|| {
        materialization_error(
            "instruction_apply.compatibility_missing",
            "the selected asset has no target compatibility result",
        )
    })?;
    if !matches!(
        compatibility.fidelity(),
        Fidelity::Native | Fidelity::Portable | Fidelity::Adapted
    ) || compatibility.adapter_version() != policy.adapter_version
    {
        return Err(materialization_error(
            "instruction_apply.compatibility_blocked",
            "target compatibility does not authorize this instruction policy",
        ));
    }
    let portable = asset.portable.as_ref().ok_or_else(|| {
        materialization_error(
            "instruction_apply.portable_missing",
            "the selected asset has no portable instruction authority",
        )
    })?;
    if portable.format != StoredInstruction::format()
        || portable.object_hash != *object.object_hash()
    {
        return Err(materialization_error(
            "instruction_apply.portable_mismatch",
            "the supplied instruction object does not match manifest authority",
        ));
    }
    if crate::instruction_risk::contains_credential_shaped_value(object.body().as_str()) {
        return Err(materialization_error(
            "instruction_apply.credential_shaped_body",
            "credential-shaped instruction authority cannot be materialized",
        ));
    }

    Ok(ValidatedInstructionSource {
        asset,
        manifest_revision: derive_manifest_revision(manifest).map_err(|_| invalid_manifest())?,
    })
}

fn matching_region_receipts<'a>(
    state: &'a LocalState,
    asset_id: &AssetId,
    policy: &InstructionTargetPolicy,
    observation: &InstructionDocumentObservation,
) -> Result<Vec<&'a DeploymentReceipt>, InstructionMaterializationError> {
    if state.receipts.values().any(|receipt| {
        receipt.scope == policy.scope
            && receipt.destination == *observation.destination()
            && receipt.target == ReceiptTarget::WholeTarget
    }) {
        return Err(materialization_error(
            "instruction_apply.destination_owned_whole",
            "a whole-target receipt owns the selected instruction document",
        ));
    }
    let matching: Vec<_> = state
        .receipts
        .values()
        .filter(|receipt| {
            receipt.scope == policy.scope
                && receipt.destination == *observation.destination()
                && receipt.target == ReceiptTarget::ManagedInstructionRegion
                && receipt.asset_id == *asset_id
        })
        .collect();
    if matching.len() > 1 {
        return Err(invalid_state());
    }
    if matching.first().is_some_and(|receipt| {
        !receipt
            .consumers()
            .any(|consumer| consumer == &policy.harness)
    }) {
        return Err(materialization_error(
            "instruction_apply.region_owned_other_target",
            "the selected instruction region is owned by another target set",
        ));
    }
    Ok(matching)
}

#[allow(clippy::too_many_arguments)]
fn apply_digest(
    asset_id: &AssetId,
    policy: &InstructionTargetPolicy,
    observation: &InstructionDocumentObservation,
    manifest_revision: &Revision,
    disposition: ApplyDisposition,
    rendered: &RenderedInstructionDocument,
    receipt_id: &ReceiptId,
    observed_state: &str,
    proposed_state: &str,
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-apply-plan-v1\0");
    for value in [
        asset_id.as_str(),
        policy.harness.as_str(),
        policy.scope.as_str(),
        policy.policy_line.as_str(),
        policy.relative_document.as_str(),
        policy.adapter_version,
        policy.evidence.as_str(),
        observation.destination().as_str(),
        manifest_revision.as_str(),
        rendered.document_hash.as_str(),
        rendered.region_hash.as_str(),
        receipt_id.as_str(),
        ContentHash::digest(observed_state.as_bytes()).as_str(),
        ContentHash::digest(proposed_state.as_bytes()).as_str(),
    ] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(&[match policy.anchor {
        InstructionTargetAnchor::Scope => 0,
        InstructionTargetAnchor::HarnessConfiguration => 1,
    }]);
    hasher.update(&[match disposition {
        ApplyDisposition::Install => 0,
        ApplyDisposition::NoOp => 1,
        ApplyDisposition::Restore => 2,
        ApplyDisposition::ManagedUpdate => 3,
        ApplyDisposition::Remove => 4,
    }]);
    if let Some(mode) = rendered.mode.unix_mode() {
        hasher.update(&[1]);
        hasher.update(&mode.to_be_bytes());
    } else {
        hasher.update(&[0]);
        hasher.update(&[u8::from(rendered.mode.readonly())]);
    }
    if let Some(hash) = observation.document_hash() {
        hasher.update(&[1]);
        hasher.update(hash.as_str().as_bytes());
    } else {
        hasher.update(&[0]);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .expect("a lowercase BLAKE3 digest is a valid content hash")
}

const fn materialization_error(
    code: &'static str,
    message: &'static str,
) -> InstructionMaterializationError {
    InstructionMaterializationError { code, message }
}

const fn invalid_manifest() -> InstructionMaterializationError {
    materialization_error(
        "instruction_apply.manifest_invalid",
        "manifest authority is invalid",
    )
}

const fn invalid_state() -> InstructionMaterializationError {
    materialization_error(
        "instruction_apply.local_state_invalid",
        "machine-local receipt authority is invalid",
    )
}

const fn render_failed() -> InstructionMaterializationError {
    materialization_error(
        "instruction_apply.render_failed",
        "the managed instruction document could not be rendered within bounds",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use kitrove_adapter_api::{
        CapabilityMatrix, InstructionTargetAnchor, InstructionTargetPolicy, PolicyLine,
    };
    use kitrove_model::{
        BindingName, BindingResolver, HarnessId, HarnessScope, MachineConfig, MachineId,
        SchemaVersion,
    };

    use super::*;
    use crate::{
        InstructionAdoptionOutcome, TierOneInstructionCapabilities, observe_instruction_document,
        plan_instruction_adoption,
    };

    fn policy() -> InstructionTargetPolicy {
        InstructionTargetPolicy::new(
            HarnessId::Claude,
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            InstructionTargetAnchor::Scope,
            "CLAUDE.md",
            "test-instructions/1",
            "claude.instructions.current",
        )
        .unwrap()
    }

    fn capabilities() -> TierOneInstructionCapabilities {
        TierOneInstructionCapabilities::new(
            [
                HarnessId::Claude,
                HarnessId::Codex,
                HarnessId::OpenCode,
                HarnessId::Pi,
            ]
            .into_iter()
            .map(|harness| {
                (
                    harness,
                    CapabilityMatrix::empty().with_portable_instructions(
                        "test-instructions/1",
                        "test adapter accepts canonical standing instructions",
                    ),
                )
            })
            .collect(),
        )
        .unwrap()
    }

    fn empty_manifest() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    fn local_state() -> LocalState {
        LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("instruction-apply-test").unwrap(),
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

    fn adopted() -> (EnvironmentManifest, StoredInstruction, AssetId) {
        let source = tempfile::tempdir().unwrap();
        fs::write(
            source.path().join("CLAUDE.md"),
            "<!-- kitrove:instruction review begin -->\nReview carefully.\n<!-- kitrove:instruction review end -->\n",
        )
        .unwrap();
        let observation = observe_instruction_document(
            &source.path().canonicalize().unwrap(),
            &policy(),
            InstructionLimits::default(),
        )
        .unwrap();
        let asset_id = AssetId::parse("review").unwrap();
        let InstructionAdoptionOutcome::Ready(plan) =
            plan_instruction_adoption(&observation, &asset_id, &empty_manifest(), &capabilities())
                .unwrap()
        else {
            panic!("valid standing instruction must be adoptable");
        };
        (
            plan.proposed_manifest().clone(),
            plan.portable_object().clone(),
            asset_id,
        )
    }

    fn observe_target(
        contents: Option<&[u8]>,
    ) -> (tempfile::TempDir, InstructionDocumentObservation) {
        let target = tempfile::tempdir().unwrap();
        if let Some(contents) = contents {
            fs::write(target.path().join("CLAUDE.md"), contents).unwrap();
        }
        let observation = observe_existing_target(&target);
        (target, observation)
    }

    fn observe_existing_target(target: &tempfile::TempDir) -> InstructionDocumentObservation {
        observe_instruction_document(
            &target.path().canonicalize().unwrap(),
            &policy(),
            InstructionLimits::default(),
        )
        .unwrap()
    }

    fn plan_for(
        manifest: &EnvironmentManifest,
        object: &StoredInstruction,
        asset_id: &AssetId,
        observation: &InstructionDocumentObservation,
        state: &LocalState,
    ) -> Result<InstructionApplyPlan, InstructionMaterializationError> {
        plan_instruction_apply(
            manifest,
            asset_id,
            object,
            &policy(),
            observation,
            &state.to_json().unwrap(),
            InstructionLimits::default(),
        )
    }

    #[test]
    fn install_preserves_co_owned_bytes_and_proposes_region_receipt() {
        let (manifest, object, asset_id) = adopted();
        let (_target, observation) = observe_target(Some(b"Human-owned preface.\n"));
        let plan = plan_for(&manifest, &object, &asset_id, &observation, &local_state()).unwrap();

        assert_eq!(plan.disposition(), ApplyDisposition::Install);
        assert!(
            plan.rendered()
                .bytes()
                .starts_with(b"Human-owned preface.\n")
        );
        assert_eq!(
            plan.proposed_receipt().target,
            ReceiptTarget::ManagedInstructionRegion
        );
        assert_eq!(
            plan.proposed_receipt().rendered_hash,
            *plan.rendered().region_hash()
        );
        assert!(!format!("{plan:?}").contains("Human-owned preface"));
        assert!(!format!("{:?}", plan.rendered()).contains("Review carefully"));
    }

    #[test]
    fn receipt_drives_noop_restore_and_managed_update_classification() {
        let (manifest, object, asset_id) = adopted();
        let (initial_target, absent) = observe_target(None);
        let first = plan_for(&manifest, &object, &asset_id, &absent, &local_state()).unwrap();
        let installed_state = first.proposed_local_state().clone();

        fs::write(
            initial_target.path().join("CLAUDE.md"),
            first.rendered().bytes(),
        )
        .unwrap();
        let installed = observe_existing_target(&initial_target);
        assert_eq!(
            plan_for(&manifest, &object, &asset_id, &installed, &installed_state)
                .unwrap()
                .disposition(),
            ApplyDisposition::NoOp
        );
        assert_eq!(
            plan_for(&manifest, &object, &asset_id, &absent, &installed_state)
                .unwrap()
                .disposition(),
            ApplyDisposition::Restore
        );

        let mut changed_manifest = manifest.clone();
        let changed_body = kitrove_instructions::InstructionBody::parse(
            "Review carefully and explain risks.",
            InstructionLimits::default().max_body_bytes,
        )
        .unwrap();
        let changed_object = StoredInstruction::new(changed_body);
        let asset = changed_manifest.assets.get_mut(&asset_id).unwrap();
        asset.portable.as_mut().unwrap().object_hash = changed_object.object_hash().clone();
        asset.refresh_content_hash();
        changed_manifest.validate().unwrap();
        assert_eq!(
            plan_for(
                &changed_manifest,
                &changed_object,
                &asset_id,
                &installed,
                &installed_state,
            )
            .unwrap()
            .disposition(),
            ApplyDisposition::ManagedUpdate
        );
    }

    #[test]
    fn unmanaged_or_modified_regions_are_never_overwritten() {
        let (manifest, object, asset_id) = adopted();
        let (_unmanaged_target, unmanaged) = observe_target(Some(
            b"<!-- kitrove:instruction review begin -->\nUnmanaged.\n<!-- kitrove:instruction review end -->\n",
        ));
        assert_eq!(
            plan_for(&manifest, &object, &asset_id, &unmanaged, &local_state())
                .unwrap_err()
                .code(),
            "instruction_apply.region_unmanaged"
        );

        let (target, absent) = observe_target(None);
        let first = plan_for(&manifest, &object, &asset_id, &absent, &local_state()).unwrap();
        let edited = String::from_utf8(first.rendered().bytes().to_vec())
            .unwrap()
            .replace("Review carefully.", "Edited outside Kitrove.");
        fs::write(target.path().join("CLAUDE.md"), edited).unwrap();
        let edited = observe_existing_target(&target);
        assert_eq!(
            plan_for(
                &manifest,
                &object,
                &asset_id,
                &edited,
                first.proposed_local_state(),
            )
            .unwrap_err()
            .code(),
            "instruction_apply.region_modified"
        );
    }

    #[test]
    fn exact_policy_and_observation_are_freshness_authority() {
        let (manifest, object, asset_id) = adopted();
        let (_target, observation) = observe_target(None);
        let mut other_policy = policy();
        other_policy.adapter_version = "other/1";
        assert_eq!(
            plan_instruction_apply(
                &manifest,
                &asset_id,
                &object,
                &other_policy,
                &observation,
                &local_state().to_json().unwrap(),
                InstructionLimits::default(),
            )
            .unwrap_err()
            .code(),
            "instruction_apply.policy_mismatch"
        );

        let plan = plan_for(&manifest, &object, &asset_id, &observation, &local_state()).unwrap();
        assert!(plan.ensure_manifest_fresh(&manifest).is_ok());
        let state_text = local_state().to_json().unwrap();
        assert!(plan.ensure_local_state_fresh(&state_text).is_ok());
        let (_changed_target, changed) = observe_target(Some(b"Human edit.\n"));
        assert_eq!(
            plan.ensure_observation_fresh(&changed).unwrap_err().code(),
            "instruction_apply.observation_stale"
        );
        let mut changed_manifest = manifest.clone();
        changed_manifest.assets.clear();
        assert_eq!(
            plan.ensure_manifest_fresh(&changed_manifest)
                .unwrap_err()
                .code(),
            "instruction_apply.manifest_stale"
        );
        let mut changed_state = local_state();
        changed_state.machine.active_profile =
            Some(kitrove_model::ProfileId::parse("other").unwrap());
        assert_eq!(
            plan.ensure_local_state_fresh(&changed_state.to_json().unwrap())
                .unwrap_err()
                .code(),
            "instruction_apply.local_state_stale"
        );
    }

    #[test]
    fn whole_document_and_shared_region_ownership_require_other_workflows() {
        let (manifest, object, asset_id) = adopted();
        let (target, absent) = observe_target(None);
        let first = plan_for(&manifest, &object, &asset_id, &absent, &local_state()).unwrap();

        let mut whole_state = local_state();
        let mut whole = first.proposed_receipt().clone();
        whole.target = ReceiptTarget::WholeTarget;
        let whole_id = whole.receipt_id().unwrap();
        whole_state.receipts.insert(whole_id, whole);
        assert_eq!(
            plan_for(&manifest, &object, &asset_id, &absent, &whole_state)
                .unwrap_err()
                .code(),
            "instruction_apply.destination_owned_whole"
        );

        fs::write(target.path().join("CLAUDE.md"), first.rendered().bytes()).unwrap();
        let installed = observe_existing_target(&target);
        let mut shared_state = local_state();
        let mut shared = first.proposed_receipt().clone();
        shared.shared_with.insert(HarnessId::Codex);
        shared
            .shared_adapter_versions
            .insert(HarnessId::Codex, "codex-instructions/1".to_owned());
        let shared_id = shared.receipt_id().unwrap();
        shared_state.receipts.insert(shared_id, shared);
        assert_eq!(
            plan_for(&manifest, &object, &asset_id, &installed, &shared_state)
                .unwrap_err()
                .code(),
            "instruction_apply.shared_batch_required"
        );
    }

    #[test]
    fn materialization_rechecks_credential_risk_without_disclosure() {
        let (mut manifest, _object, asset_id) = adopted();
        let body = kitrove_instructions::InstructionBody::parse(
            "Use sk-live-12345678901234567890 for authentication.",
            InstructionLimits::default().max_body_bytes,
        )
        .unwrap();
        let object = StoredInstruction::new(body);
        let asset = manifest.assets.get_mut(&asset_id).unwrap();
        asset.portable.as_mut().unwrap().object_hash = object.object_hash().clone();
        asset.refresh_content_hash();
        manifest.validate().unwrap();
        let (_target, observation) = observe_target(None);

        let error =
            plan_for(&manifest, &object, &asset_id, &observation, &local_state()).unwrap_err();
        assert_eq!(error.code(), "instruction_apply.credential_shaped_body");
        assert!(!format!("{error:?}").contains("sk-live"));
    }
}
