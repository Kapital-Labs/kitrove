use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_instructions::{NativeInstructionRegion, StoredInstruction};
use kitrove_model::{
    Asset, AssetId, AssetKind, ContentHash, DeploymentReceipt, EnvironmentManifest, LocalState,
    Lockfile, Revision, SchemaVersion,
};

use crate::adoption::content_addressed_update_root;
use crate::update::replace_receipt_in_local_state;
use crate::{
    InstructionAdoptionOutcome, InstructionDocumentObservation, ScanClassification, ScanReport,
    TierOneInstructionCapabilities, classify_instruction_region, compare_lockfile, derive_lockfile,
    derive_manifest_revision, plan_instruction_adoption,
};

/// Exact read-only evidence authorizing replacement of a modified managed instruction region.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionUpdateSource {
    observation: InstructionDocumentObservation,
    asset_id: AssetId,
    receipt: DeploymentReceipt,
    observed_local_state_text: String,
}

impl InstructionUpdateSource {
    #[must_use]
    pub const fn observation(&self) -> &InstructionDocumentObservation {
        &self.observation
    }

    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    #[must_use]
    pub const fn receipt(&self) -> &DeploymentReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn observed_local_state_text(&self) -> &str {
        &self.observed_local_state_text
    }
}

impl Debug for InstructionUpdateSource {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionUpdateSource")
            .field("asset_id", &self.asset_id)
            .field("receipt_id", &self.receipt.receipt_id().ok())
            .finish_non_exhaustive()
    }
}

/// A stable, authored-value-redacted instruction update failure.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionUpdateError {
    code: &'static str,
    message: &'static str,
}

impl InstructionUpdateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for InstructionUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionUpdateError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for InstructionUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for InstructionUpdateError {}

/// Complete deterministic instruction update authority that performs no writes.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionUpdatePlan {
    source: InstructionUpdateSource,
    expected_prior: ContentHash,
    prior_asset: Asset,
    asset: Asset,
    portable_object: StoredInstruction,
    native_object: NativeInstructionRegion,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    observed_lock_text: String,
    base_manifest_hash: ContentHash,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    proposed_local_state_text: String,
    digest: ContentHash,
}

impl InstructionUpdatePlan {
    #[must_use]
    pub const fn source(&self) -> &InstructionUpdateSource {
        &self.source
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
    pub const fn portable_object(&self) -> &StoredInstruction {
        &self.portable_object
    }
    #[must_use]
    pub const fn native_object(&self) -> &NativeInstructionRegion {
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
    pub fn proposed_local_state_text(&self) -> &str {
        &self.proposed_local_state_text
    }
    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    pub fn ensure_observation_fresh(
        &self,
        reread: &InstructionDocumentObservation,
    ) -> Result<(), InstructionUpdateError> {
        if self.source.observation() == reread {
            Ok(())
        } else {
            Err(update_error("instruction_update.observation_stale"))
        }
    }

    pub fn ensure_portable_authority_fresh(
        &self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), InstructionUpdateError> {
        let revision = derive_manifest_revision(manifest)
            .map_err(|_| update_error("instruction_update.manifest_stale"))?;
        if ContentHash::digest(manifest_text.as_bytes()) != self.base_manifest_hash
            || revision != self.base_manifest_revision
            || manifest
                .assets
                .get(self.source.asset_id())
                .map(|asset| &asset.content_hash)
                != Some(&self.expected_prior)
            || lock_text != Some(self.observed_lock_text.as_str())
            || compare_lockfile(manifest, lock_text).map(|comparison| comparison.status())
                != Ok(crate::LockStatus::InSync)
        {
            return Err(update_error("instruction_update.manifest_stale"));
        }
        Ok(())
    }

    pub fn ensure_local_state_fresh(
        &self,
        local_state_text: Option<&str>,
    ) -> Result<(), InstructionUpdateError> {
        if local_state_text == Some(self.source.observed_local_state_text()) {
            Ok(())
        } else {
            Err(update_error("instruction_update.local_state_stale"))
        }
    }
}

impl Debug for InstructionUpdatePlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionUpdatePlan")
            .field("asset_id", &self.asset.id)
            .field("expected_prior", &self.expected_prior)
            .field("proposed_revision", &self.asset.content_hash)
            .field("digest", &self.digest)
            .finish()
    }
}

impl ScanReport {
    /// Selects one modified managed instruction region from exact classified scan authority.
    pub fn select_instruction_update_source(
        &self,
        observation_revision: &ContentHash,
        asset_id: &AssetId,
        local_state_text: Option<&str>,
    ) -> Result<InstructionUpdateSource, InstructionUpdateError> {
        if self.mode != crate::ScanMode::Classified {
            return Err(update_error("instruction_update.classified_scan_required"));
        }
        let matching = self
            .instruction_observations()
            .iter()
            .filter(|observation| {
                observation
                    .region(asset_id)
                    .is_some_and(|region| region.observation_revision() == observation_revision)
            })
            .collect::<Vec<_>>();
        let [observation] = matching.as_slice() else {
            return Err(update_error("instruction_update.observation_unavailable"));
        };
        let entries = self
            .instructions
            .iter()
            .filter(|entry| {
                entry.asset_id == *asset_id
                    && entry.observation_revision.as_ref() == Some(observation_revision)
                    && entry.harness == *observation.harness()
                    && entry.scope == observation.scope()
                    && entry.destination == *observation.destination()
            })
            .collect::<Vec<_>>();
        let [entry] = entries.as_slice() else {
            return Err(update_error("instruction_update.classification_ambiguous"));
        };
        let region = observation
            .region(asset_id)
            .ok_or_else(|| update_error("instruction_update.observation_unavailable"))?;
        if entry.classification != ScanClassification::ManagedModified
            || !entry.findings.is_empty()
            || entry.exact_region_hash.as_ref() != Some(region.exact_region_hash())
        {
            return Err(update_error("instruction_update.managed_modified_required"));
        }
        let receipt_id = entry
            .receipt_id
            .clone()
            .ok_or_else(|| update_error("instruction_update.receipt_invalid"))?;
        let state_text = local_state_text
            .ok_or_else(|| update_error("instruction_update.local_state_invalid"))?;
        let state = LocalState::from_json(state_text)
            .map_err(|_| update_error("instruction_update.local_state_invalid"))?;
        let receipt = state
            .receipts
            .get(&receipt_id)
            .cloned()
            .ok_or_else(|| update_error("instruction_update.receipt_invalid"))?;
        if receipt.receipt_id().ok().as_ref() != Some(&receipt_id)
            || receipt.asset_id != *asset_id
            || receipt.rendered_hash == *region.exact_region_hash()
            || classify_instruction_region(observation, asset_id, Some(&receipt))
                .ok()
                .flatten()
                != Some(ScanClassification::ManagedModified)
        {
            return Err(update_error("instruction_update.receipt_invalid"));
        }
        Ok(InstructionUpdateSource {
            observation: (*observation).clone(),
            asset_id: asset_id.clone(),
            receipt,
            observed_local_state_text: state_text.to_owned(),
        })
    }
}

/// Plans an exact-prior managed instruction replacement without mutating any state.
#[allow(clippy::too_many_arguments)]
pub fn plan_instruction_update(
    source: &InstructionUpdateSource,
    expected_prior: &ContentHash,
    manifest_text: &str,
    manifest: &EnvironmentManifest,
    lock_text: Option<&str>,
    capabilities: &TierOneInstructionCapabilities,
) -> Result<InstructionUpdatePlan, InstructionUpdateError> {
    manifest
        .validate()
        .map_err(|_| update_error("instruction_update.manifest_invalid"))?;
    if EnvironmentManifest::from_toml(manifest_text).as_ref() != Ok(manifest) {
        return Err(update_error("instruction_update.manifest_invalid"));
    }
    let base_manifest_hash = ContentHash::digest(manifest_text.as_bytes());
    let base_manifest_revision = derive_manifest_revision(manifest)
        .map_err(|_| update_error("instruction_update.manifest_invalid"))?;
    let observed_lock_text = lock_text
        .filter(|text| {
            compare_lockfile(manifest, Some(text)).map(|comparison| comparison.status())
                == Ok(crate::LockStatus::InSync)
        })
        .ok_or_else(|| update_error("instruction_update.lock_not_in_sync"))?
        .to_owned();
    let prior_asset = manifest
        .assets
        .get(source.asset_id())
        .filter(|asset| asset.kind == AssetKind::Instruction)
        .ok_or_else(|| update_error("instruction_update.asset_missing"))?;
    if &prior_asset.content_hash != expected_prior {
        return Err(update_error("instruction_update.expected_prior_mismatch"));
    }
    if source.receipt.source_hash != *expected_prior
        || source.receipt.environment_revision != base_manifest_revision
    {
        return Err(update_error("instruction_update.receipt_stale"));
    }

    let empty = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let InstructionAdoptionOutcome::Ready(candidate) = plan_instruction_adoption(
        source.observation(),
        source.asset_id(),
        &empty,
        capabilities,
    )
    .map_err(|_| update_error("instruction_update.derivation_failed"))?
    else {
        return Err(update_error("instruction_update.content_blocked"));
    };
    let portable_object = candidate.portable_object().clone();
    let native_object = candidate.native_object().clone();
    let mut asset = candidate.asset().clone();
    let portable = asset
        .portable
        .as_mut()
        .ok_or_else(|| update_error("instruction_update.derivation_failed"))?;
    portable.root = content_addressed_update_root(source.asset_id(), None, &portable.object_hash)
        .map_err(|_| update_error("instruction_update.object_path_invalid"))?;
    let native = asset
        .native_variants
        .get_mut(source.observation().harness())
        .ok_or_else(|| update_error("instruction_update.derivation_failed"))?;
    native.root = content_addressed_update_root(
        source.asset_id(),
        Some(source.observation().harness()),
        &native.object_hash,
    )
    .map_err(|_| update_error("instruction_update.object_path_invalid"))?;
    asset.refresh_content_hash();
    if asset.content_hash == *expected_prior {
        return Err(update_error("instruction_update.revision_unchanged"));
    }

    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .assets
        .insert(source.asset_id().clone(), asset.clone());
    proposed_manifest
        .validate()
        .map_err(|_| update_error("instruction_update.proposed_manifest_invalid"))?;
    let proposed_lock = derive_lockfile(&proposed_manifest)
        .map_err(|_| update_error("instruction_update.proposed_lock_invalid"))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| update_error("instruction_update.proposed_manifest_invalid"))?;
    let proposed_local_state_text = rebase_receipt(source, &asset, &proposed_manifest_revision)?;
    let digest = plan_digest(
        source,
        expected_prior,
        &asset,
        &base_manifest_hash,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &observed_lock_text,
        &proposed_lock,
        &proposed_local_state_text,
    )?;
    Ok(InstructionUpdatePlan {
        source: source.clone(),
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
        proposed_local_state_text,
        digest,
    })
}

fn rebase_receipt(
    source: &InstructionUpdateSource,
    asset: &Asset,
    proposed_revision: &Revision,
) -> Result<String, InstructionUpdateError> {
    let old = source.receipt();
    let region = source
        .observation()
        .region(source.asset_id())
        .ok_or_else(|| update_error("instruction_update.observation_unavailable"))?;
    let replacement = DeploymentReceipt {
        asset_id: old.asset_id.clone(),
        harness: old.harness.clone(),
        scope: old.scope,
        destination: old.destination.clone(),
        target: old.target,
        logical_key: old.logical_key.clone(),
        shared_with: old.shared_with.clone(),
        shared_adapter_versions: old.shared_adapter_versions.clone(),
        source_hash: asset.content_hash.clone(),
        rendered_hash: region.exact_region_hash().clone(),
        document_hash: old.document_hash.clone(),
        prior_hash: Some(old.rendered_hash.clone()),
        adapter_version: old.adapter_version.clone(),
        environment_revision: proposed_revision.clone(),
    };
    replace_receipt_in_local_state(source.observed_local_state_text(), old, replacement)
        .map_err(|()| update_error("instruction_update.local_state_invalid"))
}

#[allow(clippy::too_many_arguments)]
fn plan_digest(
    source: &InstructionUpdateSource,
    expected_prior: &ContentHash,
    asset: &Asset,
    base_manifest_hash: &ContentHash,
    base_revision: &Revision,
    proposed_revision: &Revision,
    observed_lock: &str,
    proposed_lock: &Lockfile,
    proposed_state: &str,
) -> Result<ContentHash, InstructionUpdateError> {
    let lock = proposed_lock
        .to_json()
        .map_err(|_| update_error("instruction_update.plan_digest_failed"))?;
    let region = source
        .observation()
        .region(source.asset_id())
        .ok_or_else(|| update_error("instruction_update.observation_unavailable"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-update-plan-v1\0");
    for value in [
        source.asset_id().as_str(),
        region.observation_revision().as_str(),
        expected_prior.as_str(),
        asset.content_hash.as_str(),
        base_manifest_hash.as_str(),
        base_revision.as_str(),
        proposed_revision.as_str(),
        ContentHash::digest(observed_lock.as_bytes()).as_str(),
        ContentHash::digest(lock.as_bytes()).as_str(),
        ContentHash::digest(proposed_state.as_bytes()).as_str(),
    ] {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| update_error("instruction_update.plan_digest_failed"))
}

fn update_error(code: &'static str) -> InstructionUpdateError {
    let message = match code {
        "instruction_update.classified_scan_required" => {
            "instruction update selection requires a classified scan"
        }
        "instruction_update.observation_unavailable" => {
            "the exact instruction observation is unavailable"
        }
        "instruction_update.classification_ambiguous" => {
            "instruction update classification is ambiguous"
        }
        "instruction_update.managed_modified_required" => {
            "instruction update requires unambiguous managed-modified authority"
        }
        "instruction_update.receipt_invalid" => "the instruction update receipt is invalid",
        "instruction_update.local_state_invalid" => "the instruction update local state is invalid",
        "instruction_update.manifest_invalid" => {
            "instruction update planning requires a valid manifest"
        }
        "instruction_update.lock_not_in_sync" => {
            "instruction update planning requires generated lock state in sync"
        }
        "instruction_update.asset_missing" => "the instruction asset does not exist",
        "instruction_update.expected_prior_mismatch" => {
            "the expected prior instruction revision is stale"
        }
        "instruction_update.receipt_stale" => "the instruction update receipt is stale",
        "instruction_update.content_blocked" => "the instruction update content requires review",
        "instruction_update.derivation_failed" => "the instruction update could not be derived",
        "instruction_update.revision_unchanged" => {
            "the instruction update does not produce a new revision"
        }
        "instruction_update.proposed_manifest_invalid" => {
            "the proposed instruction manifest is invalid"
        }
        "instruction_update.proposed_lock_invalid" => "the proposed instruction lock is invalid",
        "instruction_update.observation_stale" => "the instruction document changed after planning",
        "instruction_update.manifest_stale" => {
            "portable instruction authority changed after planning"
        }
        "instruction_update.local_state_stale" => {
            "machine-local instruction authority changed after planning"
        }
        _ => "the instruction update proposal is invalid",
    };
    InstructionUpdateError { code, message }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kitrove_adapter_api::{
        CapabilityMatrix, InstructionTargetAnchor, InstructionTargetPolicy, PolicyLine,
    };
    use kitrove_agent_skills::CaptureUsage;
    use kitrove_instructions::InstructionLimits;
    use kitrove_model::{HarnessId, HarnessScope, MachineConfig, MachineId, ReceiptTarget};

    use super::*;
    use crate::adoption::tier_one_harnesses;
    use crate::{InstructionScanEntry, ScanMode, observe_instruction_document};

    fn capabilities() -> TierOneInstructionCapabilities {
        TierOneInstructionCapabilities::new(
            tier_one_harnesses()
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

    fn policy() -> InstructionTargetPolicy {
        InstructionTargetPolicy::new(
            HarnessId::Codex,
            HarnessScope::Project,
            PolicyLine::CodexCurrent,
            InstructionTargetAnchor::Scope,
            "AGENTS.md",
            "test-instructions/1",
            "test.instructions",
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

    fn write_region(root: &std::path::Path, body: &str) -> InstructionDocumentObservation {
        fs::write(
            root.join("AGENTS.md"),
            format!(
                "Human preface.\n<!-- kitrove:instruction review begin -->\n{body}\n<!-- kitrove:instruction review end -->\n"
            ),
        )
        .unwrap();
        observe_instruction_document(root, &policy(), InstructionLimits::default()).unwrap()
    }

    struct Fixture {
        _root: tempfile::TempDir,
        manifest: EnvironmentManifest,
        state_text: String,
        report: ScanReport,
        asset_id: AssetId,
        revision: ContentHash,
    }

    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let anchor = root.path().canonicalize().unwrap();
        let asset_id = AssetId::parse("review").unwrap();
        let old = write_region(&anchor, "Review carefully.");
        let InstructionAdoptionOutcome::Ready(adoption) =
            plan_instruction_adoption(&old, &asset_id, &empty_manifest(), &capabilities()).unwrap()
        else {
            panic!("old instruction must be adoptable");
        };
        let manifest = adoption.proposed_manifest().clone();
        let environment_revision = derive_manifest_revision(&manifest).unwrap();
        let old_region = old.region(&asset_id).unwrap();
        let receipt = DeploymentReceipt {
            asset_id: asset_id.clone(),
            harness: HarnessId::Codex,
            scope: HarnessScope::Project,
            destination: old.destination().clone(),
            target: ReceiptTarget::ManagedInstructionRegion,
            logical_key: None,
            shared_with: BTreeSet::from([HarnessId::Pi]),
            shared_adapter_versions: BTreeMap::from([(HarnessId::Pi, "preserved-pi/1".to_owned())]),
            source_hash: manifest.assets[&asset_id].content_hash.clone(),
            rendered_hash: old_region.exact_region_hash().clone(),
            document_hash: None,
            prior_hash: None,
            adapter_version: "test-instructions/1".to_owned(),
            environment_revision,
        };
        let receipt_id = receipt.receipt_id().unwrap();
        let state = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("instruction-update-test").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::new(),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: BTreeMap::from([(receipt_id.clone(), receipt)]),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::new(),
            scans: Vec::new(),
        };
        let modified = write_region(&anchor, "Review more carefully.");
        let region = modified.region(&asset_id).unwrap();
        let revision = region.observation_revision().clone();
        let entry = InstructionScanEntry {
            harness: HarnessId::Codex,
            scope: HarnessScope::Project,
            policy_line: PolicyLine::CodexCurrent,
            destination: modified.destination().clone(),
            asset_id: asset_id.clone(),
            observation_revision: Some(revision.clone()),
            exact_region_hash: Some(region.exact_region_hash().clone()),
            receipt_id: Some(receipt_id),
            classification: ScanClassification::ManagedModified,
            findings: Vec::new(),
        };
        let mut report = ScanReport::new(
            ScanMode::Classified,
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CaptureUsage::default(),
        );
        report.set_instructions(vec![entry], vec![modified], CaptureUsage::default());
        Fixture {
            _root: root,
            manifest,
            state_text: state.to_json().unwrap(),
            report,
            asset_id,
            revision,
        }
    }

    #[test]
    fn plans_content_addressed_replacement_and_exact_receipt_rebase() {
        let fixture = fixture();
        let source = fixture
            .report
            .select_instruction_update_source(
                &fixture.revision,
                &fixture.asset_id,
                Some(&fixture.state_text),
            )
            .unwrap();
        let manifest_text = fixture.manifest.to_toml().unwrap();
        let lock_text = derive_lockfile(&fixture.manifest)
            .unwrap()
            .to_json()
            .unwrap();
        let expected_prior = fixture.manifest.assets[&fixture.asset_id]
            .content_hash
            .clone();
        let plan = plan_instruction_update(
            &source,
            &expected_prior,
            &manifest_text,
            &fixture.manifest,
            Some(&lock_text),
            &capabilities(),
        )
        .unwrap();

        assert_ne!(plan.asset().content_hash, expected_prior);
        assert!(
            plan.asset()
                .portable
                .as_ref()
                .unwrap()
                .root
                .as_str()
                .contains("/updates/portable/blake3-")
        );
        let state = LocalState::from_json(plan.proposed_local_state_text()).unwrap();
        let receipt = state.receipts.values().next().unwrap();
        assert_eq!(receipt.source_hash, plan.asset().content_hash);
        assert_eq!(
            receipt.rendered_hash,
            source
                .observation()
                .region(&fixture.asset_id)
                .unwrap()
                .exact_region_hash()
                .clone()
        );
        assert_eq!(
            receipt.prior_hash.as_ref(),
            Some(&source.receipt().rendered_hash)
        );
        assert_eq!(
            receipt.shared_adapter_versions,
            source.receipt().shared_adapter_versions
        );
        assert!(plan.ensure_observation_fresh(source.observation()).is_ok());
        assert!(
            plan.ensure_local_state_fresh(Some(&fixture.state_text))
                .is_ok()
        );
        assert!(!format!("{plan:?}").contains("Review more carefully"));
    }

    #[test]
    fn selection_and_planning_fail_closed_on_changed_authority() {
        let mut fixture = fixture();
        fixture.report.instructions[0].classification = ScanClassification::Unmanaged;
        assert_eq!(
            fixture
                .report
                .select_instruction_update_source(
                    &fixture.revision,
                    &fixture.asset_id,
                    Some(&fixture.state_text),
                )
                .unwrap_err()
                .code(),
            "instruction_update.managed_modified_required"
        );

        fixture.report.instructions[0].classification = ScanClassification::ManagedModified;
        let source = fixture
            .report
            .select_instruction_update_source(
                &fixture.revision,
                &fixture.asset_id,
                Some(&fixture.state_text),
            )
            .unwrap();
        let lock_text = derive_lockfile(&fixture.manifest)
            .unwrap()
            .to_json()
            .unwrap();
        let prior = fixture.manifest.assets[&fixture.asset_id]
            .content_hash
            .clone();
        assert_eq!(
            plan_instruction_update(
                &source,
                &prior,
                "# semantically unrelated bytes\n",
                &fixture.manifest,
                Some(&lock_text),
                &capabilities(),
            )
            .unwrap_err()
            .code(),
            "instruction_update.manifest_invalid"
        );
    }
}
