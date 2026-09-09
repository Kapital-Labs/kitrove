use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use kitrove_adapter_api::{CapabilityMatrix, InstructionTargetAnchor, PolicyLine};
use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{BindingName, BindingResolver, MachineConfig, MachineId, SchemaVersion};

use super::*;
use crate::{
    AtomicApplyBatchPlan, AtomicApplyItem, InstructionAdoptionOutcome,
    InstructionRemovalProjection, ObjectStore, TierOneInstructionCapabilities,
    commit_atomic_apply_batch, observe_instruction_document, plan_coalesced_instruction_removal,
    plan_instruction_adoption,
};

fn policy(harness: HarnessId) -> InstructionTargetPolicy {
    let (line, evidence) = match harness {
        HarnessId::Claude => (PolicyLine::ClaudeCurrent, "claude.instructions.current"),
        HarnessId::Codex => (PolicyLine::CodexCurrent, "codex.instructions.current"),
        HarnessId::Pi => (PolicyLine::PiLatest, "pi.instructions.current"),
        HarnessId::OpenCode => (PolicyLine::OpenCodeCurrent, "opencode.instructions.current"),
        _ => panic!("test uses only tier-one harnesses"),
    };
    InstructionTargetPolicy::new(
        harness,
        HarnessScope::Project,
        line,
        InstructionTargetAnchor::Scope,
        "AGENTS.md",
        "test-instructions/1",
        evidence,
    )
    .unwrap()
}

fn policy_with_evidence(harness: HarnessId, evidence: &str) -> InstructionTargetPolicy {
    let mut policy = policy(harness);
    policy.evidence = kitrove_adapter_api::EvidenceRef::parse(evidence).unwrap();
    policy
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
            id: MachineId::parse("instruction-batch-test").unwrap(),
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

fn adopted_assets() -> (EnvironmentManifest, BTreeMap<AssetId, StoredInstruction>) {
    let source = tempfile::tempdir().unwrap();
    fs::write(
        source.path().join("AGENTS.md"),
        concat!(
            "<!-- kitrove:instruction review begin -->\n",
            "Review carefully.\n",
            "<!-- kitrove:instruction review end -->\n\n",
            "<!-- kitrove:instruction test begin -->\n",
            "Run focused tests.\n",
            "<!-- kitrove:instruction test end -->\n",
        ),
    )
    .unwrap();
    let observation = observe_instruction_document(
        &source.path().canonicalize().unwrap(),
        &policy(HarnessId::Codex),
        InstructionLimits::default(),
    )
    .unwrap();
    let mut manifest = empty_manifest();
    let mut objects = BTreeMap::new();
    for raw_id in ["review", "test"] {
        let asset_id = AssetId::parse(raw_id).unwrap();
        let InstructionAdoptionOutcome::Ready(plan) =
            plan_instruction_adoption(&observation, &asset_id, &manifest, &capabilities()).unwrap()
        else {
            panic!("valid standing instruction must be adoptable");
        };
        manifest = plan.proposed_manifest().clone();
        objects.insert(asset_id, plan.portable_object().clone());
    }
    (manifest, objects)
}

fn observe(target: &tempfile::TempDir, harness: HarnessId) -> InstructionDocumentObservation {
    observe_instruction_document(
        &target.path().canonicalize().unwrap(),
        &policy(harness),
        InstructionLimits::default(),
    )
    .unwrap()
}

fn projection(
    objects: &BTreeMap<AssetId, StoredInstruction>,
    asset: &str,
    harness: HarnessId,
    observation: InstructionDocumentObservation,
) -> InstructionProjection {
    let asset_id = AssetId::parse(asset).unwrap();
    InstructionProjection::new(
        asset_id.clone(),
        objects[&asset_id].clone(),
        policy(harness),
        observation,
    )
}

pub(crate) struct AtomicInstructionFixture {
    _temporary: tempfile::TempDir,
    pub(crate) environment: std::path::PathBuf,
    pub(crate) state: std::path::PathBuf,
    pub(crate) target: std::path::PathBuf,
    manifest: EnvironmentManifest,
    objects: BTreeMap<AssetId, StoredInstruction>,
}

impl AtomicInstructionFixture {
    pub(crate) fn new(initial_target: &str) -> Self {
        let (manifest, objects) = adopted_assets();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let environment = root.join("environment");
        let state = root.join("state");
        let target = root.join("target");
        fs::create_dir(&environment).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(
            environment.join("kitrove.toml"),
            manifest.to_toml().unwrap(),
        )
        .unwrap();
        let environment_store = ObjectStore::open(&environment).unwrap();
        let environment_lock = environment_store.try_lock_environment().unwrap();
        for (index, (asset_id, object)) in objects.iter().enumerate() {
            let portable = manifest.assets[asset_id].portable.as_ref().unwrap();
            let staging = kitrove_model::PortablePath::parse(format!(
                ".kitrove/test-instruction-batch-{index}"
            ))
            .unwrap();
            environment_store
                .stage_portable_instruction(&staging, object, CaptureLimits::default())
                .unwrap();
            environment_store
                .install_portable_instruction(
                    &staging,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
        }
        drop(environment_lock);
        crate::test_authority::initialize_private_state(&state, &local_state()).unwrap();
        crate::test_authority::write_owned_fixture_file(target.join("AGENTS.md"), initial_target)
            .unwrap();
        Self {
            _temporary: temporary,
            environment,
            state,
            target,
            manifest,
            objects,
        }
    }

    pub(crate) fn batch(&self) -> AtomicApplyBatchPlan {
        let observe_at = |harness| {
            observe_instruction_document(
                &self.target,
                &policy(harness),
                InstructionLimits::default(),
            )
            .unwrap()
        };
        let projections = vec![
            projection(
                &self.objects,
                "review",
                HarnessId::Codex,
                observe_at(HarnessId::Codex),
            ),
            projection(
                &self.objects,
                "review",
                HarnessId::Pi,
                observe_at(HarnessId::Pi),
            ),
            projection(
                &self.objects,
                "test",
                HarnessId::Codex,
                observe_at(HarnessId::Codex),
            ),
        ];
        let coalesced = plan_coalesced_instruction_apply(
            &self.manifest,
            projections,
            &fs::read_to_string(self.state.join("state.json")).unwrap(),
            Some(ProfileId::parse("default").unwrap()),
            InstructionLimits::default(),
        )
        .unwrap();
        AtomicApplyBatchPlan::with_instructions(Vec::new(), coalesced).unwrap()
    }

    pub(crate) fn removal_batch(
        &self,
        asset: &str,
        consumers: &[HarnessId],
    ) -> AtomicApplyBatchPlan {
        let projections = consumers
            .iter()
            .cloned()
            .map(|harness| {
                let target_policy = policy(harness);
                let observation = observe_instruction_document(
                    &self.target,
                    &target_policy,
                    InstructionLimits::default(),
                )
                .unwrap();
                InstructionRemovalProjection::new(target_policy, observation)
            })
            .collect();
        let removal = plan_coalesced_instruction_removal(
            &self.manifest,
            &AssetId::parse(asset).unwrap(),
            projections,
            &fs::read_to_string(self.state.join("state.json")).unwrap(),
            InstructionLimits::default(),
        )
        .unwrap();
        AtomicApplyBatchPlan::with_instructions(Vec::new(), removal).unwrap()
    }
}

#[test]
fn three_harnesses_share_one_physical_region_and_receipt() {
    let (manifest, objects) = adopted_assets();
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("AGENTS.md"), "Human preface.\n").unwrap();
    let projections = [HarnessId::Codex, HarnessId::Pi, HarnessId::OpenCode]
        .into_iter()
        .map(|harness| {
            projection(
                &objects,
                "review",
                harness.clone(),
                observe(&target, harness),
            )
        })
        .collect();
    let plan = plan_coalesced_instruction_apply(
        &manifest,
        projections,
        &local_state().to_json().unwrap(),
        None,
        InstructionLimits::default(),
    )
    .unwrap();

    assert_eq!(plan.documents().len(), 1);
    assert_eq!(plan.documents()[0].regions().len(), 1);
    let receipt = plan.documents()[0].regions()[0].proposed_receipt().unwrap();
    assert_eq!(receipt.consumers().count(), 3);
    assert_eq!(receipt.shared_adapter_versions.len(), 2);
    let rendered = std::str::from_utf8(plan.documents()[0].rendered().bytes()).unwrap();
    assert_eq!(
        rendered.matches("kitrove:instruction review begin").count(),
        1
    );
    assert!(rendered.starts_with("Human preface.\n"));
}

#[test]
fn multiple_assets_are_one_document_mutation_and_preserve_co_owned_bytes() {
    let (manifest, objects) = adopted_assets();
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("AGENTS.md"), "Human preface.\n").unwrap();
    let codex = observe(&target, HarnessId::Codex);
    let projections = vec![
        projection(&objects, "test", HarnessId::Codex, codex.clone()),
        projection(&objects, "review", HarnessId::Codex, codex),
    ];
    let plan = plan_coalesced_instruction_apply(
        &manifest,
        projections,
        &local_state().to_json().unwrap(),
        Some(ProfileId::parse("default").unwrap()),
        InstructionLimits::default(),
    )
    .unwrap();

    assert_eq!(plan.documents().len(), 1);
    assert_eq!(plan.documents()[0].regions().len(), 2);
    assert_eq!(plan.proposed_local_state().receipts.len(), 2);
    assert_eq!(
        plan.proposed_local_state().machine.active_profile.as_ref(),
        plan.active_profile()
    );
    let rendered = std::str::from_utf8(plan.documents()[0].rendered().bytes()).unwrap();
    assert!(rendered.starts_with("Human preface.\n"));
    assert!(rendered.contains("Review carefully."));
    assert!(rendered.contains("Run focused tests."));
}

#[test]
fn shared_receipt_replans_as_one_noop_document() {
    let (manifest, objects) = adopted_assets();
    let target = tempfile::tempdir().unwrap();
    let initial = [HarnessId::Codex, HarnessId::Pi]
        .into_iter()
        .map(|harness| {
            projection(
                &objects,
                "review",
                harness.clone(),
                observe(&target, harness),
            )
        })
        .collect();
    let first = plan_coalesced_instruction_apply(
        &manifest,
        initial,
        &local_state().to_json().unwrap(),
        None,
        InstructionLimits::default(),
    )
    .unwrap();
    fs::write(
        target.path().join("AGENTS.md"),
        first.documents()[0].rendered().bytes(),
    )
    .unwrap();
    let next = [HarnessId::Codex, HarnessId::Pi]
        .into_iter()
        .map(|harness| {
            projection(
                &objects,
                "review",
                harness.clone(),
                observe(&target, harness),
            )
        })
        .collect();
    let second = plan_coalesced_instruction_apply(
        &manifest,
        next,
        first.proposed_local_state_text(),
        None,
        InstructionLimits::default(),
    )
    .unwrap();

    assert_eq!(second.documents()[0].disposition(), ApplyDisposition::NoOp);
    assert_eq!(
        second.documents()[0].regions()[0].disposition(),
        ApplyDisposition::NoOp
    );
    assert_eq!(
        second.observed_local_state_text(),
        second.proposed_local_state_text()
    );
}

#[test]
fn disagreeing_observations_fail_before_coalescing() {
    let (manifest, objects) = adopted_assets();
    let target = tempfile::tempdir().unwrap();
    fs::write(target.path().join("AGENTS.md"), "First.\n").unwrap();
    let first = observe(&target, HarnessId::Codex);
    fs::write(target.path().join("AGENTS.md"), "Second.\n").unwrap();
    let second = observe(&target, HarnessId::Pi);
    let error = plan_coalesced_instruction_apply(
        &manifest,
        vec![
            projection(&objects, "review", HarnessId::Codex, first),
            projection(&objects, "review", HarnessId::Pi, second),
        ],
        &local_state().to_json().unwrap(),
        None,
        InstructionLimits::default(),
    )
    .unwrap_err();

    assert_eq!(
        error.code(),
        "instruction_batch.document_authority_mismatch"
    );
}

#[test]
fn document_digest_binds_exact_consumer_policy_evidence() {
    let (manifest, objects) = adopted_assets();
    let target = tempfile::tempdir().unwrap();
    let plan_for = |evidence: &str| {
        let policy = policy_with_evidence(HarnessId::Codex, evidence);
        let observation = observe_instruction_document(
            &target.path().canonicalize().unwrap(),
            &policy,
            InstructionLimits::default(),
        )
        .unwrap();
        let asset_id = AssetId::parse("review").unwrap();
        plan_coalesced_instruction_apply(
            &manifest,
            vec![InstructionProjection::new(
                asset_id.clone(),
                objects[&asset_id].clone(),
                policy,
                observation,
            )],
            &local_state().to_json().unwrap(),
            None,
            InstructionLimits::default(),
        )
        .unwrap()
    };

    assert_ne!(
        plan_for("codex.instructions.current").documents()[0].digest(),
        plan_for("codex.instructions.reviewed").documents()[0].digest()
    );
}

#[test]
fn atomic_coordinator_commits_one_shared_multi_region_document_and_state() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    let batch = fixture.batch();
    let AtomicApplyItem::Instruction(item) = &batch.items()[0] else {
        panic!("fixture must contain one physical instruction document");
    };
    let expected = item.document().rendered().bytes().to_vec();
    commit_atomic_apply_batch(
        &batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();

    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        expected
    );
    let committed =
        LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(committed.receipts.len(), 2);
    assert_eq!(
        committed.machine.active_profile,
        Some(ProfileId::parse("default").unwrap())
    );

    let noop = fixture.batch();
    assert_eq!(noop.items()[0].disposition(), ApplyDisposition::NoOp);
    commit_atomic_apply_batch(
        &noop,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        expected
    );

    fs::remove_file(fixture.target.join("AGENTS.md")).unwrap();
    let restore = fixture.batch();
    let AtomicApplyItem::Instruction(item) = &restore.items()[0] else {
        unreachable!();
    };
    assert_eq!(item.document().disposition(), ApplyDisposition::Install);
    assert!(
        item.document()
            .regions()
            .iter()
            .all(|region| region.disposition() == ApplyDisposition::Restore)
    );
    let restored = item.document().rendered().bytes().to_vec();
    commit_atomic_apply_batch(
        &restore,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        restored
    );
    assert!(
        !std::str::from_utf8(&restored)
            .unwrap()
            .contains("Human preface")
    );
}

#[test]
fn atomic_removal_preserves_co_owned_bytes_and_clears_stale_active_profile() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    let install = fixture.batch();
    commit_atomic_apply_batch(
        &install,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let batch = fixture.removal_batch("review", &[HarnessId::Codex, HarnessId::Pi]);
    commit_atomic_apply_batch(
        &batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();

    let document = fs::read_to_string(fixture.target.join("AGENTS.md")).unwrap();
    assert!(document.starts_with("Human preface.\n"));
    assert!(!document.contains("kitrove:instruction review"));
    assert!(document.contains("kitrove:instruction test"));
    let state =
        LocalState::from_json(&fs::read_to_string(fixture.state.join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.machine.active_profile, None);
}

#[test]
fn removal_refuses_a_modified_region_without_changing_state() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    commit_atomic_apply_batch(
        &fixture.batch(),
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let state_before = fs::read(fixture.state.join("state.json")).unwrap();
    let document = fs::read_to_string(fixture.target.join("AGENTS.md")).unwrap();
    fs::write(
        fixture.target.join("AGENTS.md"),
        document.replace("Review carefully.", "Review differently."),
    )
    .unwrap();
    let projections = [HarnessId::Codex, HarnessId::Pi]
        .into_iter()
        .map(|harness| {
            let target_policy = policy(harness);
            let observation = observe_instruction_document(
                &fixture.target,
                &target_policy,
                InstructionLimits::default(),
            )
            .unwrap();
            InstructionRemovalProjection::new(target_policy, observation)
        })
        .collect();
    let error = plan_coalesced_instruction_removal(
        &fixture.manifest,
        &AssetId::parse("review").unwrap(),
        projections,
        std::str::from_utf8(&state_before).unwrap(),
        InstructionLimits::default(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "instruction_remove.region_modified");
    assert_eq!(
        fs::read(fixture.state.join("state.json")).unwrap(),
        state_before
    );
}
