use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use kitrove_adapter_api::{EvidenceRef, ExtensionTargetPolicy, RootId, RootTier, TargetPolicy};
#[cfg(unix)]
use kitrove_adapter_api::{HarnessAdapter as _, VersionObservation};
#[cfg(unix)]
use kitrove_adapter_pi::PiAdapter;
use kitrove_agent_skills::{
    CapturedFile, CapturedTree, FileMode, SkillSourceLayout, StoredSkillTree, hash_tree,
};
use kitrove_model::{
    Asset, AssetId, BindingName, BindingResolver, ComponentProvenance, ContentClass, ContentHash,
    DeploymentReceipt, HarnessId, HarnessScope, LocalState, MachineConfig, MachineId, ProfileId,
    Revision, SchemaVersion, TrustDecision,
};
#[cfg(unix)]
use kitrove_version_probe::probe_pi_version;

use super::*;
use crate::adoption::tests::{capabilities, empty_manifest, make_candidate};
use crate::agent_materialization::AtomicAgentFixture;
use crate::instruction_apply_batch::AtomicInstructionFixture;
use crate::mcp_materialization::AtomicMcpFixture;
use crate::prompt_command_materialization::AtomicPromptCommandFixture;
use crate::{
    AdoptionPlanOutcome, CapturedNativeExtension, NativeExtensionLayout,
    NativeExtensionObservation, PackApplicationSelection, plan_adoption, plan_extension_removal,
    plan_extension_retention, plan_native_extension_adoption, plan_skill_apply, plan_skill_removal,
};
#[cfg(unix)]
use crate::{
    ExtensionApplyAuthority, ExtensionApplyPlan, PiProjectTrustEvidence, plan_extension_apply,
    plan_native_extension_update,
};
#[cfg(unix)]
use crate::{PiProjectTrustStatus, inspect_pi_project_trust};

#[test]
fn errors_are_path_and_content_redacted() {
    let error = stale_target();
    assert_eq!(error.code(), "apply.batch_target_stale");
    assert!(!format!("{error:?}").contains('/'));
}

#[test]
fn nested_batch_target_is_invalid_not_a_retryable_lock_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let environment_path = temporary.path().join("environment");
    let state_path = temporary.path().join("state");
    let target_path = environment_path.join("nested-target");
    fs::create_dir_all(&target_path).unwrap();
    fs::create_dir(&state_path).unwrap();
    let environment_path = environment_path.canonicalize().unwrap();
    let state_path = state_path.canonicalize().unwrap();
    let target_path = target_path.canonicalize().unwrap();
    let environment = ObjectStore::open(&environment_path).unwrap();
    let state = ObjectStore::open(&state_path).unwrap();
    let target = TargetRoot {
        identity: crate::materialization::normalized_destination_from_path(&target_path).unwrap(),
        path: target_path.clone(),
        store: ObjectStore::open(&target_path).unwrap(),
        requires_lock: true,
    };

    let Err(error) = try_lock_batch_roots(&environment, &state, &[target]) else {
        panic!("nested target roots acquired independent locks");
    };

    assert_eq!(error.code(), "apply.batch_target_invalid");
    assert!(!environment_path.join(".kitrove").exists());
    assert!(!state_path.join(".kitrove").exists());
    assert!(!target_path.join(".kitrove").exists());
}

#[test]
fn fabricated_pack_application_authority_is_rejected() {
    let fixture = AtomicPromptCommandFixture::new();
    let error = fixture
        .batch
        .clone()
        .with_pack_application_ownership(
            &fixture.manifest,
            &[PackApplicationSelection {
                pack_id: AssetId::parse("absent-pack").unwrap(),
                pack_revision: ContentHash::digest(b"fabricated-pack-revision"),
                leaf_assets: BTreeSet::from([fixture.asset_id.clone()]),
            }],
            &BTreeSet::new(),
            HarnessScope::Project,
            BTreeSet::from([HarnessId::Pi]),
        )
        .unwrap_err();
    assert_eq!(error.code(), "apply.pack_application_context_invalid");
    assert!(!format!("{error:?}").contains("absent-pack"));
}

#[test]
fn no_journal_recovery_releases_locks_before_immediate_commit() {
    let fixture = AtomicPromptCommandFixture::new();

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::NoJournal
    );
    assert_eq!(
        commit_atomic_apply_batch(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchCommitOutcome::Committed
    );
}

#[test]
fn interrupted_prompt_command_install_rolls_back_file_and_receipt() {
    let fixture = AtomicPromptCommandFixture::new();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("prompt-command target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert!(!std::path::Path::new(&fixture.destination).exists());
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn recovery_refuses_a_journal_removed_during_the_lock_handoff() {
    let fixture = AtomicPromptCommandFixture::new();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());
    let target_before_recovery = fs::read(&fixture.destination).unwrap();
    let journal = fixture
        .state
        .join(local_state_authority::ATOMIC_APPLY_JOURNAL_PATH);

    let error = recovery::recover_atomic_apply_batch_inner(
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
        || fs::remove_file(&journal).unwrap(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "apply.batch_recovery_blocked");
    assert_eq!(
        fs::read(&fixture.destination).unwrap(),
        target_before_recovery
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn interrupted_agent_install_rolls_back_file_and_receipt() {
    let fixture = AtomicAgentFixture::new();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("agent target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert!(!std::path::Path::new(&fixture.destination).exists());
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn agent_removal_deletes_projection_and_receipt_but_retains_portable_authority() {
    let fixture = AtomicAgentFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();

    commit_atomic_apply_batch(
        &removal,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();

    assert!(!std::path::Path::new(&fixture.destination).exists());
    let state = LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
        .unwrap();
    assert!(state.receipts.is_empty());
    assert!(
        fixture
            .environment
            .join(
                fixture.manifest.assets[&fixture.asset_id]
                    .portable
                    .as_ref()
                    .unwrap()
                    .root
                    .as_str()
            )
            .exists()
    );
}

#[test]
fn interrupted_agent_removal_restores_file_and_receipt() {
    let fixture = AtomicAgentFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| panic!("agent removal quarantine checkpoint"),
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(fs::read(&fixture.destination).unwrap(), fixture.expected);
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn prompt_command_removal_deletes_projection_and_receipt_but_retains_portable_authority() {
    let fixture = AtomicPromptCommandFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();

    commit_atomic_apply_batch(
        &removal,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();

    assert!(!std::path::Path::new(&fixture.destination).exists());
    let state = LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
        .unwrap();
    assert!(state.receipts.is_empty());
    assert!(
        fixture
            .environment
            .join(
                fixture.manifest.assets[&fixture.asset_id]
                    .portable
                    .as_ref()
                    .unwrap()
                    .root
                    .as_str()
            )
            .exists()
    );
}

#[test]
fn interrupted_prompt_command_removal_before_state_commit_restores_file_and_receipt() {
    let fixture = AtomicPromptCommandFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| panic!("prompt-command removal quarantine checkpoint"),
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(fs::read(&fixture.destination).unwrap(), fixture.expected);
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn interrupted_prompt_command_removal_after_state_write_completes_forward() {
    let fixture = AtomicPromptCommandFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| {},
                    || panic!("prompt-command removal state checkpoint"),
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::Completed
    );
    assert!(!std::path::Path::new(&fixture.destination).exists());
    let state = LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
        .unwrap();
    assert!(state.receipts.is_empty());
}

#[test]
fn prompt_command_removal_recovery_preserves_a_concurrent_replacement() {
    let fixture = AtomicPromptCommandFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| panic!("prompt-command removal replacement checkpoint"),
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());
    fs::write(&fixture.destination, "Concurrent replacement.\n").unwrap();

    let error = recover_atomic_apply_batch(
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.batch_recovery_blocked");
    assert_eq!(
        fs::read_to_string(&fixture.destination).unwrap(),
        "Concurrent replacement.\n"
    );
}

#[test]
fn interrupted_instruction_document_rolls_back_exact_co_owned_bytes() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    let batch = fixture.batch();
    let old_target = fs::read(fixture.target.join("AGENTS.md")).unwrap();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("instruction target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        old_target
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn interrupted_mcp_document_rolls_back_exact_co_owned_bytes() {
    let fixture = AtomicMcpFixture::new();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("MCP target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(
        fs::read(fixture.target.join("claude.json")).unwrap(),
        fixture.original_document
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn interrupted_mcp_removal_restores_entry_and_receipt_together() {
    let fixture = AtomicMcpFixture::new();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch();
    let old_document = fs::read(fixture.target.join("claude.json")).unwrap();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("MCP removal target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(
        fs::read(fixture.target.join("claude.json")).unwrap(),
        old_document
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn committed_instruction_state_phase_lag_recovers_forward() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    let batch = fixture.batch();
    let AtomicApplyItem::Instruction(item) = &batch.items()[0] else {
        panic!("fixture must contain an instruction participant");
    };
    let expected_target = item.document().rendered().bytes().to_vec();
    let expected_state = batch.proposed_local_state_text().as_bytes().to_vec();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| {},
                    || panic!("instruction state checkpoint"),
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::Completed
    );
    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        expected_target
    );
    assert_eq!(
        fs::read(fixture.state.join(STATE_PATH)).unwrap(),
        expected_state
    );
}

#[test]
fn interrupted_instruction_removal_restores_region_and_receipt_together() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    commit_atomic_apply_batch(
        &fixture.batch(),
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let removal = fixture.removal_batch("review", &[HarnessId::Codex, HarnessId::Pi]);
    let old_target = fs::read(fixture.target.join("AGENTS.md")).unwrap();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("removal target checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        old_target
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn concurrent_co_owned_instruction_edit_blocks_every_batch_mutation() {
    let fixture = AtomicInstructionFixture::new("Human preface.\n");
    let batch = fixture.batch();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    fs::write(
        fixture.target.join("AGENTS.md"),
        "Human preface changed after planning.\n",
    )
    .unwrap();
    let concurrent = fs::read(fixture.target.join("AGENTS.md")).unwrap();

    let error = commit_atomic_apply_batch(
        &batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.batch_target_stale");
    assert_eq!(
        fs::read(fixture.target.join("AGENTS.md")).unwrap(),
        concurrent
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
    assert!(
        !fixture
            .state
            .join(local_state_authority::ATOMIC_APPLY_JOURNAL_PATH)
            .exists()
    );
}

#[test]
fn commit_installs_every_target_and_one_final_profile_state() {
    let fixture = batch_fixture();
    let profile = fixture.batch.active_profile().unwrap().clone();

    assert_eq!(
        commit_atomic_apply_batch(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchCommitOutcome::Committed
    );
    assert_eq!(
        LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
            .unwrap()
            .machine
            .active_profile,
        Some(profile)
    );
    for item in fixture.batch.items() {
        assert!(
            fixture
                .target
                .join(item.relative_destination().as_str())
                .exists()
        );
    }
    assert!(
        !fixture
            .state
            .join(local_state_authority::ATOMIC_APPLY_JOURNAL_PATH)
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn commit_reclaims_prior_retained_tombstone_before_new_mutation() {
    let fixture = batch_fixture();
    let obsolete = PortablePath::parse("obsolete-control").unwrap();
    fs::write(fixture.environment.join(obsolete.as_str()), "retained").unwrap();
    let store = ObjectStore::open(&fixture.environment).unwrap();
    {
        let _lock = store.try_lock_environment().unwrap();
        store.remove_regular_file_if_present(&obsolete).unwrap();
    }
    let quarantine = fixture.environment.join(".kitrove/removal-quarantine");
    assert_eq!(fs::read_dir(&quarantine).unwrap().count(), 1);

    assert_eq!(
        commit_atomic_apply_batch(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchCommitOutcome::Committed
    );

    assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn unsafe_quarantine_blocks_commit_before_journal_target_or_state_mutation() {
    let fixture = batch_fixture();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let control = fixture.environment.join(".kitrove");
    let quarantine = control.join("removal-quarantine");
    fs::create_dir(&quarantine).unwrap();
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

    let error = commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "apply.batch_storage_failed");
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
    assert!(
        !fixture
            .state
            .join(local_state_authority::ATOMIC_APPLY_JOURNAL_PATH)
            .exists()
    );
    for item in fixture.batch.items() {
        assert!(
            !fixture
                .target
                .join(item.relative_destination().as_str())
                .exists()
        );
    }
    assert!(quarantine.join("unrecognized-retained-state").exists());
}

#[test]
fn interrupted_skill_removal_restores_every_directory_and_receipt() {
    let fixture = batch_fixture();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let state_text = std::str::from_utf8(&old_state).unwrap();
    let removals = fixture
        .batch
        .items()
        .iter()
        .map(|item| {
            let AtomicApplyItem::Skill(installed) = item else {
                unreachable!()
            };
            let relative_root = match installed.harness() {
                HarnessId::Claude => ".claude/skills",
                HarnessId::Codex => ".codex/skills",
                _ => unreachable!(),
            };
            plan_skill_removal(
                &fixture.manifest,
                &fixture.asset_id,
                &fixture.object,
                &policy(relative_root, installed.harness().clone()),
                &fixture.target,
                state_text,
                observe_skill_destination(
                    &fixture
                        .target
                        .join(installed.relative_destination().as_str()),
                    CaptureLimits::default(),
                ),
            )
            .map(AtomicApplyItem::Skill)
            .unwrap()
        })
        .collect();
    let removal =
        AtomicApplyBatchPlan::new(removals, fixture.batch.active_profile().cloned()).unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &removal,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| panic!("skill removal quarantine checkpoint"),
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
    for item in fixture.batch.items() {
        assert!(
            fixture
                .target
                .join(item.relative_destination().as_str())
                .exists()
        );
    }
}

#[test]
fn prepared_interruption_rolls_back_without_destination_authority() {
    let fixture = batch_fixture();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || panic!("prepared checkpoint"),
                    |_| {},
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    for item in fixture.batch.items() {
        assert!(
            !fixture
                .target
                .join(item.relative_destination().as_str())
                .exists()
        );
    }
}

#[test]
fn committed_state_phase_lag_recovers_forward() {
    let fixture = batch_fixture();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| {},
                    || panic!("state checkpoint"),
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::Completed
    );
    for item in fixture.batch.items() {
        assert!(
            fixture
                .target
                .join(item.relative_destination().as_str())
                .exists()
        );
    }
}

#[test]
fn partial_target_commit_rolls_back_in_reverse_order() {
    let fixture = batch_fixture();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &fixture.batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |index| {
                        if index == 0 {
                            panic!("first target checkpoint");
                        }
                    },
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    for item in fixture.batch.items() {
        assert!(
            !fixture
                .target
                .join(item.relative_destination().as_str())
                .exists()
        );
    }
}

#[test]
fn quarantined_managed_update_restores_the_exact_prior_target() {
    let fixture = batch_fixture();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let installed = match &fixture.batch.items()[0] {
        AtomicApplyItem::Skill(plan) => plan,
        AtomicApplyItem::Extension(_)
        | AtomicApplyItem::Instruction(_)
        | AtomicApplyItem::PromptCommand(_)
        | AtomicApplyItem::PromptCommandRemoval(_)
        | AtomicApplyItem::Agent(_)
        | AtomicApplyItem::AgentRemoval(_)
        | AtomicApplyItem::Mcp(_) => unreachable!(),
    };
    let old_hash = installed.rendered().rendered_hash().clone();
    let old_state = fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap();
    let destination = fixture
        .target
        .join(installed.relative_destination().as_str());

    let mut files = fixture.object.tree().files.clone();
    files
        .get_mut(&PortablePath::parse("SKILL.md").unwrap())
        .unwrap()
        .bytes = b"---\nname: review\ndescription: Review code carefully\n---\nUpdated.\n".to_vec();
    let updated_object = StoredSkillTree::new(CapturedTree {
        hash: hash_tree(&files),
        files,
    })
    .unwrap();
    let mut updated_manifest = fixture.manifest.clone();
    let asset = updated_manifest.assets.get_mut(&fixture.asset_id).unwrap();
    update_portable_revision(asset, updated_object.tree().hash.clone());
    let portable = asset.portable.clone().unwrap();
    fs::write(
        fixture.environment.join(MANIFEST_PATH),
        updated_manifest.to_toml().unwrap(),
    )
    .unwrap();
    fs::remove_dir_all(fixture.environment.join(portable.root.as_str())).unwrap();
    let environment_store = ObjectStore::open(&fixture.environment).unwrap();
    let staging = PortablePath::parse(".kitrove/updated-portable").unwrap();
    environment_store
        .stage_portable(&staging, &updated_object, CaptureLimits::default())
        .unwrap();
    environment_store
        .install_portable(
            &staging,
            &portable.root,
            &portable.object_hash,
            CaptureLimits::default(),
        )
        .unwrap();
    let update = plan_skill_apply(
        &updated_manifest,
        &fixture.asset_id,
        &updated_object,
        &policy(".claude/skills", HarnessId::Claude),
        &fixture.target,
        &old_state,
        observe_skill_destination(&destination, CaptureLimits::default()),
    )
    .unwrap();
    assert_eq!(update.disposition(), ApplyDisposition::ManagedUpdate);
    let update_batch = AtomicApplyBatchPlan::new(
        vec![AtomicApplyItem::Skill(update)],
        fixture.batch.active_profile().cloned(),
    )
    .unwrap();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &update_batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &update_batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| panic!("quarantine checkpoint"),
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());

    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(
        observe_skill_destination(&destination, CaptureLimits::default()),
        DestinationObservation::Present {
            layout: SkillSourceLayout::Directory,
            rendered_hash: old_hash,
        }
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
        old_state
    );
}

#[cfg(unix)]
#[test]
fn extension_batch_commits_standalone_directory_noop_and_restore() {
    for layout in [
        NativeExtensionLayout::Standalone,
        NativeExtensionLayout::Directory,
    ] {
        let fixture = ExtensionBatchFixture::new(layout);
        let install = fixture.batch();
        commit_atomic_apply_batch(
            &install,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        fixture.assert_destination();

        let no_op = fixture.batch();
        assert_eq!(no_op.items()[0].disposition(), ApplyDisposition::NoOp);
        commit_atomic_apply_batch(
            &no_op,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        fixture.assert_destination();

        fixture.remove_destination();
        let restore = fixture.batch();
        assert_eq!(restore.items()[0].disposition(), ApplyDisposition::Restore);
        commit_atomic_apply_batch(
            &restore,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        fixture.assert_destination();
    }
}

#[cfg(unix)]
#[test]
fn extension_batch_refuses_project_trust_revoked_after_planning() {
    let mut fixture = ExtensionBatchFixture::new(NativeExtensionLayout::Standalone);
    let trust_store = fixture.enable_project_scope();
    let batch = fixture.batch();
    fs::write(
        &trust_store,
        format!("{{\"{}\":false}}", fixture.target.display()),
    )
    .unwrap();

    let error = commit_atomic_apply_batch(
        &batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.batch_target_stale");
    assert!(!fixture.destination().exists());
}

#[test]
fn extension_removal_commits_and_interrupted_removal_restores_exact_authority() {
    for layout in [
        NativeExtensionLayout::Standalone,
        NativeExtensionLayout::Directory,
    ] {
        let fixture = ExtensionBatchFixture::new(layout);
        fixture.seed_installed();
        let state_path = fixture.state.join(STATE_PATH);
        let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
        state.trust.insert(
            fixture.object.hash().clone(),
            TrustDecision::Denied {
                rationale: "revoked after installation".to_owned(),
            },
        );
        fs::write(&state_path, state.to_json().unwrap()).unwrap();
        let retained = plan_extension_retention(
            &fixture.manifest,
            &fixture.asset_id,
            &fixture.object,
            &fixture.policy,
            &fixture.target,
            &fs::read_to_string(&state_path).unwrap(),
            crate::observe_extension_destination(
                &fixture.destination(),
                &fixture.object,
                CaptureLimits::default(),
            ),
        )
        .unwrap();
        assert_eq!(retained.disposition(), ApplyDisposition::NoOp);
        let state_before = fs::read(fixture.state.join(STATE_PATH)).unwrap();
        let removal = fixture.removal_batch();
        assert_eq!(removal.items()[0].disposition(), ApplyDisposition::Remove);

        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_locked_batch_authority(
                &removal,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                |environment, state, targets, sources| {
                    commit_locked_batch(
                        &removal,
                        environment,
                        state,
                        targets,
                        sources,
                        CaptureLimits::default(),
                        || {},
                        |_| panic!("extension removal quarantine checkpoint"),
                        |_| {},
                        || {},
                    )
                },
            )
            .unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            recover_atomic_apply_batch(
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            AtomicApplyBatchRecoveryOutcome::RolledBack
        );
        fixture.assert_destination();
        assert_eq!(
            fs::read(fixture.state.join(STATE_PATH)).unwrap(),
            state_before
        );

        let removal = fixture.removal_batch();
        commit_atomic_apply_batch(
            &removal,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        assert!(!fixture.destination().exists());
        let state =
            LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                .unwrap();
        assert!(state.receipts.is_empty());
        assert!(fixture.manifest.assets.contains_key(&fixture.asset_id));
    }
}

#[test]
fn extension_removal_refuses_modified_projection_without_releasing_receipt() {
    let fixture = ExtensionBatchFixture::new(NativeExtensionLayout::Directory);
    fixture.seed_installed();
    let state_before = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    fs::write(
        fixture.destination().join("index.ts"),
        "export default { locallyModified: true };\n",
    )
    .unwrap();
    let error = plan_extension_removal(
        &fixture.manifest,
        &fixture.asset_id,
        &fixture.object,
        &fixture.policy,
        &fixture.target,
        std::str::from_utf8(&state_before).unwrap(),
        crate::observe_extension_destination(
            &fixture.destination(),
            &fixture.object,
            CaptureLimits::default(),
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.extension_modified");
    assert_eq!(
        fs::read(fixture.state.join(STATE_PATH)).unwrap(),
        state_before
    );
}

#[cfg(unix)]
#[test]
fn interrupted_extension_update_restores_exact_prior_authority() {
    let mut fixture = ExtensionBatchFixture::new(NativeExtensionLayout::Directory);
    commit_atomic_apply_batch(
        &fixture.batch(),
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let old_object = fixture.object.clone();
    let old_hash = old_object.hash().clone();
    fixture.prepare_update();
    let update = fixture.batch();
    assert_eq!(
        update.items()[0].disposition(),
        ApplyDisposition::ManagedUpdate
    );

    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &update,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &update,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| panic!("extension quarantine checkpoint"),
                    |_| {},
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    let observed = crate::observe_extension_destination(
        &fixture.destination(),
        &old_object,
        CaptureLimits::default(),
    );
    assert_eq!(
        observed,
        ExtensionDestinationObservation::Present {
            layout: NativeExtensionLayout::Directory,
            object_hash: old_hash,
        }
    );
}

#[test]
fn batch_apply_refuses_every_foreign_recovery_artifact() {
    for path in local_state_authority::ALL_LOCAL_STATE_RECOVERY
        .iter()
        .chain(local_state_authority::ALL_PORTABLE_RECOVERY)
        .filter(|path| {
            **path != local_state_authority::ATOMIC_APPLY_JOURNAL_PATH
                && **path != local_state_authority::ATOMIC_APPLY_PENDING_PATH
        })
    {
        let fixture = batch_fixture();
        let root = if local_state_authority::ALL_PORTABLE_RECOVERY.contains(path) {
            &fixture.environment
        } else {
            &fixture.state
        };
        let artifact = root.join(path);
        if local_state_authority::ALL_PORTABLE_RECOVERY.contains(path) {
            fs::create_dir_all(artifact.parent().unwrap()).unwrap();
            fs::write(artifact, b"{}\n").unwrap();
        } else {
            crate::test_authority::stage_private_text(&fixture.state, path, "{}\n").unwrap();
        }

        let error = validate_atomic_apply_batch_authority(
            &fixture.batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "apply.batch_recovery_required");
        for item in fixture.batch.items() {
            assert!(
                !fixture
                    .target
                    .join(item.relative_destination().as_str())
                    .exists()
            );
        }
    }
}

#[test]
fn concurrent_state_change_blocks_commit_and_recovery_without_overwrite() {
    let fixture = batch_fixture();
    let state_path = fixture.state.join(STATE_PATH);
    let mut concurrent = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
    concurrent.machine.active_profile = Some(ProfileId::parse("concurrent").unwrap());
    let concurrent_text = concurrent.to_json().unwrap();

    let error = with_locked_batch_authority(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
        |environment, state, targets, sources| {
            commit_locked_batch(
                &fixture.batch,
                environment,
                state,
                targets,
                sources,
                CaptureLimits::default(),
                || fs::write(&state_path, &concurrent_text).unwrap(),
                |_| {},
                |_| {},
                || {},
            )
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.batch_state_stale");
    let recovery = recover_atomic_apply_batch(
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap_err();
    assert_eq!(recovery.code(), "apply.batch_recovery_blocked");
    assert_eq!(fs::read_to_string(state_path).unwrap(), concurrent_text);
}

#[test]
fn concurrent_target_creation_blocks_commit_and_survives_rollback() {
    let fixture = batch_fixture();
    let destination = fixture
        .target
        .join(fixture.batch.items()[0].relative_destination().as_str());
    let canary = b"unmanaged concurrent target\n";

    let error = with_locked_batch_authority(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
        |environment, state, targets, sources| {
            commit_locked_batch(
                &fixture.batch,
                environment,
                state,
                targets,
                sources,
                CaptureLimits::default(),
                || {
                    fs::create_dir_all(&destination).unwrap();
                    fs::write(destination.join("SKILL.md"), canary).unwrap();
                },
                |_| {},
                |_| {},
                || {},
            )
        },
    )
    .unwrap_err();
    assert_eq!(error.code(), "apply.batch_target_stale");
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(fs::read(destination.join("SKILL.md")).unwrap(), canary);
}

#[cfg(unix)]
#[test]
fn interrupted_extension_restore_returns_to_the_exact_missing_target() {
    let fixture = ExtensionBatchFixture::new(NativeExtensionLayout::Standalone);
    commit_atomic_apply_batch(
        &fixture.batch(),
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let state_before = fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap();
    fixture.remove_destination();
    let restore = fixture.batch();
    assert_eq!(restore.items()[0].disposition(), ApplyDisposition::Restore);

    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            &restore,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    &restore,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| panic!("extension restore checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert!(!fixture.destination().exists());
    assert_eq!(
        fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
        state_before
    );
}

struct ExtensionBatchFixture {
    _root: tempfile::TempDir,
    environment: PathBuf,
    state: PathBuf,
    target: PathBuf,
    manifest: EnvironmentManifest,
    object: NativeExtensionObject,
    policy: ExtensionTargetPolicy,
    #[cfg(unix)]
    project_trust: Option<PiProjectTrustEvidence>,
    asset_id: AssetId,
}

impl ExtensionBatchFixture {
    fn new(layout: NativeExtensionLayout) -> Self {
        let root = tempfile::tempdir().unwrap();
        let environment = create_root(root.path(), "extension-environment");
        let state = environment.parent().unwrap().join("extension-state");
        let target = create_root(root.path(), "extension-home");
        let asset_id = AssetId::parse("native-review").unwrap();
        let (source, entrypoint, files) = extension_source(layout, false);
        let observation = NativeExtensionObservation::new(
            HarnessScope::User,
            RootTier::User,
            RootId::parse("pi.user.native.extensions").unwrap(),
            15,
            PortablePath::parse(source).unwrap(),
            "review",
            CapturedNativeExtension {
                layout,
                entrypoint: entrypoint.to_owned(),
                exact: CapturedTree {
                    hash: hash_tree(&files),
                    files,
                },
                content_class: ContentClass::Executable,
            },
        )
        .unwrap();
        let empty = EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
        let adoption =
            plan_native_extension_adoption(&observation, Some(asset_id.clone()), &empty).unwrap();
        let manifest = adoption.proposed_manifest().clone();
        let object = adoption.native_object().clone();
        fs::write(environment.join(MANIFEST_PATH), manifest.to_toml().unwrap()).unwrap();
        install_extension_object(&environment, &manifest, &asset_id, &object, "initial");
        let local = LocalState {
            schema_version: SchemaVersion::V1,
            machine: MachineConfig {
                id: MachineId::parse("extension-batch-machine").unwrap(),
                active_profile: None,
                enabled_targets: BTreeSet::from([HarnessId::Pi]),
                harness_roots: BTreeMap::new(),
            },
            bindings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            pack_applications: BTreeMap::new(),
            trust: BTreeMap::from([(
                object.hash().clone(),
                TrustDecision::Trusted {
                    rationale: "reviewed".to_owned(),
                },
            )]),
            scans: vec![],
        };
        crate::test_authority::initialize_private_state(&state, &local).unwrap();
        let policy = ExtensionTargetPolicy::pi_native_extensions(
            HarnessScope::User,
            kitrove_adapter_api::VersionObservationOwned::Unknown,
        );
        Self {
            _root: root,
            environment,
            state,
            target,
            manifest,
            object,
            policy,
            #[cfg(unix)]
            project_trust: None,
            asset_id,
        }
    }

    #[cfg(unix)]
    fn plan(&self) -> ExtensionApplyPlan {
        let version_root = tempfile::tempdir().unwrap();
        let binary = version_root.path().join("pi");
        fs::write(&binary, "#!/bin/sh\nprintf '0.83.0\\n'\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let version = probe_pi_version(&binary).unwrap();
        let policy = PiAdapter
            .extension_target_policy(
                self.policy.scope,
                VersionObservation::Verified(version.evidence()),
            )
            .unwrap();
        plan_extension_apply(
            &self.manifest,
            &self.asset_id,
            &self.object,
            &policy,
            ExtensionApplyAuthority::new(&self.target, &version, self.project_trust.as_ref()),
            &fs::read_to_string(self.state.join(STATE_PATH)).unwrap(),
            crate::observe_extension_destination(
                &self.destination(),
                &self.object,
                CaptureLimits::default(),
            ),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn batch(&self) -> AtomicApplyBatchPlan {
        AtomicApplyBatchPlan::new(vec![AtomicApplyItem::Extension(self.plan())], None).unwrap()
    }

    fn removal_batch(&self) -> AtomicApplyBatchPlan {
        let state_text = fs::read_to_string(self.state.join(STATE_PATH)).unwrap();
        let plan = plan_extension_removal(
            &self.manifest,
            &self.asset_id,
            &self.object,
            &self.policy,
            &self.target,
            &state_text,
            crate::observe_extension_destination(
                &self.destination(),
                &self.object,
                CaptureLimits::default(),
            ),
        )
        .unwrap();
        AtomicApplyBatchPlan::new(vec![AtomicApplyItem::Extension(plan)], None).unwrap()
    }

    fn seed_installed(&self) {
        let destination = self.destination();
        match self.object.layout() {
            NativeExtensionLayout::Standalone => {
                fs::create_dir_all(destination.parent().unwrap()).unwrap();
                let file = self.object.tree().files.values().next().unwrap();
                crate::test_authority::write_owned_fixture_file(&destination, &file.bytes).unwrap();
            }
            NativeExtensionLayout::Directory => {
                crate::test_authority::create_owned_fixture_directory(
                    &self.target,
                    &format!("{}/review", self.policy.relative_root.as_str()),
                );
                for (relative, file) in &self.object.tree().files {
                    let target = destination.join(relative.as_str());
                    fs::create_dir_all(target.parent().unwrap()).unwrap();
                    crate::test_authority::write_owned_fixture_file(target, &file.bytes).unwrap();
                }
            }
        }
        let mut local =
            LocalState::from_json(&fs::read_to_string(self.state.join(STATE_PATH)).unwrap())
                .unwrap();
        let asset = &self.manifest.assets[&self.asset_id];
        let compatibility = &asset.compatibility[&HarnessId::Pi];
        let receipt = DeploymentReceipt {
            asset_id: self.asset_id.clone(),
            harness: HarnessId::Pi,
            scope: self.policy.scope,
            destination: crate::materialization::normalized_destination_from_path(&destination)
                .unwrap(),
            target: Default::default(),
            logical_key: None,
            shared_with: Default::default(),
            shared_adapter_versions: Default::default(),
            source_hash: asset.content_hash.clone(),
            rendered_hash: self.object.hash().clone(),
            document_hash: None,
            prior_hash: None,
            adapter_version: compatibility.adapter_version().to_owned(),
            environment_revision: crate::derive_manifest_revision(&self.manifest).unwrap(),
        };
        local
            .receipts
            .insert(receipt.receipt_id().unwrap(), receipt);
        fs::write(self.state.join(STATE_PATH), local.to_json().unwrap()).unwrap();
    }

    fn destination(&self) -> PathBuf {
        self.target
            .join(self.policy.relative_root.as_str())
            .join(match self.object.layout() {
                NativeExtensionLayout::Standalone => "review.ts",
                NativeExtensionLayout::Directory => "review",
            })
    }

    #[cfg(unix)]
    fn enable_project_scope(&mut self) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        self.policy = ExtensionTargetPolicy::pi_native_extensions(
            HarnessScope::Project,
            kitrove_adapter_api::VersionObservationOwned::Unknown,
        );
        let agent = self.target.join(".pi/agent");
        fs::create_dir_all(&agent).unwrap();
        for directory in [self.target.join(".pi"), agent.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let trust_store = agent.join("trust.json");
        fs::write(
            &trust_store,
            format!("{{\"{}\":true}}", self.target.display()),
        )
        .unwrap();
        fs::set_permissions(&trust_store, fs::Permissions::from_mode(0o600)).unwrap();
        let PiProjectTrustStatus::Trusted(evidence) =
            inspect_pi_project_trust(&trust_store, &self.target).unwrap()
        else {
            panic!("saved project trust should be effective");
        };
        self.project_trust = Some(evidence);
        trust_store
    }

    fn assert_destination(&self) {
        assert_eq!(
            crate::observe_extension_destination(
                &self.destination(),
                &self.object,
                CaptureLimits::default(),
            ),
            ExtensionDestinationObservation::Present {
                layout: self.object.layout(),
                object_hash: self.object.hash().clone(),
            }
        );
    }

    #[cfg(unix)]
    fn remove_destination(&self) {
        match self.object.layout() {
            NativeExtensionLayout::Standalone => fs::remove_file(self.destination()).unwrap(),
            NativeExtensionLayout::Directory => fs::remove_dir_all(self.destination()).unwrap(),
        }
    }

    #[cfg(unix)]
    fn prepare_update(&mut self) {
        let (source, entrypoint, files) = extension_source(self.object.layout(), true);
        let observation = NativeExtensionObservation::new(
            HarnessScope::User,
            RootTier::User,
            RootId::parse("pi.user.native.extensions").unwrap(),
            15,
            PortablePath::parse(source).unwrap(),
            "review",
            CapturedNativeExtension {
                layout: self.object.layout(),
                entrypoint: entrypoint.to_owned(),
                exact: CapturedTree {
                    hash: hash_tree(&files),
                    files,
                },
                content_class: ContentClass::Executable,
            },
        )
        .unwrap();
        let update = plan_native_extension_update(
            &observation,
            self.asset_id.clone(),
            self.manifest.assets[&self.asset_id].content_hash.clone(),
            &self.manifest,
        )
        .unwrap();
        self.manifest = update.proposed_manifest().clone();
        self.object = update.native_object().clone();
        fs::write(
            self.environment.join(MANIFEST_PATH),
            self.manifest.to_toml().unwrap(),
        )
        .unwrap();
        install_extension_object(
            &self.environment,
            &self.manifest,
            &self.asset_id,
            &self.object,
            "updated",
        );
        let state_path = self.state.join(STATE_PATH);
        let mut state = LocalState::from_json(&fs::read_to_string(&state_path).unwrap()).unwrap();
        state.trust.insert(
            self.object.hash().clone(),
            TrustDecision::Trusted {
                rationale: "reviewed update".to_owned(),
            },
        );
        fs::write(state_path, state.to_json().unwrap()).unwrap();
    }
}

fn extension_source(
    layout: NativeExtensionLayout,
    updated: bool,
) -> (
    &'static str,
    &'static str,
    BTreeMap<PortablePath, CapturedFile>,
) {
    let body = if updated {
        b"export default { updated: true };\n".to_vec()
    } else {
        b"export default {};\n".to_vec()
    };
    match layout {
        NativeExtensionLayout::Standalone => (
            "review.ts",
            "review.ts",
            BTreeMap::from([(
                PortablePath::parse("review.ts").unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: body,
                },
            )]),
        ),
        NativeExtensionLayout::Directory => (
            "review",
            "index.ts",
            BTreeMap::from([
                (
                    PortablePath::parse("index.ts").unwrap(),
                    CapturedFile {
                        mode: FileMode::Regular,
                        bytes: body,
                    },
                ),
                (
                    PortablePath::parse("helper.ts").unwrap(),
                    CapturedFile {
                        mode: FileMode::Regular,
                        bytes: b"export const helper = true;\n".to_vec(),
                    },
                ),
            ]),
        ),
    }
}

fn install_extension_object(
    environment: &Path,
    manifest: &EnvironmentManifest,
    asset_id: &AssetId,
    object: &NativeExtensionObject,
    staging_name: &str,
) {
    let root = &manifest.assets[asset_id].native_variants[&HarnessId::Pi].root;
    let staging = PortablePath::parse(format!(".kitrove/{staging_name}-extension")).unwrap();
    let store = ObjectStore::open(environment).unwrap();
    let _environment_lock = store.try_lock_environment().unwrap();
    store
        .stage_native_extension(&staging, object, CaptureLimits::default())
        .unwrap();
    store
        .install_native_extension(&staging, root, object.hash(), CaptureLimits::default())
        .unwrap();
}

struct BatchFixture {
    _root: tempfile::TempDir,
    environment: PathBuf,
    target: PathBuf,
    state: PathBuf,
    batch: AtomicApplyBatchPlan,
    manifest: EnvironmentManifest,
    object: StoredSkillTree,
    asset_id: AssetId,
}

fn batch_fixture() -> BatchFixture {
    let root = tempfile::tempdir().unwrap();
    let environment = create_root(root.path(), "environment");
    let target = create_root(root.path(), "target");
    let state = environment.parent().unwrap().join("state");
    let candidate = make_candidate(FileMode::Regular, "review");
    let AdoptionPlanOutcome::Ready(adoption) =
        plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap()
    else {
        panic!("candidate must be adoptable");
    };
    let manifest = adoption.proposed_manifest().clone();
    let object = adoption.portable_object().clone();
    let asset_id = adoption.asset().id.clone();
    fs::write(environment.join(MANIFEST_PATH), manifest.to_toml().unwrap()).unwrap();
    let portable = manifest.assets[&asset_id].portable.as_ref().unwrap();
    let store = ObjectStore::open(&environment).unwrap();
    let environment_lock = store.try_lock_environment().unwrap();
    let staging = PortablePath::parse(".kitrove/test-portable").unwrap();
    store
        .stage_portable(&staging, &object, CaptureLimits::default())
        .unwrap();
    store
        .install_portable(
            &staging,
            &portable.root,
            &portable.object_hash,
            CaptureLimits::default(),
        )
        .unwrap();
    drop(environment_lock);
    let local = empty_local_state();
    let initial_state = local.to_json().unwrap();
    crate::test_authority::initialize_private_state(&state, &local).unwrap();
    let first = plan_skill_apply(
        &manifest,
        &asset_id,
        &object,
        &policy(".claude/skills", HarnessId::Claude),
        &target,
        &initial_state,
        DestinationObservation::Absent,
    )
    .unwrap();
    let second = plan_skill_apply(
        &manifest,
        &asset_id,
        &object,
        &policy(".codex/skills", HarnessId::Codex),
        &target,
        &initial_state,
        DestinationObservation::Absent,
    )
    .unwrap();
    let profile = ProfileId::parse("workstation").unwrap();
    let batch = AtomicApplyBatchPlan::new(
        vec![
            AtomicApplyItem::Skill(first),
            AtomicApplyItem::Skill(second),
        ],
        Some(profile.clone()),
    )
    .unwrap();
    BatchFixture {
        _root: root,
        environment,
        target,
        state,
        batch,
        manifest,
        object,
        asset_id,
    }
}

fn update_portable_revision(asset: &mut Asset, object_hash: kitrove_model::ContentHash) {
    let prior_id = asset.portable.as_ref().unwrap().provenance.clone();
    let prior = asset.provenance.get(&prior_id).unwrap();
    let provenance = ComponentProvenance::new(
        prior.source().clone(),
        Revision::parse("revision-two").unwrap(),
        object_hash.clone(),
        prior.origin_scope(),
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    asset.provenance.insert(provenance_id.clone(), provenance);
    let portable = asset.portable.as_mut().unwrap();
    portable.object_hash = object_hash;
    portable.provenance = provenance_id;
    asset.refresh_content_hash();
}

fn create_root(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::canonicalize(path).unwrap()
}

fn empty_local_state() -> LocalState {
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

fn policy(relative_root: &str, harness: HarnessId) -> TargetPolicy {
    let (policy_line, evidence) = match harness {
        HarnessId::Claude => (
            kitrove_adapter_api::PolicyLine::ClaudeCurrent,
            "test.claude",
        ),
        HarnessId::Codex => (kitrove_adapter_api::PolicyLine::CodexCurrent, "test.codex"),
        _ => (
            kitrove_adapter_api::PolicyLine::ClaudeCurrent,
            "test.harness",
        ),
    };
    TargetPolicy {
        harness,
        scope: kitrove_model::HarnessScope::User,
        policy_line,
        relative_root: PortablePath::parse(relative_root).unwrap(),
        layout: SkillSourceLayout::Directory,
        document_name: PortablePath::parse("SKILL.md").unwrap(),
        adapter_version: "test-agent-skills/1",
        evidence: EvidenceRef::parse(evidence).unwrap(),
    }
}
