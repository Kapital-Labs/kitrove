use super::*;
use crate::{observe_prompt_command_destination, plan_prompt_command_apply};
use kitrove_prompt_commands::{
    PromptBody, PromptCommand, PromptCommandLimits, StoredPromptCommand,
};

#[derive(Clone, Copy, Debug)]
enum Cut {
    Entry,
    RemovePending,
    TargetRemoved,
    Removed,
    RestorePending,
    TargetRestored,
    ParticipantRolledBack,
    Terminal,
}

fn fixture(disposition: StoredDisposition) -> (AtomicPromptCommandFixture, AtomicApplyBatchPlan) {
    let mut fixture = AtomicPromptCommandFixture::new();
    if disposition == StoredDisposition::Install {
        let batch = fixture.batch.clone();
        return (fixture, batch);
    }
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    if disposition == StoredDisposition::Remove {
        let batch = fixture.removal_batch();
        return (fixture, batch);
    }
    if disposition == StoredDisposition::Restore {
        fs::remove_file(&fixture.destination).unwrap();
    }
    if disposition == StoredDisposition::ManagedUpdate {
        let previous = fixture.object.command();
        let command = PromptCommand::try_new(
            previous.name().clone(),
            previous.description().cloned(),
            PromptBody::parse(
                &format!("Changed. {}", previous.body().as_str()),
                PromptCommandLimits::default().max_document_bytes,
            )
            .unwrap(),
            previous.argument_mode(),
        )
        .unwrap();
        fixture.object = StoredPromptCommand::new(command);
        let asset = fixture.manifest.assets.get_mut(&fixture.asset_id).unwrap();
        update_portable_revision(asset, fixture.object.object_hash().clone());
        let portable = asset.portable.as_ref().unwrap();
        // Only the disposable fixture's old portable object is replaced.
        fs::remove_dir_all(fixture.environment.join(portable.root.as_str())).unwrap();
        let store = ObjectStore::open(&fixture.environment).unwrap();
        let _lock = store.try_lock_environment().unwrap();
        let staging = PortablePath::parse(".kitrove/test-updated-command").unwrap();
        store
            .stage_portable_prompt_command(&staging, &fixture.object, CaptureLimits::default())
            .unwrap();
        store
            .install_portable_prompt_command(
                &staging,
                &portable.root,
                &portable.object_hash,
                CaptureLimits::default(),
            )
            .unwrap();
        fs::write(
            fixture.environment.join(MANIFEST_PATH),
            fixture.manifest.to_toml().unwrap(),
        )
        .unwrap();
    }
    let local = fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap();
    let observed = observe_prompt_command_destination(
        &fixture.target,
        &fixture.policy,
        fixture.object.command().name(),
        PromptCommandLimits::default(),
    )
    .unwrap();
    let plan = plan_prompt_command_apply(
        &fixture.manifest,
        &fixture.asset_id,
        &fixture.object,
        &fixture.policy,
        &observed,
        &local,
    )
    .unwrap();
    let expected = match disposition {
        StoredDisposition::NoOp => ApplyDisposition::NoOp,
        StoredDisposition::Restore => ApplyDisposition::Restore,
        StoredDisposition::ManagedUpdate => ApplyDisposition::ManagedUpdate,
        _ => unreachable!(),
    };
    assert_eq!(plan.disposition(), expected);
    let batch =
        AtomicApplyBatchPlan::new(vec![AtomicApplyItem::PromptCommand(plan)], None).unwrap();
    (fixture, batch)
}

fn interrupt(fixture: &AtomicPromptCommandFixture, batch: &AtomicApplyBatchPlan, no_op: bool) {
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_locked_batch_authority(
            batch,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            |environment, state, targets, sources| {
                commit_locked_batch(
                    batch,
                    environment,
                    state,
                    targets,
                    sources,
                    CaptureLimits::default(),
                    || {},
                    |_| {},
                    |_| {
                        if !no_op {
                            panic!("rollback resume target checkpoint");
                        }
                    },
                    || panic!("rollback resume unchanged-state checkpoint"),
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());
}

fn checkpoint(fixture: &AtomicPromptCommandFixture, disposition: StoredDisposition, cut: Cut) {
    let state = ObjectStore::open_private_state_for_mutation(&fixture.state).unwrap();
    let _lock = ObjectStore::try_lock_distinct_roots(&[&state]).unwrap();
    let mut journal = AtomicApplyBatchJournalCursor::load(&state)
        .unwrap()
        .unwrap();
    journal
        .transition_phase(&state, AtomicApplyBatchPhase::RollingBack)
        .unwrap();
    if matches!(cut, Cut::Entry) {
        return;
    }
    let restores = matches!(
        disposition,
        StoredDisposition::ManagedUpdate | StoredDisposition::Remove
    );
    if !matches!(
        disposition,
        StoredDisposition::Remove | StoredDisposition::NoOp
    ) {
        journal
            .transition_participant(&state, 0, Progress::RemovePending)
            .unwrap();
        if matches!(cut, Cut::RemovePending) {
            return;
        }
        fs::remove_file(&fixture.destination).unwrap();
        if matches!(cut, Cut::TargetRemoved) {
            return;
        }
        journal
            .transition_participant(&state, 0, Progress::Removed)
            .unwrap();
        if matches!(cut, Cut::Removed) {
            return;
        }
    }
    if restores {
        journal
            .transition_participant(&state, 0, Progress::RestorePending)
            .unwrap();
        if matches!(cut, Cut::RestorePending) {
            return;
        }
        fs::rename(
            fixture
                .target
                .join(journal.participants()[0].backup_target().as_str()),
            &fixture.destination,
        )
        .unwrap();
        if matches!(cut, Cut::TargetRestored) {
            return;
        }
    }
    journal
        .transition_participant(&state, 0, Progress::RolledBack)
        .unwrap();
    if matches!(cut, Cut::Terminal) {
        journal
            .transition_phase(&state, AtomicApplyBatchPhase::RolledBack)
            .unwrap();
    }
}

fn assert_resume(disposition: StoredDisposition, cut: Cut) {
    let (fixture, batch) = fixture(disposition);
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    let old_target = fs::read(&fixture.destination).ok();
    interrupt(&fixture, &batch, disposition == StoredDisposition::NoOp);
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
    checkpoint(&fixture, disposition, cut);
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack,
        "{disposition:?} {cut:?}"
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
    assert_eq!(fs::read(&fixture.destination).ok(), old_target);
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::NoJournal
    );
}

#[test]
fn install_and_restore_resume_each_removal_boundary() {
    assert_cuts(
        &[StoredDisposition::Install, StoredDisposition::Restore],
        &[
            Cut::Entry,
            Cut::RemovePending,
            Cut::TargetRemoved,
            Cut::Removed,
            Cut::ParticipantRolledBack,
            Cut::Terminal,
        ],
    );
}

#[test]
fn managed_update_resumes_each_removal_and_restoration_boundary() {
    assert_cuts(
        &[StoredDisposition::ManagedUpdate],
        &[
            Cut::Entry,
            Cut::RemovePending,
            Cut::TargetRemoved,
            Cut::Removed,
            Cut::RestorePending,
            Cut::TargetRestored,
            Cut::ParticipantRolledBack,
            Cut::Terminal,
        ],
    );
}

#[test]
fn removal_resumes_each_restoration_boundary() {
    assert_cuts(
        &[StoredDisposition::Remove],
        &[
            Cut::Entry,
            Cut::RestorePending,
            Cut::TargetRestored,
            Cut::ParticipantRolledBack,
            Cut::Terminal,
        ],
    );
}

#[test]
fn noop_resumes_without_removing_its_unchanged_target() {
    assert_cuts(
        &[StoredDisposition::NoOp],
        &[Cut::Entry, Cut::ParticipantRolledBack, Cut::Terminal],
    );
}

fn assert_cuts(dispositions: &[StoredDisposition], cuts: &[Cut]) {
    let mut failures = Vec::new();
    for disposition in dispositions {
        for cut in cuts {
            if std::panic::catch_unwind(|| assert_resume(*disposition, *cut)).is_err() {
                failures.push((*disposition, *cut));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "resume checkpoints failed: {failures:?}"
    );
}

#[test]
fn changed_target_during_pending_removal_is_preserved_and_blocks_recovery() {
    let (fixture, batch) = fixture(StoredDisposition::Install);
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    interrupt(&fixture, &batch, false);
    checkpoint(&fixture, StoredDisposition::Install, Cut::RemovePending);
    fs::write(&fixture.destination, b"later user content").unwrap();
    assert!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(&fixture.destination).unwrap(),
        b"later user content"
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn terminal_cleanup_preserves_later_destination_changes() {
    let (fixture, batch) = fixture(StoredDisposition::Install);
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    interrupt(&fixture, &batch, false);
    checkpoint(&fixture, StoredDisposition::Install, Cut::Terminal);
    kitrove_testkit::owned_fixture::create(Path::new(&fixture.destination), b"later user content");
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert_eq!(
        fs::read(&fixture.destination).unwrap(),
        b"later user content"
    );
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn changed_backup_during_pending_restoration_is_preserved_and_blocks_recovery() {
    let (fixture, batch) = fixture(StoredDisposition::ManagedUpdate);
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    interrupt(&fixture, &batch, false);
    checkpoint(
        &fixture,
        StoredDisposition::ManagedUpdate,
        Cut::RestorePending,
    );
    let backup = {
        let state = ObjectStore::open_private_state_for_mutation(&fixture.state).unwrap();
        let _lock = ObjectStore::try_lock_distinct_roots(&[&state]).unwrap();
        let journal = AtomicApplyBatchJournalCursor::load(&state)
            .unwrap()
            .unwrap();
        fixture
            .target
            .join(journal.participants()[0].backup_target().as_str())
    };
    fs::write(&backup, b"changed backup").unwrap();
    assert!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .is_err()
    );
    assert_eq!(fs::read(&backup).unwrap(), b"changed backup");
    assert!(!Path::new(&fixture.destination).exists());
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
}

#[test]
fn changed_live_state_blocks_resume_without_touching_target_or_journal() {
    let (fixture, batch) = fixture(StoredDisposition::Install);
    interrupt(&fixture, &batch, false);
    checkpoint(&fixture, StoredDisposition::Install, Cut::RemovePending);
    let journal_path = fixture
        .state
        .join(local_state_authority::ATOMIC_APPLY_JOURNAL_PATH);
    let journal_before = fs::read(&journal_path).unwrap();
    let target_before = fs::read(&fixture.destination).unwrap();
    fs::write(fixture.state.join(STATE_PATH), b"changed state").unwrap();
    assert!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.destination).unwrap(), target_before);
    assert_eq!(fs::read(&journal_path).unwrap(), journal_before);
    assert_eq!(
        fs::read(fixture.state.join(STATE_PATH)).unwrap(),
        b"changed state"
    );
}

#[test]
fn terminal_cleanup_refuses_changed_staged_state() {
    let (fixture, batch) = fixture(StoredDisposition::Install);
    let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
    interrupt(&fixture, &batch, false);
    checkpoint(&fixture, StoredDisposition::Install, Cut::Terminal);
    let staging = {
        let state = ObjectStore::open_private_state_for_mutation(&fixture.state).unwrap();
        let _lock = ObjectStore::try_lock_distinct_roots(&[&state]).unwrap();
        let journal = AtomicApplyBatchJournalCursor::load(&state)
            .unwrap()
            .unwrap();
        fixture.state.join(journal.staging_state().as_str())
    };
    fs::write(&staging, b"changed staged state").unwrap();
    assert!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .is_err()
    );
    assert_eq!(fs::read(staging).unwrap(), b"changed staged state");
    assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
    assert!(!Path::new(&fixture.destination).exists());
}

#[test]
fn mixed_restore_and_noop_resume_with_an_already_rolled_back_participant() {
    let fixture = batch_fixture();
    commit_atomic_apply_batch(
        &fixture.batch,
        &fixture.environment,
        &fixture.state,
        CaptureLimits::default(),
    )
    .unwrap();
    let old_state = fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap();
    let restored_destination = fixture.target.join(".claude/skills/review");
    let retained_destination = fixture.target.join(".codex/skills/review");
    fs::remove_dir_all(&restored_destination).unwrap();
    let mut items = Vec::new();
    for (harness, root) in [
        (HarnessId::Claude, ".claude/skills"),
        (HarnessId::Codex, ".codex/skills"),
    ] {
        let destination = fixture.target.join(root).join("review");
        let plan = plan_skill_apply(
            &fixture.manifest,
            &fixture.asset_id,
            &fixture.object,
            &policy(root, harness.clone()),
            &fixture.target,
            &old_state,
            observe_skill_destination(&destination, CaptureLimits::default()),
        )
        .unwrap();
        assert_eq!(
            plan.disposition(),
            if harness == HarnessId::Claude {
                ApplyDisposition::Restore
            } else {
                ApplyDisposition::NoOp
            }
        );
        items.push(AtomicApplyItem::Skill(plan));
    }
    let batch = AtomicApplyBatchPlan::new(items, fixture.batch.active_profile().cloned()).unwrap();
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
                    |_| panic!("mixed restore checkpoint"),
                    || {},
                )
            },
        )
        .unwrap();
    }));
    assert!(interrupted.is_err());
    {
        let state = ObjectStore::open_private_state_for_mutation(&fixture.state).unwrap();
        let _lock = ObjectStore::try_lock_distinct_roots(&[&state]).unwrap();
        let mut journal = AtomicApplyBatchJournalCursor::load(&state)
            .unwrap()
            .unwrap();
        journal
            .transition_phase(&state, AtomicApplyBatchPhase::RollingBack)
            .unwrap();
        assert_eq!(
            journal.participants()[1].disposition(),
            StoredDisposition::NoOp
        );
        journal
            .transition_participant(&state, 1, Progress::RolledBack)
            .unwrap();
        journal
            .transition_participant(&state, 0, Progress::RemovePending)
            .unwrap();
    }
    // A later edit to the completed no-op participant must not be rolled back again.
    fs::write(retained_destination.join("SKILL.md"), b"later user edit").unwrap();
    assert_eq!(
        recover_atomic_apply_batch(
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default()
        )
        .unwrap(),
        AtomicApplyBatchRecoveryOutcome::RolledBack
    );
    assert!(!restored_destination.exists());
    assert_eq!(
        fs::read(retained_destination.join("SKILL.md")).unwrap(),
        b"later user edit"
    );
    assert_eq!(
        fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
        old_state
    );
}
