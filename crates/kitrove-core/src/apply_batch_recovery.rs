use super::*;

/// Result of resolving a durable atomic batch journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicApplyBatchRecoveryOutcome {
    NoJournal,
    RolledBack,
    Completed,
}

/// Resolves an interrupted atomic batch solely from its digest-bound journal authority.
pub fn recover_atomic_apply_batch(
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<AtomicApplyBatchRecoveryOutcome, AtomicApplyBatchTransactionError> {
    recover_atomic_apply_batch_inner(environment_root, state_root, limits, || {})
}

pub(super) fn recover_atomic_apply_batch_inner(
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
    after_preliminary_unlock: impl FnOnce(),
) -> Result<AtomicApplyBatchRecoveryOutcome, AtomicApplyBatchTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(|_| storage_failed())?;
    let state =
        ObjectStore::open_private_state_for_mutation(state_root).map_err(|_| storage_failed())?;
    environment
        .require_non_overlapping_root(&state)
        .map_err(|_| root_overlap())?;
    let preliminary_roots =
        ObjectStore::try_lock_distinct_roots(&[&environment, &state]).map_err(root_lock_error)?;
    ensure_no_foreign_recovery(&environment, &state)?;
    let Some(journal) = AtomicApplyBatchJournalCursor::load(&state).map_err(journal_error)? else {
        drop(preliminary_roots);
        return Ok(AtomicApplyBatchRecoveryOutcome::NoJournal);
    };
    let encoded_authority = journal.encoded_authority().to_owned();
    let targets = open_recovery_target_roots(&journal, &environment, &state)?;
    drop(journal);
    drop(preliminary_roots);
    after_preliminary_unlock();
    let _root_locks = try_lock_batch_roots(&environment, &state, &targets)?;
    ensure_no_foreign_recovery(&environment, &state)?;
    let Some(mut journal) = AtomicApplyBatchJournalCursor::load(&state).map_err(journal_error)?
    else {
        return Err(recovery_blocked());
    };
    if journal.encoded_authority() != encoded_authority {
        return Err(recovery_blocked());
    }
    let current_state = required_text(&state, STATE_PATH)?;
    let current_hash = kitrove_model::ContentHash::digest(current_state.as_bytes());
    let state_is_old = &current_hash == journal.old_state_hash();
    let state_is_new = &current_hash == journal.new_state_hash();
    let state_phase_committed = matches!(
        journal.phase(),
        AtomicApplyBatchPhase::StateCommitted | AtomicApplyBatchPhase::Verified
    );
    // A no-op or restore batch may have identical old and new state bytes. Before the durable
    // state phase, that ambiguity resolves toward rollback so target authority cannot advance alone.
    let direction = if state_is_new && state_phase_committed {
        RecoveryDirection::Forward
    } else if state_is_old && !state_phase_committed {
        RecoveryDirection::Rollback
    } else if state_is_new {
        RecoveryDirection::Forward
    } else {
        return Err(recovery_blocked());
    };
    let (full_forward, full_rollback) = recovery_mutation_work(&journal, limits)?;
    let (forward, rollback) = match direction {
        RecoveryDirection::Forward => (full_forward, MutationWork::none()),
        RecoveryDirection::Rollback => (MutationWork::none(), full_rollback),
    };
    let cleanup_budget = cleanup_batch_roots(&environment, &state, &targets, forward, rollback)?;
    if direction == RecoveryDirection::Forward {
        let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
        recover_forward(&environment, &state, &targets, &mut journal, limits)?;
        Ok(AtomicApplyBatchRecoveryOutcome::Completed)
    } else {
        let _mutation_budget = cleanup_budget.begin_rollback().map_err(cleanup_error)?;
        recover_rollback(&state, &targets, &mut journal, limits)?;
        Ok(AtomicApplyBatchRecoveryOutcome::RolledBack)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecoveryDirection {
    Forward,
    Rollback,
}

fn recovery_mutation_work(
    journal: &AtomicApplyBatchJournalCursor,
    limits: CaptureLimits,
) -> Result<(MutationWork, MutationWork), AtomicApplyBatchTransactionError> {
    let inventory = AtomicMutationInventory::from_tree_kinds(journal.participants().iter().map(
        |participant| {
            matches!(
                participant.kind(),
                ParticipantKind::Skill | ParticipantKind::Extension
            )
        },
    ))?;
    inventory.reservation(AtomicForwardPath::Recovery, limits)
}

fn recover_forward(
    environment: &ObjectStore,
    state: &ObjectStore,
    targets: &[TargetRoot],
    journal: &mut AtomicApplyBatchJournalCursor,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let manifest = EnvironmentManifest::from_toml(&required_text(environment, MANIFEST_PATH)?)
        .map_err(|_| recovery_blocked())?;
    if derive_manifest_revision(&manifest).map_err(|_| recovery_blocked())?
        != *journal.manifest_revision()
    {
        return Err(recovery_blocked());
    }
    for participant in journal.participants() {
        let target = recovery_target_for(participant, targets)?;
        if participant.disposition() == StoredDisposition::Remove {
            if !participant_is_missing(
                participant,
                target,
                participant.relative_destination(),
                limits,
            )? {
                return Err(recovery_blocked());
            }
            continue;
        }
        if !participant_is_new(
            participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            if !participant_is_missing(
                participant,
                target,
                participant.relative_destination(),
                limits,
            )? || !participant_is_new(participant, target, participant.staging_target(), limits)?
            {
                return Err(recovery_blocked());
            }
            let identity = recovery_identity(
                participant,
                target,
                participant.staging_target(),
                false,
                limits,
            )?;
            apply_target::install(
                &target.store,
                participant.staging_target(),
                participant.relative_destination(),
                &identity.as_apply(),
                limits,
            )
            .map_err(|_| recovery_blocked())?;
        }
    }
    if journal.phase() == AtomicApplyBatchPhase::NewTargetsCommitted {
        journal
            .transition_phase(state, AtomicApplyBatchPhase::StateCommitted)
            .map_err(journal_error)?;
    }
    if journal.phase() == AtomicApplyBatchPhase::StateCommitted {
        for index in 0..journal.participants().len() {
            if journal.participants()[index].progress() == Progress::Committed {
                journal
                    .transition_participant(state, index, Progress::Verified)
                    .map_err(journal_error)?;
            }
        }
        journal
            .transition_phase(state, AtomicApplyBatchPhase::Verified)
            .map_err(journal_error)?;
    }
    if journal.phase() != AtomicApplyBatchPhase::Verified {
        return Err(recovery_blocked());
    }
    cleanup_recovery_artifacts(state, targets, journal, limits)
}

fn recover_rollback(
    state: &ObjectStore,
    targets: &[TargetRoot],
    journal: &mut AtomicApplyBatchJournalCursor,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    journal
        .transition_phase(state, AtomicApplyBatchPhase::RollingBack)
        .map_err(journal_error)?;
    for index in (0..journal.participants().len()).rev() {
        rollback_participant(state, targets, journal, index, limits)?;
    }
    journal
        .transition_phase(state, AtomicApplyBatchPhase::RolledBack)
        .map_err(journal_error)?;
    cleanup_recovery_artifacts(state, targets, journal, limits)
}

fn rollback_participant(
    state: &ObjectStore,
    targets: &[TargetRoot],
    journal: &mut AtomicApplyBatchJournalCursor,
    index: usize,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    let participant = journal.participants()[index].clone();
    let target = recovery_target_for(&participant, targets)?;
    let progress = participant.progress();
    if participant.disposition() == StoredDisposition::NoOp {
        if !participant_is_new(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            return Err(recovery_blocked());
        }
        journal
            .transition_participant(state, index, Progress::RolledBack)
            .map_err(journal_error)?;
        return Ok(());
    }

    if participant.disposition() == StoredDisposition::Remove {
        if participant_is_old(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            journal
                .transition_participant(state, index, Progress::RolledBack)
                .map_err(journal_error)?;
            return Ok(());
        }
        if !participant_is_missing(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            return Err(recovery_blocked());
        }
        if progress != Progress::RestorePending {
            journal
                .transition_participant(state, index, Progress::RestorePending)
                .map_err(journal_error)?;
        }
        let identity = recovery_identity(
            &participant,
            target,
            participant.backup_target(),
            true,
            limits,
        )?;
        apply_target::restore_quarantined(
            &target.store,
            participant.backup_target(),
            participant.relative_destination(),
            &identity.as_apply(),
            limits,
        )
        .map_err(|_| recovery_blocked())?;
        journal
            .transition_participant(state, index, Progress::RolledBack)
            .map_err(journal_error)?;
        return Ok(());
    }

    let destination_is_new = participant_is_new(
        &participant,
        target,
        participant.relative_destination(),
        limits,
    )?;
    let mut progress = progress;
    if matches!(progress, Progress::CommitPending | Progress::Committed) {
        journal
            .transition_participant(state, index, Progress::RemovePending)
            .map_err(journal_error)?;
        if destination_is_new {
            let identity = recovery_identity(
                &participant,
                target,
                participant.relative_destination(),
                false,
                limits,
            )?;
            apply_target::remove_exact(
                &target.store,
                participant.relative_destination(),
                &identity.as_apply(),
                limits,
            )
            .map_err(|_| recovery_blocked())?;
        } else if !participant_is_missing(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? && !participant_is_old(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            return Err(recovery_blocked());
        }
        journal
            .transition_participant(state, index, Progress::Removed)
            .map_err(journal_error)?;
        progress = Progress::Removed;
    } else if destination_is_new {
        return Err(recovery_blocked());
    }

    if participant.disposition() == StoredDisposition::ManagedUpdate {
        if participant_is_old(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            if matches!(
                progress,
                Progress::Unstaged
                    | Progress::StagingPending
                    | Progress::Prepared
                    | Progress::QuarantinePending
            ) {
                journal
                    .transition_participant(state, index, Progress::RolledBack)
                    .map_err(journal_error)?;
                return Ok(());
            }
        } else if participant_is_missing(
            &participant,
            target,
            participant.relative_destination(),
            limits,
        )? {
            if progress != Progress::RestorePending {
                journal
                    .transition_participant(state, index, Progress::RestorePending)
                    .map_err(journal_error)?;
            }
            let identity = recovery_identity(
                &participant,
                target,
                participant.backup_target(),
                true,
                limits,
            )?;
            apply_target::restore_quarantined(
                &target.store,
                participant.backup_target(),
                participant.relative_destination(),
                &identity.as_apply(),
                limits,
            )
            .map_err(|_| recovery_blocked())?;
            journal
                .transition_participant(state, index, Progress::RolledBack)
                .map_err(journal_error)?;
            return Ok(());
        } else {
            return Err(recovery_blocked());
        }
    }
    journal
        .transition_participant(state, index, Progress::RolledBack)
        .map_err(journal_error)
}

fn cleanup_recovery_artifacts(
    state: &ObjectStore,
    targets: &[TargetRoot],
    journal: &AtomicApplyBatchJournalCursor,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    for participant in journal.participants() {
        let target = recovery_target_for(participant, targets)?;
        if participant.disposition() != StoredDisposition::Remove {
            clear_exact_recovery_path(
                participant,
                target,
                participant.staging_target(),
                false,
                limits,
            )?;
        }
        clear_exact_recovery_path(
            participant,
            target,
            participant.backup_target(),
            true,
            limits,
        )?;
    }
    match state
        .read_text(journal.staging_state(), MAX_CONTROL_BYTES)
        .map_err(|_| recovery_blocked())?
    {
        None => {}
        Some(text)
            if kitrove_model::ContentHash::digest(text.as_bytes()) == *journal.new_state_hash() =>
        {
            state
                .remove_regular_file_if_present(journal.staging_state())
                .map_err(|_| recovery_blocked())?;
        }
        Some(_) => return Err(recovery_blocked()),
    }
    journal.remove_terminal(state).map_err(journal_error)
}

fn clear_exact_recovery_path(
    participant: &BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    old: bool,
    limits: CaptureLimits,
) -> Result<(), AtomicApplyBatchTransactionError> {
    if participant_is_missing(participant, target, path, limits)? {
        return Ok(());
    }
    let identity = recovery_identity(participant, target, path, old, limits)?;
    apply_target::remove_exact(&target.store, path, &identity.as_apply(), limits)
        .map_err(|_| recovery_blocked())
}

fn recovery_target_for<'a>(
    participant: &BatchParticipantJournal,
    targets: &'a [TargetRoot],
) -> Result<&'a TargetRoot, AtomicApplyBatchTransactionError> {
    targets
        .binary_search_by(|target| target.identity.cmp(participant.target_anchor()))
        .ok()
        .and_then(|index| targets.get(index))
        .ok_or_else(recovery_blocked)
}

enum RecoveryIdentity<'a> {
    Skill(&'a kitrove_model::ContentHash),
    Extension(NativeExtensionObject),
    ExactText {
        text: String,
        mode: crate::read_only_fs::RegularFileMode,
        max_bytes: usize,
    },
}

impl RecoveryIdentity<'_> {
    fn as_apply(&self) -> ApplyTargetIdentity<'_> {
        match self {
            Self::Skill(hash) => ApplyTargetIdentity::Skill(hash),
            Self::Extension(object) => ApplyTargetIdentity::Extension(object),
            Self::ExactText {
                text,
                mode,
                max_bytes,
            } => ApplyTargetIdentity::ExactText {
                text,
                mode: *mode,
                max_bytes: *max_bytes,
            },
        }
    }
}

fn recovery_identity<'a>(
    participant: &'a BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    old: bool,
    limits: CaptureLimits,
) -> Result<RecoveryIdentity<'a>, AtomicApplyBatchTransactionError> {
    match participant.kind() {
        ParticipantKind::Skill => Ok(RecoveryIdentity::Skill(if old {
            participant.old_target_hash().ok_or_else(recovery_blocked)?
        } else {
            participant.new_target_hash()
        })),
        ParticipantKind::Extension => {
            let object = capture_journal_extension(participant, target, path, old, limits)?;
            Ok(RecoveryIdentity::Extension(object))
        }
        ParticipantKind::Instruction
        | ParticipantKind::PromptCommand
        | ParticipantKind::Agent
        | ParticipantKind::Mcp => {
            let exact_file = participant.exact_file().ok_or_else(recovery_blocked)?;
            let (text, mode) = target
                .store
                .read_text_with_mode(path, exact_file.max_bytes())
                .map_err(|_| recovery_blocked())?
                .ok_or_else(recovery_blocked)?;
            let expected = if old {
                participant.old_target_hash().ok_or_else(recovery_blocked)?
            } else {
                participant.new_target_hash()
            };
            if mode != exact_file.mode()
                || !exact_file_matches(participant.kind(), text.as_bytes(), mode, expected)
            {
                return Err(recovery_blocked());
            }
            Ok(RecoveryIdentity::ExactText {
                text,
                mode,
                max_bytes: exact_file.max_bytes(),
            })
        }
    }
}

fn capture_journal_extension(
    participant: &BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    old: bool,
    limits: CaptureLimits,
) -> Result<NativeExtensionObject, AtomicApplyBatchTransactionError> {
    let extension = participant.extension().ok_or_else(recovery_blocked)?;
    let layout = if old {
        extension.old_layout().ok_or_else(recovery_blocked)?
    } else {
        extension.layout()
    };
    let expected_hash = if old {
        participant.old_target_hash().ok_or_else(recovery_blocked)?
    } else {
        participant.new_target_hash()
    };
    target
        .store
        .capture_extension_target_object(
            path,
            layout,
            extension.entrypoint(),
            extension.native_id(),
            limits,
        )
        .map_err(|_| recovery_blocked())?
        .filter(|object| object.hash() == expected_hash)
        .ok_or_else(recovery_blocked)
}

fn participant_is_new(
    participant: &BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    limits: CaptureLimits,
) -> Result<bool, AtomicApplyBatchTransactionError> {
    participant_matches(participant, target, path, false, limits)
}

fn participant_is_old(
    participant: &BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    limits: CaptureLimits,
) -> Result<bool, AtomicApplyBatchTransactionError> {
    if participant.old_target_hash().is_none() {
        return Ok(false);
    }
    participant_matches(participant, target, path, true, limits)
}

fn participant_matches(
    participant: &BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    old: bool,
    limits: CaptureLimits,
) -> Result<bool, AtomicApplyBatchTransactionError> {
    match participant.kind() {
        ParticipantKind::Skill => {
            let expected = if old {
                participant.old_target_hash().ok_or_else(recovery_blocked)?
            } else {
                participant.new_target_hash()
            };
            Ok(matches!(
                observe_skill_destination(&target.path.join(path.as_str()), limits),
                DestinationObservation::Present { rendered_hash, .. } if rendered_hash == *expected
            ))
        }
        ParticipantKind::Extension => {
            Ok(capture_journal_extension(participant, target, path, old, limits).is_ok())
        }
        ParticipantKind::Instruction
        | ParticipantKind::PromptCommand
        | ParticipantKind::Agent
        | ParticipantKind::Mcp => {
            let exact_file = participant.exact_file().ok_or_else(recovery_blocked)?;
            let Some((text, mode)) = target
                .store
                .read_text_with_mode(path, exact_file.max_bytes())
                .map_err(|_| recovery_blocked())?
            else {
                return Ok(false);
            };
            let expected = if old {
                participant.old_target_hash().ok_or_else(recovery_blocked)?
            } else {
                participant.new_target_hash()
            };
            Ok(mode == exact_file.mode()
                && exact_file_matches(participant.kind(), text.as_bytes(), mode, expected))
        }
    }
}

fn participant_is_missing(
    participant: &BatchParticipantJournal,
    target: &TargetRoot,
    path: &PortablePath,
    limits: CaptureLimits,
) -> Result<bool, AtomicApplyBatchTransactionError> {
    match participant.kind() {
        ParticipantKind::Skill => Ok(observe_skill_destination(
            &target.path.join(path.as_str()),
            limits,
        ) == DestinationObservation::Absent),
        ParticipantKind::Extension => {
            let extension = participant.extension().ok_or_else(recovery_blocked)?;
            target
                .store
                .capture_extension_target_object(
                    path,
                    extension.layout(),
                    extension.entrypoint(),
                    extension.native_id(),
                    limits,
                )
                .map(|object| object.is_none())
                .map_err(|_| recovery_blocked())
        }
        ParticipantKind::Instruction
        | ParticipantKind::PromptCommand
        | ParticipantKind::Agent
        | ParticipantKind::Mcp => {
            let exact_file = participant.exact_file().ok_or_else(recovery_blocked)?;
            target
                .store
                .read_text(path, exact_file.max_bytes())
                .map(|text| text.is_none())
                .map_err(|_| recovery_blocked())
        }
    }
}

fn exact_file_matches(
    kind: ParticipantKind,
    bytes: &[u8],
    mode: crate::read_only_fs::RegularFileMode,
    expected: &kitrove_model::ContentHash,
) -> bool {
    if kind == ParticipantKind::Mcp {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return false;
        };
        return [
            kitrove_mcp::NativeMcpDialect::ClaudeCurrent,
            kitrove_mcp::NativeMcpDialect::CodexCurrent,
            kitrove_mcp::NativeMcpDialect::OpenCodeV2,
        ]
        .into_iter()
        .filter_map(|dialect| {
            kitrove_mcp::parse_native_mcp_document(
                text,
                dialect,
                kitrove_mcp::McpParseLimits::default(),
            )
            .ok()
        })
        .any(|document| document.exact_document_hash() == expected);
    }
    exact_file_hash(kind, bytes, mode) == *expected
}

fn exact_file_hash(
    kind: ParticipantKind,
    bytes: &[u8],
    mode: crate::read_only_fs::RegularFileMode,
) -> kitrove_model::ContentHash {
    match kind {
        ParticipantKind::Instruction => kitrove_instructions::hash_instruction_document(bytes),
        ParticipantKind::PromptCommand => {
            crate::prompt_command_materialization::hash_prompt_command_target(bytes, mode)
        }
        ParticipantKind::Agent => crate::agent_materialization::hash_agent_target(bytes, mode),
        ParticipantKind::Skill | ParticipantKind::Extension | ParticipantKind::Mcp => {
            unreachable!("only exact-file participants use exact-file hashing")
        }
    }
}
