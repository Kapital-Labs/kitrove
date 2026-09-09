use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_agent_skills::CaptureLimits;
use kitrove_instructions::{InstructionLimits, hash_instruction_document};
use kitrove_model::{
    AssetId, ContentHash, DeploymentReceipt, EnvironmentManifest, LocalState,
    NormalizedDestination, PortablePath, ReceiptTarget, Revision,
};
use serde::{Deserialize, Serialize};

use crate::guarded_journal::{self, GuardedJournalError};
use crate::local_state_authority;
use crate::materialization::{ApplyDisposition, normalized_destination_from_path};
use crate::object_mutation::guarded_backup_path;
use crate::quarantine_cleanup::coordinator::{
    LockedMutationBudget, MutationCleanupError, MutationWork, cleanup_locked_stores,
};
use crate::read_only_fs::RegularFileMode;
use crate::{
    InstructionApplyPlan, ObjectStore, observe_instruction_document, plan_instruction_apply,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;
const STATE_PATH: &str = "state.json";
const MANIFEST_PATH: &str = "kitrove.toml";
const JOURNAL_PATH: &str = local_state_authority::INSTRUCTION_APPLY_JOURNAL_PATH;
const PENDING_PATH: &str = local_state_authority::INSTRUCTION_APPLY_PENDING_PATH;
const JOURNAL_TRANSITIONS: usize = 3;
const TARGET_AND_STATE_INSTALLS: usize = 2;
const CLEANUP_ARTIFACTS: usize = 7;

/// Successful result of committing one standing-instruction projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionApplyCommitOutcome {
    Committed,
    NoOp,
    Recovered,
}

/// Result of reconciling one interrupted standing-instruction projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstructionApplyRecoveryOutcome {
    Absent,
    Aborted,
    Completed,
}

/// Stable, content- and path-redacted instruction transaction failure.
#[derive(Clone, Eq, PartialEq)]
pub struct InstructionApplyTransactionError {
    code: &'static str,
    message: &'static str,
}

impl InstructionApplyTransactionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for InstructionApplyTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstructionApplyTransactionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for InstructionApplyTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for InstructionApplyTransactionError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Preparing,
    Prepared,
    TargetCommitted,
    StateCommitted,
}

impl JournalPhase {
    const fn next(self) -> Option<Self> {
        match self {
            Self::Preparing => Some(Self::Prepared),
            Self::Prepared => Some(Self::TargetCommitted),
            Self::TargetCommitted => Some(Self::StateCommitted),
            Self::StateCommitted => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredDisposition {
    Install,
    Restore,
    ManagedUpdate,
}

impl StoredDisposition {
    fn from_plan(value: ApplyDisposition) -> Result<Self, InstructionApplyTransactionError> {
        match value {
            ApplyDisposition::Install => Ok(Self::Install),
            ApplyDisposition::Restore => Ok(Self::Restore),
            ApplyDisposition::ManagedUpdate => Ok(Self::ManagedUpdate),
            ApplyDisposition::Remove => Err(journal_invalid()),
            ApplyDisposition::NoOp => Err(journal_invalid()),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstructionApplyJournal {
    schema_version: u32,
    phase: JournalPhase,
    transaction_digest: ContentHash,
    plan_digest: ContentHash,
    asset_id: AssetId,
    manifest_revision: Revision,
    destination: NormalizedDestination,
    relative_document: PortablePath,
    disposition: StoredDisposition,
    old_document_hash: Option<ContentHash>,
    new_document_hash: ContentHash,
    new_region_hash: ContentHash,
    old_state_hash: ContentHash,
    new_state_hash: ContentHash,
    mode: RegularFileMode,
    observed_receipt: Option<DeploymentReceipt>,
    proposed_receipt: DeploymentReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Checkpoint {
    IntentRecorded,
    TargetStaged,
    StateStaged,
    Prepared,
    TargetInstalled,
    TargetCommitted,
    StateInstalled,
    StateCommitted,
}

/// Commits one exact instruction plan through a crash-recoverable target/state transaction.
pub fn commit_instruction_apply(
    plan: &InstructionApplyPlan,
    environment_root: &Path,
    state_root: &Path,
    target_anchor: &Path,
    capture_limits: CaptureLimits,
    instruction_limits: InstructionLimits,
) -> Result<InstructionApplyCommitOutcome, InstructionApplyTransactionError> {
    commit_instruction_apply_inner(
        plan,
        environment_root,
        state_root,
        target_anchor,
        capture_limits,
        instruction_limits,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_instruction_apply_inner(
    plan: &InstructionApplyPlan,
    environment_root: &Path,
    state_root: &Path,
    target_anchor: &Path,
    capture_limits: CaptureLimits,
    instruction_limits: InstructionLimits,
    interrupt_after: Option<Checkpoint>,
) -> Result<InstructionApplyCommitOutcome, InstructionApplyTransactionError> {
    let (forward_work, rollback_work) = instruction_commit_work(capture_limits)?;
    let environment = ObjectStore::open(environment_root).map_err(mutation_error)?;
    let state = ObjectStore::open_private_state_for_mutation(state_root).map_err(mutation_error)?;
    let target = ObjectStore::open(target_anchor).map_err(mutation_error)?;
    let _root_locks = ObjectStore::try_lock_distinct_roots(&[&environment, &state, &target])
        .map_err(mutation_error)?;
    ensure_no_foreign_journal(&environment, &state)?;

    let recovered = recover_locked(
        &environment,
        &state,
        &target,
        target_anchor,
        instruction_limits,
    )?;
    let cleanup_budget =
        cleanup_instruction_roots(&environment, &state, &target, forward_work, rollback_work)?;
    let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;
    let refreshed = refresh_plan(
        plan,
        &environment,
        &state,
        target_anchor,
        capture_limits,
        instruction_limits,
    )?;
    if refreshed.digest() != plan.digest() {
        if recovered == InstructionApplyRecoveryOutcome::Completed
            && refreshed.disposition() == ApplyDisposition::NoOp
        {
            return Ok(InstructionApplyCommitOutcome::Recovered);
        }
        return Err(transaction_error(
            "instruction_apply.plan_stale",
            "standing-instruction authority changed after planning",
        ));
    }
    if refreshed.disposition() == ApplyDisposition::NoOp {
        return Ok(InstructionApplyCommitOutcome::NoOp);
    }

    let old_document = refreshed.observation().document_text();
    if refreshed.observation().is_present() && old_document.is_none() {
        return Err(transaction_error(
            "instruction_apply.document_invalid",
            "the co-owned instruction document is not valid UTF-8 authority",
        ));
    }
    let new_document = std::str::from_utf8(refreshed.rendered().bytes()).map_err(|_| {
        transaction_error(
            "instruction_apply.document_invalid",
            "the rendered instruction document is not valid UTF-8 authority",
        )
    })?;
    let old_state = refreshed.observed_local_state_text();
    let new_state = refreshed
        .proposed_local_state()
        .to_json()
        .map_err(|_| recovery_conflict())?;
    let mut journal = journal_from_plan(&refreshed, old_state, &new_state)?;
    let target_staging = target_staging_path(&journal)?;
    let state_staging = state_staging_path(&journal)?;

    install_initial_journal(&state, &journal)?;
    interrupt(Checkpoint::IntentRecorded, interrupt_after)?;
    target
        .stage_text_with_mode(
            &target_staging,
            new_document,
            refreshed.rendered().mode(),
            instruction_limits.max_document_bytes,
        )
        .map_err(mutation_error)?;
    interrupt(Checkpoint::TargetStaged, interrupt_after)?;
    state
        .stage_private_text(&state_staging, &new_state, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?;
    interrupt(Checkpoint::StateStaged, interrupt_after)?;
    advance_journal(&state, &mut journal, JournalPhase::Prepared)?;
    interrupt(Checkpoint::Prepared, interrupt_after)?;

    let revalidated = refresh_plan(
        plan,
        &environment,
        &state,
        target_anchor,
        capture_limits,
        instruction_limits,
    )?;
    if revalidated.digest() != plan.digest() {
        return Err(transaction_error(
            "instruction_apply.plan_stale",
            "standing-instruction authority changed after transaction preparation",
        ));
    }
    target
        .install_staged_text_guarded_from_old(
            &target_staging,
            &journal.relative_document,
            old_document,
            new_document,
            instruction_limits.max_document_bytes,
        )
        .map_err(mutation_error)?;
    interrupt(Checkpoint::TargetInstalled, interrupt_after)?;
    advance_journal(&state, &mut journal, JournalPhase::TargetCommitted)?;
    interrupt(Checkpoint::TargetCommitted, interrupt_after)?;

    state
        .install_staged_text_guarded(
            &state_staging,
            &portable_path(STATE_PATH)?,
            Some(old_state),
            &new_state,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)?;
    interrupt(Checkpoint::StateInstalled, interrupt_after)?;
    advance_journal(&state, &mut journal, JournalPhase::StateCommitted)?;
    interrupt(Checkpoint::StateCommitted, interrupt_after)?;
    cleanup(&state, &target, &journal, instruction_limits)?;
    Ok(InstructionApplyCommitOutcome::Committed)
}

/// Reconciles an interrupted instruction apply using only its journaled exact authority.
pub fn recover_instruction_apply(
    environment_root: &Path,
    state_root: &Path,
    target_anchor: &Path,
    instruction_limits: InstructionLimits,
) -> Result<InstructionApplyRecoveryOutcome, InstructionApplyTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(mutation_error)?;
    let state = ObjectStore::open_private_state_for_mutation(state_root).map_err(mutation_error)?;
    let target = ObjectStore::open(target_anchor).map_err(mutation_error)?;
    let _root_locks = ObjectStore::try_lock_distinct_roots(&[&environment, &state, &target])
        .map_err(mutation_error)?;
    ensure_no_foreign_journal(&environment, &state)?;
    recover_locked(
        &environment,
        &state,
        &target,
        target_anchor,
        instruction_limits,
    )
}

fn refresh_plan(
    original: &InstructionApplyPlan,
    environment: &ObjectStore,
    state: &ObjectStore,
    target_anchor: &Path,
    capture_limits: CaptureLimits,
    instruction_limits: InstructionLimits,
) -> Result<InstructionApplyPlan, InstructionApplyTransactionError> {
    let manifest_text = environment
        .read_text(&portable_path(MANIFEST_PATH)?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(|| {
            transaction_error(
                "instruction_apply.manifest_missing",
                "manifest authority is missing",
            )
        })?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| {
        transaction_error(
            "instruction_apply.manifest_invalid",
            "manifest authority is invalid",
        )
    })?;
    let portable_root = manifest
        .assets
        .get(original.asset_id())
        .and_then(|asset| asset.portable.as_ref())
        .map(|portable| &portable.root)
        .ok_or_else(|| {
            transaction_error(
                "instruction_apply.asset_invalid",
                "portable instruction authority is missing",
            )
        })?;
    let object = environment
        .load_portable_instruction(portable_root, capture_limits)
        .map_err(mutation_error)?;
    let state_text = state
        .read_text(&portable_path(STATE_PATH)?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(|| {
            transaction_error(
                "instruction_apply.local_state_missing",
                "machine-local state authority is missing",
            )
        })?;
    let observation =
        observe_instruction_document(target_anchor, original.policy(), instruction_limits)
            .map_err(|error| transaction_error(error.code(), error.message()))?;
    plan_instruction_apply(
        &manifest,
        original.asset_id(),
        &object,
        original.policy(),
        &observation,
        &state_text,
        instruction_limits,
    )
    .map_err(|error| transaction_error(error.code(), error.message()))
}

fn recover_locked(
    environment: &ObjectStore,
    state: &ObjectStore,
    target: &ObjectStore,
    target_anchor: &Path,
    limits: InstructionLimits,
) -> Result<InstructionApplyRecoveryOutcome, InstructionApplyTransactionError> {
    let Some(journal) = inspect_journal(state)? else {
        return Ok(InstructionApplyRecoveryOutcome::Absent);
    };
    validate_target_anchor(&journal, target_anchor)?;
    let state_staging = state_staging_path(&journal)?;
    let target_staging = target_staging_path(&journal)?;
    let current_state = state
        .read_text(&portable_path(STATE_PATH)?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(recovery_conflict)?;
    let current_target = target
        .read_text(&journal.relative_document, limits.max_document_bytes)
        .map_err(mutation_error)?;
    let current_state_hash = ContentHash::digest(current_state.as_bytes());
    let current_target_hash = current_target
        .as_deref()
        .map(|text| hash_instruction_document(text.as_bytes()));

    let direction = if current_target_hash == journal.old_document_hash
        && current_state_hash == journal.old_state_hash
        && matches!(
            journal.phase,
            JournalPhase::Preparing | JournalPhase::Prepared
        ) {
        if journal.phase == JournalPhase::Prepared {
            validate_staged_authority(state, target, &journal, limits)?;
        }
        RecoveryDirection::Abort
    } else if journal.phase == JournalPhase::Preparing {
        return Err(recovery_conflict());
    } else {
        RecoveryDirection::Forward
    };

    let (forward_work, rollback_work) = instruction_recovery_work(direction)?;
    let cleanup_budget =
        cleanup_locked_stores(&[environment, state, target], forward_work, rollback_work)
            .map_err(cleanup_error)?;
    let _mutation_budget = match direction {
        RecoveryDirection::Forward => cleanup_budget.begin_forward(),
        RecoveryDirection::Abort => cleanup_budget.begin_rollback(),
    }
    .map_err(cleanup_error)?;
    reconcile_journal(state)?;
    if inspect_journal(state)?.as_ref() != Some(&journal) {
        return Err(recovery_conflict());
    }

    if direction == RecoveryDirection::Abort {
        cleanup(state, target, &journal, limits)?;
        return Ok(InstructionApplyRecoveryOutcome::Aborted);
    }

    if current_target_hash != Some(journal.new_document_hash.clone()) {
        resume_incomplete_target(target, &journal, &target_staging, limits)?;
    } else {
        prove_target_install(target, &journal, &target_staging, limits)?;
    }
    let installed_target = target
        .read_text(&journal.relative_document, limits.max_document_bytes)
        .map_err(mutation_error)?;
    if installed_target
        .as_deref()
        .map(|text| hash_instruction_document(text.as_bytes()))
        != Some(journal.new_document_hash.clone())
    {
        return Err(recovery_conflict());
    }

    if journal.old_state_hash == journal.new_state_hash {
        validate_new_state(&current_state, &journal)?;
    } else {
        match current_state_hash {
            hash if hash == journal.old_state_hash => {
                let staged_state = state
                    .read_text(&state_staging, MAX_CONTROL_BYTES)
                    .map_err(mutation_error)?
                    .ok_or_else(recovery_conflict)?;
                if ContentHash::digest(staged_state.as_bytes()) != journal.new_state_hash {
                    return Err(recovery_conflict());
                }
                validate_state_transition(&current_state, &staged_state, &journal)?;
                state
                    .install_staged_text_guarded(
                        &state_staging,
                        &portable_path(STATE_PATH)?,
                        Some(&current_state),
                        &staged_state,
                        MAX_CONTROL_BYTES,
                    )
                    .map_err(mutation_error)?;
            }
            hash if hash == journal.new_state_hash => {
                validate_new_state(&current_state, &journal)?;
            }
            _ => return Err(recovery_conflict()),
        }
    }
    cleanup(state, target, &journal, limits)?;
    Ok(InstructionApplyRecoveryOutcome::Completed)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RecoveryDirection {
    Forward,
    Abort,
}

fn instruction_commit_work(
    capture_limits: CaptureLimits,
) -> Result<(MutationWork, MutationWork), InstructionApplyTransactionError> {
    let forward = instruction_mutation_tombstones(JOURNAL_TRANSITIONS, TARGET_AND_STATE_INSTALLS)?;
    let rollback = instruction_mutation_tombstones(1, 0)?;
    Ok((
        MutationWork::try_from_counts(forward, 0, capture_limits).map_err(cleanup_error)?,
        MutationWork::try_from_counts(rollback, 0, capture_limits).map_err(cleanup_error)?,
    ))
}

fn instruction_recovery_work(
    direction: RecoveryDirection,
) -> Result<(MutationWork, MutationWork), InstructionApplyTransactionError> {
    let recovery = match direction {
        RecoveryDirection::Forward => instruction_mutation_tombstones(1, TARGET_AND_STATE_INSTALLS),
        RecoveryDirection::Abort => instruction_mutation_tombstones(1, 0),
    }?;
    let work = MutationWork::try_from_counts(recovery, 0, CaptureLimits::default())
        .map_err(cleanup_error)?;
    Ok(match direction {
        RecoveryDirection::Forward => (work, MutationWork::none()),
        RecoveryDirection::Abort => (MutationWork::none(), work),
    })
}

fn instruction_mutation_tombstones(
    journal_transitions: usize,
    guarded_installs: usize,
) -> Result<usize, InstructionApplyTransactionError> {
    journal_transitions
        .checked_mul(guarded_journal::RECONCILE_TOMBSTONES)
        .and_then(|work| work.checked_add(guarded_installs))
        .and_then(|work| work.checked_add(CLEANUP_ARTIFACTS))
        .ok_or_else(cleanup_limit)
}

fn cleanup_instruction_roots<'a>(
    environment: &'a ObjectStore,
    state: &'a ObjectStore,
    target: &'a ObjectStore,
    forward: MutationWork,
    rollback: MutationWork,
) -> Result<LockedMutationBudget, InstructionApplyTransactionError> {
    cleanup_locked_stores(&[environment, state, target], forward, rollback).map_err(cleanup_error)
}

fn prove_target_install(
    target: &ObjectStore,
    journal: &InstructionApplyJournal,
    staging: &PortablePath,
    limits: InstructionLimits,
) -> Result<(), InstructionApplyTransactionError> {
    match target
        .read_text(staging, limits.max_document_bytes)
        .map_err(mutation_error)?
    {
        None => Ok(()),
        Some(staged)
            if journal
                .old_document_hash
                .as_ref()
                .is_some_and(|old| hash_instruction_document(staged.as_bytes()) == *old) =>
        {
            Ok(())
        }
        Some(_) => Err(recovery_conflict()),
    }
}

fn resume_incomplete_target(
    target: &ObjectStore,
    journal: &InstructionApplyJournal,
    staging: &PortablePath,
    limits: InstructionLimits,
) -> Result<(), InstructionApplyTransactionError> {
    let old_hash = journal
        .old_document_hash
        .as_ref()
        .ok_or_else(recovery_conflict)?;
    let backup_path = guarded_backup_path(staging).map_err(mutation_error)?;
    let old = target
        .read_text(&backup_path, limits.max_document_bytes)
        .map_err(mutation_error)?
        .ok_or_else(recovery_conflict)?;
    let new = target
        .read_text(staging, limits.max_document_bytes)
        .map_err(mutation_error)?
        .ok_or_else(recovery_conflict)?;
    if hash_instruction_document(old.as_bytes()) != *old_hash
        || hash_instruction_document(new.as_bytes()) != journal.new_document_hash
    {
        return Err(recovery_conflict());
    }
    target
        .install_staged_text_guarded(
            staging,
            &journal.relative_document,
            Some(&old),
            &new,
            limits.max_document_bytes,
        )
        .map_err(mutation_error)
}

fn journal_from_plan(
    plan: &InstructionApplyPlan,
    old_state: &str,
    new_state: &str,
) -> Result<InstructionApplyJournal, InstructionApplyTransactionError> {
    let mut journal = InstructionApplyJournal {
        schema_version: 1,
        phase: JournalPhase::Preparing,
        transaction_digest: ContentHash::digest(b"pending"),
        plan_digest: plan.digest().clone(),
        asset_id: plan.asset_id().clone(),
        manifest_revision: plan.manifest_revision().clone(),
        destination: plan.observation().destination().clone(),
        relative_document: plan.policy().relative_document.clone(),
        disposition: StoredDisposition::from_plan(plan.disposition())?,
        old_document_hash: plan.observation().document_hash().cloned(),
        new_document_hash: plan.rendered().document_hash().clone(),
        new_region_hash: plan.rendered().region_hash().clone(),
        old_state_hash: ContentHash::digest(old_state.as_bytes()),
        new_state_hash: ContentHash::digest(new_state.as_bytes()),
        mode: plan.rendered().mode(),
        observed_receipt: plan.observed_receipt().cloned(),
        proposed_receipt: plan.proposed_receipt().clone(),
    };
    journal.transaction_digest = transaction_digest(&journal)?;
    validate_journal(&journal)?;
    validate_state_transition(old_state, new_state, &journal)?;
    Ok(journal)
}

fn transaction_digest(
    journal: &InstructionApplyJournal,
) -> Result<ContentHash, InstructionApplyTransactionError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-instruction-apply-transaction-v1\0");
    for value in [
        journal.plan_digest.as_str(),
        journal.asset_id.as_str(),
        journal.manifest_revision.as_str(),
        journal.destination.as_str(),
        journal.relative_document.as_str(),
        journal.new_document_hash.as_str(),
        journal.new_region_hash.as_str(),
        journal.old_state_hash.as_str(),
        journal.new_state_hash.as_str(),
    ] {
        write_record(&mut hasher, value);
    }
    write_optional_record(
        &mut hasher,
        journal.old_document_hash.as_ref().map(ContentHash::as_str),
    );
    hasher.update(&[match journal.disposition {
        StoredDisposition::Install => 0,
        StoredDisposition::Restore => 1,
        StoredDisposition::ManagedUpdate => 2,
    }]);
    if let Some(mode) = journal.mode.unix_mode() {
        hasher.update(&[1]);
        hasher.update(&mode.to_be_bytes());
    } else {
        hasher.update(&[0, u8::from(journal.mode.readonly())]);
    }
    for receipt in [
        journal.observed_receipt.as_ref(),
        Some(&journal.proposed_receipt),
    ] {
        match receipt {
            Some(receipt) => {
                hasher.update(&[1]);
                let encoded = serde_json::to_vec(receipt).map_err(|_| journal_invalid())?;
                write_record(&mut hasher, ContentHash::digest(&encoded).as_str());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
        .map_err(|_| journal_invalid())
}

fn validate_journal(
    journal: &InstructionApplyJournal,
) -> Result<(), InstructionApplyTransactionError> {
    let receipt_shape = journal.proposed_receipt.asset_id == journal.asset_id
        && journal.proposed_receipt.destination == journal.destination
        && journal.proposed_receipt.target == ReceiptTarget::ManagedInstructionRegion
        && journal.proposed_receipt.shared_with.is_empty()
        && journal.proposed_receipt.rendered_hash == journal.new_region_hash
        && journal.proposed_receipt.environment_revision == journal.manifest_revision
        && journal.proposed_receipt.receipt_id().is_ok();
    let disposition_shape = match (journal.disposition, &journal.observed_receipt) {
        (StoredDisposition::Install, None) => journal.proposed_receipt.prior_hash.is_none(),
        (StoredDisposition::Restore, Some(observed)) => {
            journal.old_document_hash.is_none()
                && journal.proposed_receipt.prior_hash == observed.prior_hash
        }
        (StoredDisposition::ManagedUpdate, Some(observed)) => {
            journal.old_document_hash.is_some()
                && journal.proposed_receipt.prior_hash == Some(observed.rendered_hash.clone())
        }
        _ => false,
    };
    let unchanged_state_is_restore = journal.disposition == StoredDisposition::Restore
        && journal.observed_receipt.as_ref() == Some(&journal.proposed_receipt);
    if journal.schema_version != 1
        || (journal.old_state_hash == journal.new_state_hash && !unchanged_state_is_restore)
        || !journal.mode.is_valid_for_platform()
        || !receipt_shape
        || !disposition_shape
        || transaction_digest(journal)? != journal.transaction_digest
    {
        return Err(journal_invalid());
    }
    if let Some(receipt) = &journal.observed_receipt {
        if receipt.asset_id != journal.asset_id
            || receipt.destination != journal.destination
            || receipt.target != ReceiptTarget::ManagedInstructionRegion
            || !receipt.shared_with.is_empty()
            || receipt.harness != journal.proposed_receipt.harness
            || receipt.scope != journal.proposed_receipt.scope
            || receipt.receipt_id().is_err()
        {
            return Err(journal_invalid());
        }
    }
    Ok(())
}

fn validate_state_transition(
    old_text: &str,
    new_text: &str,
    journal: &InstructionApplyJournal,
) -> Result<(), InstructionApplyTransactionError> {
    if ContentHash::digest(old_text.as_bytes()) != journal.old_state_hash
        || ContentHash::digest(new_text.as_bytes()) != journal.new_state_hash
    {
        return Err(recovery_conflict());
    }
    let mut old = LocalState::from_json(old_text).map_err(|_| recovery_conflict())?;
    let mut new = LocalState::from_json(new_text).map_err(|_| recovery_conflict())?;
    let new_id = journal
        .proposed_receipt
        .receipt_id()
        .map_err(|_| recovery_conflict())?;
    if old.receipts.contains_key(&new_id) && journal.observed_receipt.is_none() {
        return Err(recovery_conflict());
    }
    if new.receipts.get(&new_id) != Some(&journal.proposed_receipt) {
        return Err(recovery_conflict());
    }
    if let Some(receipt) = &journal.observed_receipt {
        let old_id = receipt.receipt_id().map_err(|_| recovery_conflict())?;
        if old.receipts.get(&old_id) != Some(receipt) {
            return Err(recovery_conflict());
        }
        old.receipts.remove(&old_id);
        new.receipts.remove(&old_id);
    }
    old.receipts.remove(&new_id);
    new.receipts.remove(&new_id);
    if old != new {
        return Err(recovery_conflict());
    }
    Ok(())
}

fn validate_new_state(
    text: &str,
    journal: &InstructionApplyJournal,
) -> Result<(), InstructionApplyTransactionError> {
    if ContentHash::digest(text.as_bytes()) != journal.new_state_hash {
        return Err(recovery_conflict());
    }
    let state = LocalState::from_json(text).map_err(|_| recovery_conflict())?;
    let receipt_id = journal
        .proposed_receipt
        .receipt_id()
        .map_err(|_| recovery_conflict())?;
    if state.receipts.get(&receipt_id) != Some(&journal.proposed_receipt) {
        return Err(recovery_conflict());
    }
    Ok(())
}

fn validate_staged_authority(
    state: &ObjectStore,
    target: &ObjectStore,
    journal: &InstructionApplyJournal,
    limits: InstructionLimits,
) -> Result<(), InstructionApplyTransactionError> {
    let (target_text, target_mode) = target
        .read_text_with_mode(&target_staging_path(journal)?, limits.max_document_bytes)
        .map_err(mutation_error)?
        .ok_or_else(recovery_conflict)?;
    let state_text = state
        .read_text(&state_staging_path(journal)?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(recovery_conflict)?;
    if hash_instruction_document(target_text.as_bytes()) != journal.new_document_hash
        || target_mode != journal.mode
        || ContentHash::digest(state_text.as_bytes()) != journal.new_state_hash
    {
        return Err(recovery_conflict());
    }
    let current_state = state
        .read_text(&portable_path(STATE_PATH)?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(recovery_conflict)?;
    validate_state_transition(&current_state, &state_text, journal)
}

fn validate_target_anchor(
    journal: &InstructionApplyJournal,
    target_anchor: &Path,
) -> Result<(), InstructionApplyTransactionError> {
    let destination =
        normalized_destination_from_path(&target_anchor.join(journal.relative_document.as_str()))
            .map_err(|_| recovery_conflict())?;
    if destination != journal.destination {
        return Err(recovery_conflict());
    }
    Ok(())
}

fn install_initial_journal(
    state: &ObjectStore,
    journal: &InstructionApplyJournal,
) -> Result<(), InstructionApplyTransactionError> {
    if inspect_journal(state)?.is_some() {
        return Err(recovery_conflict());
    }
    state
        .stage_private_text(
            &portable_path(JOURNAL_PATH)?,
            &journal_text(journal)?,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)
}

fn advance_journal(
    state: &ObjectStore,
    journal: &mut InstructionApplyJournal,
    next: JournalPhase,
) -> Result<(), InstructionApplyTransactionError> {
    if journal.phase.next() != Some(next) {
        return Err(journal_invalid());
    }
    journal.phase = next;
    state
        .stage_private_text(
            &portable_path(PENDING_PATH)?,
            &journal_text(journal)?,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)?;
    reconcile_journal(state)
}

fn inspect_journal(
    state: &ObjectStore,
) -> Result<Option<InstructionApplyJournal>, InstructionApplyTransactionError> {
    guarded_journal::inspect(
        state,
        &portable_path(JOURNAL_PATH)?,
        &portable_path(PENDING_PATH)?,
        MAX_CONTROL_BYTES,
        parse_journal,
        valid_transition,
        journal_invalid,
    )
    .map_err(guarded_error)
}

fn reconcile_journal(state: &ObjectStore) -> Result<(), InstructionApplyTransactionError> {
    guarded_journal::reconcile(
        state,
        &portable_path(JOURNAL_PATH)?,
        &portable_path(PENDING_PATH)?,
        MAX_CONTROL_BYTES,
        parse_journal,
        valid_transition,
        journal_invalid,
    )
    .map_err(guarded_error)
}

fn parse_journal(text: &str) -> Result<InstructionApplyJournal, InstructionApplyTransactionError> {
    let journal: InstructionApplyJournal =
        serde_json::from_str(text).map_err(|_| journal_invalid())?;
    validate_journal(&journal)?;
    Ok(journal)
}

fn valid_transition(old: &InstructionApplyJournal, next: &InstructionApplyJournal) -> bool {
    let mut expected = old.clone();
    let Some(next_phase) = old.phase.next() else {
        return false;
    };
    expected.phase = next_phase;
    expected == *next
}

fn cleanup(
    state: &ObjectStore,
    target: &ObjectStore,
    journal: &InstructionApplyJournal,
    limits: InstructionLimits,
) -> Result<(), InstructionApplyTransactionError> {
    let target_staging = target_staging_path(journal)?;
    let state_staging = state_staging_path(journal)?;
    let old_document_hash = journal.old_document_hash.as_ref();
    target
        .remove_regular_file_if_matches(&target_staging, limits.max_document_bytes, |bytes| {
            let hash = hash_instruction_document(bytes);
            hash == journal.new_document_hash || old_document_hash.is_some_and(|old| &hash == old)
        })
        .map_err(mutation_error)?;
    target
        .remove_regular_file_if_matches(
            &guarded_backup_path(&target_staging).map_err(mutation_error)?,
            limits.max_document_bytes,
            |bytes| old_document_hash.is_some_and(|old| hash_instruction_document(bytes) == *old),
        )
        .map_err(mutation_error)?;
    state
        .remove_regular_file_if_matches(&state_staging, MAX_CONTROL_BYTES, |bytes| {
            let hash = ContentHash::digest(bytes);
            hash == journal.old_state_hash || hash == journal.new_state_hash
        })
        .map_err(mutation_error)?;
    state
        .remove_regular_file_if_matches(
            &guarded_backup_path(&state_staging).map_err(mutation_error)?,
            MAX_CONTROL_BYTES,
            |bytes| ContentHash::digest(bytes) == journal.old_state_hash,
        )
        .map_err(mutation_error)?;
    for path in [
        portable_path(PENDING_PATH)?,
        guarded_backup_path(&portable_path(PENDING_PATH)?).map_err(mutation_error)?,
        portable_path(JOURNAL_PATH)?,
    ] {
        state
            .remove_regular_file_if_matches(&path, MAX_CONTROL_BYTES, |bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|text| parse_journal(text).ok())
                    .is_some_and(|candidate| {
                        candidate.transaction_digest == journal.transaction_digest
                    })
            })
            .map_err(mutation_error)?;
    }
    Ok(())
}

fn ensure_no_foreign_journal(
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<(), InstructionApplyTransactionError> {
    let local = local_state_authority::any_journal_present(
        state,
        local_state_authority::FOREIGN_TO_INSTRUCTION_APPLY,
        MAX_CONTROL_BYTES,
    )
    .map_err(mutation_error)?;
    let portable = local_state_authority::any_journal_present(
        environment,
        local_state_authority::ALL_PORTABLE_RECOVERY,
        MAX_CONTROL_BYTES,
    )
    .map_err(mutation_error)?;
    if local || portable {
        return Err(transaction_error(
            "instruction_apply.recovery_required",
            "another transaction must recover before instruction authority can change",
        ));
    }
    Ok(())
}

fn target_staging_path(
    journal: &InstructionApplyJournal,
) -> Result<PortablePath, InstructionApplyTransactionError> {
    let token = digest_token(&journal.transaction_digest)?;
    let value = journal.relative_document.as_str();
    let (parent, name) = value.rsplit_once('/').unwrap_or(("", value));
    let staging_name = format!(".{name}.kitrove-{token}.staged");
    let path = if parent.is_empty() {
        staging_name
    } else {
        format!("{parent}/{staging_name}")
    };
    portable_path(&path)
}

fn state_staging_path(
    journal: &InstructionApplyJournal,
) -> Result<PortablePath, InstructionApplyTransactionError> {
    portable_path(&format!(
        ".kitrove/instruction-apply-staging/{}.state.json",
        digest_token(&journal.transaction_digest)?
    ))
}

fn journal_text(
    journal: &InstructionApplyJournal,
) -> Result<String, InstructionApplyTransactionError> {
    let mut text = serde_json::to_string_pretty(journal).map_err(|_| journal_invalid())?;
    text.push('\n');
    Ok(text)
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn write_optional_record(hasher: &mut blake3::Hasher, value: Option<&str>) {
    if let Some(value) = value {
        hasher.update(&[1]);
        write_record(hasher, value);
    } else {
        hasher.update(&[0]);
    }
}

fn digest_token(digest: &ContentHash) -> Result<&str, InstructionApplyTransactionError> {
    digest
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(journal_invalid)
}

fn portable_path(value: &str) -> Result<PortablePath, InstructionApplyTransactionError> {
    PortablePath::parse(value).map_err(|_| {
        transaction_error(
            "instruction_apply.transaction_path_invalid",
            "instruction transaction path authority is invalid",
        )
    })
}

fn guarded_error(
    error: GuardedJournalError<InstructionApplyTransactionError>,
) -> InstructionApplyTransactionError {
    match error {
        GuardedJournalError::Storage => transaction_error(
            "instruction_apply.storage_failed",
            "instruction transaction storage failed",
        ),
        GuardedJournalError::Authority(error) => error,
    }
}

fn mutation_error(error: crate::ObjectMutationError) -> InstructionApplyTransactionError {
    transaction_error(error.code(), error.message())
}

fn cleanup_error(error: MutationCleanupError) -> InstructionApplyTransactionError {
    match error {
        MutationCleanupError::InvalidReservation => cleanup_limit(),
        MutationCleanupError::CleanupFailed => transaction_error(
            "instruction_apply.storage_failed",
            "instruction transaction storage failed",
        ),
    }
}

const fn cleanup_limit() -> InstructionApplyTransactionError {
    transaction_error(
        "instruction_apply.cleanup_limit",
        "the instruction transaction exceeds the supported mutation cleanup limit",
    )
}

const fn journal_invalid() -> InstructionApplyTransactionError {
    transaction_error(
        "instruction_apply.journal_invalid",
        "instruction recovery journal authority is invalid",
    )
}

const fn recovery_conflict() -> InstructionApplyTransactionError {
    transaction_error(
        "instruction_apply.recovery_conflict",
        "instruction recovery requires attention",
    )
}

const fn transaction_error(
    code: &'static str,
    message: &'static str,
) -> InstructionApplyTransactionError {
    InstructionApplyTransactionError { code, message }
}

fn interrupt(
    reached: Checkpoint,
    requested: Option<Checkpoint>,
) -> Result<(), InstructionApplyTransactionError> {
    if requested == Some(reached) {
        Err(transaction_error(
            "instruction_apply.test_interrupted",
            "the instruction transaction was interrupted",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use kitrove_adapter_api::{
        CapabilityMatrix, InstructionTargetAnchor, InstructionTargetPolicy, PolicyLine,
    };
    use kitrove_instructions::StoredInstruction;
    use kitrove_model::{
        BindingName, BindingResolver, HarnessId, HarnessScope, MachineConfig, MachineId,
        SchemaVersion,
    };

    use super::*;
    use crate::{
        InstructionAdoptionOutcome, TierOneInstructionCapabilities, plan_instruction_adoption,
    };

    struct Fixture {
        _temporary: tempfile::TempDir,
        environment: std::path::PathBuf,
        state: std::path::PathBuf,
        target: std::path::PathBuf,
        manifest: EnvironmentManifest,
        object: StoredInstruction,
        asset_id: AssetId,
        policy: InstructionTargetPolicy,
    }

    impl Fixture {
        fn new(initial_target: Option<&str>) -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let environment = root.join("environment");
            let state = root.join("state");
            let target = root.join("target");
            let origin = root.join("origin");
            fs::create_dir(&environment).unwrap();
            fs::create_dir(&target).unwrap();
            fs::create_dir(&origin).unwrap();

            let policy = policy();
            fs::write(
                origin.join("CLAUDE.md"),
                "<!-- kitrove:instruction review begin -->\nReview carefully.\n<!-- kitrove:instruction review end -->\n",
            )
            .unwrap();
            let origin_observation =
                observe_instruction_document(&origin, &policy, InstructionLimits::default())
                    .unwrap();
            let asset_id = AssetId::parse("review").unwrap();
            let InstructionAdoptionOutcome::Ready(adoption) = plan_instruction_adoption(
                &origin_observation,
                &asset_id,
                &empty_manifest(),
                &capabilities(),
            )
            .unwrap() else {
                panic!("valid instruction must be adoptable");
            };
            let manifest = adoption.proposed_manifest().clone();
            let object = adoption.portable_object().clone();
            fs::write(environment.join(MANIFEST_PATH), manifest.to_toml().unwrap()).unwrap();
            let portable = manifest.assets[&asset_id].portable.as_ref().unwrap();
            let store = ObjectStore::open(&environment).unwrap();
            let environment_lock = store.try_lock_environment().unwrap();
            let staging = PortablePath::parse(".kitrove/test-instruction-object").unwrap();
            store
                .stage_portable_instruction(&staging, &object, CaptureLimits::default())
                .unwrap();
            store
                .install_portable_instruction(
                    &staging,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
            drop(environment_lock);

            crate::test_authority::initialize_private_state(&state, &local_state()).unwrap();
            if let Some(initial_target) = initial_target {
                crate::test_authority::write_owned_fixture_file(
                    target.join("CLAUDE.md"),
                    initial_target,
                )
                .unwrap();
            }
            Self {
                _temporary: temporary,
                environment,
                state,
                target,
                manifest,
                object,
                asset_id,
                policy,
            }
        }

        fn plan(&self) -> InstructionApplyPlan {
            let observation = observe_instruction_document(
                &self.target,
                &self.policy,
                InstructionLimits::default(),
            )
            .unwrap();
            plan_instruction_apply(
                &self.manifest,
                &self.asset_id,
                &self.object,
                &self.policy,
                &observation,
                &fs::read_to_string(self.state.join(STATE_PATH)).unwrap(),
                InstructionLimits::default(),
            )
            .unwrap()
        }

        fn commit_inner(
            &self,
            plan: &InstructionApplyPlan,
            checkpoint: Option<Checkpoint>,
        ) -> Result<InstructionApplyCommitOutcome, InstructionApplyTransactionError> {
            commit_instruction_apply_inner(
                plan,
                &self.environment,
                &self.state,
                &self.target,
                CaptureLimits::default(),
                InstructionLimits::default(),
                checkpoint,
            )
        }

        fn recover(
            &self,
        ) -> Result<InstructionApplyRecoveryOutcome, InstructionApplyTransactionError> {
            recover_instruction_apply(
                &self.environment,
                &self.state,
                &self.target,
                InstructionLimits::default(),
            )
        }

        fn receipt_count(&self) -> usize {
            LocalState::from_json(&fs::read_to_string(self.state.join(STATE_PATH)).unwrap())
                .unwrap()
                .receipts
                .len()
        }

        fn replace_object(&mut self, body: &str) {
            let body = kitrove_instructions::InstructionBody::parse(
                body,
                InstructionLimits::default().max_body_bytes,
            )
            .unwrap();
            self.object = StoredInstruction::new(body);
            let portable = self
                .manifest
                .assets
                .get_mut(&self.asset_id)
                .unwrap()
                .portable
                .as_mut()
                .unwrap();
            portable.root = PortablePath::parse("assets/review/portable-v2").unwrap();
            portable.object_hash = self.object.object_hash().clone();
            self.manifest
                .assets
                .get_mut(&self.asset_id)
                .unwrap()
                .refresh_content_hash();
            self.manifest.validate().unwrap();
            fs::write(
                self.environment.join(MANIFEST_PATH),
                self.manifest.to_toml().unwrap(),
            )
            .unwrap();
            let store = ObjectStore::open(&self.environment).unwrap();
            let staging = PortablePath::parse(".kitrove/test-instruction-object-v2").unwrap();
            store
                .stage_portable_instruction(&staging, &self.object, CaptureLimits::default())
                .unwrap();
            let portable = self.manifest.assets[&self.asset_id]
                .portable
                .as_ref()
                .unwrap();
            store
                .install_portable_instruction(
                    &staging,
                    &portable.root,
                    &portable.object_hash,
                    CaptureLimits::default(),
                )
                .unwrap();
        }
    }

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
                id: MachineId::parse("instruction-transaction-test").unwrap(),
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

    #[test]
    fn commit_installs_one_region_receipt_and_is_idempotent() {
        let fixture = Fixture::new(Some("Human preface.\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                fixture.target.join("CLAUDE.md"),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        let plan = fixture.plan();
        assert_eq!(
            fixture.commit_inner(&plan, None).unwrap(),
            InstructionApplyCommitOutcome::Committed
        );
        let document = fs::read_to_string(fixture.target.join("CLAUDE.md")).unwrap();
        assert!(document.starts_with("Human preface.\n"));
        assert!(document.contains("Review carefully."));
        assert_eq!(fixture.receipt_count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(fixture.target.join("CLAUDE.md"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }
        assert!(!fixture.state.join(JOURNAL_PATH).exists());

        let repeated = fixture.plan();
        assert_eq!(
            fixture.commit_inner(&repeated, None).unwrap(),
            InstructionApplyCommitOutcome::NoOp
        );
    }

    #[test]
    fn commit_and_recovery_require_the_external_target_root_lock() {
        let fixture = Fixture::new(Some("Human preface.\n"));
        let plan = fixture.plan();
        let target = ObjectStore::open(&fixture.target).unwrap();
        let held = target.try_lock_environment().unwrap();

        let commit_error = fixture.commit_inner(&plan, None).unwrap_err();
        assert_eq!(commit_error.code(), "object.environment_locked");
        assert_eq!(fixture.receipt_count(), 0);
        assert_eq!(
            fs::read_to_string(fixture.target.join("CLAUDE.md")).unwrap(),
            "Human preface.\n"
        );
        let recovery_error = fixture.recover().unwrap_err();
        assert_eq!(recovery_error.code(), "object.environment_locked");

        drop(held);
        assert_eq!(
            fixture.recover().unwrap(),
            InstructionApplyRecoveryOutcome::Absent
        );
    }

    #[cfg(unix)]
    #[test]
    fn commit_reclaims_prior_retained_tombstone_before_new_mutation() {
        let fixture = Fixture::new(None);
        let obsolete = PortablePath::parse("obsolete-control").unwrap();
        fs::write(fixture.environment.join(obsolete.as_str()), "retained").unwrap();
        let store = ObjectStore::open(&fixture.environment).unwrap();
        {
            let _lock = store.try_lock_environment().unwrap();
            store.remove_regular_file_if_present(&obsolete).unwrap();
        }
        let quarantine = fixture.environment.join(".kitrove/removal-quarantine");
        assert_eq!(fs::read_dir(&quarantine).unwrap().count(), 1);

        let plan = fixture.plan();
        assert_eq!(
            fixture.commit_inner(&plan, None).unwrap(),
            InstructionApplyCommitOutcome::Committed
        );

        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn recovery_reclaims_retained_state_from_the_complete_locked_root_set() {
        let fixture = Fixture::new(None);
        let plan = fixture.plan();
        fixture
            .commit_inner(&plan, Some(Checkpoint::TargetStaged))
            .unwrap_err();
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
            fixture.recover().unwrap(),
            InstructionApplyRecoveryOutcome::Aborted
        );

        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_blocks_commit_before_journal_target_or_state_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new(None);
        let plan = fixture.plan();
        let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
        let control = fixture.environment.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error = fixture.commit_inner(&plan, None).unwrap_err();

        assert_eq!(error.code(), "instruction_apply.storage_failed");
        assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
        assert!(!fixture.target.join("CLAUDE.md").exists());
        assert!(!fixture.state.join(JOURNAL_PATH).exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[test]
    fn unsupported_capture_limit_is_rejected_before_mutation() {
        let fixture = Fixture::new(None);
        let plan = fixture.plan();
        let old_state = fs::read(fixture.state.join(STATE_PATH)).unwrap();
        let limits = CaptureLimits {
            max_files: kitrove_model::MAX_SUPPORTED_SYNC_COMPONENTS + 1,
            ..CaptureLimits::default()
        };

        let error = commit_instruction_apply(
            &plan,
            &fixture.environment,
            &fixture.state,
            &fixture.target,
            limits,
            InstructionLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "instruction_apply.cleanup_limit");
        assert_eq!(fs::read(fixture.state.join(STATE_PATH)).unwrap(), old_state);
        assert!(!fixture.target.join("CLAUDE.md").exists());
        assert!(!fixture.state.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn mutation_inventory_uses_exact_checked_commit_and_recovery_totals() {
        assert_eq!(
            instruction_mutation_tombstones(JOURNAL_TRANSITIONS, TARGET_AND_STATE_INSTALLS)
                .unwrap(),
            12
        );
        assert_eq!(instruction_mutation_tombstones(1, 0).unwrap(), 8);
        assert_eq!(
            instruction_mutation_tombstones(1, TARGET_AND_STATE_INSTALLS).unwrap(),
            10
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_blocks_recovery_before_journal_reconciliation() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new(None);
        let plan = fixture.plan();
        fixture
            .commit_inner(&plan, Some(Checkpoint::TargetStaged))
            .unwrap_err();
        let journal_path = fixture.state.join(JOURNAL_PATH);
        let pending_path = fixture.state.join(PENDING_PATH);
        let backup_path = fixture.state.join(
            guarded_backup_path(&portable_path(PENDING_PATH).unwrap())
                .unwrap()
                .as_str(),
        );
        let journal_before = fs::read(&journal_path).unwrap();
        let journal = parse_journal(std::str::from_utf8(&journal_before).unwrap()).unwrap();
        let target_staging = fixture
            .target
            .join(target_staging_path(&journal).unwrap().as_str());
        let target_staging_before = fs::read(&target_staging).unwrap();
        let pending_before = fs::read(&pending_path).ok();
        let backup_before = fs::read(&backup_path).ok();
        let state_before = fs::read(fixture.state.join(STATE_PATH)).unwrap();
        let control = fixture.environment.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error = fixture.recover().unwrap_err();

        assert_eq!(error.code(), "instruction_apply.storage_failed");
        assert_eq!(fs::read(journal_path).unwrap(), journal_before);
        assert_eq!(fs::read(pending_path).ok(), pending_before);
        assert_eq!(fs::read(backup_path).ok(), backup_before);
        assert_eq!(
            fs::read(fixture.state.join(STATE_PATH)).unwrap(),
            state_before
        );
        assert_eq!(fs::read(target_staging).unwrap(), target_staging_before);
        assert!(!fixture.target.join("CLAUDE.md").exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[test]
    fn every_durable_checkpoint_aborts_or_completes_from_exact_evidence() {
        for (checkpoint, expected, installed) in [
            (
                Checkpoint::IntentRecorded,
                InstructionApplyRecoveryOutcome::Aborted,
                false,
            ),
            (
                Checkpoint::TargetStaged,
                InstructionApplyRecoveryOutcome::Aborted,
                false,
            ),
            (
                Checkpoint::StateStaged,
                InstructionApplyRecoveryOutcome::Aborted,
                false,
            ),
            (
                Checkpoint::Prepared,
                InstructionApplyRecoveryOutcome::Aborted,
                false,
            ),
            (
                Checkpoint::TargetInstalled,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
            (
                Checkpoint::TargetCommitted,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
            (
                Checkpoint::StateInstalled,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
            (
                Checkpoint::StateCommitted,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
        ] {
            let fixture = Fixture::new(None);
            let plan = fixture.plan();
            assert_eq!(
                fixture
                    .commit_inner(&plan, Some(checkpoint))
                    .unwrap_err()
                    .code(),
                "instruction_apply.test_interrupted"
            );
            assert_eq!(
                fixture
                    .recover()
                    .unwrap_or_else(|error| panic!("{checkpoint:?}: {error:?}")),
                expected
            );
            assert_eq!(fixture.target.join("CLAUDE.md").exists(), installed);
            assert_eq!(fixture.receipt_count(), usize::from(installed));
            #[cfg(unix)]
            if installed {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    fs::metadata(fixture.target.join("CLAUDE.md"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
            assert!(!fixture.state.join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn receipt_backed_restore_and_managed_update_commit_exactly() {
        let mut fixture = Fixture::new(Some("Human preface.\n"));
        let first = fixture.plan();
        fixture.commit_inner(&first, None).unwrap();
        fs::remove_file(fixture.target.join("CLAUDE.md")).unwrap();
        let restore = fixture.plan();
        assert_eq!(restore.disposition(), ApplyDisposition::Restore);
        fixture.commit_inner(&restore, None).unwrap();
        assert!(
            fs::read_to_string(fixture.target.join("CLAUDE.md"))
                .unwrap()
                .contains("Review carefully.")
        );

        let restored = fs::read_to_string(fixture.target.join("CLAUDE.md")).unwrap();
        fs::write(
            fixture.target.join("CLAUDE.md"),
            format!("Human preface.\n{restored}"),
        )
        .unwrap();

        fixture.replace_object("Review carefully and explain material risks.");
        let update = fixture.plan();
        assert_eq!(update.disposition(), ApplyDisposition::ManagedUpdate);
        fixture.commit_inner(&update, None).unwrap();
        let updated = fs::read_to_string(fixture.target.join("CLAUDE.md")).unwrap();
        assert!(updated.starts_with("Human preface.\n"));
        assert!(updated.contains("explain material risks"));
        assert_eq!(fixture.receipt_count(), 1);
    }

    #[test]
    fn restore_recovers_when_receipt_state_is_already_exact() {
        for (checkpoint, expected, restored) in [
            (
                Checkpoint::Prepared,
                InstructionApplyRecoveryOutcome::Aborted,
                false,
            ),
            (
                Checkpoint::TargetInstalled,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
            (
                Checkpoint::TargetCommitted,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
            (
                Checkpoint::StateInstalled,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
            (
                Checkpoint::StateCommitted,
                InstructionApplyRecoveryOutcome::Completed,
                true,
            ),
        ] {
            let fixture = Fixture::new(None);
            let first = fixture.plan();
            fixture.commit_inner(&first, None).unwrap();
            fs::remove_file(fixture.target.join("CLAUDE.md")).unwrap();
            let restore = fixture.plan();
            assert_eq!(restore.disposition(), ApplyDisposition::Restore);
            fixture
                .commit_inner(&restore, Some(checkpoint))
                .unwrap_err();

            assert_eq!(fixture.recover().unwrap(), expected);
            assert_eq!(fixture.target.join("CLAUDE.md").exists(), restored);
            assert_eq!(fixture.receipt_count(), 1);
        }
    }

    #[test]
    fn managed_update_recovery_keeps_target_and_receipt_in_one_revision() {
        for (checkpoint, completed) in [
            (Checkpoint::Prepared, false),
            (Checkpoint::TargetInstalled, true),
            (Checkpoint::TargetCommitted, true),
            (Checkpoint::StateInstalled, true),
            (Checkpoint::StateCommitted, true),
        ] {
            let mut fixture = Fixture::new(Some("Human preface.\n"));
            let first = fixture.plan();
            fixture.commit_inner(&first, None).unwrap();
            let old_receipt =
                LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                    .unwrap()
                    .receipts
                    .into_values()
                    .next()
                    .unwrap();
            fixture.replace_object("Use the revised review policy.");
            let update = fixture.plan();
            fixture.commit_inner(&update, Some(checkpoint)).unwrap_err();
            fixture.recover().unwrap();

            let document = fs::read_to_string(fixture.target.join("CLAUDE.md")).unwrap();
            let state =
                LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                    .unwrap();
            let receipt = state.receipts.into_values().next().unwrap();
            assert!(document.starts_with("Human preface.\n"));
            assert_eq!(document.contains("revised review policy"), completed);
            assert_eq!(receipt == old_receipt, !completed);
        }
    }

    #[test]
    fn concurrent_human_edit_blocks_recovery_without_receipt_advance() {
        let fixture = Fixture::new(Some("Human preface.\n"));
        let plan = fixture.plan();
        fixture
            .commit_inner(&plan, Some(Checkpoint::Prepared))
            .unwrap_err();
        fs::write(
            fixture.target.join("CLAUDE.md"),
            "Human changed this while Kitrove was interrupted.\n",
        )
        .unwrap();

        assert_eq!(
            fixture.recover().unwrap_err().code(),
            "instruction_apply.recovery_conflict"
        );
        assert_eq!(fixture.receipt_count(), 0);
        assert_eq!(
            fs::read_to_string(fixture.target.join("CLAUDE.md")).unwrap(),
            "Human changed this while Kitrove was interrupted.\n"
        );
        assert!(fixture.state.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn identical_concurrent_target_creation_is_not_claimed_as_kitrove_commit() {
        for checkpoint in [Checkpoint::IntentRecorded, Checkpoint::Prepared] {
            let fixture = Fixture::new(None);
            let plan = fixture.plan();
            fixture.commit_inner(&plan, Some(checkpoint)).unwrap_err();
            fs::write(fixture.target.join("CLAUDE.md"), plan.rendered().bytes()).unwrap();

            assert_eq!(
                fixture.recover().unwrap_err().code(),
                "instruction_apply.recovery_conflict"
            );
            assert_eq!(fixture.receipt_count(), 0);
            assert_eq!(
                fs::read(fixture.target.join("CLAUDE.md")).unwrap(),
                plan.rendered().bytes()
            );
        }
    }
}
