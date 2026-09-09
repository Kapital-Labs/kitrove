use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{AssetId, ContentHash, EnvironmentManifest, HarnessId, PortablePath, Revision};
use serde::{Deserialize, Serialize};

use crate::guarded_control::{self, GuardedControlError};
use crate::guarded_journal::{self, GuardedJournalError};
use crate::quarantine_cleanup::coordinator::{MutationCleanupError, cleanup_locked_stores};
use crate::{ExecutableTrustDecision, local_state_authority};
use crate::{ExecutableTrustDisposition, ExecutableTrustPlan, ObjectStore, plan_executable_trust};

mod cleanup_inventory;

use cleanup_inventory::{TrustMutationInventory, TrustRecoveryDirection};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;
const STATE_PATH: &str = "state.json";
const JOURNAL_PATH: &str = local_state_authority::TRUST_JOURNAL_PATH;
const JOURNAL_PENDING_PATH: &str = local_state_authority::TRUST_PENDING_PATH;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableTrustCommitOutcome {
    Committed,
    NoOp,
    Recovered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableTrustRecoveryOutcome {
    Absent,
    Aborted,
    Completed,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutableTrustTransactionError {
    code: &'static str,
    message: &'static str,
}

impl ExecutableTrustTransactionError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for ExecutableTrustTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableTrustTransactionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for ExecutableTrustTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for ExecutableTrustTransactionError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TrustJournalPhase {
    Prepared,
    StateCommitted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TrustJournal {
    schema_version: u32,
    phase: TrustJournalPhase,
    plan_digest: ContentHash,
    asset_id: AssetId,
    object_hash: ContentHash,
    manifest_revision: Revision,
    disposition: ExecutableTrustDisposition,
    old_decision: Option<ExecutableTrustDecision>,
    new_decision: ExecutableTrustDecision,
    old_state_hash: ContentHash,
    new_state_hash: ContentHash,
    staging_state: PortablePath,
}

/// Commits one exact confirmed trust plan to machine-local authority only.
pub fn commit_executable_trust(
    plan: &ExecutableTrustPlan,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
) -> Result<ExecutableTrustCommitOutcome, ExecutableTrustTransactionError> {
    commit_executable_trust_inner(plan, environment_root, state_root, limits, None)
}

fn commit_executable_trust_inner(
    plan: &ExecutableTrustPlan,
    environment_root: &Path,
    state_root: &Path,
    limits: CaptureLimits,
    interrupt_after: Option<TrustJournalPhase>,
) -> Result<ExecutableTrustCommitOutcome, ExecutableTrustTransactionError> {
    let (forward_work, rollback_work) = TrustMutationInventory::commit_work(limits)?;
    let environment = ObjectStore::open(environment_root).map_err(mutation_error)?;
    let state = ObjectStore::open_private_state_for_mutation(state_root).map_err(mutation_error)?;
    let _root_locks =
        ObjectStore::try_lock_distinct_roots(&[&environment, &state]).map_err(mutation_error)?;
    ensure_no_foreign_journal(&environment, &state)?;

    let recovered = recover_locked(&environment, &state, limits)?;
    let manifest_text = environment
        .read_text(&portable_path("kitrove.toml")?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(|| {
            transaction_error(
                "trust.manifest_missing",
                "portable manifest authority is missing",
            )
        })?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| {
        transaction_error(
            "trust.manifest_invalid",
            "portable manifest authority is invalid",
        )
    })?;
    let current_state = state
        .read_text(&portable_path(STATE_PATH)?, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?
        .ok_or_else(|| {
            transaction_error(
                "trust.local_state_missing",
                "machine-local state authority is missing",
            )
        })?;
    let native_root = manifest
        .assets
        .get(plan.asset_id())
        .and_then(|asset| asset.native_variants.get(&HarnessId::Pi))
        .map(|variant| &variant.root)
        .ok_or_else(|| {
            transaction_error(
                "trust.asset_invalid",
                "the selected asset is not a closed verified native extension",
            )
        })?;
    let object = environment
        .load_native_extension_bounded(
            native_root,
            limits,
            crate::object_store::envelope_limits(limits).max_total_bytes,
        )
        .map_err(mutation_error)?;
    let refreshed = plan_executable_trust(
        &manifest_text,
        &current_state,
        plan.asset_id(),
        &object,
        plan.decision(),
    )
    .map_err(|error| transaction_error(error.code(), error.message()))?;
    if refreshed.digest() != plan.digest() {
        if recovered == ExecutableTrustRecoveryOutcome::Completed
            && refreshed.disposition() == ExecutableTrustDisposition::NoOp
        {
            return Ok(ExecutableTrustCommitOutcome::Recovered);
        }
        return Err(transaction_error(
            "trust.plan_stale",
            "executable trust authority changed after planning",
        ));
    }
    if refreshed.disposition() == ExecutableTrustDisposition::NoOp {
        return Ok(ExecutableTrustCommitOutcome::NoOp);
    }
    let cleanup_budget =
        cleanup_locked_stores(&[&environment, &state], forward_work, rollback_work)
            .map_err(cleanup_error)?;
    let _mutation_budget = cleanup_budget.begin_forward().map_err(cleanup_error)?;

    let new_state = refreshed.proposed_local_state().to_json().map_err(|_| {
        transaction_error(
            "trust.local_state_invalid",
            "machine-local state authority is invalid",
        )
    })?;
    let staging_state = staging_state_path(refreshed.digest())?;
    let mut journal = TrustJournal {
        schema_version: 1,
        phase: TrustJournalPhase::Prepared,
        plan_digest: refreshed.digest().clone(),
        asset_id: refreshed.asset_id().clone(),
        object_hash: refreshed.object_hash().clone(),
        manifest_revision: refreshed.manifest_revision().clone(),
        disposition: refreshed.disposition(),
        old_decision: state_decision(&current_state, refreshed.object_hash())?,
        new_decision: refreshed.decision(),
        old_state_hash: ContentHash::digest(current_state.as_bytes()),
        new_state_hash: ContentHash::digest(new_state.as_bytes()),
        staging_state: staging_state.clone(),
    };
    let prepared_text = journal_text(&journal)?;
    state
        .stage_private_text(&staging_state, &new_state, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?;
    state
        .stage_private_text(
            &portable_path(JOURNAL_PENDING_PATH)?,
            &prepared_text,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)?;
    state
        .install_staged_text_guarded(
            &portable_path(JOURNAL_PENDING_PATH)?,
            &portable_path(JOURNAL_PATH)?,
            None,
            &prepared_text,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)?;
    interrupt(TrustJournalPhase::Prepared, interrupt_after)?;

    state
        .install_staged_text_guarded(
            &staging_state,
            &portable_path(STATE_PATH)?,
            Some(&current_state),
            &new_state,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)?;
    journal.phase = TrustJournalPhase::StateCommitted;
    let committed_text = journal_text(&journal)?;
    let journal_pending = portable_path(JOURNAL_PENDING_PATH)?;
    state
        .stage_private_text(&journal_pending, &committed_text, MAX_CONTROL_BYTES)
        .map_err(mutation_error)?;
    state
        .install_staged_text_guarded(
            &journal_pending,
            &portable_path(JOURNAL_PATH)?,
            Some(&prepared_text),
            &committed_text,
            MAX_CONTROL_BYTES,
        )
        .map_err(mutation_error)?;
    interrupt(TrustJournalPhase::StateCommitted, interrupt_after)?;
    cleanup_transaction_files(&state, &journal)?;
    Ok(ExecutableTrustCommitOutcome::Committed)
}

/// Safely resolves an interrupted local trust transaction without changing portable authority.
pub fn recover_executable_trust(
    environment_root: &Path,
    state_root: &Path,
) -> Result<ExecutableTrustRecoveryOutcome, ExecutableTrustTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(mutation_error)?;
    let state = ObjectStore::open_private_state_for_mutation(state_root).map_err(mutation_error)?;
    let _root_locks =
        ObjectStore::try_lock_distinct_roots(&[&environment, &state]).map_err(mutation_error)?;
    ensure_no_foreign_journal(&environment, &state)?;
    recover_locked(&environment, &state, CaptureLimits::default())
}

fn recover_locked(
    environment: &ObjectStore,
    state: &ObjectStore,
    limits: CaptureLimits,
) -> Result<ExecutableTrustRecoveryOutcome, ExecutableTrustTransactionError> {
    let Some(recovery) = inspect_recovery(state)? else {
        return Ok(ExecutableTrustRecoveryOutcome::Absent);
    };
    let (forward_work, rollback_work) =
        TrustMutationInventory::recovery_work(recovery.direction, limits)?;
    let cleanup_budget = cleanup_locked_stores(&[environment, state], forward_work, rollback_work)
        .map_err(cleanup_error)?;
    let _mutation_budget = match recovery.direction {
        TrustRecoveryDirection::Completed => cleanup_budget.begin_forward(),
        TrustRecoveryDirection::Aborted => cleanup_budget.begin_rollback(),
    }
    .map_err(cleanup_error)?;
    recover_locked_inner(state, &recovery)
}

struct InspectedTrustRecovery {
    journal: TrustJournal,
    state: String,
    direction: TrustRecoveryDirection,
}

fn inspect_recovery(
    state: &ObjectStore,
) -> Result<Option<InspectedTrustRecovery>, ExecutableTrustTransactionError> {
    let Some(journal) = inspect_trust_journal(state)? else {
        return Ok(None);
    };
    let current = inspect_trust_state(state, &journal)?.ok_or_else(recovery_conflict)?;
    let current_hash = ContentHash::digest(current.as_bytes());
    if current_hash == journal.new_state_hash {
        validate_new_decision(&current, &journal)?;
        return Ok(Some(InspectedTrustRecovery {
            journal,
            state: current,
            direction: TrustRecoveryDirection::Completed,
        }));
    }
    if current_hash == journal.old_state_hash && journal.phase == TrustJournalPhase::Prepared {
        let staged = state
            .read_text(&journal.staging_state, MAX_CONTROL_BYTES)
            .map_err(mutation_error)?
            .ok_or_else(recovery_conflict)?;
        if ContentHash::digest(staged.as_bytes()) != journal.new_state_hash {
            return Err(recovery_conflict());
        }
        validate_decision_transition(&current, &staged, &journal)?;
        return Ok(Some(InspectedTrustRecovery {
            journal,
            state: current,
            direction: TrustRecoveryDirection::Aborted,
        }));
    }
    Err(recovery_conflict())
}

fn recover_locked_inner(
    state: &ObjectStore,
    expected: &InspectedTrustRecovery,
) -> Result<ExecutableTrustRecoveryOutcome, ExecutableTrustTransactionError> {
    let current = inspect_recovery(state)?.ok_or_else(recovery_conflict)?;
    if current.direction != expected.direction
        || current.journal != expected.journal
        || current.state != expected.state
    {
        return Err(recovery_conflict());
    }
    reconcile_trust_journal(state)?;
    reconcile_trust_state(state, &current.journal)?;
    cleanup_transaction_files(state, &current.journal)?;
    Ok(match current.direction {
        TrustRecoveryDirection::Completed => ExecutableTrustRecoveryOutcome::Completed,
        TrustRecoveryDirection::Aborted => ExecutableTrustRecoveryOutcome::Aborted,
    })
}

fn inspect_trust_journal(
    state: &ObjectStore,
) -> Result<Option<TrustJournal>, ExecutableTrustTransactionError> {
    guarded_journal::inspect(
        state,
        &portable_path(JOURNAL_PATH)?,
        &portable_path(JOURNAL_PENDING_PATH)?,
        MAX_CONTROL_BYTES,
        parse_trust_journal,
        valid_trust_journal_transition,
        journal_invalid,
    )
    .map_err(map_guarded_journal_error)
}

fn reconcile_trust_journal(state: &ObjectStore) -> Result<(), ExecutableTrustTransactionError> {
    guarded_journal::reconcile(
        state,
        &portable_path(JOURNAL_PATH)?,
        &portable_path(JOURNAL_PENDING_PATH)?,
        MAX_CONTROL_BYTES,
        parse_trust_journal,
        valid_trust_journal_transition,
        journal_invalid,
    )
    .map_err(map_guarded_journal_error)
}

fn inspect_trust_state(
    state: &ObjectStore,
    journal: &TrustJournal,
) -> Result<Option<String>, ExecutableTrustTransactionError> {
    guarded_control::inspect(
        state,
        &journal.staging_state,
        &portable_path(STATE_PATH)?,
        Some(&journal.old_state_hash),
        &journal.new_state_hash,
        MAX_CONTROL_BYTES,
        recovery_conflict,
    )
    .map_err(map_guarded_control_error)
}

fn reconcile_trust_state(
    state: &ObjectStore,
    journal: &TrustJournal,
) -> Result<(), ExecutableTrustTransactionError> {
    guarded_control::reconcile(
        state,
        &journal.staging_state,
        &portable_path(STATE_PATH)?,
        Some(&journal.old_state_hash),
        &journal.new_state_hash,
        MAX_CONTROL_BYTES,
        recovery_conflict,
    )
    .map_err(map_guarded_control_error)
}

fn map_guarded_control_error(
    error: GuardedControlError<ExecutableTrustTransactionError>,
) -> ExecutableTrustTransactionError {
    match error {
        GuardedControlError::Storage(error) => mutation_error(error),
        GuardedControlError::Authority(error) => error,
    }
}

fn map_guarded_journal_error(
    error: GuardedJournalError<ExecutableTrustTransactionError>,
) -> ExecutableTrustTransactionError {
    match error {
        GuardedJournalError::Storage => transaction_error(
            "trust.recovery_io",
            "machine-local trust recovery storage failed",
        ),
        GuardedJournalError::Authority(error) => error,
    }
}

fn ensure_no_foreign_journal(
    environment: &ObjectStore,
    state: &ObjectStore,
) -> Result<(), ExecutableTrustTransactionError> {
    let local_pending = local_state_authority::any_journal_present(
        state,
        local_state_authority::FOREIGN_TO_TRUST,
        MAX_CONTROL_BYTES,
    )
    .map_err(mutation_error)?;
    let portable_pending = local_state_authority::any_journal_present(
        environment,
        local_state_authority::ALL_PORTABLE_RECOVERY,
        MAX_CONTROL_BYTES,
    )
    .map_err(mutation_error)?;
    if local_pending || portable_pending {
        return Err(transaction_error(
            "trust.local_state_recovery_required",
            "another local-state transaction must recover before executable trust can change",
        ));
    }
    Ok(())
}

fn state_decision(
    state_text: &str,
    object_hash: &ContentHash,
) -> Result<Option<ExecutableTrustDecision>, ExecutableTrustTransactionError> {
    let state =
        kitrove_model::LocalState::from_json(state_text).map_err(|_| recovery_conflict())?;
    Ok(match state.trust.get(object_hash) {
        Some(kitrove_model::TrustDecision::Trusted { .. }) => {
            Some(ExecutableTrustDecision::Trusted)
        }
        Some(kitrove_model::TrustDecision::Denied { .. }) => Some(ExecutableTrustDecision::Denied),
        None => None,
    })
}

fn validate_new_decision(
    new_state: &str,
    journal: &TrustJournal,
) -> Result<(), ExecutableTrustTransactionError> {
    if state_decision(new_state, &journal.object_hash)? != Some(journal.new_decision) {
        return Err(recovery_conflict());
    }
    Ok(())
}

fn validate_decision_transition(
    old_state: &str,
    new_state: &str,
    journal: &TrustJournal,
) -> Result<(), ExecutableTrustTransactionError> {
    let mut old =
        kitrove_model::LocalState::from_json(old_state).map_err(|_| recovery_conflict())?;
    let mut new =
        kitrove_model::LocalState::from_json(new_state).map_err(|_| recovery_conflict())?;
    if state_decision(old_state, &journal.object_hash)? != journal.old_decision
        || state_decision(new_state, &journal.object_hash)? != Some(journal.new_decision)
    {
        return Err(recovery_conflict());
    }
    old.trust.remove(&journal.object_hash);
    new.trust.remove(&journal.object_hash);
    if old != new {
        return Err(recovery_conflict());
    }
    Ok(())
}

const fn recovery_conflict() -> ExecutableTrustTransactionError {
    transaction_error(
        "trust.recovery_conflict",
        "machine-local trust recovery requires attention",
    )
}

fn cleanup_transaction_files(
    state: &ObjectStore,
    journal: &TrustJournal,
) -> Result<(), ExecutableTrustTransactionError> {
    state
        .remove_regular_file_if_present(&journal.staging_state)
        .map_err(mutation_error)?;
    state
        .remove_regular_file_if_present(&portable_path(JOURNAL_PENDING_PATH)?)
        .map_err(mutation_error)?;
    state
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(mutation_error)
}

fn validate_journal(journal: &TrustJournal) -> Result<(), ExecutableTrustTransactionError> {
    let disposition_matches = match journal.disposition {
        ExecutableTrustDisposition::First => journal.old_decision.is_none(),
        ExecutableTrustDisposition::Replace => {
            journal.old_decision.is_some() && journal.old_decision != Some(journal.new_decision)
        }
        ExecutableTrustDisposition::NoOp => false,
    };
    let expected_digest = crate::executable_trust::trust_plan_digest_from_hashes(
        &journal.asset_id,
        &journal.object_hash,
        journal.new_decision,
        journal.disposition,
        &journal.manifest_revision,
        &journal.old_state_hash,
        &journal.new_state_hash,
    )
    .map_err(|_| journal_invalid())?;
    if journal.schema_version != 1
        || journal.staging_state != staging_state_path(&journal.plan_digest)?
        || journal.old_state_hash == journal.new_state_hash
        || !disposition_matches
        || expected_digest != journal.plan_digest
    {
        return Err(journal_invalid());
    }
    Ok(())
}

fn parse_trust_journal(encoded: &str) -> Result<TrustJournal, ExecutableTrustTransactionError> {
    let journal: TrustJournal = serde_json::from_str(encoded).map_err(|_| journal_invalid())?;
    validate_journal(&journal)?;
    if journal_text(&journal)? != encoded {
        return Err(journal_invalid());
    }
    Ok(journal)
}

fn valid_trust_journal_transition(old: &TrustJournal, next: &TrustJournal) -> bool {
    let mut expected = old.clone();
    expected.phase = TrustJournalPhase::StateCommitted;
    old.phase == TrustJournalPhase::Prepared && expected == *next
}

const fn journal_invalid() -> ExecutableTrustTransactionError {
    transaction_error(
        "trust.journal_invalid",
        "the executable trust recovery journal is invalid",
    )
}

fn journal_text(journal: &TrustJournal) -> Result<String, ExecutableTrustTransactionError> {
    let mut text = serde_json::to_string_pretty(journal).map_err(|_| {
        transaction_error(
            "trust.journal_invalid",
            "the executable trust recovery journal is invalid",
        )
    })?;
    text.push('\n');
    Ok(text)
}

fn staging_state_path(
    digest: &ContentHash,
) -> Result<PortablePath, ExecutableTrustTransactionError> {
    portable_path(&format!(
        ".kitrove/trust-staging/{}.json",
        digest_token(digest)?
    ))
}

fn digest_token(digest: &ContentHash) -> Result<&str, ExecutableTrustTransactionError> {
    digest.as_str().strip_prefix("blake3:").ok_or_else(|| {
        transaction_error(
            "trust.journal_invalid",
            "the executable trust recovery journal is invalid",
        )
    })
}

fn portable_path(value: &str) -> Result<PortablePath, ExecutableTrustTransactionError> {
    PortablePath::parse(value).map_err(|_| {
        transaction_error(
            "trust.transaction_path_invalid",
            "the executable trust transaction path is invalid",
        )
    })
}

fn mutation_error(error: crate::ObjectMutationError) -> ExecutableTrustTransactionError {
    transaction_error(error.code(), error.message())
}

fn cleanup_error(error: MutationCleanupError) -> ExecutableTrustTransactionError {
    match error {
        MutationCleanupError::InvalidReservation => transaction_error(
            "trust.cleanup_limit",
            "the executable trust transaction exceeds the supported cleanup limit",
        ),
        MutationCleanupError::CleanupFailed => transaction_error(
            "trust.cleanup_failed",
            "executable trust transaction cleanup failed",
        ),
    }
}

const fn transaction_error(
    code: &'static str,
    message: &'static str,
) -> ExecutableTrustTransactionError {
    ExecutableTrustTransactionError::new(code, message)
}

fn interrupt(
    reached: TrustJournalPhase,
    requested: Option<TrustJournalPhase>,
) -> Result<(), ExecutableTrustTransactionError> {
    if requested == Some(reached) {
        return Err(transaction_error(
            "trust.test_interrupted",
            "the executable trust transaction was interrupted",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use kitrove_adapter_api::{RootId, RootTier};
    use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, hash_tree};
    use kitrove_model::{
        ContentClass, HarnessScope, LocalState, MachineConfig, MachineId, SchemaVersion,
        TrustDecision,
    };

    use super::*;
    use crate::{
        CapturedNativeExtension, ExecutableTrustDecision, NativeExtensionLayout,
        NativeExtensionObservation, plan_native_extension_adoption,
    };

    struct Fixture {
        _temporary: tempfile::TempDir,
        environment: std::path::PathBuf,
        state: std::path::PathBuf,
        manifest_text: String,
        object: crate::NativeExtensionObject,
        state_text: String,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temporary.path()).unwrap();
            let environment = root.join("environment");
            let state = root.join("state");
            fs::create_dir_all(&environment).unwrap();
            let files = BTreeMap::from([(
                PortablePath::parse("review.ts").unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: b"export default {};\n".to_vec(),
                },
            )]);
            let observation = NativeExtensionObservation::new(
                HarnessScope::User,
                RootTier::User,
                RootId::parse("pi.user.native.extensions").unwrap(),
                15,
                PortablePath::parse("review.ts").unwrap(),
                "review",
                CapturedNativeExtension {
                    layout: NativeExtensionLayout::Standalone,
                    entrypoint: "review.ts".to_owned(),
                    exact: CapturedTree {
                        hash: hash_tree(&files),
                        files,
                    },
                    content_class: ContentClass::Executable,
                },
            )
            .unwrap();
            let manifest = EnvironmentManifest::from_toml("schema_version = 1\n").unwrap();
            let adoption = plan_native_extension_adoption(
                &observation,
                Some(AssetId::parse("native-review").unwrap()),
                &manifest,
            )
            .unwrap();
            let manifest_text = adoption.proposed_manifest().to_toml().unwrap();
            fs::write(environment.join("kitrove.toml"), &manifest_text).unwrap();
            let object = adoption.native_object().clone();
            let destination = adoption.proposed_manifest().assets
                [&AssetId::parse("native-review").unwrap()]
                .native_variants[&HarnessId::Pi]
                .root
                .clone();
            let staging = PortablePath::parse(".kitrove/test-object-staging").unwrap();
            let store = ObjectStore::open(&environment).unwrap();
            let environment_lock = store.try_lock_environment().unwrap();
            store
                .stage_native_extension(&staging, &object, CaptureLimits::default())
                .unwrap();
            store
                .install_native_extension(
                    &staging,
                    &destination,
                    object.hash(),
                    CaptureLimits::default(),
                )
                .unwrap();
            drop(environment_lock);
            let local = LocalState {
                schema_version: SchemaVersion::V1,
                machine: MachineConfig {
                    id: MachineId::parse("trust-transaction-machine").unwrap(),
                    active_profile: None,
                    enabled_targets: BTreeSet::from([HarnessId::Pi]),
                    harness_roots: BTreeMap::new(),
                },
                bindings: BTreeMap::new(),
                receipts: BTreeMap::new(),
                pack_applications: BTreeMap::new(),
                trust: BTreeMap::new(),
                scans: vec![],
            };
            let state_text = local.to_json().unwrap();
            crate::test_authority::initialize_private_state(&state, &local).unwrap();
            Self {
                _temporary: temporary,
                environment,
                state,
                manifest_text,
                object,
                state_text,
            }
        }

        fn plan(&self) -> ExecutableTrustPlan {
            self.plan_for(ExecutableTrustDecision::Trusted)
        }

        fn plan_for(&self, decision: ExecutableTrustDecision) -> ExecutableTrustPlan {
            plan_executable_trust(
                &self.manifest_text,
                &fs::read_to_string(self.state.join(STATE_PATH)).unwrap(),
                &AssetId::parse("native-review").unwrap(),
                &self.object,
                decision,
            )
            .unwrap()
        }
    }

    #[test]
    fn confirmed_commit_is_local_exact_and_idempotent() {
        let fixture = Fixture::new();
        let manifest_before = fs::read(fixture.environment.join("kitrove.toml")).unwrap();
        let plan = fixture.plan();
        assert_eq!(
            commit_executable_trust(
                &plan,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            ExecutableTrustCommitOutcome::Committed
        );
        let state =
            LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                .unwrap();
        assert!(matches!(
            state.trust[fixture.object.hash()],
            TrustDecision::Trusted { .. }
        ));
        assert_eq!(
            fs::read(fixture.environment.join("kitrove.toml")).unwrap(),
            manifest_before
        );
        assert!(!fixture.state.join(JOURNAL_PATH).exists());

        let repeated = fixture.plan();
        assert_eq!(
            commit_executable_trust(
                &repeated,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            ExecutableTrustCommitOutcome::NoOp
        );
    }

    #[cfg(unix)]
    #[test]
    fn commit_reclaims_retained_state_from_both_locked_roots() {
        let fixture = Fixture::new();
        let environment_obsolete = PortablePath::parse("obsolete-environment-control").unwrap();
        let state_obsolete = PortablePath::parse("obsolete-state-control").unwrap();
        fs::write(
            fixture.environment.join(environment_obsolete.as_str()),
            "retained",
        )
        .unwrap();
        fs::write(fixture.state.join(state_obsolete.as_str()), "retained").unwrap();
        let environment_store = ObjectStore::open(&fixture.environment).unwrap();
        {
            let _lock = environment_store.try_lock_environment().unwrap();
            environment_store
                .remove_regular_file_if_present(&environment_obsolete)
                .unwrap();
        }
        let state_store = ObjectStore::open_private_state_for_mutation(&fixture.state).unwrap();
        {
            let _lock = state_store.try_lock_environment().unwrap();
            state_store
                .remove_regular_file_if_present(&state_obsolete)
                .unwrap();
        }
        let retained = [&fixture.environment, &fixture.state].map(|root| {
            let quarantine = root.join(".kitrove/removal-quarantine");
            let names = fs::read_dir(&quarantine)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert!(!names.is_empty());
            (quarantine, names)
        });

        assert_eq!(
            commit_executable_trust(
                &fixture.plan(),
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap(),
            ExecutableTrustCommitOutcome::Committed
        );

        for (quarantine, names) in retained {
            for name in names {
                assert!(!quarantine.join(name).exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_blocks_commit_before_local_authority_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        let state_before = fs::read(fixture.state.join(STATE_PATH)).unwrap();
        let control = fixture.state.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error = commit_executable_trust(
            &fixture.plan(),
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "trust.cleanup_failed");
        assert_eq!(
            fs::read(fixture.state.join(STATE_PATH)).unwrap(),
            state_before
        );
        assert!(!fixture.state.join(JOURNAL_PATH).exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_environment_quarantine_blocks_recovery_before_cleanup_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        commit_executable_trust_inner(
            &fixture.plan(),
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            Some(TrustJournalPhase::Prepared),
        )
        .unwrap_err();
        let journal_path = fixture.state.join(JOURNAL_PATH);
        let journal_before = fs::read(&journal_path).unwrap();
        let journal: TrustJournal = serde_json::from_slice(&journal_before).unwrap();
        let state_before = fs::read(fixture.state.join(STATE_PATH)).unwrap();
        let staged_path = fixture.state.join(journal.staging_state.as_str());
        let staged_before = fs::read(&staged_path).unwrap();
        let control = fixture.environment.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(quarantine.join("unrecognized-retained-state"), b"authority").unwrap();

        let error = recover_executable_trust(&fixture.environment, &fixture.state).unwrap_err();

        assert_eq!(error.code(), "trust.cleanup_failed");
        assert_eq!(fs::read(journal_path).unwrap(), journal_before);
        assert_eq!(
            fs::read(fixture.state.join(STATE_PATH)).unwrap(),
            state_before
        );
        assert_eq!(fs::read(staged_path).unwrap(), staged_before);
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[test]
    fn recovery_aborts_prepared_and_completes_committed_boundaries() {
        for (phase, expected, trusted) in [
            (
                TrustJournalPhase::Prepared,
                ExecutableTrustRecoveryOutcome::Aborted,
                false,
            ),
            (
                TrustJournalPhase::StateCommitted,
                ExecutableTrustRecoveryOutcome::Completed,
                true,
            ),
        ] {
            let fixture = Fixture::new();
            let plan = fixture.plan();
            let error = commit_executable_trust_inner(
                &plan,
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(phase),
            )
            .unwrap_err();
            assert_eq!(error.code(), "trust.test_interrupted");
            assert_eq!(
                recover_executable_trust(&fixture.environment, &fixture.state).unwrap(),
                expected
            );
            let state =
                LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                    .unwrap();
            assert_eq!(state.trust.contains_key(fixture.object.hash()), trusted);
            assert!(!fixture.state.join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn recovery_reconciles_both_guarded_state_replacement_windows() {
        for destination_installed in [false, true] {
            let fixture = Fixture::new();
            commit_executable_trust_inner(
                &fixture.plan(),
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(TrustJournalPhase::Prepared),
            )
            .unwrap_err();
            let journal: TrustJournal = serde_json::from_str(
                &fs::read_to_string(fixture.state.join(JOURNAL_PATH)).unwrap(),
            )
            .unwrap();
            let staging = fixture.state.join(journal.staging_state.as_str());
            let backup = crate::object_mutation::guarded_backup_path(&journal.staging_state)
                .map(|path| fixture.state.join(path.as_str()))
                .unwrap();
            fs::rename(fixture.state.join(STATE_PATH), &backup).unwrap();
            if destination_installed {
                fs::rename(&staging, fixture.state.join(STATE_PATH)).unwrap();
            }

            let expected = if destination_installed {
                ExecutableTrustRecoveryOutcome::Completed
            } else {
                ExecutableTrustRecoveryOutcome::Aborted
            };
            assert_eq!(
                recover_executable_trust(&fixture.environment, &fixture.state).unwrap(),
                expected
            );
            let recovered =
                LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                    .unwrap();
            assert_eq!(
                recovered.trust.contains_key(fixture.object.hash()),
                destination_installed
            );
            assert!(!backup.exists());
            assert!(!staging.exists());
            assert!(!fixture.state.join(JOURNAL_PATH).exists());
        }
    }

    #[test]
    fn recovery_reconciles_both_guarded_journal_replacement_windows() {
        for destination_installed in [false, true] {
            let fixture = Fixture::new();
            commit_executable_trust_inner(
                &fixture.plan(),
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
                Some(TrustJournalPhase::StateCommitted),
            )
            .unwrap_err();
            let journal_path = fixture.state.join(JOURNAL_PATH);
            let committed_text = fs::read_to_string(&journal_path).unwrap();
            let mut prepared: TrustJournal = serde_json::from_str(&committed_text).unwrap();
            prepared.phase = TrustJournalPhase::Prepared;
            let pending_path = portable_path(JOURNAL_PENDING_PATH).unwrap();
            let pending = fixture.state.join(pending_path.as_str());
            let backup_path = crate::object_mutation::guarded_backup_path(&pending_path).unwrap();
            let backup = fixture.state.join(backup_path.as_str());
            crate::test_authority::stage_private_text(
                &fixture.state,
                backup_path.as_str(),
                &journal_text(&prepared).unwrap(),
            )
            .unwrap();
            if destination_installed {
                assert!(!pending.exists());
            } else {
                fs::remove_file(&journal_path).unwrap();
                crate::test_authority::stage_private_text(
                    &fixture.state,
                    pending_path.as_str(),
                    &committed_text,
                )
                .unwrap();
            }

            assert_eq!(
                recover_executable_trust(&fixture.environment, &fixture.state).unwrap(),
                ExecutableTrustRecoveryOutcome::Completed
            );
            let recovered =
                LocalState::from_json(&fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap())
                    .unwrap();
            assert!(recovered.trust.contains_key(fixture.object.hash()));
            assert!(!backup.exists());
            assert!(!pending.exists());
            assert!(!journal_path.exists());
        }
    }

    #[test]
    fn replacement_recovery_preserves_the_exact_trusted_denied_tuple() {
        for (initial, replacement) in [
            (
                ExecutableTrustDecision::Trusted,
                ExecutableTrustDecision::Denied,
            ),
            (
                ExecutableTrustDecision::Denied,
                ExecutableTrustDecision::Trusted,
            ),
        ] {
            for (phase, expected) in [
                (TrustJournalPhase::Prepared, initial),
                (TrustJournalPhase::StateCommitted, replacement),
            ] {
                let fixture = Fixture::new();
                let initial_plan = fixture.plan_for(initial);
                commit_executable_trust(
                    &initial_plan,
                    &fixture.environment,
                    &fixture.state,
                    CaptureLimits::default(),
                )
                .unwrap();
                let replacement_plan = fixture.plan_for(replacement);
                let error = commit_executable_trust_inner(
                    &replacement_plan,
                    &fixture.environment,
                    &fixture.state,
                    CaptureLimits::default(),
                    Some(phase),
                )
                .unwrap_err();
                assert_eq!(error.code(), "trust.test_interrupted");
                recover_executable_trust(&fixture.environment, &fixture.state).unwrap();
                let state = LocalState::from_json(
                    &fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
                )
                .unwrap();
                let observed = match state.trust.get(fixture.object.hash()).unwrap() {
                    TrustDecision::Trusted { .. } => ExecutableTrustDecision::Trusted,
                    TrustDecision::Denied { .. } => ExecutableTrustDecision::Denied,
                };
                assert_eq!(observed, expected);
            }
        }
    }

    #[test]
    fn recovery_refuses_concurrent_local_state_and_preserves_it() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        commit_executable_trust_inner(
            &plan,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            Some(TrustJournalPhase::Prepared),
        )
        .unwrap_err();
        let concurrent = fixture.state_text.replace(
            "trust-transaction-machine",
            "concurrent-transaction-machine",
        );
        fs::write(fixture.state.join(STATE_PATH), &concurrent).unwrap();
        let error = recover_executable_trust(&fixture.environment, &fixture.state).unwrap_err();
        assert_eq!(error.code(), "trust.recovery_conflict");
        assert_eq!(
            fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
            concurrent
        );
    }

    #[test]
    fn recovery_rejects_a_valid_but_forged_decision_transition() {
        let fixture = Fixture::new();
        let plan = fixture.plan();
        commit_executable_trust_inner(
            &plan,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            Some(TrustJournalPhase::Prepared),
        )
        .unwrap_err();

        let journal_path = fixture.state.join(JOURNAL_PATH);
        let mut journal: TrustJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        let staged_path = fixture.state.join(journal.staging_state.as_str());
        let mut staged = LocalState::from_json(&fs::read_to_string(&staged_path).unwrap()).unwrap();
        staged.trust.insert(
            ContentHash::digest(b"unrelated executable"),
            TrustDecision::Denied {
                rationale: "forged transition".to_owned(),
            },
        );
        let forged = staged.to_json().unwrap();
        fs::write(&staged_path, &forged).unwrap();
        journal.new_state_hash = ContentHash::digest(forged.as_bytes());
        fs::write(&journal_path, journal_text(&journal).unwrap()).unwrap();

        let error = recover_executable_trust(&fixture.environment, &fixture.state).unwrap_err();
        assert_eq!(error.code(), "trust.journal_invalid");
        assert_eq!(
            fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
            fixture.state_text
        );
        assert!(journal_path.exists());
    }

    #[test]
    fn committed_recovery_rejects_a_forged_complete_journal_tuple() {
        let fixture = Fixture::new();
        commit_executable_trust_inner(
            &fixture.plan(),
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
            Some(TrustJournalPhase::StateCommitted),
        )
        .unwrap_err();
        let journal_path = fixture.state.join(JOURNAL_PATH);
        let mut journal: TrustJournal =
            serde_json::from_str(&fs::read_to_string(&journal_path).unwrap()).unwrap();
        journal.asset_id = AssetId::parse("forged-review").unwrap();
        fs::write(&journal_path, journal_text(&journal).unwrap()).unwrap();
        let error = recover_executable_trust(&fixture.environment, &fixture.state).unwrap_err();
        assert_eq!(error.code(), "trust.journal_invalid");
        assert!(journal_path.exists());
    }

    #[test]
    fn trust_refuses_every_foreign_local_state_recovery_artifact() {
        for (in_environment, path) in [
            (false, local_state_authority::EXTENSION_APPLY_JOURNAL_PATH),
            (false, local_state_authority::SKILL_APPLY_JOURNAL_PATH),
            (false, local_state_authority::SKILL_APPLY_PENDING_PATH),
            (true, local_state_authority::ADOPTION_JOURNAL_PATH),
            (true, local_state_authority::ADOPTION_PENDING_PATH),
        ] {
            let fixture = Fixture::new();
            let root = if in_environment {
                &fixture.environment
            } else {
                &fixture.state
            };
            if in_environment {
                fs::create_dir_all(root.join(".kitrove")).unwrap();
                fs::write(root.join(path), "{}\n").unwrap();
            } else {
                crate::test_authority::stage_private_text(&fixture.state, path, "{}\n").unwrap();
            }
            let error = commit_executable_trust(
                &fixture.plan(),
                &fixture.environment,
                &fixture.state,
                CaptureLimits::default(),
            )
            .unwrap_err();
            assert_eq!(error.code(), "trust.local_state_recovery_required");
            assert_eq!(
                fs::read_to_string(fixture.state.join(STATE_PATH)).unwrap(),
                fixture.state_text
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn committed_local_state_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        let plan = fixture.plan();
        commit_executable_trust(
            &plan,
            &fixture.environment,
            &fixture.state,
            CaptureLimits::default(),
        )
        .unwrap();
        let mode = fs::metadata(fixture.state.join(STATE_PATH))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
