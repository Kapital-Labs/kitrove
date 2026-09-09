use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{
    ObjectDescriptor, PortablePath, PublicationId, RemoteKey, SnapshotObjectKind, SyncLimits,
};

use crate::guarded_journal;
use crate::local_state_authority;
use crate::merge::{VerifiedSkillObjectCatalog, validate_manifest_object_risk};
use crate::quarantine_cleanup::coordinator::{
    ActiveMutationBudget, MutationCleanupError, cleanup_locked_stores,
};
use crate::sync_backend::VerifiedDocumentObject;
use crate::sync_portable_transaction::{
    SyncPortableJournalBinding, bind_sync_portable_journal,
    commit_sync_portable_snapshot_under_lock, recover_sync_portable_snapshot_under_lock,
};
use crate::{
    ObjectStore, PortableSnapshotV1, PublicationStatus, RetainedSyncBase, SyncBackend,
    SyncBackendApply, SyncBaseStore, SyncJournal, SyncJournalPhase, SyncPlan,
    SyncPortableRecoveryOutcome, VerifiedObjectEnvelope,
};

mod cleanup_inventory;

use cleanup_inventory::SyncMutationInventory;

/// Successful outcome of one confirmed cross-machine sync transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncCommitOutcome {
    Committed,
    Recovered,
}

/// Result of resolving an outer cross-machine sync journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncRecoveryOutcome {
    NoJournal,
    Completed,
}

/// Returns the machine-local journal path for one opaque remote identity.
pub fn sync_transaction_journal_path(
    remote_key: &RemoteKey,
) -> Result<PortablePath, SyncTransactionError> {
    PortablePath::parse(format!("sync/{}/journal.json", remote_hex(remote_key)?))
        .map_err(|_| input_invalid())
}

/// Stable path-, revision-, and content-redacted sync transaction failure.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncTransactionError {
    code: &'static str,
    message: &'static str,
}

impl SyncTransactionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for SyncTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncTransactionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for SyncTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SyncTransactionError {}

/// Applies one already-confirmed exact sync plan under local-then-backend locks.
#[allow(clippy::too_many_arguments)]
pub fn commit_sync_transaction<B: SyncBackend>(
    environment_root: &Path,
    local_state_root: &Path,
    backend: &B,
    remote_key: &RemoteKey,
    plan: &SyncPlan,
    merged_objects: &[VerifiedObjectEnvelope],
    publication_id: Option<PublicationId>,
    limits: SyncLimits,
) -> Result<SyncCommitOutcome, SyncTransactionError> {
    commit_sync_transaction_inner(
        environment_root,
        local_state_root,
        backend,
        remote_key,
        plan,
        merged_objects,
        publication_id,
        limits,
        None,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_sync_transaction_inner<B: SyncBackend>(
    environment_root: &Path,
    local_state_root: &Path,
    backend: &B,
    remote_key: &RemoteKey,
    plan: &SyncPlan,
    merged_objects: &[VerifiedObjectEnvelope],
    publication_id: Option<PublicationId>,
    limits: SyncLimits,
    interrupt_after: Option<SyncJournalPhase>,
    interrupt_after_remote_publish: bool,
) -> Result<SyncCommitOutcome, SyncTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(storage_error)?;
    let state =
        ObjectStore::open_or_create_private_state(local_state_root).map_err(storage_error)?;
    environment
        .require_non_overlapping_root(&state)
        .map_err(storage_error)?;
    let _root_locks =
        ObjectStore::try_lock_distinct_roots(&[&environment, &state]).map_err(lock_error)?;
    let _state_lock = state
        .try_lock_file(&sync_lock_path(remote_key)?)
        .map_err(lock_error)?;
    ensure_no_adoption_journal(&environment, limits)?;
    ensure_no_local_state_journal(&state, limits)?;
    if let Some(recovery) = inspect_sync_recovery(&state, remote_key, limits)? {
        let nested_journal =
            bind_sync_portable_journal(&environment, limits).map_err(portable_error)?;
        let (forward, rollback) = SyncMutationInventory::from_snapshot(&recovery.merged)
            .recovery_work(&recovery.merged, limits)?;
        let budget = cleanup_locked_stores(&[&environment, &state], forward, rollback)
            .map_err(cleanup_coordinator_error)?;
        let mutation_budget = budget.begin_forward().map_err(cleanup_coordinator_error)?;
        let bases = SyncBaseStore::from_private_state_store(&state).map_err(base_error)?;
        let mut session = backend.begin_apply(limits).map_err(backend_error)?;
        recover_with_stores(
            &environment,
            &state,
            &bases,
            &mut session,
            remote_key,
            limits,
            &guarded_journal::JournalExpectation::Present(recovery.journal.clone()),
            &nested_journal,
            &mutation_budget,
        )?;
        return Ok(SyncCommitOutcome::Recovered);
    }
    let nested_journal =
        bind_sync_portable_journal(&environment, limits).map_err(|_| orphan_local_journal())?;
    if !nested_journal.is_absent() {
        return Err(orphan_local_journal());
    }

    validate_local_authority(&environment, plan.local(), limits)?;
    validate_objects(plan.merged(), merged_objects, limits)?;
    validate_snapshot_risk(plan.merged(), merged_objects, limits)?;
    let publication_required = plan
        .remote_snapshot()
        .is_none_or(|remote| remote.snapshot_digest() != plan.merged().snapshot_digest());
    if publication_required != publication_id.is_some() {
        return Err(input_invalid());
    }
    let (forward, rollback) = SyncMutationInventory::from_snapshot(plan.merged()).commit_work(
        plan.merged(),
        publication_required,
        limits,
    )?;
    let budget = cleanup_locked_stores(&[&environment, &state], forward, rollback)
        .map_err(cleanup_coordinator_error)?;
    let mutation_budget = budget.begin_forward().map_err(cleanup_coordinator_error)?;
    let bases = SyncBaseStore::from_private_state_store(&state).map_err(base_error)?;
    let mut session = backend.begin_apply(limits).map_err(backend_error)?;
    let remote = session.inspect(limits).map_err(backend_error)?;
    if remote.revision() != plan.remote_revision() || remote.snapshot() != plan.remote_snapshot() {
        return Err(stale_remote());
    }
    revalidate_downloads(&mut session, plan, merged_objects, limits)?;
    let retained = bases.inspect(remote_key, limits).map_err(base_error)?;
    validate_planned_base(plan, retained.as_ref())?;
    let prior_generation = retained
        .as_ref()
        .map(|retained| retained.generation().clone());

    let publication = publication_id
        .map(|id| {
            session
                .prepare_publication(
                    plan.remote_revision(),
                    &id,
                    plan.merged(),
                    merged_objects,
                    limits,
                )
                .map(|intent| (id, intent))
                .map_err(backend_error)
        })
        .transpose()?;

    let mut journal = SyncJournal::prepared(
        plan,
        remote_key.clone(),
        publication
            .as_ref()
            .map(|(id, intent)| (id.clone(), intent)),
        prior_generation,
        limits,
    )
    .map_err(journal_error)?;
    install_outer_guard(&environment, remote_key, limits)?;
    stage_outer(
        &state,
        &journal,
        plan.local(),
        plan.merged(),
        merged_objects,
        limits,
    )?;
    let mut encoded = install_initial_journal(&state, &journal, limits)?;
    interrupt(SyncJournalPhase::Prepared, interrupt_after)?;

    if let Some((_, intent)) = publication.as_ref() {
        advance_journal(
            &state,
            &mut journal,
            &mut encoded,
            SyncJournalPhase::Publishing,
            limits,
        )?;
        interrupt(SyncJournalPhase::Publishing, interrupt_after)?;
        match session
            .publish(intent, plan.merged(), merged_objects, limits)
            .map_err(backend_error)?
        {
            PublicationStatus::Published(revision)
                if &revision == journal.proposed_remote_revision() => {}
            PublicationStatus::Published(_) | PublicationStatus::Ready => {
                return Err(publication_invalid());
            }
            PublicationStatus::Uncertain => return Err(publication_uncertain()),
        }
        if interrupt_after_remote_publish {
            return Err(error(
                "sync.test_interrupted",
                "synchronization was interrupted after remote publication",
            ));
        }
    }
    advance_journal(
        &state,
        &mut journal,
        &mut encoded,
        SyncJournalPhase::RemotePublished,
        limits,
    )?;
    interrupt(SyncJournalPhase::RemotePublished, interrupt_after)?;
    finish_local_and_base(
        &environment,
        &state,
        &bases,
        &mut journal,
        &mut encoded,
        plan.local(),
        plan.merged(),
        merged_objects,
        limits,
        interrupt_after,
        &mutation_budget,
        &nested_journal,
    )?;
    cleanup_outer(&state, &journal, merged_objects, limits)?;
    remove_outer_guard(&environment)?;
    Ok(SyncCommitOutcome::Committed)
}

/// Recovers an interrupted cross-machine sync without trusting caller-supplied snapshots.
pub fn recover_sync_transaction<B: SyncBackend>(
    environment_root: &Path,
    local_state_root: &Path,
    backend: &B,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<SyncRecoveryOutcome, SyncTransactionError> {
    let environment = ObjectStore::open(environment_root).map_err(storage_error)?;
    let state =
        ObjectStore::open_or_create_private_state(local_state_root).map_err(storage_error)?;
    environment
        .require_non_overlapping_root(&state)
        .map_err(storage_error)?;
    let _root_locks =
        ObjectStore::try_lock_distinct_roots(&[&environment, &state]).map_err(lock_error)?;
    let _state_lock = state
        .try_lock_file(&sync_lock_path(remote_key)?)
        .map_err(lock_error)?;
    ensure_no_adoption_journal(&environment, limits)?;
    ensure_no_local_state_journal(&state, limits)?;
    let inspected = inspect_sync_recovery(&state, remote_key, limits)?;
    let outer_journal = guarded_journal::JournalExpectation::from_option(
        inspected.as_ref().map(|recovery| recovery.journal.clone()),
    );
    let nested_journal =
        bind_sync_portable_journal(&environment, limits).map_err(portable_error)?;
    let (forward, rollback) = match inspected.as_ref() {
        Some(recovery) => SyncMutationInventory::from_snapshot(&recovery.merged)
            .recovery_work(&recovery.merged, limits)?,
        None => SyncMutationInventory::orphan_guard_work(limits)?,
    };
    let budget = cleanup_locked_stores(&[&environment, &state], forward, rollback)
        .map_err(cleanup_coordinator_error)?;
    let mutation_budget = budget.begin_forward().map_err(cleanup_coordinator_error)?;
    let bases = SyncBaseStore::from_private_state_store(&state).map_err(base_error)?;
    let mut session = backend.begin_apply(limits).map_err(backend_error)?;
    recover_with_stores(
        &environment,
        &state,
        &bases,
        &mut session,
        remote_key,
        limits,
        &outer_journal,
        &nested_journal,
        &mutation_budget,
    )
}

struct InspectedSyncRecovery {
    journal: SyncJournal,
    merged: PortableSnapshotV1,
}

fn inspect_sync_recovery(
    state: &ObjectStore,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<Option<InspectedSyncRecovery>, SyncTransactionError> {
    let Some((journal, _)) = read_journal(state, remote_key, limits)? else {
        return Ok(None);
    };
    if journal.remote_key() != remote_key {
        return Err(journal_invalid());
    }
    let merged = load_staged_merged(state, &journal, limits)?;
    let objects = load_staged_objects(state, &journal, &merged, limits)?;
    validate_snapshot_risk(&merged, &objects, limits)?;
    Ok(Some(InspectedSyncRecovery { journal, merged }))
}

#[allow(clippy::too_many_arguments)]
fn recover_with_stores(
    environment: &ObjectStore,
    state: &ObjectStore,
    bases: &SyncBaseStore,
    session: &mut impl SyncBackendApply,
    remote_key: &RemoteKey,
    limits: SyncLimits,
    expected: &guarded_journal::JournalExpectation<SyncJournal>,
    nested_journal: &SyncPortableJournalBinding,
    mutation_budget: &ActiveMutationBudget,
) -> Result<SyncRecoveryOutcome, SyncTransactionError> {
    let inspected = read_journal(state, remote_key, limits)?;
    if !expected.matches(inspected.as_ref().map(|(journal, _)| journal)) {
        return Err(recovery_blocked());
    }
    let Some((mut journal, mut encoded)) = inspected else {
        reconcile_orphan_outer_guard(environment, remote_key, limits)?;
        return Ok(SyncRecoveryOutcome::NoJournal);
    };
    require_outer_guard(environment, remote_key, limits)?;
    if journal.remote_key() != remote_key {
        return Err(journal_invalid());
    }
    let local = load_staged_local(state, &journal, limits)?;
    let merged = load_staged_merged(state, &journal, limits)?;
    let objects = load_staged_objects(state, &journal, &merged, limits)?;
    validate_snapshot_risk(&merged, &objects, limits)?;
    reconcile_outer_journal(state, remote_key, limits)?;
    if journal.phase() >= SyncJournalPhase::BaseCommitting {
        bases
            .reconcile_interrupted_pointer(
                journal.remote_key(),
                journal.prior_base_generation(),
                journal.proposed_base_generation(),
                journal.plan_digest(),
                limits,
            )
            .map_err(base_error)?;
    }

    if let Some(intent) = journal.publication_intent(limits).map_err(journal_error)? {
        let status = session
            .reconcile(&intent, limits)
            .map_err(|_| recovery_blocked())?;
        match status {
            PublicationStatus::Published(revision)
                if &revision == journal.proposed_remote_revision() => {}
            PublicationStatus::Ready => {
                if !matches!(
                    journal.phase(),
                    SyncJournalPhase::Prepared | SyncJournalPhase::Publishing
                ) {
                    return Err(recovery_blocked());
                }
                validate_recovery_prepublication_authority(
                    environment,
                    bases,
                    &journal,
                    &local,
                    limits,
                )?;
                if journal.phase() == SyncJournalPhase::Prepared {
                    advance_journal(
                        state,
                        &mut journal,
                        &mut encoded,
                        SyncJournalPhase::Publishing,
                        limits,
                    )?;
                }
                match session
                    .publish(&intent, &merged, &objects, limits)
                    .map_err(|_| recovery_blocked())?
                {
                    PublicationStatus::Published(revision)
                        if &revision == journal.proposed_remote_revision() => {}
                    PublicationStatus::Published(_) | PublicationStatus::Ready => {
                        return Err(publication_invalid());
                    }
                    PublicationStatus::Uncertain => return Err(recovery_blocked()),
                }
            }
            PublicationStatus::Published(_) => return Err(publication_invalid()),
            PublicationStatus::Uncertain => return Err(recovery_blocked()),
        }
    } else {
        let remote = session.inspect(limits).map_err(backend_error)?;
        if remote.revision() != journal.proposed_remote_revision()
            || remote
                .snapshot()
                .is_none_or(|snapshot| snapshot.snapshot_digest() != merged.snapshot_digest())
        {
            return Err(stale_remote());
        }
    }
    advance_to_at_least(
        state,
        &mut journal,
        &mut encoded,
        SyncJournalPhase::RemotePublished,
        limits,
    )?;
    finish_local_and_base(
        environment,
        state,
        bases,
        &mut journal,
        &mut encoded,
        &local,
        &merged,
        &objects,
        limits,
        None,
        mutation_budget,
        nested_journal,
    )?;
    cleanup_outer(state, &journal, &objects, limits)?;
    remove_outer_guard(environment)?;
    Ok(SyncRecoveryOutcome::Completed)
}

fn ensure_no_adoption_journal(
    environment: &ObjectStore,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    if local_state_authority::any_journal_present(
        environment,
        local_state_authority::ADOPTION_RECOVERY,
        control_limit(limits)?,
    )
    .map_err(storage_error)?
    {
        return Err(orphan_local_journal());
    }
    Ok(())
}

fn ensure_no_local_state_journal(
    state: &ObjectStore,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    if local_state_authority::any_journal_present(
        state,
        local_state_authority::ALL_LOCAL_STATE_RECOVERY,
        control_limit(limits)?,
    )
    .map_err(storage_error)?
    {
        return Err(orphan_local_journal());
    }
    Ok(())
}

fn outer_guard_path() -> Result<PortablePath, SyncTransactionError> {
    portable_path(local_state_authority::OUTER_SYNC_GUARD_PATH)
}

fn outer_guard_text(remote_key: &RemoteKey) -> String {
    format!("{}\n", remote_key.as_str())
}

fn install_outer_guard(
    environment: &ObjectStore,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    environment
        .stage_text(
            &outer_guard_path()?,
            &outer_guard_text(remote_key),
            control_limit(limits)?,
        )
        .map_err(journal_write_error)
}

fn require_outer_guard(
    environment: &ObjectStore,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    if environment
        .read_text(&outer_guard_path()?, control_limit(limits)?)
        .map_err(journal_read_error)?
        .as_deref()
        != Some(outer_guard_text(remote_key).as_str())
    {
        return Err(journal_invalid());
    }
    Ok(())
}

fn reconcile_orphan_outer_guard(
    environment: &ObjectStore,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    let observed = environment
        .read_text(&outer_guard_path()?, control_limit(limits)?)
        .map_err(journal_read_error)?;
    match observed.as_deref() {
        None => Ok(()),
        Some(value) if value == outer_guard_text(remote_key) => remove_outer_guard(environment),
        Some(_) => Err(orphan_local_journal()),
    }
}

fn remove_outer_guard(environment: &ObjectStore) -> Result<(), SyncTransactionError> {
    environment
        .remove_regular_file_if_present(&outer_guard_path()?)
        .map_err(cleanup_error)
}

fn validate_recovery_prepublication_authority(
    environment: &ObjectStore,
    bases: &SyncBaseStore,
    journal: &SyncJournal,
    local: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    validate_local_authority(environment, local, limits)?;
    let retained = bases
        .inspect(journal.remote_key(), limits)
        .map_err(base_error)?;
    if retained.as_ref().map(RetainedSyncBase::generation) != journal.prior_base_generation() {
        return Err(base_stale());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_local_and_base(
    environment: &ObjectStore,
    state: &ObjectStore,
    bases: &SyncBaseStore,
    journal: &mut SyncJournal,
    encoded: &mut String,
    local: &PortableSnapshotV1,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
    interrupt_after: Option<SyncJournalPhase>,
    mutation_budget: &ActiveMutationBudget,
    nested_journal: &SyncPortableJournalBinding,
) -> Result<(), SyncTransactionError> {
    advance_to_at_least(
        state,
        journal,
        encoded,
        SyncJournalPhase::LocalCommitting,
        limits,
    )?;
    interrupt(SyncJournalPhase::LocalCommitting, interrupt_after)?;
    match recover_sync_portable_snapshot_under_lock(
        environment,
        merged,
        objects,
        journal.plan_digest(),
        limits,
        mutation_budget,
        nested_journal,
    )
    .map_err(portable_error)?
    {
        SyncPortableRecoveryOutcome::Completed => {}
        SyncPortableRecoveryOutcome::NoJournal => {
            if authority_matches(environment, merged, limits)? {
                // The nested journal was cleaned before the outer phase advanced.
            } else {
                commit_sync_portable_snapshot_under_lock(
                    environment,
                    local,
                    merged,
                    objects,
                    journal.plan_digest(),
                    limits,
                    mutation_budget,
                )
                .map_err(portable_error)?;
            }
        }
    }
    advance_to_at_least(
        state,
        journal,
        encoded,
        SyncJournalPhase::LocalCommitted,
        limits,
    )?;
    interrupt(SyncJournalPhase::LocalCommitted, interrupt_after)?;
    advance_to_at_least(
        state,
        journal,
        encoded,
        SyncJournalPhase::BaseCommitting,
        limits,
    )?;
    interrupt(SyncJournalPhase::BaseCommitting, interrupt_after)?;

    let current = bases
        .inspect(journal.remote_key(), limits)
        .map_err(base_error)?;
    if current.as_ref().map(RetainedSyncBase::generation)
        != Some(journal.proposed_base_generation())
    {
        if current.as_ref().map(RetainedSyncBase::generation) != journal.prior_base_generation() {
            return Err(base_stale());
        }
        let retained = bases
            .commit(
                journal.remote_key(),
                journal.prior_base_generation(),
                merged,
                journal.proposed_remote_revision(),
                objects,
                journal.plan_digest(),
                limits,
            )
            .map_err(base_error)?;
        if retained.generation() != journal.proposed_base_generation() {
            return Err(base_invalid());
        }
    }
    advance_to_at_least(
        state,
        journal,
        encoded,
        SyncJournalPhase::BaseCommitted,
        limits,
    )?;
    interrupt(SyncJournalPhase::BaseCommitted, interrupt_after)?;
    advance_to_at_least(state, journal, encoded, SyncJournalPhase::Complete, limits)?;
    interrupt(SyncJournalPhase::Complete, interrupt_after)
}

fn interrupt(
    phase: SyncJournalPhase,
    interrupt_after: Option<SyncJournalPhase>,
) -> Result<(), SyncTransactionError> {
    if interrupt_after == Some(phase) {
        Err(error(
            "sync.test_interrupted",
            "synchronization was interrupted at a durable test boundary",
        ))
    } else {
        Ok(())
    }
}

fn validate_planned_base(
    plan: &SyncPlan,
    retained: Option<&RetainedSyncBase>,
) -> Result<(), SyncTransactionError> {
    match (plan.base(), retained) {
        (None, None) => Ok(()),
        (Some(planned), Some(retained)) if planned == retained.input() => Ok(()),
        _ => Err(base_stale()),
    }
}

fn validate_local_authority(
    store: &ObjectStore,
    expected: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    if store
        .read_text(&portable_path("kitrove.toml")?, manifest_limit(limits)?)
        .map_err(storage_error)?
        .as_deref()
        != Some(expected.manifest_toml())
        || store
            .read_text(&portable_path("kitrove.lock.json")?, lock_limit(limits)?)
            .map_err(storage_error)?
            .as_deref()
            != Some(expected.lock_json())
    {
        return Err(local_stale());
    }
    let capture = capture_limits(limits);
    for descriptor in expected.objects() {
        let verified = match descriptor.kind() {
            SnapshotObjectKind::PortableSkillTree => store
                .load_portable(descriptor.root(), capture)
                .ok()
                .and_then(|object| {
                    VerifiedObjectEnvelope::portable(descriptor.root().clone(), object).ok()
                }),
            SnapshotObjectKind::NativeSkillObject => store
                .load_native(descriptor.root(), capture)
                .ok()
                .and_then(|object| {
                    VerifiedObjectEnvelope::native(descriptor.root().clone(), object).ok()
                }),
            SnapshotObjectKind::NativeExtensionObject => store
                .load_native_extension_bounded(descriptor.root(), capture, descriptor.encoded_len())
                .ok()
                .and_then(|object| {
                    VerifiedObjectEnvelope::native_extension(descriptor.root().clone(), object).ok()
                }),
            kind @ (SnapshotObjectKind::PortableInstruction
            | SnapshotObjectKind::NativeInstruction
            | SnapshotObjectKind::PortablePromptCommand
            | SnapshotObjectKind::NativePromptCommand
            | SnapshotObjectKind::PortableAgent
            | SnapshotObjectKind::NativeAgent
            | SnapshotObjectKind::PortableMcp
            | SnapshotObjectKind::NativeMcp) => VerifiedDocumentObject::load(
                store,
                descriptor.root(),
                kind,
                capture,
                descriptor.encoded_len(),
            )
            .ok()
            .and_then(|object| {
                VerifiedObjectEnvelope::document(descriptor.root().clone(), object).ok()
            }),
        };
        if verified.is_none_or(|object| object.descriptor() != descriptor) {
            return Err(local_stale());
        }
    }
    Ok(())
}

fn revalidate_downloads(
    session: &mut impl SyncBackendApply,
    plan: &SyncPlan,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    for descriptor in plan.download() {
        let fetched = session
            .fetch_object(descriptor, limits)
            .map_err(backend_error)?;
        if !objects.iter().any(|object| object == &fetched) {
            return Err(staging_invalid());
        }
    }
    Ok(())
}

fn stage_outer(
    state: &ObjectStore,
    journal: &SyncJournal,
    local: &PortableSnapshotV1,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    validate_objects(merged, objects, limits)?;
    let snapshot = merged.to_json(limits).map_err(snapshot_error)?;
    let local_snapshot = local.to_json(limits).map_err(snapshot_error)?;
    state
        .stage_text(
            journal.staging_snapshot(),
            &snapshot,
            snapshot_limit(limits)?,
        )
        .map_err(staging_error)?;
    state
        .stage_text(
            &local_snapshot_path(journal)?,
            &local_snapshot,
            snapshot_limit(limits)?,
        )
        .map_err(staging_error)?;
    state
        .stage_text(
            journal.staging_manifest(),
            merged.manifest_toml(),
            manifest_limit(limits)?,
        )
        .map_err(staging_error)?;
    state
        .stage_text(
            journal.staging_lock(),
            merged.lock_json(),
            lock_limit(limits)?,
        )
        .map_err(staging_error)?;
    stage_outer_objects(state, &payload_base(journal)?, objects, limits)
}

fn stage_outer_objects(
    state: &ObjectStore,
    base: &PortablePath,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    let mut ordered: Vec<_> = objects.iter().collect();
    ordered.sort_by_key(|object| object.descriptor());
    for (index, object) in ordered.into_iter().enumerate() {
        let path = outer_object_path(base, index)?;
        match object {
            VerifiedObjectEnvelope::Portable { object, .. } => state
                .stage_portable(&path, object, capture_limits(limits))
                .map_err(staging_error)
                .map(|_| ())?,
            VerifiedObjectEnvelope::Native { object, .. } => state
                .stage_native(&path, object, capture_limits(limits))
                .map_err(staging_error)
                .map(|_| ())?,
            VerifiedObjectEnvelope::NativeExtension { object, .. } => state
                .stage_native_extension(&path, object, capture_limits(limits))
                .map_err(staging_error)
                .map(|_| ())?,
            VerifiedObjectEnvelope::Document { object, .. } => object
                .stage(state, &path, capture_limits(limits))
                .map_err(staging_error)?,
        };
        let loaded = load_one_object(state, &path, object.descriptor(), limits)?;
        if loaded.descriptor() != object.descriptor() {
            return Err(staging_invalid());
        }
    }
    Ok(())
}

fn load_staged_local(
    state: &ObjectStore,
    journal: &SyncJournal,
    limits: SyncLimits,
) -> Result<PortableSnapshotV1, SyncTransactionError> {
    let encoded = required_text(
        state,
        &local_snapshot_path(journal)?,
        snapshot_limit(limits)?,
    )?;
    let snapshot = PortableSnapshotV1::from_json(&encoded, limits).map_err(snapshot_error)?;
    if snapshot.snapshot_digest() != journal.local_snapshot_digest() {
        return Err(staging_invalid());
    }
    Ok(snapshot)
}

fn load_staged_merged(
    state: &ObjectStore,
    journal: &SyncJournal,
    limits: SyncLimits,
) -> Result<PortableSnapshotV1, SyncTransactionError> {
    let encoded = required_text(state, journal.staging_snapshot(), snapshot_limit(limits)?)?;
    let snapshot = PortableSnapshotV1::from_json(&encoded, limits).map_err(snapshot_error)?;
    if snapshot.snapshot_digest() != journal.merged_snapshot_digest()
        || required_text(state, journal.staging_manifest(), manifest_limit(limits)?)?
            != snapshot.manifest_toml()
        || required_text(state, journal.staging_lock(), lock_limit(limits)?)?
            != snapshot.lock_json()
    {
        return Err(staging_invalid());
    }
    Ok(snapshot)
}

fn load_staged_objects(
    state: &ObjectStore,
    journal: &SyncJournal,
    merged: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<Vec<VerifiedObjectEnvelope>, SyncTransactionError> {
    let mut objects = Vec::with_capacity(merged.objects().len());
    for (index, descriptor) in merged.objects().iter().enumerate() {
        objects.push(load_one_object(
            state,
            &outer_object_path(&payload_base(journal)?, index)?,
            descriptor,
            limits,
        )?);
    }
    validate_objects(merged, &objects, limits)?;
    Ok(objects)
}

fn load_one_object(
    store: &ObjectStore,
    path: &PortablePath,
    descriptor: &ObjectDescriptor,
    limits: SyncLimits,
) -> Result<VerifiedObjectEnvelope, SyncTransactionError> {
    let object = match descriptor.kind() {
        SnapshotObjectKind::PortableSkillTree => VerifiedObjectEnvelope::portable(
            descriptor.root().clone(),
            store
                .load_portable(path, capture_limits(limits))
                .map_err(storage_error)?,
        ),
        SnapshotObjectKind::NativeSkillObject => VerifiedObjectEnvelope::native(
            descriptor.root().clone(),
            store
                .load_native(path, capture_limits(limits))
                .map_err(storage_error)?,
        ),
        SnapshotObjectKind::NativeExtensionObject => VerifiedObjectEnvelope::native_extension(
            descriptor.root().clone(),
            store
                .load_native_extension_bounded(
                    path,
                    capture_limits(limits),
                    descriptor.encoded_len(),
                )
                .map_err(storage_error)?,
        ),
        kind @ (SnapshotObjectKind::PortableInstruction
        | SnapshotObjectKind::NativeInstruction
        | SnapshotObjectKind::PortablePromptCommand
        | SnapshotObjectKind::NativePromptCommand
        | SnapshotObjectKind::PortableAgent
        | SnapshotObjectKind::NativeAgent
        | SnapshotObjectKind::PortableMcp
        | SnapshotObjectKind::NativeMcp) => VerifiedObjectEnvelope::document(
            descriptor.root().clone(),
            VerifiedDocumentObject::load(
                store,
                path,
                kind,
                capture_limits(limits),
                descriptor.encoded_len(),
            )
            .map_err(storage_error)?,
        ),
    }
    .map_err(|_| staging_invalid())?;
    if object.descriptor() != descriptor {
        return Err(staging_invalid());
    }
    Ok(object)
}

fn validate_objects(
    snapshot: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    if objects.len() > limits.max_object_count() {
        return Err(input_invalid());
    }
    let descriptors: BTreeSet<_> = objects
        .iter()
        .map(|object| object.descriptor().clone())
        .collect();
    if descriptors.len() != objects.len() || descriptors != *snapshot.objects() {
        return Err(input_invalid());
    }
    Ok(())
}

fn validate_snapshot_risk(
    snapshot: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    let portable = objects.iter().filter_map(|object| match object {
        VerifiedObjectEnvelope::Portable { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Native { .. } => None,
        VerifiedObjectEnvelope::NativeExtension { .. } => None,
        VerifiedObjectEnvelope::Document { .. } => None,
    });
    let native = objects.iter().filter_map(|object| match object {
        VerifiedObjectEnvelope::Native { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Portable { .. } => None,
        VerifiedObjectEnvelope::NativeExtension { .. } => None,
        VerifiedObjectEnvelope::Document { .. } => None,
    });
    let native_extensions = objects.iter().filter_map(|object| match object {
        VerifiedObjectEnvelope::NativeExtension { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Portable { .. } | VerifiedObjectEnvelope::Native { .. } => None,
        VerifiedObjectEnvelope::Document { .. } => None,
    });
    let documents = objects.iter().filter_map(|object| match object {
        VerifiedObjectEnvelope::Document { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Portable { .. }
        | VerifiedObjectEnvelope::Native { .. }
        | VerifiedObjectEnvelope::NativeExtension { .. } => None,
    });
    let catalog = VerifiedSkillObjectCatalog::new_with_documents(
        portable,
        native,
        native_extensions,
        documents,
    )
    .map_err(|_| staging_invalid())?;
    validate_manifest_object_risk(snapshot.manifest(), &catalog, limits)
        .map_err(|_| staging_invalid())
}

fn authority_matches(
    environment: &ObjectStore,
    snapshot: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<bool, SyncTransactionError> {
    if environment
        .read_text(&portable_path("kitrove.toml")?, manifest_limit(limits)?)
        .map_err(storage_error)?
        .as_deref()
        != Some(snapshot.manifest_toml())
        || environment
            .read_text(&portable_path("kitrove.lock.json")?, lock_limit(limits)?)
            .map_err(storage_error)?
            .as_deref()
            != Some(snapshot.lock_json())
    {
        return Ok(false);
    }
    for descriptor in snapshot.objects() {
        if load_one_object(environment, descriptor.root(), descriptor, limits).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn install_initial_journal(
    state: &ObjectStore,
    journal: &SyncJournal,
    limits: SyncLimits,
) -> Result<String, SyncTransactionError> {
    let encoded = journal.to_json(limits).map_err(journal_error)?;
    let pending = journal_pending_path(journal.remote_key())?;
    state
        .stage_text(&pending, &encoded, control_limit(limits)?)
        .map_err(journal_write_error)?;
    state
        .install_staged_text_guarded(
            &pending,
            &sync_transaction_journal_path(journal.remote_key())?,
            None,
            &encoded,
            control_limit(limits)?,
        )
        .map_err(journal_write_error)?;
    Ok(encoded)
}

fn read_journal(
    state: &ObjectStore,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<Option<(SyncJournal, String)>, SyncTransactionError> {
    let journal = guarded_journal::inspect(
        state,
        &sync_transaction_journal_path(remote_key)?,
        &journal_pending_path(remote_key)?,
        control_limit(limits)?,
        |encoded| SyncJournal::from_json(encoded, limits).map_err(journal_error),
        valid_outer_journal_transition,
        journal_invalid,
    )
    .map_err(map_guarded_journal_error)?;
    journal
        .map(|journal| {
            let encoded = journal.to_json(limits).map_err(journal_error)?;
            Ok((journal, encoded))
        })
        .transpose()
}

fn reconcile_outer_journal(
    state: &ObjectStore,
    remote_key: &RemoteKey,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    guarded_journal::reconcile(
        state,
        &sync_transaction_journal_path(remote_key)?,
        &journal_pending_path(remote_key)?,
        control_limit(limits)?,
        |encoded| SyncJournal::from_json(encoded, limits).map_err(journal_error),
        valid_outer_journal_transition,
        journal_invalid,
    )
    .map_err(map_guarded_journal_error)
}

fn valid_outer_journal_transition(old: &SyncJournal, next: &SyncJournal) -> bool {
    old.advance(next.phase())
        .is_ok_and(|expected| expected == *next)
}

fn advance_journal(
    state: &ObjectStore,
    journal: &mut SyncJournal,
    encoded: &mut String,
    next: SyncJournalPhase,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    let advanced = journal.advance(next).map_err(journal_error)?;
    let next_encoded = advanced.to_json(limits).map_err(journal_error)?;
    state
        .replace_text_atomically_guarded(
            &journal_pending_path(journal.remote_key())?,
            &sync_transaction_journal_path(journal.remote_key())?,
            Some(encoded),
            &next_encoded,
            control_limit(limits)?,
        )
        .map_err(journal_write_error)?;
    *journal = advanced;
    *encoded = next_encoded;
    Ok(())
}

fn advance_to_at_least(
    state: &ObjectStore,
    journal: &mut SyncJournal,
    encoded: &mut String,
    target: SyncJournalPhase,
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    while journal.phase() < target {
        let next = match journal.phase() {
            SyncJournalPhase::Prepared => {
                if journal
                    .publication_intent(limits)
                    .map_err(journal_error)?
                    .is_some()
                {
                    SyncJournalPhase::Publishing
                } else {
                    SyncJournalPhase::RemotePublished
                }
            }
            SyncJournalPhase::Publishing => SyncJournalPhase::RemotePublished,
            SyncJournalPhase::RemotePublished => SyncJournalPhase::LocalCommitting,
            SyncJournalPhase::LocalCommitting => SyncJournalPhase::LocalCommitted,
            SyncJournalPhase::LocalCommitted => SyncJournalPhase::BaseCommitting,
            SyncJournalPhase::BaseCommitting => SyncJournalPhase::BaseCommitted,
            SyncJournalPhase::BaseCommitted => SyncJournalPhase::Complete,
            SyncJournalPhase::Complete => return Err(journal_invalid()),
        };
        advance_journal(state, journal, encoded, next, limits)?;
    }
    Ok(())
}

fn cleanup_outer(
    state: &ObjectStore,
    journal: &SyncJournal,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncTransactionError> {
    state
        .remove_regular_file_if_present(&journal_pending_path(journal.remote_key())?)
        .map_err(cleanup_error)?;
    state
        .remove_regular_file_if_present(&sync_transaction_journal_path(journal.remote_key())?)
        .map_err(cleanup_error)?;
    for (index, object) in sorted_objects(objects).into_iter().enumerate() {
        let path = outer_object_path(&payload_base(journal)?, index)?;
        match object.descriptor().kind() {
            SnapshotObjectKind::PortableSkillTree => state.clear_portable_staging(
                &path,
                object.descriptor().object_hash(),
                capture_limits(limits),
            ),
            SnapshotObjectKind::NativeSkillObject => state.clear_native_staging(
                &path,
                object.descriptor().object_hash(),
                capture_limits(limits),
            ),
            SnapshotObjectKind::NativeExtensionObject => state.clear_native_extension_staging(
                &path,
                object.descriptor().object_hash(),
                capture_limits(limits),
            ),
            kind @ (SnapshotObjectKind::PortableInstruction
            | SnapshotObjectKind::NativeInstruction
            | SnapshotObjectKind::PortablePromptCommand
            | SnapshotObjectKind::NativePromptCommand
            | SnapshotObjectKind::PortableAgent
            | SnapshotObjectKind::NativeAgent
            | SnapshotObjectKind::PortableMcp
            | SnapshotObjectKind::NativeMcp) => VerifiedDocumentObject::clear_staging(
                state,
                &path,
                kind,
                object.descriptor().object_hash(),
                capture_limits(limits),
            ),
        }
        .map_err(cleanup_error)?;
    }
    for path in [
        journal.staging_snapshot(),
        journal.staging_manifest(),
        journal.staging_lock(),
        &local_snapshot_path(journal)?,
    ] {
        state
            .remove_regular_file_if_present(path)
            .map_err(cleanup_error)?;
    }
    state
        .remove_empty_directory_if_present(&joined(&payload_base(journal)?, "objects")?)
        .map_err(cleanup_error)?;
    state
        .remove_empty_directory_if_present(&payload_base(journal)?)
        .map_err(cleanup_error)?;
    Ok(())
}

fn sorted_objects(objects: &[VerifiedObjectEnvelope]) -> Vec<&VerifiedObjectEnvelope> {
    let mut ordered: Vec<_> = objects.iter().collect();
    ordered.sort_by_key(|object| object.descriptor());
    ordered
}

fn local_snapshot_path(journal: &SyncJournal) -> Result<PortablePath, SyncTransactionError> {
    joined(&payload_base(journal)?, "local-snapshot.json")
}

fn payload_base(journal: &SyncJournal) -> Result<PortablePath, SyncTransactionError> {
    let prefix = journal
        .staging_snapshot()
        .as_str()
        .strip_suffix("/snapshot.json")
        .ok_or_else(journal_invalid)?;
    portable_path(&format!("{prefix}/payload"))
}

fn outer_object_path(
    base: &PortablePath,
    index: usize,
) -> Result<PortablePath, SyncTransactionError> {
    joined(base, &format!("objects/{index:08}"))
}

fn joined(base: &PortablePath, suffix: &str) -> Result<PortablePath, SyncTransactionError> {
    portable_path(&format!("{}/{suffix}", base.as_str()))
}

fn required_text(
    store: &ObjectStore,
    path: &PortablePath,
    max_bytes: usize,
) -> Result<String, SyncTransactionError> {
    store
        .read_text(path, max_bytes)
        .map_err(storage_error)?
        .ok_or_else(staging_invalid)
}

fn portable_path(path: &str) -> Result<PortablePath, SyncTransactionError> {
    PortablePath::parse(path).map_err(|_| input_invalid())
}

fn remote_hex(remote_key: &RemoteKey) -> Result<&str, SyncTransactionError> {
    remote_key
        .as_str()
        .rsplit(':')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(input_invalid)
}

fn journal_pending_path(remote_key: &RemoteKey) -> Result<PortablePath, SyncTransactionError> {
    portable_path(&format!("sync/{}/journal.pending", remote_hex(remote_key)?))
}

fn sync_lock_path(remote_key: &RemoteKey) -> Result<PortablePath, SyncTransactionError> {
    portable_path(&format!("sync/{}/lock", remote_hex(remote_key)?))
}

fn capture_limits(limits: SyncLimits) -> CaptureLimits {
    CaptureLimits {
        max_files: limits.max_components(),
        max_file_bytes: limits.max_object_bytes(),
        max_total_bytes: limits.max_object_bytes(),
    }
}

fn control_limit(limits: SyncLimits) -> Result<usize, SyncTransactionError> {
    usize::try_from(limits.max_control_bytes()).map_err(|_| input_invalid())
}

fn manifest_limit(limits: SyncLimits) -> Result<usize, SyncTransactionError> {
    usize::try_from(limits.max_manifest_bytes()).map_err(|_| input_invalid())
}

fn lock_limit(limits: SyncLimits) -> Result<usize, SyncTransactionError> {
    usize::try_from(limits.max_lock_bytes()).map_err(|_| input_invalid())
}

fn snapshot_limit(limits: SyncLimits) -> Result<usize, SyncTransactionError> {
    usize::try_from(limits.max_snapshot_bytes()).map_err(|_| input_invalid())
}

fn error(code: &'static str, message: &'static str) -> SyncTransactionError {
    SyncTransactionError { code, message }
}

fn input_invalid() -> SyncTransactionError {
    error(
        "sync.input_invalid",
        "confirmed synchronization input is invalid",
    )
}

fn stale_remote() -> SyncTransactionError {
    error(
        "sync.remote_stale",
        "remote authority changed after synchronization planning",
    )
}

fn publication_uncertain() -> SyncTransactionError {
    error(
        "sync.publication_uncertain",
        "remote publication cannot be safely proved or retried",
    )
}

fn recovery_blocked() -> SyncTransactionError {
    error(
        "sync.recovery_blocked",
        "synchronization recovery lacks positive publication evidence",
    )
}

fn publication_invalid() -> SyncTransactionError {
    error(
        "sync.publication_invalid",
        "remote publication evidence does not match the confirmed transaction",
    )
}

fn base_stale() -> SyncTransactionError {
    error(
        "sync.base_stale",
        "retained synchronization base changed after planning",
    )
}

fn local_stale() -> SyncTransactionError {
    error(
        "sync.local_stale",
        "local synchronization authority changed before apply",
    )
}

fn base_invalid() -> SyncTransactionError {
    error(
        "sync.base_invalid",
        "retained synchronization base does not match committed authority",
    )
}

fn staging_invalid() -> SyncTransactionError {
    error(
        "sync.staging_invalid",
        "durable synchronization staging is not exact and complete",
    )
}

fn orphan_local_journal() -> SyncTransactionError {
    error(
        "sync.local_recovery_required",
        "an unmatched local sync transaction requires recovery before remote mutation",
    )
}

fn journal_invalid() -> SyncTransactionError {
    error(
        "sync.journal_invalid",
        "durable synchronization journal is invalid",
    )
}

fn storage_error(_: crate::ObjectMutationError) -> SyncTransactionError {
    error(
        "sync.storage_failed",
        "synchronization storage failed safely",
    )
}

fn lock_error(_: crate::ObjectMutationError) -> SyncTransactionError {
    error(
        "sync.lock_failed",
        "synchronization transaction lock could not be acquired",
    )
}

fn backend_error(_: crate::BackendError) -> SyncTransactionError {
    error(
        "sync.backend_failed",
        "synchronization backend operation failed safely",
    )
}

fn base_error(_: crate::SyncBaseStoreError) -> SyncTransactionError {
    error(
        "sync.base_failed",
        "retained synchronization base operation failed safely",
    )
}

fn snapshot_error(_: crate::SnapshotError) -> SyncTransactionError {
    staging_invalid()
}

fn journal_error(_: crate::SyncJournalError) -> SyncTransactionError {
    journal_invalid()
}

fn portable_error(_: crate::SyncPortableTransactionError) -> SyncTransactionError {
    error(
        "sync.local_commit_failed",
        "local portable authority could not be committed or recovered safely",
    )
}

fn staging_error(_: crate::ObjectMutationError) -> SyncTransactionError {
    error(
        "sync.staging_blocked",
        "synchronization staging contains unexpected or unsafe state",
    )
}

fn journal_read_error(_: crate::ObjectMutationError) -> SyncTransactionError {
    error(
        "sync.journal_read_failed",
        "synchronization journal could not be inspected safely",
    )
}

fn journal_write_error(_: crate::ObjectMutationError) -> SyncTransactionError {
    error(
        "sync.journal_write_failed",
        "synchronization journal could not be persisted safely",
    )
}

fn cleanup_error(_: crate::ObjectMutationError) -> SyncTransactionError {
    error(
        "sync.cleanup_failed",
        "completed synchronization staging could not be cleaned safely",
    )
}

fn cleanup_limit() -> SyncTransactionError {
    error(
        "sync.cleanup_limit",
        "synchronization exceeds the supported cleanup limit",
    )
}

fn cleanup_coordinator_error(cause: MutationCleanupError) -> SyncTransactionError {
    match cause {
        MutationCleanupError::InvalidReservation => cleanup_limit(),
        MutationCleanupError::CleanupFailed => {
            error("sync.cleanup_failed", "synchronization cleanup failed")
        }
    }
}

fn map_guarded_journal_error(
    cause: guarded_journal::GuardedJournalError<SyncTransactionError>,
) -> SyncTransactionError {
    match cause {
        guarded_journal::GuardedJournalError::Storage => error(
            "sync.journal_read_failed",
            "synchronization journal could not be inspected safely",
        ),
        guarded_journal::GuardedJournalError::Authority(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_agent_skills::capture_tree;
    use kitrove_model::{
        BindingName, ContentHash, EnvironmentManifest, RemoteRevision, SchemaVersion, SyncLimits,
    };

    use super::*;
    use crate::adoption::tests::capabilities;
    use crate::{
        FilesystemSyncBackend, RemoteSnapshot, SyncPlanOutcome, VerifiedSkillObjectCatalog,
        plan_sync,
    };

    fn snapshot(binding: Option<&str>) -> PortableSnapshotV1 {
        PortableSnapshotV1::new(
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: binding
                    .map(|name| BTreeSet::from([BindingName::parse(name).unwrap()]))
                    .unwrap_or_default(),
            },
            BTreeSet::new(),
            SyncLimits::default(),
        )
        .unwrap()
    }

    fn environment(snapshot: &PortableSnapshotV1) -> (tempfile::TempDir, std::path::PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let environment = temporary.path().canonicalize().unwrap().join("environment");
        crate::test_authority::initialize_portable_environment(
            &environment,
            snapshot.manifest_toml(),
            snapshot.lock_json(),
        )
        .unwrap();
        let root = std::fs::canonicalize(environment).unwrap();
        (temporary, root)
    }

    fn empty_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap().join("root");
        crate::test_authority::initialize_empty_private_root(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        (temporary, root)
    }

    fn plan(local: PortableSnapshotV1, remote: RemoteSnapshot) -> Box<SyncPlan> {
        plan_with_objects(local, remote, &[])
    }

    fn plan_with_objects(
        local: PortableSnapshotV1,
        remote: RemoteSnapshot,
        objects: &[VerifiedObjectEnvelope],
    ) -> Box<SyncPlan> {
        let portable = objects.iter().filter_map(|object| match object {
            VerifiedObjectEnvelope::Portable { object, .. } => Some(object.clone()),
            VerifiedObjectEnvelope::Native { .. } => None,
            VerifiedObjectEnvelope::NativeExtension { .. } => None,
            VerifiedObjectEnvelope::Document { .. } => None,
        });
        let native = objects.iter().filter_map(|object| match object {
            VerifiedObjectEnvelope::Native { object, .. } => Some(object.clone()),
            VerifiedObjectEnvelope::Portable { .. } => None,
            VerifiedObjectEnvelope::NativeExtension { .. } => None,
            VerifiedObjectEnvelope::Document { .. } => None,
        });
        let catalog = VerifiedSkillObjectCatalog::new(portable, native).unwrap();
        let SyncPlanOutcome::Ready(plan) = plan_sync(
            local,
            None,
            remote,
            &catalog,
            &capabilities(),
            SyncLimits::default(),
        )
        .unwrap() else {
            panic!("test synchronization must be ready");
        };
        plan
    }

    fn publication() -> PublicationId {
        PublicationId::parse(format!("publication:blake3:{}", "b".repeat(64))).unwrap()
    }

    fn populated_snapshot() -> (PortableSnapshotV1, Vec<VerifiedObjectEnvelope>) {
        let (adoption, _, _) = crate::adoption::tests::ready_plan();
        let asset = adoption.asset();
        let portable = asset.portable.as_ref().unwrap();
        let native = asset
            .native_variants
            .get(adoption.origin_harness())
            .unwrap();
        let objects = vec![
            VerifiedObjectEnvelope::portable(
                portable.root.clone(),
                adoption.portable_object().clone(),
            )
            .unwrap(),
            VerifiedObjectEnvelope::native(native.root.clone(), adoption.native_object().clone())
                .unwrap(),
        ];
        let descriptors = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        (
            PortableSnapshotV1::new(
                adoption.proposed_manifest().clone(),
                descriptors,
                SyncLimits::default(),
            )
            .unwrap(),
            objects,
        )
    }

    fn competing_publication() -> PublicationId {
        PublicationId::parse(format!("publication:blake3:{}", "c".repeat(64))).unwrap()
    }

    fn journal_file(backend: &FilesystemSyncBackend) -> PortablePath {
        sync_transaction_journal_path(backend.remote_key()).unwrap()
    }

    fn leave_publishing_journal(
        environment_root: &Path,
        state_root: &Path,
        backend: &FilesystemSyncBackend,
        plan: &SyncPlan,
        publish: bool,
    ) {
        leave_prepublication_journal(
            environment_root,
            state_root,
            backend,
            plan,
            SyncJournalPhase::Publishing,
            publish,
        );
    }

    fn leave_prepublication_journal(
        environment_root: &Path,
        state_root: &Path,
        backend: &FilesystemSyncBackend,
        plan: &SyncPlan,
        phase: SyncJournalPhase,
        publish: bool,
    ) {
        let limits = SyncLimits::default();
        let environment = ObjectStore::open(environment_root).unwrap();
        let state = ObjectStore::open_private_state_for_mutation(state_root).unwrap();
        let _environment_lock = environment.try_lock_environment().unwrap();
        let _state_lock = state
            .try_lock_file(&sync_lock_path(backend.remote_key()).unwrap())
            .unwrap();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                plan.remote_revision(),
                &publication(),
                plan.merged(),
                &[],
                limits,
            )
            .unwrap();
        let mut journal = SyncJournal::prepared(
            plan,
            backend.remote_key().clone(),
            Some((publication(), &intent)),
            None,
            limits,
        )
        .unwrap();
        install_outer_guard(&environment, backend.remote_key(), limits).unwrap();
        stage_outer(&state, &journal, plan.local(), plan.merged(), &[], limits).unwrap();
        let mut encoded = install_initial_journal(&state, &journal, limits).unwrap();
        if phase == SyncJournalPhase::Publishing {
            advance_journal(
                &state,
                &mut journal,
                &mut encoded,
                SyncJournalPhase::Publishing,
                limits,
            )
            .unwrap();
        } else {
            assert_eq!(phase, SyncJournalPhase::Prepared);
        }
        if publish {
            assert!(matches!(
                session
                    .publish(&intent, plan.merged(), &[], limits)
                    .unwrap(),
                PublicationStatus::Published(_)
            ));
        }
    }

    #[test]
    fn recovery_refuses_stale_local_authority_before_retrying_prepared_or_publishing() {
        let limits = SyncLimits::default();
        for phase in [SyncJournalPhase::Prepared, SyncJournalPhase::Publishing] {
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local.clone(),
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );
            leave_prepublication_journal(
                &environment_root,
                &state_root,
                &backend,
                &plan,
                phase,
                false,
            );
            std::fs::write(environment_root.join("kitrove.toml"), "STALE-LOCAL-CANARY").unwrap();

            let error = recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.local_stale");
            assert!(backend.inspect(limits).unwrap().snapshot().is_none());
            assert!(state_root.join(journal_file(&backend).as_str()).exists());
        }
    }

    #[test]
    fn recovery_refuses_stale_base_before_retrying_prepared_or_publishing() {
        let limits = SyncLimits::default();
        for phase in [SyncJournalPhase::Prepared, SyncJournalPhase::Publishing] {
            let initial = snapshot(Some("shared"));
            let (_environment_temporary, environment_root) = environment(&initial);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let bootstrap = plan(
                initial.clone(),
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );
            commit_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &bootstrap,
                &[],
                Some(publication()),
                limits,
            )
            .unwrap();
            let bases = SyncBaseStore::open_or_create(&state_root).unwrap();
            let retained = bases
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .unwrap();
            let changed = snapshot(Some("local"));
            std::fs::write(
                environment_root.join("kitrove.toml"),
                changed.manifest_toml(),
            )
            .unwrap();
            std::fs::write(
                environment_root.join("kitrove.lock.json"),
                changed.lock_json(),
            )
            .unwrap();
            let SyncPlanOutcome::Ready(next) = plan_sync(
                changed,
                Some(retained.input().clone()),
                backend.inspect(limits).unwrap(),
                &VerifiedSkillObjectCatalog::new([], []).unwrap(),
                &capabilities(),
                limits,
            )
            .unwrap() else {
                panic!("local-only change must produce a ready plan");
            };
            let interrupted = commit_sync_transaction_inner(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &next,
                &[],
                Some(competing_publication()),
                limits,
                Some(phase),
                false,
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "sync.test_interrupted");
            let remote_before = backend.inspect(limits).unwrap().revision().clone();
            bases
                .commit(
                    backend.remote_key(),
                    Some(retained.generation()),
                    &initial,
                    &RemoteRevision::parse("filesystem:recovery-base-race").unwrap(),
                    &[],
                    &ContentHash::parse(format!("blake3:{}", "f".repeat(64))).unwrap(),
                    limits,
                )
                .unwrap();

            let error = recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.base_stale");
            assert_eq!(backend.inspect(limits).unwrap().revision(), &remote_before);
            assert!(state_root.join(journal_file(&backend).as_str()).exists());
        }
    }

    #[test]
    fn confirmed_publish_commits_remote_local_and_retained_base() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );

        assert_eq!(
            commit_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
            )
            .unwrap(),
            SyncCommitOutcome::Committed
        );
        assert_eq!(backend.inspect(limits).unwrap().snapshot(), Some(&local));
        let retained = SyncBaseStore::open(&state_root)
            .unwrap()
            .inspect(backend.remote_key(), limits)
            .unwrap()
            .unwrap();
        assert_eq!(retained.input().snapshot(), &local);
        assert_eq!(
            recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap(),
            SyncRecoveryOutcome::NoJournal
        );
    }

    #[test]
    fn confirmed_receive_commits_manifest_then_base_without_republication() {
        let limits = SyncLimits::default();
        let source = snapshot(Some("workspace"));
        let (_source_environment_temporary, source_environment_root) = environment(&source);
        let (_source_state_temporary, source_state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let publish = plan(
            source.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        commit_sync_transaction(
            &source_environment_root,
            &source_state_root,
            &backend,
            backend.remote_key(),
            &publish,
            &[],
            Some(publication()),
            limits,
        )
        .unwrap();

        let empty = snapshot(None);
        let (_destination_temporary, destination_root) = environment(&empty);
        let (_destination_state_temporary, destination_state_root) = empty_root();
        let remote = backend.inspect(limits).unwrap();
        let receive = plan(empty, remote);
        commit_sync_transaction(
            &destination_root,
            &destination_state_root,
            &backend,
            backend.remote_key(),
            &receive,
            &[],
            None,
            limits,
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(destination_root.join("kitrove.toml")).unwrap(),
            source.manifest_toml()
        );
        assert_eq!(
            SyncBaseStore::open(&destination_state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .unwrap()
                .input()
                .snapshot(),
            &source
        );
    }

    #[test]
    fn confirmed_publish_transports_and_retains_every_exact_object() {
        let limits = SyncLimits::default();
        let empty = snapshot(None);
        let (local, objects) = populated_snapshot();
        let (_environment_temporary, environment_root) = environment(&empty);
        crate::commit_sync_portable_snapshot(
            &environment_root,
            &empty,
            &local,
            &objects,
            &ContentHash::parse(format!("blake3:{}", "d".repeat(64))).unwrap(),
            limits,
        )
        .unwrap();
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let publish = plan_with_objects(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            &objects,
        );

        commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &publish,
            &objects,
            Some(publication()),
            limits,
        )
        .unwrap();

        for descriptor in local.objects() {
            assert_eq!(
                backend
                    .fetch_object(descriptor, limits)
                    .unwrap()
                    .descriptor(),
                descriptor
            );
        }
        assert_eq!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .unwrap()
                .objects()
                .len(),
            objects.len()
        );
    }

    #[test]
    fn recovery_reconciles_an_already_published_intent() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        leave_publishing_journal(&environment_root, &state_root, &backend, &plan, true);

        assert_eq!(
            recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap(),
            SyncRecoveryOutcome::Completed
        );
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
        assert_eq!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .unwrap()
                .input()
                .snapshot(),
            &local
        );
    }

    #[test]
    fn recovery_proves_publication_through_a_third_party_successor() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let local_canaries = [
            ("state.json", "RECOVERY-MACHINE-CONFIG-CANARY"),
            ("receipts.json", "RECOVERY-RECEIPT-CANARY"),
            ("trust.json", "RECOVERY-TRUST-CANARY"),
            ("bindings.json", "RECOVERY-BINDING-CANARY"),
            ("destinations.json", "RECOVERY-DESTINATION-CANARY"),
            ("scan-history.json", "RECOVERY-SCAN-HISTORY-CANARY"),
        ];
        for (path, value) in local_canaries {
            std::fs::write(state_root.join(path), value).unwrap();
        }
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        leave_publishing_journal(&environment_root, &state_root, &backend, &plan, true);
        let published = backend.inspect(limits).unwrap().revision().clone();
        let mut session = backend.begin_apply(limits).unwrap();
        let successor = session
            .prepare_publication(&published, &competing_publication(), &local, &[], limits)
            .unwrap();
        let PublicationStatus::Published(successor_revision) =
            session.publish(&successor, &local, &[], limits).unwrap()
        else {
            panic!("third-party successor must publish");
        };
        drop(session);

        assert_eq!(
            recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap(),
            SyncRecoveryOutcome::Completed
        );
        assert_eq!(
            backend.inspect(limits).unwrap().revision(),
            &successor_revision
        );
        let retained = SyncBaseStore::open(&state_root)
            .unwrap()
            .inspect(backend.remote_key(), limits)
            .unwrap()
            .unwrap();
        assert_eq!(retained.input().backend_revision(), &published);
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
        for (path, value) in local_canaries {
            assert_eq!(
                std::fs::read_to_string(state_root.join(path)).unwrap(),
                value
            );
        }
    }

    #[test]
    fn stale_selected_snapshot_file_refuses_apply_without_local_or_base_mutation() {
        let limits = SyncLimits::default();
        let empty = snapshot(None);
        let (remote_snapshot, objects) = populated_snapshot();
        let (_environment_temporary, environment_root) = environment(&empty);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &RemoteRevision::parse("filesystem:absent:v1").unwrap(),
                &publication(),
                &remote_snapshot,
                &objects,
                limits,
            )
            .unwrap();
        session
            .publish(&intent, &remote_snapshot, &objects, limits)
            .unwrap();
        drop(session);
        let plan = plan_with_objects(empty.clone(), backend.inspect(limits).unwrap(), &objects);
        let pointer_before = std::fs::read(remote_root.join(".kitrove-sync/current.json")).unwrap();
        let snapshot_file = remote_root.join(format!(
            ".kitrove-sync/snapshots/{}.json",
            remote_snapshot
                .snapshot_digest()
                .as_str()
                .rsplit(':')
                .next()
                .unwrap()
        ));
        std::fs::write(&snapshot_file, "STALE-REMOTE-SNAPSHOT-CANARY").unwrap();

        let error = commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &plan,
            &objects,
            None,
            limits,
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync.backend_failed");
        assert_eq!(
            std::fs::read_to_string(environment_root.join("kitrove.toml")).unwrap(),
            empty.manifest_toml()
        );
        assert_eq!(
            std::fs::read(remote_root.join(".kitrove-sync/current.json")).unwrap(),
            pointer_before
        );
        assert!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .is_none()
        );
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
    }

    #[test]
    fn recovery_retries_only_an_exact_ready_publication() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        leave_publishing_journal(&environment_root, &state_root, &backend, &plan, false);

        recover_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            limits,
        )
        .unwrap();
        assert_eq!(backend.inspect(limits).unwrap().snapshot(), Some(&local));
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
    }

    #[test]
    fn alternate_publication_blocks_recovery_without_advancing_local_base() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        leave_publishing_journal(&environment_root, &state_root, &backend, &plan, false);
        {
            let mut session = backend.begin_apply(limits).unwrap();
            let intent = session
                .prepare_publication(
                    plan.remote_revision(),
                    &competing_publication(),
                    &local,
                    &[],
                    limits,
                )
                .unwrap();
            assert!(matches!(
                session.publish(&intent, &local, &[], limits).unwrap(),
                PublicationStatus::Published(_)
            ));
        }

        let error = recover_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            limits,
        )
        .unwrap_err();
        assert_eq!(error.code(), "sync.recovery_blocked");
        assert!(state_root.join(journal_file(&backend).as_str()).exists());
        assert!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn broken_selected_history_blocks_recovery_without_discarding_evidence() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        leave_publishing_journal(&environment_root, &state_root, &backend, &plan, false);
        {
            let mut session = backend.begin_apply(limits).unwrap();
            let intent = session
                .prepare_publication(
                    plan.remote_revision(),
                    &competing_publication(),
                    &local,
                    &[],
                    limits,
                )
                .unwrap();
            session.publish(&intent, &local, &[], limits).unwrap();
        }
        let current: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(remote_root.join(".kitrove-sync/current.json")).unwrap(),
        )
        .unwrap();
        let head = current["head_path"].as_str().unwrap();
        std::fs::write(remote_root.join(head), "BROKEN-HISTORY-CANARY").unwrap();

        let error = recover_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            limits,
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync.recovery_blocked");
        assert!(state_root.join(journal_file(&backend).as_str()).exists());
        assert_eq!(
            std::fs::read_to_string(remote_root.join(head)).unwrap(),
            "BROKEN-HISTORY-CANARY"
        );
        assert!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn orphan_local_journal_blocks_before_any_remote_mutation() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        std::fs::create_dir_all(environment_root.join(".kitrove")).unwrap();
        std::fs::write(
            environment_root.join(".kitrove/sync-portable-journal.json"),
            "UNMATCHED-LOCAL-JOURNAL-CANARY",
        )
        .unwrap();
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local,
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );

        let error = commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &plan,
            &[],
            Some(publication()),
            limits,
        )
        .unwrap_err();
        assert_eq!(error.code(), "sync.local_recovery_required");
        assert!(backend.inspect(limits).unwrap().snapshot().is_none());
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_in_either_root_blocks_outer_commit_before_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        for unsafe_environment in [true, false] {
            let limits = SyncLimits::default();
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let root = if unsafe_environment {
                &environment_root
            } else {
                &state_root
            };
            let control = root.join(".kitrove");
            let quarantine = control.join("removal-quarantine");
            std::fs::create_dir_all(&quarantine).unwrap();
            std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(quarantine.join("unrecognized-retained-state"), "authority").unwrap();
            let plan = plan(
                local,
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );

            let error = commit_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.cleanup_failed");
            assert!(backend.inspect(limits).unwrap().snapshot().is_none());
            assert!(!state_root.join(journal_file(&backend).as_str()).exists());
            assert!(quarantine.join("unrecognized-retained-state").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn outer_commit_reclaims_retained_state_from_both_locked_roots() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let obsolete = PortablePath::parse("obsolete-sync-control").unwrap();
        for (root, private) in [(&environment_root, false), (&state_root, true)] {
            std::fs::write(root.join(obsolete.as_str()), "retained").unwrap();
            let store = if private {
                ObjectStore::open_private_state_for_mutation(root).unwrap()
            } else {
                ObjectStore::open(root).unwrap()
            };
            let _lock = store.try_lock_environment().unwrap();
            store.remove_regular_file_if_present(&obsolete).unwrap();
        }
        let retained = [&environment_root, &state_root].map(|root| {
            let quarantine = root.join(".kitrove/removal-quarantine");
            let names = std::fs::read_dir(&quarantine)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert!(!names.is_empty());
            (quarantine, names)
        });
        let plan = plan(
            local,
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );

        commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &plan,
            &[],
            Some(publication()),
            limits,
        )
        .unwrap();

        for (quarantine, names) in retained {
            for name in names {
                assert!(!quarantine.join(name).exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_in_either_root_blocks_outer_recovery_before_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        for unsafe_environment in [true, false] {
            let limits = SyncLimits::default();
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local,
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );
            let interrupted = commit_sync_transaction_inner(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
                Some(SyncJournalPhase::Prepared),
                false,
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "sync.test_interrupted");
            let journal = state_root.join(journal_file(&backend).as_str());
            let journal_before = std::fs::read(&journal).unwrap();
            let root = if unsafe_environment {
                &environment_root
            } else {
                &state_root
            };
            let control = root.join(".kitrove");
            let quarantine = control.join("removal-quarantine");
            std::fs::create_dir_all(&quarantine).unwrap();
            std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(quarantine.join("unrecognized-retained-state"), "authority").unwrap();

            let error = recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.cleanup_failed");
            assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
            assert!(backend.inspect(limits).unwrap().snapshot().is_none());
        }
    }

    #[test]
    fn every_local_state_transaction_blocks_before_remote_mutation() {
        let limits = SyncLimits::default();
        for journal in local_state_authority::ALL_LOCAL_STATE_RECOVERY {
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let journal_path = state_root.join(journal);
            crate::test_authority::stage_private_text(
                &state_root,
                journal,
                "FOREIGN-LOCAL-JOURNAL-CANARY",
            )
            .unwrap();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local,
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );

            let error = commit_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.local_recovery_required", "{journal}");
            assert!(backend.inspect(limits).unwrap().snapshot().is_none());
            assert!(journal_path.exists());
            assert!(!state_root.join(journal_file(&backend).as_str()).exists());
        }
    }

    #[test]
    fn stale_local_manifest_and_lock_refuse_before_journal_or_remote_staging() {
        let limits = SyncLimits::default();
        for changed in ["kitrove.toml", "kitrove.lock.json"] {
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local,
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );
            std::fs::write(environment_root.join(changed), "stale-authority-canary").unwrap();

            let error = commit_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.local_stale");
            assert!(backend.inspect(limits).unwrap().snapshot().is_none());
            assert!(!state_root.join(journal_file(&backend).as_str()).exists());
            assert!(!remote_root.join(".kitrove-sync/staging").exists());
        }
    }

    #[test]
    fn stale_local_object_refuses_before_journal_or_remote_staging() {
        let limits = SyncLimits::default();
        let empty = snapshot(None);
        let (local, objects) = populated_snapshot();
        let (_environment_temporary, environment_root) = environment(&empty);
        crate::commit_sync_portable_snapshot(
            &environment_root,
            &empty,
            &local,
            &objects,
            &ContentHash::parse(format!("blake3:{}", "e".repeat(64))).unwrap(),
            limits,
        )
        .unwrap();
        let stale_root = environment_root.join(objects[0].descriptor().root().as_str());
        let moved = stale_root.parent().unwrap().join("stale-object-canary");
        std::fs::rename(&stale_root, moved).unwrap();
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan_with_objects(
            local,
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            &objects,
        );

        let error = commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &plan,
            &objects,
            Some(publication()),
            limits,
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync.local_stale");
        assert!(backend.inspect(limits).unwrap().snapshot().is_none());
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
        assert!(!remote_root.join(".kitrove-sync/staging").exists());
    }

    #[test]
    fn stale_fetched_remote_object_refuses_before_local_or_base_mutation() {
        let limits = SyncLimits::default();
        let empty = snapshot(None);
        let (remote_snapshot, objects) = populated_snapshot();
        let (_environment_temporary, environment_root) = environment(&empty);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &RemoteRevision::parse("filesystem:absent:v1").unwrap(),
                &publication(),
                &remote_snapshot,
                &objects,
                limits,
            )
            .unwrap();
        session
            .publish(&intent, &remote_snapshot, &objects, limits)
            .unwrap();
        drop(session);
        let plan = plan_with_objects(empty.clone(), backend.inspect(limits).unwrap(), &objects);
        assert!(!plan.download().is_empty());
        let remote_object = remote_root
            .join(".kitrove-sync")
            .join(plan.download().first().unwrap().root().as_str());
        let moved = remote_object.parent().unwrap().join("stale-object-canary");
        std::fs::rename(&remote_object, moved).unwrap();

        let error = commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &plan,
            &objects,
            None,
            limits,
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync.backend_failed");
        assert_eq!(
            std::fs::read_to_string(environment_root.join("kitrove.toml")).unwrap(),
            empty.manifest_toml()
        );
        assert!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .is_none()
        );
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
    }

    #[test]
    fn stale_remote_pointer_refuses_before_journal_or_base_mutation() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let stale_plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        let mut session = backend.begin_apply(limits).unwrap();
        let winner = session
            .prepare_publication(
                stale_plan.remote_revision(),
                &competing_publication(),
                &local,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&winner, &local, &[], limits).unwrap();
        drop(session);

        let error = commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &stale_plan,
            &[],
            Some(publication()),
            limits,
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync.remote_stale");
        assert_eq!(
            backend.inspect(limits).unwrap().revision(),
            winner.proposed_revision()
        );
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
        assert!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stale_base_pointer_refuses_before_journal_or_remote_publication() {
        let limits = SyncLimits::default();
        let initial = snapshot(Some("shared"));
        let (_environment_temporary, environment_root) = environment(&initial);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let bootstrap = plan(
            initial.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );
        commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &bootstrap,
            &[],
            Some(publication()),
            limits,
        )
        .unwrap();
        let retained = SyncBaseStore::open(&state_root)
            .unwrap()
            .inspect(backend.remote_key(), limits)
            .unwrap()
            .unwrap();
        let changed = PortableSnapshotV1::new(
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: ["shared", "local"]
                    .into_iter()
                    .map(|name| BindingName::parse(name).unwrap())
                    .collect(),
            },
            BTreeSet::new(),
            limits,
        )
        .unwrap();
        std::fs::write(
            environment_root.join("kitrove.toml"),
            changed.manifest_toml(),
        )
        .unwrap();
        std::fs::write(
            environment_root.join("kitrove.lock.json"),
            changed.lock_json(),
        )
        .unwrap();
        let SyncPlanOutcome::Ready(stale_plan) = plan_sync(
            changed,
            Some(retained.input().clone()),
            backend.inspect(limits).unwrap(),
            &VerifiedSkillObjectCatalog::new([], []).unwrap(),
            &capabilities(),
            limits,
        )
        .unwrap() else {
            panic!("local-only change must produce a ready plan");
        };
        let remote_before = backend.inspect(limits).unwrap().revision().clone();
        SyncBaseStore::open_or_create(&state_root)
            .unwrap()
            .commit(
                backend.remote_key(),
                Some(retained.generation()),
                &initial,
                &RemoteRevision::parse("filesystem:base-race").unwrap(),
                &[],
                &ContentHash::parse(format!("blake3:{}", "f".repeat(64))).unwrap(),
                limits,
            )
            .unwrap();

        let error = commit_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &stale_plan,
            &[],
            Some(competing_publication()),
            limits,
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync.base_stale");
        assert_eq!(backend.inspect(limits).unwrap().revision(), &remote_before);
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
    }

    #[test]
    fn every_outer_journal_phase_recovers_from_durable_evidence() {
        let limits = SyncLimits::default();
        for phase in [
            SyncJournalPhase::Prepared,
            SyncJournalPhase::Publishing,
            SyncJournalPhase::RemotePublished,
            SyncJournalPhase::LocalCommitting,
            SyncJournalPhase::LocalCommitted,
            SyncJournalPhase::BaseCommitting,
            SyncJournalPhase::BaseCommitted,
            SyncJournalPhase::Complete,
        ] {
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local.clone(),
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );

            let interrupted = commit_sync_transaction_inner(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
                Some(phase),
                false,
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "sync.test_interrupted");
            assert!(state_root.join(journal_file(&backend).as_str()).exists());
            assert!(
                environment_root
                    .join(local_state_authority::OUTER_SYNC_GUARD_PATH)
                    .exists()
            );
            assert_eq!(
                recover_sync_transaction(
                    &environment_root,
                    &state_root,
                    &backend,
                    backend.remote_key(),
                    limits,
                )
                .unwrap(),
                SyncRecoveryOutcome::Completed
            );
            assert!(!state_root.join(journal_file(&backend).as_str()).exists());
            assert!(
                !environment_root
                    .join(local_state_authority::OUTER_SYNC_GUARD_PATH)
                    .exists()
            );
            assert_eq!(
                SyncBaseStore::open(&state_root)
                    .unwrap()
                    .inspect(backend.remote_key(), limits)
                    .unwrap()
                    .unwrap()
                    .input()
                    .snapshot(),
                &local
            );
        }
    }

    #[test]
    fn outer_recovery_reconciles_every_guarded_journal_window() {
        #[derive(Clone, Copy)]
        enum Window {
            BackupAndPending,
            BackupAndLive,
            LiveAndPending,
        }

        let limits = SyncLimits::default();
        for window in [
            Window::BackupAndPending,
            Window::BackupAndLive,
            Window::LiveAndPending,
        ] {
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local,
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );
            let interrupted = commit_sync_transaction_inner(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
                Some(SyncJournalPhase::Prepared),
                false,
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "sync.test_interrupted");

            let live_path = journal_file(&backend);
            let pending_path = journal_pending_path(backend.remote_key()).unwrap();
            let backup_path = crate::object_mutation::guarded_backup_path(&pending_path).unwrap();
            let live = state_root.join(live_path.as_str());
            let pending = state_root.join(pending_path.as_str());
            let backup = state_root.join(backup_path.as_str());
            let old = std::fs::read_to_string(&live).unwrap();
            let journal = SyncJournal::from_json(&old, limits).unwrap();
            let next = journal
                .advance(SyncJournalPhase::Publishing)
                .unwrap()
                .to_json(limits)
                .unwrap();
            let environment = ObjectStore::open(&environment_root).unwrap();
            let state = ObjectStore::open_private_state_for_mutation(&state_root).unwrap();
            let _root_locks =
                ObjectStore::try_lock_distinct_roots(&[&environment, &state]).unwrap();
            let _sync_lock = state
                .try_lock_file(&sync_lock_path(backend.remote_key()).unwrap())
                .unwrap();
            match window {
                Window::BackupAndPending => {
                    std::fs::rename(&live, &backup).unwrap();
                    state
                        .stage_private_text(&pending_path, &next, control_limit(limits).unwrap())
                        .unwrap();
                }
                Window::BackupAndLive => {
                    std::fs::rename(&live, &backup).unwrap();
                    state
                        .stage_private_text(&live_path, &next, control_limit(limits).unwrap())
                        .unwrap();
                }
                Window::LiveAndPending => state
                    .stage_private_text(&pending_path, &next, control_limit(limits).unwrap())
                    .unwrap(),
            }
            drop(_sync_lock);
            drop(_root_locks);
            drop(state);
            drop(environment);

            assert_eq!(
                recover_sync_transaction(
                    &environment_root,
                    &state_root,
                    &backend,
                    backend.remote_key(),
                    limits,
                )
                .unwrap(),
                SyncRecoveryOutcome::Completed
            );
            assert!(!live.exists());
            assert!(!pending.exists());
            assert!(!backup.exists());
            assert!(backend.inspect(limits).unwrap().snapshot().is_some());
        }
    }

    #[test]
    fn outer_journal_branch_is_bound_across_cleanup() {
        fn stage_outer_journal(
            environment: &ObjectStore,
            state: &ObjectStore,
            backend: &FilesystemSyncBackend,
            plan: &SyncPlan,
            limits: SyncLimits,
        ) {
            let mut session = backend.begin_apply(limits).unwrap();
            let intent = session
                .prepare_publication(
                    plan.remote_revision(),
                    &publication(),
                    plan.merged(),
                    &[],
                    limits,
                )
                .unwrap();
            let journal = SyncJournal::prepared(
                plan,
                backend.remote_key().clone(),
                Some((publication(), &intent)),
                None,
                limits,
            )
            .unwrap();
            install_outer_guard(environment, backend.remote_key(), limits).unwrap();
            stage_outer(state, &journal, plan.local(), plan.merged(), &[], limits).unwrap();
            install_initial_journal(state, &journal, limits).unwrap();
        }

        for initially_present in [false, true] {
            let limits = SyncLimits::default();
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local.clone(),
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );
            let environment = ObjectStore::open(&environment_root).unwrap();
            let state = ObjectStore::open_or_create_private_state(&state_root).unwrap();
            let _root_locks =
                ObjectStore::try_lock_distinct_roots(&[&environment, &state]).unwrap();
            let _state_lock = state
                .try_lock_file(&sync_lock_path(backend.remote_key()).unwrap())
                .unwrap();
            if initially_present {
                stage_outer_journal(&environment, &state, &backend, &plan, limits);
            }
            let inspected = inspect_sync_recovery(&state, backend.remote_key(), limits).unwrap();
            let expected = guarded_journal::JournalExpectation::from_option(
                inspected.as_ref().map(|recovery| recovery.journal.clone()),
            );
            let nested_journal = bind_sync_portable_journal(&environment, limits).unwrap();
            let (forward, rollback) = match inspected.as_ref() {
                Some(recovery) => SyncMutationInventory::from_snapshot(&recovery.merged)
                    .recovery_work(&recovery.merged, limits)
                    .unwrap(),
                None => SyncMutationInventory::orphan_guard_work(limits).unwrap(),
            };
            let budget = cleanup_locked_stores(&[&environment, &state], forward, rollback).unwrap();
            let mutation_budget = budget.begin_forward().unwrap();
            if initially_present {
                std::fs::remove_file(state_root.join(journal_file(&backend).as_str())).unwrap();
            } else {
                stage_outer_journal(&environment, &state, &backend, &plan, limits);
            }
            let remote_before = backend.inspect(limits).unwrap();
            let manifest_before = std::fs::read(environment_root.join("kitrove.toml")).unwrap();
            let bases = SyncBaseStore::from_private_state_store(&state).unwrap();
            assert!(
                !bases
                    .has_selected_base(backend.remote_key(), limits)
                    .unwrap()
            );
            let mut session = backend.begin_apply(limits).unwrap();

            let error = recover_with_stores(
                &environment,
                &state,
                &bases,
                &mut session,
                backend.remote_key(),
                limits,
                &expected,
                &nested_journal,
                &mutation_budget,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.recovery_blocked");
            assert_eq!(backend.inspect(limits).unwrap(), remote_before);
            assert_eq!(
                std::fs::read(environment_root.join("kitrove.toml")).unwrap(),
                manifest_before
            );
            assert!(
                !bases
                    .has_selected_base(backend.remote_key(), limits)
                    .unwrap()
            );
        }
    }

    #[test]
    fn post_publication_phases_never_republish_after_remote_rewind() {
        let limits = SyncLimits::default();
        for phase in [
            SyncJournalPhase::RemotePublished,
            SyncJournalPhase::LocalCommitting,
            SyncJournalPhase::LocalCommitted,
            SyncJournalPhase::BaseCommitting,
            SyncJournalPhase::BaseCommitted,
            SyncJournalPhase::Complete,
        ] {
            let local = snapshot(Some("workspace"));
            let (_environment_temporary, environment_root) = environment(&local);
            let (_state_temporary, state_root) = empty_root();
            let (_remote_temporary, remote_root) = empty_root();
            let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
            let plan = plan(
                local.clone(),
                RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            );

            let interrupted = commit_sync_transaction_inner(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                &plan,
                &[],
                Some(publication()),
                limits,
                Some(phase),
                false,
            )
            .unwrap_err();
            assert_eq!(interrupted.code(), "sync.test_interrupted");
            std::fs::remove_file(remote_root.join(".kitrove-sync/current.json")).unwrap();
            let remote_before = capture_tree(&remote_root, capture_limits(limits)).unwrap();

            let error = recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync.recovery_blocked");
            assert_eq!(
                capture_tree(&remote_root, capture_limits(limits)).unwrap(),
                remote_before
            );
            assert!(state_root.join(journal_file(&backend).as_str()).exists());
        }
    }

    #[test]
    fn recovery_proves_remote_publication_before_the_published_journal_write() {
        let limits = SyncLimits::default();
        let local = snapshot(Some("workspace"));
        let (_environment_temporary, environment_root) = environment(&local);
        let (_state_temporary, state_root) = empty_root();
        let (_remote_temporary, remote_root) = empty_root();
        let backend = FilesystemSyncBackend::open(&remote_root).unwrap();
        let plan = plan(
            local.clone(),
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        );

        let interrupted = commit_sync_transaction_inner(
            &environment_root,
            &state_root,
            &backend,
            backend.remote_key(),
            &plan,
            &[],
            Some(publication()),
            limits,
            None,
            true,
        )
        .unwrap_err();
        assert_eq!(interrupted.code(), "sync.test_interrupted");
        assert_eq!(
            backend.inspect(limits).unwrap().snapshot(),
            Some(plan.merged())
        );

        assert_eq!(
            recover_sync_transaction(
                &environment_root,
                &state_root,
                &backend,
                backend.remote_key(),
                limits,
            )
            .unwrap(),
            SyncRecoveryOutcome::Completed
        );
        assert!(!state_root.join(journal_file(&backend).as_str()).exists());
        assert_eq!(
            SyncBaseStore::open(&state_root)
                .unwrap()
                .inspect(backend.remote_key(), limits)
                .unwrap()
                .unwrap()
                .input()
                .snapshot(),
            &local
        );
    }
}
