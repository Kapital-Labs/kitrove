use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{ContentHash, ObjectDescriptor, PortablePath, SnapshotObjectKind, SyncLimits};
use serde::{Deserialize, Serialize};

use crate::local_state_authority;
use crate::quarantine_cleanup::coordinator::{
    ActiveMutationBudget, MutationCleanupError, MutationWork, cleanup_locked_stores,
};
use crate::sync_backend::VerifiedDocumentObject;
use crate::{ObjectInstallOutcome, ObjectStore, PortableSnapshotV1, VerifiedObjectEnvelope};
use crate::{guarded_control, guarded_journal};

const JOURNAL_PATH: &str = ".kitrove/sync-portable-journal.json";
const JOURNAL_PENDING_PATH: &str = ".kitrove/sync-portable-journal.pending";
const MANIFEST_PATH: &str = "kitrove.toml";
const LOCK_PATH: &str = "kitrove.lock.json";

mod cleanup_inventory;

use cleanup_inventory::SyncPortableMutationInventory;

/// Durable phase of the local portable-authority portion of a sync transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum SyncPortablePhase {
    Prepared,
    ObjectsInstalled,
    ManifestCommitted,
    LockCommitted,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortableCheckpoint {
    BeforeJournal(SyncPortablePhase),
    AfterJournal(SyncPortablePhase),
    BeforeObject(usize),
    AfterObject(usize),
    BeforeManifest,
    AfterManifest,
    BeforeLock,
    AfterLock,
}

/// Successful local portable-authority transaction result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPortableCommitOutcome {
    Committed,
    Recovered,
}

/// Result of attempting to recover local portable authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPortableRecoveryOutcome {
    NoJournal,
    Completed,
}

/// Stable path- and content-redacted local sync transaction failure.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncPortableTransactionError {
    code: &'static str,
    message: &'static str,
}

impl SyncPortableTransactionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for SyncPortableTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncPortableTransactionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for SyncPortableTransactionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SyncPortableTransactionError {}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SyncPortableJournal {
    schema_version: u32,
    phase: SyncPortablePhase,
    plan_digest: ContentHash,
    old_manifest_hash: ContentHash,
    old_lock_hash: ContentHash,
    new_manifest_hash: ContentHash,
    new_lock_hash: ContentHash,
    objects: BTreeSet<ObjectDescriptor>,
    staging_manifest: PortablePath,
    staging_lock: PortablePath,
}

#[derive(Clone)]
struct TransactionPaths {
    base: PortablePath,
    manifest: PortablePath,
    lock: PortablePath,
}

/// Exact nested-journal state bound before transaction-global cleanup.
pub(crate) struct SyncPortableJournalBinding(
    guarded_journal::JournalExpectation<SyncPortableJournal>,
);

impl SyncPortableJournalBinding {
    pub(crate) fn is_absent(&self) -> bool {
        self.0.is_absent()
    }
}

pub(crate) fn bind_sync_portable_journal(
    store: &ObjectStore,
    limits: SyncLimits,
) -> Result<SyncPortableJournalBinding, SyncPortableTransactionError> {
    Ok(SyncPortableJournalBinding(
        guarded_journal::JournalExpectation::from_option(inspect_journal(store, limits)?),
    ))
}

/// Commits one exact merged snapshot under the environment's exclusive mutation lock.
pub fn commit_sync_portable_snapshot(
    environment_root: &Path,
    expected_local: &PortableSnapshotV1,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    plan_digest: &ContentHash,
    limits: SyncLimits,
) -> Result<SyncPortableCommitOutcome, SyncPortableTransactionError> {
    let inventory = SyncPortableMutationInventory::from_objects(merged.objects().iter().cloned())?;
    let store = ObjectStore::open(environment_root).map_err(store_error)?;
    let _lock = store.try_lock_environment().map_err(store_error)?;
    ensure_no_foreign_environment_journal(&store, limits)?;
    let journal_binding = bind_sync_portable_journal(&store, limits)?;
    if !journal_binding.is_absent() {
        let (forward, rollback) = inventory.recovery_work(limits)?;
        let budget = cleanup_locked_stores(&[&store], forward, rollback)
            .map_err(cleanup_coordinator_error)?;
        let _mutation_budget = budget.begin_forward().map_err(cleanup_coordinator_error)?;
        recover_sync_portable_snapshot_under_lock(
            &store,
            merged,
            objects,
            plan_digest,
            limits,
            &_mutation_budget,
            &journal_binding,
        )?;
        return Ok(SyncPortableCommitOutcome::Recovered);
    }
    let (forward, rollback) = inventory.commit_work(limits)?;
    let budget =
        cleanup_locked_stores(&[&store], forward, rollback).map_err(cleanup_coordinator_error)?;
    let _mutation_budget = budget.begin_forward().map_err(cleanup_coordinator_error)?;
    match recover_sync_portable_snapshot_under_lock(
        &store,
        merged,
        objects,
        plan_digest,
        limits,
        &_mutation_budget,
        &journal_binding,
    )? {
        SyncPortableRecoveryOutcome::Completed => {
            return Ok(SyncPortableCommitOutcome::Recovered);
        }
        SyncPortableRecoveryOutcome::NoJournal => {}
    }
    commit_sync_portable_snapshot_under_lock(
        &store,
        expected_local,
        merged,
        objects,
        plan_digest,
        limits,
        &_mutation_budget,
    )?;
    Ok(SyncPortableCommitOutcome::Committed)
}

/// Recovers an interrupted exact local portable-authority sync transaction.
pub fn recover_sync_portable_snapshot(
    environment_root: &Path,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    plan_digest: &ContentHash,
    limits: SyncLimits,
) -> Result<SyncPortableRecoveryOutcome, SyncPortableTransactionError> {
    let inventory = SyncPortableMutationInventory::from_objects(merged.objects().iter().cloned())?;
    let store = ObjectStore::open(environment_root).map_err(store_error)?;
    let _lock = store.try_lock_environment().map_err(store_error)?;
    ensure_no_foreign_environment_journal(&store, limits)?;
    let journal_binding = bind_sync_portable_journal(&store, limits)?;
    if journal_binding.is_absent() {
        return Ok(SyncPortableRecoveryOutcome::NoJournal);
    }
    let (forward, rollback) = inventory.recovery_work(limits)?;
    let budget =
        cleanup_locked_stores(&[&store], forward, rollback).map_err(cleanup_coordinator_error)?;
    let _mutation_budget = budget.begin_forward().map_err(cleanup_coordinator_error)?;
    recover_sync_portable_snapshot_under_lock(
        &store,
        merged,
        objects,
        plan_digest,
        limits,
        &_mutation_budget,
        &journal_binding,
    )
}

fn ensure_no_foreign_environment_journal(
    store: &ObjectStore,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    if local_state_authority::any_journal_present(
        store,
        local_state_authority::FOREIGN_TO_SYNC_PORTABLE,
        max_control_bytes(limits)?,
    )
    .map_err(recovery_error)?
    {
        return Err(recovery_required());
    }
    Ok(())
}

pub(crate) fn commit_sync_portable_snapshot_under_lock(
    store: &ObjectStore,
    expected_local: &PortableSnapshotV1,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    plan_digest: &ContentHash,
    limits: SyncLimits,
    _mutation_budget: &ActiveMutationBudget,
) -> Result<(), SyncPortableTransactionError> {
    commit_sync_portable_snapshot_with_checkpoints(
        store,
        expected_local,
        merged,
        objects,
        plan_digest,
        limits,
        |_| Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_sync_portable_snapshot_with_checkpoints(
    store: &ObjectStore,
    expected_local: &PortableSnapshotV1,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    plan_digest: &ContentHash,
    limits: SyncLimits,
    mut checkpoint: impl FnMut(PortableCheckpoint) -> Result<(), SyncPortableTransactionError>,
) -> Result<(), SyncPortableTransactionError> {
    let by_descriptor = validate_inputs(merged, objects, limits)?;
    let paths = transaction_paths(plan_digest)?;
    let max_control = max_control_bytes(limits)?;
    require_exact_authority(store, expected_local, max_control)?;
    verify_snapshot_objects(store, expected_local.objects(), limits)?;
    stage_objects(store, &by_descriptor, &paths, limits)?;
    store
        .stage_text(&paths.manifest, merged.manifest_toml(), max_control)
        .map_err(stage_error)?;
    store
        .stage_text(&paths.lock, merged.lock_json(), max_control)
        .map_err(stage_error)?;

    let mut journal = SyncPortableJournal {
        schema_version: 1,
        phase: SyncPortablePhase::Prepared,
        plan_digest: plan_digest.clone(),
        old_manifest_hash: ContentHash::digest(expected_local.manifest_toml().as_bytes()),
        old_lock_hash: ContentHash::digest(expected_local.lock_json().as_bytes()),
        new_manifest_hash: ContentHash::digest(merged.manifest_toml().as_bytes()),
        new_lock_hash: ContentHash::digest(merged.lock_json().as_bytes()),
        objects: merged.objects().clone(),
        staging_manifest: paths.manifest.clone(),
        staging_lock: paths.lock.clone(),
    };
    journal.validate(merged, plan_digest, limits)?;
    checkpoint(PortableCheckpoint::BeforeJournal(
        SyncPortablePhase::Prepared,
    ))?;
    let mut encoded = install_initial_journal(store, &journal, limits)?;
    checkpoint(PortableCheckpoint::AfterJournal(
        SyncPortablePhase::Prepared,
    ))?;

    install_objects_with_checkpoints(store, &by_descriptor, &paths, limits, &mut checkpoint)?;
    checkpoint(PortableCheckpoint::BeforeJournal(
        SyncPortablePhase::ObjectsInstalled,
    ))?;
    advance_journal(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::ObjectsInstalled,
        limits,
    )?;
    checkpoint(PortableCheckpoint::AfterJournal(
        SyncPortablePhase::ObjectsInstalled,
    ))?;
    checkpoint(PortableCheckpoint::BeforeManifest)?;
    store
        .install_staged_text_guarded(
            &paths.manifest,
            &portable_path(MANIFEST_PATH)?,
            Some(expected_local.manifest_toml()),
            merged.manifest_toml(),
            max_control,
        )
        .map_err(commit_error)?;
    checkpoint(PortableCheckpoint::AfterManifest)?;
    checkpoint(PortableCheckpoint::BeforeJournal(
        SyncPortablePhase::ManifestCommitted,
    ))?;
    advance_journal(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::ManifestCommitted,
        limits,
    )?;
    checkpoint(PortableCheckpoint::AfterJournal(
        SyncPortablePhase::ManifestCommitted,
    ))?;
    checkpoint(PortableCheckpoint::BeforeLock)?;
    store
        .install_staged_text_guarded(
            &paths.lock,
            &portable_path(LOCK_PATH)?,
            Some(expected_local.lock_json()),
            merged.lock_json(),
            max_control,
        )
        .map_err(commit_error)?;
    checkpoint(PortableCheckpoint::AfterLock)?;
    checkpoint(PortableCheckpoint::BeforeJournal(
        SyncPortablePhase::LockCommitted,
    ))?;
    advance_journal(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::LockCommitted,
        limits,
    )?;
    checkpoint(PortableCheckpoint::AfterJournal(
        SyncPortablePhase::LockCommitted,
    ))?;
    verify_complete(store, merged, limits)?;
    checkpoint(PortableCheckpoint::BeforeJournal(
        SyncPortablePhase::Complete,
    ))?;
    advance_journal(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::Complete,
        limits,
    )?;
    checkpoint(PortableCheckpoint::AfterJournal(
        SyncPortablePhase::Complete,
    ))?;
    cleanup_transaction(store, &by_descriptor, &paths, limits)
}

pub(crate) fn recover_sync_portable_snapshot_under_lock(
    store: &ObjectStore,
    merged: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    plan_digest: &ContentHash,
    limits: SyncLimits,
    _mutation_budget: &ActiveMutationBudget,
    journal_binding: &SyncPortableJournalBinding,
) -> Result<SyncPortableRecoveryOutcome, SyncPortableTransactionError> {
    let inspected = inspect_journal(store, limits)?;
    if !journal_binding.0.matches(inspected.as_ref()) {
        return Err(recovery_unknown());
    }
    let Some(mut journal) = inspected else {
        return Ok(SyncPortableRecoveryOutcome::NoJournal);
    };
    journal.validate(merged, plan_digest, limits)?;
    let paths = transaction_paths(plan_digest)?;
    let max_control = max_control_bytes(limits)?;
    let mut encoded = journal.to_json(limits)?;
    let manifest = classify_authority(
        store,
        &journal.staging_manifest,
        &portable_path(MANIFEST_PATH)?,
        &journal.old_manifest_hash,
        merged.manifest_toml(),
        max_control,
    )?;
    let lock = classify_authority(
        store,
        &journal.staging_lock,
        &portable_path(LOCK_PATH)?,
        &journal.old_lock_hash,
        merged.lock_json(),
        max_control,
    )?;
    if manifest.is_old() && lock.is_new() {
        return Err(recovery_order_invalid());
    }
    let by_descriptor = validate_inputs(merged, objects, limits)?;

    reconcile_journal(store, limits)?;
    reconcile_authority_control(
        store,
        &journal.staging_manifest,
        &portable_path(MANIFEST_PATH)?,
        &journal.old_manifest_hash,
        &journal.new_manifest_hash,
        max_control,
    )?;
    reconcile_authority_control(
        store,
        &journal.staging_lock,
        &portable_path(LOCK_PATH)?,
        &journal.old_lock_hash,
        &journal.new_lock_hash,
        max_control,
    )?;

    stage_objects(store, &by_descriptor, &paths, limits)?;
    store
        .stage_text(&paths.manifest, merged.manifest_toml(), max_control)
        .map_err(stage_error)?;
    store
        .stage_text(&paths.lock, merged.lock_json(), max_control)
        .map_err(stage_error)?;
    install_objects(store, &by_descriptor, &paths, limits)?;
    advance_to_at_least(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::ObjectsInstalled,
        limits,
    )?;

    if manifest.is_old() {
        let old = required_text(store, MANIFEST_PATH, max_control)?;
        store
            .install_staged_text_guarded(
                &paths.manifest,
                &portable_path(MANIFEST_PATH)?,
                Some(&old),
                merged.manifest_toml(),
                max_control,
            )
            .map_err(commit_error)?;
    } else {
        store
            .remove_regular_file_if_present(&paths.manifest)
            .map_err(cleanup_error)?;
    }
    advance_to_at_least(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::ManifestCommitted,
        limits,
    )?;

    if lock.is_old() {
        let old = required_text(store, LOCK_PATH, max_control)?;
        store
            .install_staged_text_guarded(
                &paths.lock,
                &portable_path(LOCK_PATH)?,
                Some(&old),
                merged.lock_json(),
                max_control,
            )
            .map_err(commit_error)?;
    } else {
        store
            .remove_regular_file_if_present(&paths.lock)
            .map_err(cleanup_error)?;
    }
    advance_to_at_least(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::LockCommitted,
        limits,
    )?;
    verify_complete(store, merged, limits)?;
    advance_to_at_least(
        store,
        &mut journal,
        &mut encoded,
        SyncPortablePhase::Complete,
        limits,
    )?;
    cleanup_transaction(store, &by_descriptor, &paths, limits)?;
    Ok(SyncPortableRecoveryOutcome::Completed)
}

pub(crate) fn sync_portable_commit_work(
    snapshot: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<(MutationWork, MutationWork), SyncPortableTransactionError> {
    SyncPortableMutationInventory::from_objects(snapshot.objects().iter().cloned())?
        .commit_work(limits)
}

pub(crate) fn sync_portable_recovery_work(
    snapshot: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<(MutationWork, MutationWork), SyncPortableTransactionError> {
    SyncPortableMutationInventory::from_objects(snapshot.objects().iter().cloned())?
        .recovery_work(limits)
}

impl SyncPortableJournal {
    fn from_json(input: &str, limits: SyncLimits) -> Result<Self, SyncPortableTransactionError> {
        if input.len() > max_control_bytes(limits)? {
            return Err(journal_invalid());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Persisted {
            schema_version: u32,
            phase: SyncPortablePhase,
            plan_digest: ContentHash,
            old_manifest_hash: ContentHash,
            old_lock_hash: ContentHash,
            new_manifest_hash: ContentHash,
            new_lock_hash: ContentHash,
            objects: BTreeSet<ObjectDescriptor>,
            staging_manifest: PortablePath,
            staging_lock: PortablePath,
        }
        let value: Persisted = serde_json::from_str(input).map_err(|_| journal_invalid())?;
        let journal = Self {
            schema_version: value.schema_version,
            phase: value.phase,
            plan_digest: value.plan_digest,
            old_manifest_hash: value.old_manifest_hash,
            old_lock_hash: value.old_lock_hash,
            new_manifest_hash: value.new_manifest_hash,
            new_lock_hash: value.new_lock_hash,
            objects: value.objects,
            staging_manifest: value.staging_manifest,
            staging_lock: value.staging_lock,
        };
        if journal.to_json(limits)? != input {
            return Err(journal_invalid());
        }
        Ok(journal)
    }

    fn to_json(&self, limits: SyncLimits) -> Result<String, SyncPortableTransactionError> {
        let mut encoded = serde_json::to_string_pretty(self).map_err(|_| journal_invalid())?;
        encoded.push('\n');
        if encoded.len() > max_control_bytes(limits)? {
            return Err(journal_invalid());
        }
        Ok(encoded)
    }

    fn validate(
        &self,
        merged: &PortableSnapshotV1,
        plan_digest: &ContentHash,
        limits: SyncLimits,
    ) -> Result<(), SyncPortableTransactionError> {
        let paths = transaction_paths(plan_digest)?;
        if self.schema_version != 1
            || &self.plan_digest != plan_digest
            || self.new_manifest_hash != ContentHash::digest(merged.manifest_toml().as_bytes())
            || self.new_lock_hash != ContentHash::digest(merged.lock_json().as_bytes())
            || self.objects != *merged.objects()
            || self.staging_manifest != paths.manifest
            || self.staging_lock != paths.lock
            || self.objects.len() > limits.max_object_count()
        {
            return Err(journal_invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuthorityState {
    Old,
    New,
}

impl AuthorityState {
    const fn is_old(self) -> bool {
        matches!(self, Self::Old)
    }

    const fn is_new(self) -> bool {
        matches!(self, Self::New)
    }
}

fn classify_authority(
    store: &ObjectStore,
    staging: &PortablePath,
    path: &PortablePath,
    old_hash: &ContentHash,
    new: &str,
    max_control: usize,
) -> Result<AuthorityState, SyncPortableTransactionError> {
    let new_hash = ContentHash::digest(new.as_bytes());
    let current = guarded_control::inspect_accepting_duplicate_new(
        store,
        staging,
        path,
        Some(old_hash),
        &new_hash,
        max_control,
        recovery_unknown,
    )
    .map_err(map_guarded_control_error)?
    .ok_or_else(recovery_unknown)?;
    let hash = ContentHash::digest(current.as_bytes());
    if hash == *old_hash {
        Ok(AuthorityState::Old)
    } else if current == new {
        Ok(AuthorityState::New)
    } else {
        Err(recovery_unknown())
    }
}

fn reconcile_authority_control(
    store: &ObjectStore,
    staging: &PortablePath,
    path: &PortablePath,
    old_hash: &ContentHash,
    new_hash: &ContentHash,
    max_control: usize,
) -> Result<(), SyncPortableTransactionError> {
    guarded_control::reconcile_accepting_duplicate_new(
        store,
        staging,
        path,
        Some(old_hash),
        new_hash,
        max_control,
        recovery_unknown,
    )
    .map_err(map_guarded_control_error)
}

fn validate_inputs<'a>(
    merged: &PortableSnapshotV1,
    objects: &'a [VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<BTreeMap<ObjectDescriptor, &'a VerifiedObjectEnvelope>, SyncPortableTransactionError> {
    if objects.len() > limits.max_object_count() {
        return Err(input_invalid());
    }
    let mut by_descriptor = BTreeMap::new();
    for object in objects {
        if by_descriptor
            .insert(object.descriptor().clone(), object)
            .is_some()
        {
            return Err(input_invalid());
        }
    }
    if by_descriptor.keys().cloned().collect::<BTreeSet<_>>() != *merged.objects() {
        return Err(input_invalid());
    }
    Ok(by_descriptor)
}

fn require_exact_authority(
    store: &ObjectStore,
    expected: &PortableSnapshotV1,
    max_control: usize,
) -> Result<(), SyncPortableTransactionError> {
    if required_text(store, MANIFEST_PATH, max_control)? != expected.manifest_toml()
        || required_text(store, LOCK_PATH, max_control)? != expected.lock_json()
    {
        return Err(precondition_failed());
    }
    Ok(())
}

fn stage_objects(
    store: &ObjectStore,
    objects: &BTreeMap<ObjectDescriptor, &VerifiedObjectEnvelope>,
    paths: &TransactionPaths,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    let capture = capture_limits(limits);
    for (index, (descriptor, object)) in objects.iter().enumerate() {
        let staging = object_staging_path(&paths.base, index)?;
        object
            .stage_to(store, &staging, capture)
            .map_err(stage_error)?;
        verify_one_object(store, &staging, descriptor, limits)?;
    }
    Ok(())
}

fn install_objects(
    store: &ObjectStore,
    objects: &BTreeMap<ObjectDescriptor, &VerifiedObjectEnvelope>,
    paths: &TransactionPaths,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    install_objects_with_checkpoints(store, objects, paths, limits, &mut |_| Ok(()))
}

fn install_objects_with_checkpoints(
    store: &ObjectStore,
    objects: &BTreeMap<ObjectDescriptor, &VerifiedObjectEnvelope>,
    paths: &TransactionPaths,
    limits: SyncLimits,
    checkpoint: &mut impl FnMut(PortableCheckpoint) -> Result<(), SyncPortableTransactionError>,
) -> Result<(), SyncPortableTransactionError> {
    let capture = capture_limits(limits);
    for (index, (descriptor, envelope)) in objects.iter().enumerate() {
        let staging = object_staging_path(&paths.base, index)?;
        checkpoint(PortableCheckpoint::BeforeObject(index))?;
        let outcome = envelope
            .install_from(store, &staging, capture)
            .map_err(commit_error)?;
        if outcome == ObjectInstallOutcome::AlreadyPresent {
            clear_object_staging(store, &staging, descriptor, limits)?;
        }
        verify_one_object(store, descriptor.root(), descriptor, limits)?;
        checkpoint(PortableCheckpoint::AfterObject(index))?;
    }
    Ok(())
}

fn verify_snapshot_objects(
    store: &ObjectStore,
    descriptors: &BTreeSet<ObjectDescriptor>,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    for descriptor in descriptors {
        verify_one_object(store, descriptor.root(), descriptor, limits)?;
    }
    Ok(())
}

pub(crate) fn verify_one_object(
    store: &ObjectStore,
    root: &PortablePath,
    descriptor: &ObjectDescriptor,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    let capture = capture_limits(limits);
    if verified_object_matches(store, root, descriptor, capture) {
        Ok(())
    } else {
        Err(verification_failed())
    }
}

pub(crate) fn verified_object_matches(
    store: &ObjectStore,
    root: &PortablePath,
    descriptor: &ObjectDescriptor,
    capture: CaptureLimits,
) -> bool {
    match descriptor.kind() {
        SnapshotObjectKind::PortableSkillTree => {
            store.load_portable(root, capture).ok().and_then(|object| {
                VerifiedObjectEnvelope::portable(descriptor.root().clone(), object).ok()
            })
        }
        SnapshotObjectKind::NativeSkillObject => {
            store.load_native(root, capture).ok().and_then(|object| {
                VerifiedObjectEnvelope::native(descriptor.root().clone(), object).ok()
            })
        }
        SnapshotObjectKind::NativeExtensionObject => store
            .load_native_extension_bounded(root, capture, descriptor.encoded_len())
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
        | SnapshotObjectKind::NativeMcp) => {
            VerifiedDocumentObject::load(store, root, kind, capture, descriptor.encoded_len())
                .ok()
                .and_then(|object| {
                    VerifiedObjectEnvelope::document(descriptor.root().clone(), object).ok()
                })
        }
    }
    .is_some_and(|object| object.descriptor() == descriptor)
}

fn verify_complete(
    store: &ObjectStore,
    merged: &PortableSnapshotV1,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    require_exact_authority(store, merged, max_control_bytes(limits)?)?;
    verify_snapshot_objects(store, merged.objects(), limits)
}

fn clear_object_staging(
    store: &ObjectStore,
    staging: &PortablePath,
    descriptor: &ObjectDescriptor,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    match descriptor.kind() {
        SnapshotObjectKind::PortableSkillTree => {
            store.clear_portable_staging(staging, descriptor.object_hash(), capture_limits(limits))
        }
        SnapshotObjectKind::NativeSkillObject => {
            store.clear_native_staging(staging, descriptor.object_hash(), capture_limits(limits))
        }
        SnapshotObjectKind::NativeExtensionObject => store.clear_native_extension_staging(
            staging,
            descriptor.object_hash(),
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
            store,
            staging,
            kind,
            descriptor.object_hash(),
            capture_limits(limits),
        ),
    }
    .map_err(cleanup_error)
}

fn install_initial_journal(
    store: &ObjectStore,
    journal: &SyncPortableJournal,
    limits: SyncLimits,
) -> Result<String, SyncPortableTransactionError> {
    let encoded = journal.to_json(limits)?;
    let pending = portable_path(JOURNAL_PENDING_PATH)?;
    let live = portable_path(JOURNAL_PATH)?;
    store
        .stage_text(&pending, &encoded, max_control_bytes(limits)?)
        .map_err(journal_write_error)?;
    store
        .install_staged_text_guarded(&pending, &live, None, &encoded, max_control_bytes(limits)?)
        .map_err(journal_write_error)?;
    Ok(encoded)
}

fn advance_journal(
    store: &ObjectStore,
    journal: &mut SyncPortableJournal,
    encoded: &mut String,
    next: SyncPortablePhase,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    if next as u8 != journal.phase as u8 + 1 {
        return Err(journal_invalid());
    }
    journal.phase = next;
    let next_encoded = journal.to_json(limits)?;
    store
        .replace_text_atomically_guarded(
            &portable_path(JOURNAL_PENDING_PATH)?,
            &portable_path(JOURNAL_PATH)?,
            Some(encoded),
            &next_encoded,
            max_control_bytes(limits)?,
        )
        .map_err(journal_write_error)?;
    *encoded = next_encoded;
    Ok(())
}

fn advance_to_at_least(
    store: &ObjectStore,
    journal: &mut SyncPortableJournal,
    encoded: &mut String,
    target: SyncPortablePhase,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    while journal.phase < target {
        let next = match journal.phase {
            SyncPortablePhase::Prepared => SyncPortablePhase::ObjectsInstalled,
            SyncPortablePhase::ObjectsInstalled => SyncPortablePhase::ManifestCommitted,
            SyncPortablePhase::ManifestCommitted => SyncPortablePhase::LockCommitted,
            SyncPortablePhase::LockCommitted => SyncPortablePhase::Complete,
            SyncPortablePhase::Complete => return Err(journal_invalid()),
        };
        advance_journal(store, journal, encoded, next, limits)?;
    }
    Ok(())
}

fn inspect_journal(
    store: &ObjectStore,
    limits: SyncLimits,
) -> Result<Option<SyncPortableJournal>, SyncPortableTransactionError> {
    guarded_journal::inspect(
        store,
        &portable_path(JOURNAL_PATH)?,
        &portable_path(JOURNAL_PENDING_PATH)?,
        max_control_bytes(limits)?,
        |encoded| SyncPortableJournal::from_json(encoded, limits),
        valid_journal_transition,
        journal_invalid,
    )
    .map_err(map_guarded_journal_error)
}

fn reconcile_journal(
    store: &ObjectStore,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    guarded_journal::reconcile(
        store,
        &portable_path(JOURNAL_PATH)?,
        &portable_path(JOURNAL_PENDING_PATH)?,
        max_control_bytes(limits)?,
        |encoded| SyncPortableJournal::from_json(encoded, limits),
        valid_journal_transition,
        journal_invalid,
    )
    .map_err(map_guarded_journal_error)
}

fn valid_journal_transition(old: &SyncPortableJournal, next: &SyncPortableJournal) -> bool {
    let mut expected = old.clone();
    expected.phase = next.phase;
    next.phase as u8 == old.phase as u8 + 1 && expected == *next
}

fn cleanup_transaction(
    store: &ObjectStore,
    objects: &BTreeMap<ObjectDescriptor, &VerifiedObjectEnvelope>,
    paths: &TransactionPaths,
    limits: SyncLimits,
) -> Result<(), SyncPortableTransactionError> {
    for (index, descriptor) in objects.keys().enumerate() {
        clear_object_staging(
            store,
            &object_staging_path(&paths.base, index)?,
            descriptor,
            limits,
        )?;
    }
    store
        .remove_regular_file_if_present(&paths.manifest)
        .map_err(cleanup_error)?;
    store
        .remove_regular_file_if_present(&paths.lock)
        .map_err(cleanup_error)?;
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PENDING_PATH)?)
        .map_err(cleanup_error)?;
    store
        .remove_regular_file_if_present(&portable_path(JOURNAL_PATH)?)
        .map_err(cleanup_error)?;
    cleanup_empty_parents(store, &paths.base)?;
    Ok(())
}

fn cleanup_empty_parents(
    store: &ObjectStore,
    base: &PortablePath,
) -> Result<(), SyncPortableTransactionError> {
    for suffix in ["objects", ""] {
        let path = if suffix.is_empty() {
            base.clone()
        } else {
            joined(base, suffix)?
        };
        store
            .remove_empty_directory_if_present(&path)
            .map_err(cleanup_error)?;
    }
    Ok(())
}

fn transaction_paths(
    plan_digest: &ContentHash,
) -> Result<TransactionPaths, SyncPortableTransactionError> {
    let suffix = plan_digest
        .as_str()
        .rsplit(':')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(input_invalid)?;
    let base = portable_path(&format!(".kitrove/sync/{suffix}/portable"))?;
    Ok(TransactionPaths {
        manifest: joined(&base, "manifest.toml")?,
        lock: joined(&base, "lock.json")?,
        base,
    })
}

fn object_staging_path(
    base: &PortablePath,
    index: usize,
) -> Result<PortablePath, SyncPortableTransactionError> {
    joined(base, &format!("objects/{index:08}"))
}

fn joined(base: &PortablePath, suffix: &str) -> Result<PortablePath, SyncPortableTransactionError> {
    portable_path(&format!("{}/{suffix}", base.as_str()))
}

fn required_text(
    store: &ObjectStore,
    path: &str,
    max_control: usize,
) -> Result<String, SyncPortableTransactionError> {
    store
        .read_text(&portable_path(path)?, max_control)
        .map_err(recovery_error)?
        .ok_or_else(precondition_failed)
}

fn portable_path(path: &str) -> Result<PortablePath, SyncPortableTransactionError> {
    PortablePath::parse(path).map_err(|_| input_invalid())
}

fn max_control_bytes(limits: SyncLimits) -> Result<usize, SyncPortableTransactionError> {
    usize::try_from(limits.max_control_bytes()).map_err(|_| input_invalid())
}

fn capture_limits(limits: SyncLimits) -> CaptureLimits {
    CaptureLimits {
        max_files: limits.max_components(),
        max_file_bytes: limits.max_object_bytes(),
        max_total_bytes: limits.max_object_bytes(),
    }
}

fn error(code: &'static str, message: &'static str) -> SyncPortableTransactionError {
    SyncPortableTransactionError { code, message }
}

fn input_invalid() -> SyncPortableTransactionError {
    error(
        "sync_portable.input_invalid",
        "local sync transaction input is invalid",
    )
}

fn journal_invalid() -> SyncPortableTransactionError {
    error(
        "sync_portable.journal_invalid",
        "local sync transaction journal is invalid",
    )
}

fn precondition_failed() -> SyncPortableTransactionError {
    error(
        "sync_portable.precondition_failed",
        "local portable authority changed after planning",
    )
}

fn recovery_unknown() -> SyncPortableTransactionError {
    error(
        "sync_portable.recovery_unknown",
        "local portable authority cannot be safely reconciled",
    )
}

fn recovery_required() -> SyncPortableTransactionError {
    error(
        "sync_portable.foreign_recovery_required",
        "another portable transaction must recover before local sync can continue",
    )
}

fn recovery_order_invalid() -> SyncPortableTransactionError {
    error(
        "sync_portable.recovery_order_invalid",
        "generated lock authority is ahead of manifest authority",
    )
}

fn verification_failed() -> SyncPortableTransactionError {
    error(
        "sync_portable.verification_failed",
        "local portable authority did not verify exactly",
    )
}

fn store_error(_: crate::ObjectMutationError) -> SyncPortableTransactionError {
    error(
        "sync_portable.storage_error",
        "local sync transaction storage failed",
    )
}

fn stage_error(_: crate::ObjectMutationError) -> SyncPortableTransactionError {
    error(
        "sync_portable.staging_blocked",
        "local sync transaction staging is not exact and safe",
    )
}

fn commit_error(_: crate::ObjectMutationError) -> SyncPortableTransactionError {
    error(
        "sync_portable.commit_failed",
        "local portable authority could not be committed safely",
    )
}

fn recovery_error(_: crate::ObjectMutationError) -> SyncPortableTransactionError {
    error(
        "sync_portable.recovery_failed",
        "local sync transaction recovery could not inspect exact state",
    )
}

fn journal_write_error(_: crate::ObjectMutationError) -> SyncPortableTransactionError {
    error(
        "sync_portable.journal_write_failed",
        "local sync transaction journal could not be persisted safely",
    )
}

fn cleanup_error(_: crate::ObjectMutationError) -> SyncPortableTransactionError {
    error(
        "sync_portable.cleanup_failed",
        "completed local sync transaction staging could not be cleaned safely",
    )
}

fn cleanup_coordinator_error(cause: MutationCleanupError) -> SyncPortableTransactionError {
    match cause {
        MutationCleanupError::InvalidReservation => error(
            "sync_portable.cleanup_limit",
            "local sync transaction exceeds the supported cleanup limit",
        ),
        MutationCleanupError::CleanupFailed => error(
            "sync_portable.cleanup_failed",
            "local sync transaction cleanup failed",
        ),
    }
}

fn map_guarded_control_error(
    error: guarded_control::GuardedControlError<SyncPortableTransactionError>,
) -> SyncPortableTransactionError {
    match error {
        guarded_control::GuardedControlError::Storage(error) => recovery_error(error),
        guarded_control::GuardedControlError::Authority(error) => error,
    }
}

fn map_guarded_journal_error(
    error: guarded_journal::GuardedJournalError<SyncPortableTransactionError>,
) -> SyncPortableTransactionError {
    match error {
        guarded_journal::GuardedJournalError::Storage => recovery_error_storage(),
        guarded_journal::GuardedJournalError::Authority(error) => error,
    }
}

fn recovery_error_storage() -> SyncPortableTransactionError {
    error(
        "sync_portable.recovery_failed",
        "local sync transaction recovery could not inspect exact state",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{BindingName, EnvironmentManifest, SchemaVersion};

    use super::*;

    fn snapshot(binding: Option<&str>) -> PortableSnapshotV1 {
        let required_bindings = binding
            .map(|name| BTreeSet::from([BindingName::parse(name).unwrap()]))
            .unwrap_or_default();
        PortableSnapshotV1::new(
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings,
            },
            BTreeSet::new(),
            SyncLimits::default(),
        )
        .unwrap()
    }

    fn plan() -> ContentHash {
        ContentHash::parse(format!("blake3:{}", "a".repeat(64))).unwrap()
    }

    fn environment(local: &PortableSnapshotV1) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let environment = root.path().canonicalize().unwrap().join("environment");
        crate::test_authority::initialize_portable_environment(
            &environment,
            local.manifest_toml(),
            local.lock_json(),
        )
        .unwrap();
        let canonical = std::fs::canonicalize(environment).unwrap();
        (root, canonical)
    }

    #[test]
    fn direct_local_sync_refuses_foreign_environment_recovery_artifacts() {
        for path in [
            local_state_authority::ADOPTION_JOURNAL_PATH,
            local_state_authority::ADOPTION_PENDING_PATH,
            local_state_authority::OUTER_SYNC_GUARD_PATH,
        ] {
            let local = snapshot(None);
            let (_temporary, root) = environment(&local);
            std::fs::create_dir_all(root.join(".kitrove")).unwrap();
            std::fs::write(root.join(path), "foreign\n").unwrap();
            let store = ObjectStore::open(&root).unwrap();

            let error =
                ensure_no_foreign_environment_journal(&store, SyncLimits::default()).unwrap_err();

            assert_eq!(error.code(), "sync_portable.foreign_recovery_required");
        }
    }

    fn populated_snapshot() -> (PortableSnapshotV1, Vec<VerifiedObjectEnvelope>) {
        let limits = SyncLimits::default();
        let adoption = crate::native_extension_adoption::tests::ready_plan();
        let native = &adoption.asset().native_variants[&kitrove_model::HarnessId::Pi];
        let objects = vec![
            VerifiedObjectEnvelope::native_extension(
                native.root.clone(),
                adoption.native_object().clone(),
            )
            .unwrap(),
        ];
        let descriptors = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        (
            PortableSnapshotV1::new(adoption.proposed_manifest().clone(), descriptors, limits)
                .unwrap(),
            objects,
        )
    }

    fn prepared_journal(
        store: &ObjectStore,
        local: &PortableSnapshotV1,
        merged: &PortableSnapshotV1,
    ) -> (SyncPortableJournal, TransactionPaths) {
        let limits = SyncLimits::default();
        let paths = transaction_paths(&plan()).unwrap();
        store
            .stage_text(
                &paths.manifest,
                merged.manifest_toml(),
                max_control_bytes(limits).unwrap(),
            )
            .unwrap();
        store
            .stage_text(
                &paths.lock,
                merged.lock_json(),
                max_control_bytes(limits).unwrap(),
            )
            .unwrap();
        let journal = SyncPortableJournal {
            schema_version: 1,
            phase: SyncPortablePhase::Prepared,
            plan_digest: plan(),
            old_manifest_hash: ContentHash::digest(local.manifest_toml().as_bytes()),
            old_lock_hash: ContentHash::digest(local.lock_json().as_bytes()),
            new_manifest_hash: ContentHash::digest(merged.manifest_toml().as_bytes()),
            new_lock_hash: ContentHash::digest(merged.lock_json().as_bytes()),
            objects: merged.objects().clone(),
            staging_manifest: paths.manifest.clone(),
            staging_lock: paths.lock.clone(),
        };
        install_initial_journal(store, &journal, limits).unwrap();
        (journal, paths)
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_quarantine_blocks_portable_commit_before_authority_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let local = snapshot(None);
        let merged = snapshot(Some("workspace"));
        let (_temporary, root) = environment(&local);
        let control = root.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        std::fs::create_dir_all(&quarantine).unwrap();
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&quarantine, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(quarantine.join("unrecognized-retained-state"), "authority").unwrap();

        let error = commit_sync_portable_snapshot(
            &root,
            &local,
            &merged,
            &[],
            &plan(),
            SyncLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code(), "sync_portable.cleanup_failed");
        assert_eq!(
            std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
            local.manifest_toml()
        );
        assert_eq!(
            std::fs::read_to_string(root.join(LOCK_PATH)).unwrap(),
            local.lock_json()
        );
        assert!(!root.join(JOURNAL_PATH).exists());
        assert!(quarantine.join("unrecognized-retained-state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn portable_commit_reclaims_retained_state() {
        let local = snapshot(None);
        let merged = snapshot(Some("workspace"));
        let (_temporary, root) = environment(&local);
        let obsolete = PortablePath::parse("obsolete-sync-control").unwrap();
        std::fs::write(root.join(obsolete.as_str()), "retained").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _lock = store.try_lock_environment().unwrap();
        store.remove_regular_file_if_present(&obsolete).unwrap();
        drop(_lock);
        let quarantine = root.join(".kitrove/removal-quarantine");
        let retained = std::fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(!retained.is_empty());

        commit_sync_portable_snapshot(&root, &local, &merged, &[], &plan(), SyncLimits::default())
            .unwrap();

        for name in retained {
            assert!(!quarantine.join(name).exists());
        }
    }

    #[test]
    fn portable_recovery_reconciles_every_guarded_journal_window() {
        #[derive(Clone, Copy)]
        enum Window {
            BackupAndPending,
            BackupAndLive,
            LiveAndPending,
        }

        let limits = SyncLimits::default();
        let local = snapshot(None);
        let merged = snapshot(Some("workspace"));
        for window in [
            Window::BackupAndPending,
            Window::BackupAndLive,
            Window::LiveAndPending,
        ] {
            let (_temporary, root) = environment(&local);
            let store = ObjectStore::open(&root).unwrap();
            let (journal, _) = prepared_journal(&store, &local, &merged);
            let old = journal.to_json(limits).unwrap();
            let mut next_journal = journal.clone();
            next_journal.phase = SyncPortablePhase::ObjectsInstalled;
            let next = next_journal.to_json(limits).unwrap();
            let live = root.join(JOURNAL_PATH);
            let pending = root.join(JOURNAL_PENDING_PATH);
            let backup = root.join(
                crate::object_mutation::guarded_backup_path(
                    &portable_path(JOURNAL_PENDING_PATH).unwrap(),
                )
                .unwrap()
                .as_str(),
            );
            match window {
                Window::BackupAndPending => {
                    std::fs::rename(&live, &backup).unwrap();
                    crate::test_authority::write_owned_fixture_file(&pending, &next).unwrap();
                }
                Window::BackupAndLive => {
                    std::fs::rename(&live, &backup).unwrap();
                    crate::test_authority::write_owned_fixture_file(&live, &next).unwrap();
                }
                Window::LiveAndPending => {
                    assert_eq!(std::fs::read_to_string(&live).unwrap(), old);
                    crate::test_authority::write_owned_fixture_file(&pending, &next).unwrap();
                }
            }

            assert_eq!(
                recover_sync_portable_snapshot(&root, &merged, &[], &plan(), limits).unwrap(),
                SyncPortableRecoveryOutcome::Completed
            );
            assert_eq!(
                std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
                merged.manifest_toml()
            );
            assert_eq!(
                std::fs::read_to_string(root.join(LOCK_PATH)).unwrap(),
                merged.lock_json()
            );
            assert!(!live.exists());
            assert!(!pending.exists());
            assert!(!backup.exists());
        }
    }

    #[test]
    fn portable_journal_branch_is_bound_across_cleanup() {
        for initially_present in [false, true] {
            let limits = SyncLimits::default();
            let local = snapshot(None);
            let merged = snapshot(Some("workspace"));
            let (_temporary, root) = environment(&local);
            let store = ObjectStore::open(&root).unwrap();
            let _lock = store.try_lock_environment().unwrap();
            if initially_present {
                prepared_journal(&store, &local, &merged);
            }
            let binding = bind_sync_portable_journal(&store, limits).unwrap();
            let inventory = SyncPortableMutationInventory::from_objects([]).unwrap();
            let (forward, rollback) = if initially_present {
                inventory.recovery_work(limits).unwrap()
            } else {
                inventory.commit_work(limits).unwrap()
            };
            let budget = cleanup_locked_stores(&[&store], forward, rollback).unwrap();
            let mutation_budget = budget.begin_forward().unwrap();
            if initially_present {
                std::fs::remove_file(root.join(JOURNAL_PATH)).unwrap();
            } else {
                prepared_journal(&store, &local, &merged);
            }

            let error = recover_sync_portable_snapshot_under_lock(
                &store,
                &merged,
                &[],
                &plan(),
                limits,
                &mutation_budget,
                &binding,
            )
            .unwrap_err();

            assert_eq!(error.code(), "sync_portable.recovery_unknown");
            assert_eq!(
                std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
                local.manifest_toml()
            );
        }
    }

    #[test]
    fn commits_manifest_before_generated_lock_and_cleans_durable_state() {
        let local = snapshot(None);
        let merged = snapshot(Some("workspace"));
        let (_temporary, root) = environment(&local);

        assert_eq!(
            commit_sync_portable_snapshot(
                &root,
                &local,
                &merged,
                &[],
                &plan(),
                SyncLimits::default(),
            )
            .unwrap(),
            SyncPortableCommitOutcome::Committed
        );
        assert_eq!(
            std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
            merged.manifest_toml()
        );
        assert_eq!(
            std::fs::read_to_string(root.join(LOCK_PATH)).unwrap(),
            merged.lock_json()
        );
        assert!(!root.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn commits_and_verifies_every_exact_snapshot_object() {
        let limits = SyncLimits::default();
        let local = snapshot(None);
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
        let merged =
            PortableSnapshotV1::new(adoption.proposed_manifest().clone(), descriptors, limits)
                .unwrap();
        let (_temporary, root) = environment(&local);

        commit_sync_portable_snapshot(&root, &local, &merged, &objects, &plan(), limits).unwrap();

        let store = ObjectStore::open(&root).unwrap();
        verify_snapshot_objects(&store, merged.objects(), limits).unwrap();
        assert!(portable.root != native.root);
    }

    #[test]
    fn exact_manifest_commit_with_old_lock_is_recovered_forward() {
        let local = snapshot(None);
        let merged = snapshot(Some("workspace"));
        let (_temporary, root) = environment(&local);
        let store = ObjectStore::open(&root).unwrap();
        let (_journal, paths) = prepared_journal(&store, &local, &merged);
        store
            .install_staged_text_guarded(
                &paths.manifest,
                &portable_path(MANIFEST_PATH).unwrap(),
                Some(local.manifest_toml()),
                merged.manifest_toml(),
                max_control_bytes(SyncLimits::default()).unwrap(),
            )
            .unwrap();

        assert_eq!(
            recover_sync_portable_snapshot(&root, &merged, &[], &plan(), SyncLimits::default(),)
                .unwrap(),
            SyncPortableRecoveryOutcome::Completed
        );
        assert_eq!(
            std::fs::read_to_string(root.join(LOCK_PATH)).unwrap(),
            merged.lock_json()
        );
        assert!(!root.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn recovery_rejects_generated_lock_ahead_of_manifest() {
        let local = snapshot(None);
        let manifest = kitrove_testkit::portable_manifest();
        let descriptors = manifest
            .assets
            .values()
            .flat_map(|asset| {
                asset
                    .portable
                    .iter()
                    .map(|object| {
                        ObjectDescriptor::new(
                            SnapshotObjectKind::PortableSkillTree,
                            object.root.clone(),
                            object.object_hash.clone(),
                            1,
                        )
                        .unwrap()
                    })
                    .chain(asset.native_variants.values().map(|object| {
                        ObjectDescriptor::new(
                            SnapshotObjectKind::NativeSkillObject,
                            object.root.clone(),
                            object.object_hash.clone(),
                            1,
                        )
                        .unwrap()
                    }))
            })
            .collect();
        let merged = PortableSnapshotV1::new(manifest, descriptors, SyncLimits::default()).unwrap();
        let (_temporary, root) = environment(&local);
        let store = ObjectStore::open(&root).unwrap();
        prepared_journal(&store, &local, &merged);
        std::fs::write(root.join(LOCK_PATH), merged.lock_json()).unwrap();

        let error =
            recover_sync_portable_snapshot(&root, &merged, &[], &plan(), SyncLimits::default())
                .unwrap_err();
        assert_eq!(error.code(), "sync_portable.recovery_order_invalid");
        assert!(root.join(JOURNAL_PATH).exists());
    }

    #[test]
    fn unknown_transaction_staging_blocks_without_deletion() {
        let local = snapshot(None);
        let merged = snapshot(Some("workspace"));
        let (_temporary, root) = environment(&local);
        let store = ObjectStore::open(&root).unwrap();
        let paths = transaction_paths(&plan()).unwrap();
        store
            .stage_text(
                &paths.manifest,
                "UNKNOWN-STAGING-CANARY",
                max_control_bytes(SyncLimits::default()).unwrap(),
            )
            .unwrap();

        let error = commit_sync_portable_snapshot(
            &root,
            &local,
            &merged,
            &[],
            &plan(),
            SyncLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "sync_portable.staging_blocked");
        assert_eq!(
            std::fs::read_to_string(root.join(paths.manifest.as_str())).unwrap(),
            "UNKNOWN-STAGING-CANARY"
        );
        assert_eq!(
            std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
            local.manifest_toml()
        );
    }

    #[test]
    fn every_durable_portable_boundary_retries_or_recovers_exactly() {
        let limits = SyncLimits::default();
        let local = snapshot(None);
        let (merged, objects) = populated_snapshot();
        let mut checkpoints = Vec::new();
        for phase in [
            SyncPortablePhase::Prepared,
            SyncPortablePhase::ObjectsInstalled,
            SyncPortablePhase::ManifestCommitted,
            SyncPortablePhase::LockCommitted,
            SyncPortablePhase::Complete,
        ] {
            checkpoints.push(PortableCheckpoint::BeforeJournal(phase));
            checkpoints.push(PortableCheckpoint::AfterJournal(phase));
        }
        for index in 0..objects.len() {
            checkpoints.push(PortableCheckpoint::BeforeObject(index));
            checkpoints.push(PortableCheckpoint::AfterObject(index));
        }
        checkpoints.extend([
            PortableCheckpoint::BeforeManifest,
            PortableCheckpoint::AfterManifest,
            PortableCheckpoint::BeforeLock,
            PortableCheckpoint::AfterLock,
        ]);

        for target in checkpoints {
            let (_temporary, root) = environment(&local);
            let prior_canary = root.join(".kitrove/prior-immutable-canary");
            std::fs::create_dir_all(prior_canary.parent().unwrap()).unwrap();
            std::fs::write(&prior_canary, "PRIOR-IMMUTABLE-CANARY").unwrap();
            let store = ObjectStore::open(&root).unwrap();
            let error = commit_sync_portable_snapshot_with_checkpoints(
                &store,
                &local,
                &merged,
                &objects,
                &plan(),
                limits,
                |checkpoint| {
                    if checkpoint == target {
                        Err(test_interrupted())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), "sync_portable.test_interrupted");
            if std::fs::read_to_string(root.join(LOCK_PATH)).unwrap() == merged.lock_json() {
                assert_eq!(
                    std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
                    merged.manifest_toml()
                );
            }

            if target == PortableCheckpoint::BeforeJournal(SyncPortablePhase::Prepared) {
                assert_eq!(
                    commit_sync_portable_snapshot(
                        &root,
                        &local,
                        &merged,
                        &objects,
                        &plan(),
                        limits,
                    )
                    .unwrap(),
                    SyncPortableCommitOutcome::Committed
                );
            } else {
                assert_eq!(
                    recover_sync_portable_snapshot(&root, &merged, &objects, &plan(), limits)
                        .unwrap(),
                    SyncPortableRecoveryOutcome::Completed
                );
            }
            assert_eq!(
                std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
                merged.manifest_toml()
            );
            assert_eq!(
                std::fs::read_to_string(root.join(LOCK_PATH)).unwrap(),
                merged.lock_json()
            );
            verify_snapshot_objects(&store, merged.objects(), limits).unwrap();
            assert_eq!(
                std::fs::read_to_string(&prior_canary).unwrap(),
                "PRIOR-IMMUTABLE-CANARY"
            );
            assert!(!root.join(JOURNAL_PATH).exists());
        }
    }

    fn test_interrupted() -> SyncPortableTransactionError {
        error(
            "sync_portable.test_interrupted",
            "portable transaction test interrupted at a durable boundary",
        )
    }
}
