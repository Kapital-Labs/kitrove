use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{
    ObjectDescriptor, PortablePath, PublicationId, RemoteKey, RemoteRevision, SnapshotDigest,
    SnapshotObjectKind, SyncLimits,
};
use serde::{Deserialize, Serialize};

use crate::object_mutation::EnvironmentLock;
use crate::sync_backend::{sealed::Sealed, validate_descriptor_budget};
use crate::{
    BackendError, ObjectStore, PortableSnapshotV1, PublicationIntent, PublicationStatus,
    RemoteSnapshot, SyncBackend, SyncBackendApply, SyncBackendRead, VerifiedObjectEnvelope,
    VerifiedRemoteHistory, sync_backend::VerifiedDocumentObject,
};

const ABSENT_REVISION: &str = "filesystem:absent:v1";
const CONTROL_ROOT: &str = ".kitrove-sync";

/// Capability-scoped filesystem synchronization transport.
pub struct FilesystemSyncBackend {
    store: ObjectStore,
    remote_key: RemoteKey,
}

impl FilesystemSyncBackend {
    /// Opens one existing caller-selected remote root without following link-like ancestors.
    pub fn open(root: &Path) -> Result<Self, BackendError> {
        let normalized_root = normalize_root(root)?;
        let normalized = normalized_root.to_str().ok_or_else(invalid_remote)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"kitrove-filesystem-remote-key-v1\0");
        hasher.update(&(normalized.len() as u64).to_be_bytes());
        hasher.update(normalized.as_bytes());
        let remote_key = RemoteKey::parse(format!("remote:blake3:{}", hasher.finalize().to_hex()))
            .map_err(|_| invalid_remote())?;
        Ok(Self {
            store: ObjectStore::open(&normalized_root).map_err(map_store)?,
            remote_key,
        })
    }

    /// Returns the machine-local hashed identity of this backend root.
    #[must_use]
    pub const fn remote_key(&self) -> &RemoteKey {
        &self.remote_key
    }
}

fn normalize_root(root: &Path) -> Result<PathBuf, BackendError> {
    let absolute = std::path::absolute(root).map_err(|_| invalid_remote())?;
    #[cfg(windows)]
    if absolute
        .as_os_str()
        .to_string_lossy()
        .split(['/', '\\'])
        .any(|component| component == "..")
    {
        return Err(invalid_remote());
    }
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(value) if value == "." => {}
            Component::Normal(value) if value == ".." => return Err(invalid_remote()),
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => return Err(invalid_remote()),
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(invalid_remote());
    }
    Ok(normalized)
}

impl Debug for FilesystemSyncBackend {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilesystemSyncBackend")
            .field("root", &"[redacted]")
            .finish()
    }
}

impl Sealed for FilesystemSyncBackend {}

impl SyncBackend for FilesystemSyncBackend {
    type ReadSession<'a> = FilesystemReadSession<'a>;

    type ApplySession<'a> = FilesystemApplySession<'a>;

    fn inspect(&self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        inspect_store(&self.store, limits).map(|value| value.remote)
    }

    fn fetch_object(
        &self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        fetch_store_object(&self.store, descriptor, limits)
    }

    fn begin_read(&self, _limits: SyncLimits) -> Result<Self::ReadSession<'_>, BackendError> {
        let lock = self
            .store
            .try_lock_existing_file_shared(&portable(".kitrove-sync/lock")?)
            .map_err(map_store)?;
        Ok(FilesystemReadSession {
            store: &self.store,
            _lock: lock,
        })
    }

    fn begin_apply(&self, _limits: SyncLimits) -> Result<Self::ApplySession<'_>, BackendError> {
        let lock_path = portable(".kitrove-sync/lock")?;
        let lock = self.store.try_lock_file(&lock_path).map_err(map_store)?;
        Ok(FilesystemApplySession {
            store: &self.store,
            _lock: lock,
        })
    }
}

/// Mutation-free filesystem backend session, shared-locked once initialized.
pub struct FilesystemReadSession<'a> {
    store: &'a ObjectStore,
    _lock: Option<EnvironmentLock>,
}

impl SyncBackendRead for FilesystemReadSession<'_> {
    fn inspect(&mut self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        inspect_store(self.store, limits).map(|value| value.remote)
    }

    fn inspect_history(
        &mut self,
        limits: SyncLimits,
    ) -> Result<VerifiedRemoteHistory, BackendError> {
        inspect_store_history(self.store, limits)
    }

    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        fetch_store_object(self.store, descriptor, limits)
    }
}

/// Exclusive filesystem backend apply session.
pub struct FilesystemApplySession<'a> {
    store: &'a ObjectStore,
    _lock: EnvironmentLock,
}

impl SyncBackendApply for FilesystemApplySession<'_> {
    fn inspect(&mut self, limits: SyncLimits) -> Result<RemoteSnapshot, BackendError> {
        inspect_store(self.store, limits).map(|value| value.remote)
    }

    fn fetch_object(
        &mut self,
        descriptor: &ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<VerifiedObjectEnvelope, BackendError> {
        fetch_store_object(self.store, descriptor, limits)
    }

    fn prepare_publication(
        &mut self,
        expected: &RemoteRevision,
        publication_id: &PublicationId,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationIntent, BackendError> {
        let supplied: BTreeSet<_> = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        if supplied != *staged.objects() {
            return Err(object_mismatch());
        }
        validate_object_budget(objects, limits)?;
        let inspected = inspect_store(self.store, limits)?;
        if inspected.remote.revision() != expected {
            return Err(stale());
        }
        let (generation, prior_head_path, prior_generation) = match inspected.head {
            Some(head) => {
                let generation = head
                    .generation
                    .checked_add(1)
                    .ok_or_else(generation_overflow)?;
                if usize::try_from(generation)
                    .map_or(true, |generation| generation > limits.max_backend_history())
                {
                    return Err(history_exceeded());
                }
                (generation, inspected.head_path, Some(head.generation))
            }
            None => (1, None, None),
        };
        let snapshot_file = snapshot_path(staged.snapshot_digest())?;
        let head = Head {
            schema_version: 1,
            publication_id: publication_id.clone(),
            generation,
            snapshot_digest: staged.snapshot_digest().clone(),
            snapshot_file,
            prior_head_path,
            prior_generation,
            prior_revision: expected.clone(),
        };
        let encoded = canonical(&head)?;
        let revision = head_revision(&encoded)?;
        PublicationIntent::from_persisted(encoded, revision, limits)
    }

    fn publish(
        &mut self,
        intent: &PublicationIntent,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError> {
        self.publish_with_checkpoints(intent, staged, objects, limits, |_| Ok(()))
    }

    fn reconcile(
        &mut self,
        intent: &PublicationIntent,
        limits: SyncLimits,
    ) -> Result<PublicationStatus, BackendError> {
        let proposed = parse_head(intent.as_persisted(), limits)?;
        if head_revision(intent.as_persisted())? != *intent.proposed_revision() {
            return Err(intent_invalid());
        }
        let Ok(inspected) = inspect_store(self.store, limits) else {
            return Ok(PublicationStatus::Uncertain);
        };
        if inspected.history.contains(intent.proposed_revision()) {
            return Ok(PublicationStatus::Published(
                intent.proposed_revision().clone(),
            ));
        }
        if inspected.remote.revision() == &proposed.prior_revision {
            return Ok(PublicationStatus::Ready);
        }
        Ok(PublicationStatus::Uncertain)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishCheckpoint {
    BeforeHeadInstall,
    AfterHeadInstall,
    BeforePointerReplace,
    AfterPointerReplace,
}

impl FilesystemApplySession<'_> {
    fn publish_with_checkpoints(
        &mut self,
        intent: &PublicationIntent,
        staged: &PortableSnapshotV1,
        objects: &[VerifiedObjectEnvelope],
        limits: SyncLimits,
        mut checkpoint: impl FnMut(PublishCheckpoint) -> Result<(), BackendError>,
    ) -> Result<PublicationStatus, BackendError> {
        let head = parse_head(intent.as_persisted(), limits)?;
        if head_revision(intent.as_persisted())? != *intent.proposed_revision()
            || head.snapshot_digest != *staged.snapshot_digest()
        {
            return Err(intent_invalid());
        }
        let current = inspect_store(self.store, limits)?;
        if current.remote.revision() != &head.prior_revision {
            return Ok(PublicationStatus::Uncertain);
        }
        let supplied: BTreeSet<_> = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        if supplied != *staged.objects() {
            return Err(object_mismatch());
        }
        validate_object_budget(objects, limits)?;
        let capture = capture_limits(limits);
        let stage_prefix = stage_prefix(&head.publication_id)?;
        for object in objects {
            let destination = remote_object_path(object.descriptor())?;
            let staging = joined(&stage_prefix, object.descriptor().root().as_str())?;
            match object {
                VerifiedObjectEnvelope::Portable { descriptor, object } => {
                    self.store
                        .stage_portable(&staging, object, capture)
                        .map_err(map_store)?;
                    self.store
                        .install_portable(&staging, &destination, descriptor.object_hash(), capture)
                        .map_err(map_store)?;
                }
                VerifiedObjectEnvelope::Native { descriptor, object } => {
                    self.store
                        .stage_native(&staging, object, capture)
                        .map_err(map_store)?;
                    self.store
                        .install_native(&staging, &destination, descriptor.object_hash(), capture)
                        .map_err(map_store)?;
                }
                VerifiedObjectEnvelope::NativeExtension { descriptor, object } => {
                    self.store
                        .stage_native_extension(&staging, object, capture)
                        .map_err(map_store)?;
                    self.store
                        .install_native_extension(
                            &staging,
                            &destination,
                            descriptor.object_hash(),
                            capture,
                        )
                        .map_err(map_store)?;
                }
                VerifiedObjectEnvelope::Document { descriptor, object } => {
                    object
                        .stage(self.store, &staging, capture)
                        .map_err(map_store)?;
                    object
                        .install(
                            self.store,
                            &staging,
                            &destination,
                            descriptor.object_hash(),
                            capture,
                        )
                        .map_err(map_store)?;
                }
            }
        }
        let snapshot_text = staged.to_json(limits).map_err(|_| invalid_remote())?;
        install_immutable_text(
            self.store,
            &joined(&stage_prefix, "snapshot.json")?,
            &head.snapshot_file,
            &snapshot_text,
            limits,
        )?;
        let head_path = head_path(&head, intent.as_persisted())?;
        checkpoint(PublishCheckpoint::BeforeHeadInstall)?;
        install_immutable_text(
            self.store,
            &joined(&stage_prefix, "head.json")?,
            &head_path,
            intent.as_persisted(),
            limits,
        )?;
        checkpoint(PublishCheckpoint::AfterHeadInstall)?;
        let pointer = Current {
            schema_version: 1,
            head_path,
            revision: intent.proposed_revision().clone(),
        };
        let pointer_text = canonical(&pointer)?;
        checkpoint(PublishCheckpoint::BeforePointerReplace)?;
        self.store
            .replace_text_atomically_guarded(
                &joined(&stage_prefix, "current.json")?,
                &portable(".kitrove-sync/current.json")?,
                current.current_text.as_deref(),
                &pointer_text,
                usize_limit(limits)?,
            )
            .map_err(|_| stale())?;
        checkpoint(PublishCheckpoint::AfterPointerReplace)?;
        Ok(PublicationStatus::Published(
            intent.proposed_revision().clone(),
        ))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Current {
    schema_version: u32,
    head_path: PortablePath,
    revision: RemoteRevision,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Head {
    schema_version: u32,
    publication_id: PublicationId,
    generation: u64,
    snapshot_digest: SnapshotDigest,
    snapshot_file: PortablePath,
    prior_head_path: Option<PortablePath>,
    prior_generation: Option<u64>,
    prior_revision: RemoteRevision,
}

struct Inspected {
    remote: RemoteSnapshot,
    current_text: Option<String>,
    head: Option<Head>,
    head_path: Option<PortablePath>,
    history: Vec<RemoteRevision>,
}

struct HistoryEntry {
    revision: RemoteRevision,
    head: Head,
}

struct InspectedHistory {
    current_text: String,
    head_path: PortablePath,
    entries: Vec<HistoryEntry>,
}

fn inspect_history_chain(
    store: &ObjectStore,
    limits: SyncLimits,
) -> Result<Option<InspectedHistory>, BackendError> {
    let mut control_budget = ReadBudget::control(limits);
    let current_path = portable(".kitrove-sync/current.json")?;
    let Some(current_text) = read_budgeted_text(store, &current_path, &mut control_budget)? else {
        return Ok(None);
    };
    let current: Current = parse_canonical(&current_text)?;
    if current.schema_version != 1 {
        return Err(invalid_remote());
    }
    let mut path = current.head_path.clone();
    let mut revision = current.revision.clone();
    let mut child: Option<Head> = None;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for index in 0..limits.max_backend_history() {
        if !seen.insert(revision.as_str().to_owned()) {
            return Err(invalid_remote());
        }
        let text =
            read_budgeted_text(store, &path, &mut control_budget)?.ok_or_else(invalid_remote)?;
        let head = parse_head(&text, limits)?;
        if head_revision(&text)? != revision || head_path(&head, &text)? != path {
            return Err(invalid_remote());
        }
        if let Some(child) = &child {
            if child.prior_head_path.as_ref() != Some(&path)
                || child.prior_generation != Some(head.generation)
                || child.prior_revision != revision
                || child.generation != head.generation.checked_add(1).ok_or_else(invalid_remote)?
            {
                return Err(invalid_remote());
            }
        }
        entries.push(HistoryEntry {
            revision: revision.clone(),
            head: head.clone(),
        });
        match (&head.prior_head_path, head.prior_generation) {
            (None, None) if head.generation == 1 && head.prior_revision == absent_revision() => {
                break;
            }
            (Some(prior), Some(generation))
                if generation.checked_add(1) == Some(head.generation) =>
            {
                path = prior.clone();
                revision = head.prior_revision.clone();
                child = Some(head);
            }
            _ => return Err(invalid_remote()),
        }
        if index + 1 == limits.max_backend_history() {
            return Err(history_exceeded());
        }
    }
    Ok(Some(InspectedHistory {
        current_text,
        head_path: current.head_path,
        entries,
    }))
}

fn inspect_store(store: &ObjectStore, limits: SyncLimits) -> Result<Inspected, BackendError> {
    let Some(history) = inspect_history_chain(store, limits)? else {
        return Ok(Inspected {
            remote: RemoteSnapshot::absent(absent_revision()),
            current_text: None,
            head: None,
            head_path: None,
            history: Vec::new(),
        });
    };
    let selected = history.entries.first().ok_or_else(invalid_remote)?;
    let head = &selected.head;
    let snapshot_text = store
        .read_text(&head.snapshot_file, usize_limit_snapshot(limits)?)
        .map_err(map_store)?
        .ok_or_else(invalid_remote)?;
    let snapshot =
        PortableSnapshotV1::from_json(&snapshot_text, limits).map_err(|_| invalid_remote())?;
    if snapshot.snapshot_digest() != &head.snapshot_digest
        || snapshot_path(snapshot.snapshot_digest())? != head.snapshot_file
    {
        return Err(invalid_remote());
    }
    Ok(Inspected {
        remote: RemoteSnapshot::present(selected.revision.clone(), snapshot),
        current_text: Some(history.current_text),
        head: Some(head.clone()),
        head_path: Some(history.head_path),
        history: history
            .entries
            .into_iter()
            .map(|entry| entry.revision)
            .collect(),
    })
}

fn inspect_store_history(
    store: &ObjectStore,
    limits: SyncLimits,
) -> Result<VerifiedRemoteHistory, BackendError> {
    let Some(history) = inspect_history_chain(store, limits)? else {
        return Err(invalid_remote());
    };
    let mut snapshots = Vec::with_capacity(history.entries.len());
    let mut loaded: BTreeMap<SnapshotDigest, Arc<PortableSnapshotV1>> = BTreeMap::new();
    let mut snapshot_budget = ReadBudget::snapshots(limits);
    for entry in history.entries {
        if snapshot_path(&entry.head.snapshot_digest)? != entry.head.snapshot_file {
            return Err(invalid_remote());
        }
        let snapshot = if let Some(snapshot) = loaded.get(&entry.head.snapshot_digest) {
            Arc::clone(snapshot)
        } else {
            let snapshot_text =
                read_budgeted_text(store, &entry.head.snapshot_file, &mut snapshot_budget)?
                    .ok_or_else(invalid_remote)?;
            let snapshot = PortableSnapshotV1::from_json(&snapshot_text, limits)
                .map_err(|_| invalid_remote())?;
            if snapshot.snapshot_digest() != &entry.head.snapshot_digest {
                return Err(invalid_remote());
            }
            let snapshot = Arc::new(snapshot);
            loaded.insert(entry.head.snapshot_digest.clone(), Arc::clone(&snapshot));
            snapshot
        };
        snapshots.push((entry.revision, snapshot));
    }
    verify_history_objects(store, &snapshots, limits)?;
    VerifiedRemoteHistory::new(snapshots, limits).map_err(|_| invalid_remote())
}

fn verify_history_objects(
    store: &ObjectStore,
    snapshots: &[(RemoteRevision, Arc<PortableSnapshotV1>)],
    limits: SyncLimits,
) -> Result<(), BackendError> {
    let descriptors: BTreeSet<_> = snapshots
        .iter()
        .flat_map(|(_, snapshot)| snapshot.objects())
        .collect();
    validate_descriptor_budget(descriptors.iter().copied(), limits)
        .map_err(|_| object_budget_exceeded())?;
    for descriptor in descriptors {
        fetch_store_object(store, descriptor, limits)?;
    }
    Ok(())
}

struct ReadBudget {
    remaining: u64,
    exceeded: fn() -> BackendError,
}

impl ReadBudget {
    const fn control(limits: SyncLimits) -> Self {
        Self {
            remaining: limits.max_control_bytes(),
            exceeded: control_budget_exceeded,
        }
    }

    const fn snapshots(limits: SyncLimits) -> Self {
        Self {
            remaining: limits.max_snapshot_bytes(),
            exceeded: snapshot_budget_exceeded,
        }
    }

    fn charge(&mut self, text: &str) -> Result<(), BackendError> {
        let bytes = u64::try_from(text.len()).map_err(|_| (self.exceeded)())?;
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| (self.exceeded)())?;
        Ok(())
    }

    fn read_limit(&self) -> Result<usize, BackendError> {
        usize::try_from(self.remaining).map_err(|_| (self.exceeded)())
    }
}

fn read_budgeted_text(
    store: &ObjectStore,
    path: &PortablePath,
    budget: &mut ReadBudget,
) -> Result<Option<String>, BackendError> {
    let text = store
        .read_text(path, budget.read_limit()?)
        .map_err(|error| {
            if error.code() == "object.control_file_invalid" {
                (budget.exceeded)()
            } else {
                map_store(error)
            }
        })?;
    if let Some(text) = text.as_deref() {
        budget.charge(text)?;
    }
    Ok(text)
}

fn validate_object_budget(
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), BackendError> {
    validate_descriptor_budget(
        objects.iter().map(VerifiedObjectEnvelope::descriptor),
        limits,
    )
    .map_err(|_| object_budget_exceeded())
}

fn fetch_store_object(
    store: &ObjectStore,
    descriptor: &ObjectDescriptor,
    limits: SyncLimits,
) -> Result<VerifiedObjectEnvelope, BackendError> {
    let path = remote_object_path(descriptor)?;
    let capture = capture_limits(limits);
    let object = match descriptor.kind() {
        SnapshotObjectKind::PortableSkillTree => VerifiedObjectEnvelope::portable(
            descriptor.root().clone(),
            store
                .load_portable_bounded(&path, capture, descriptor.encoded_len())
                .map_err(map_store)?,
        )?,
        SnapshotObjectKind::NativeSkillObject => VerifiedObjectEnvelope::native(
            descriptor.root().clone(),
            store
                .load_native_bounded(&path, capture, descriptor.encoded_len())
                .map_err(map_store)?,
        )?,
        SnapshotObjectKind::NativeExtensionObject => VerifiedObjectEnvelope::native_extension(
            descriptor.root().clone(),
            store
                .load_native_extension_bounded(&path, capture, descriptor.encoded_len())
                .map_err(map_store)?,
        )?,
        kind @ (SnapshotObjectKind::PortableInstruction
        | SnapshotObjectKind::NativeInstruction
        | SnapshotObjectKind::PortablePromptCommand
        | SnapshotObjectKind::NativePromptCommand
        | SnapshotObjectKind::PortableAgent
        | SnapshotObjectKind::NativeAgent
        | SnapshotObjectKind::PortableMcp
        | SnapshotObjectKind::NativeMcp) => VerifiedObjectEnvelope::document(
            descriptor.root().clone(),
            VerifiedDocumentObject::load(store, &path, kind, capture, descriptor.encoded_len())
                .map_err(map_store)?,
        )?,
    };
    if object.descriptor() != descriptor {
        return Err(object_mismatch());
    }
    Ok(object)
}

fn install_immutable_text(
    store: &ObjectStore,
    staging: &PortablePath,
    destination: &PortablePath,
    text: &str,
    limits: SyncLimits,
) -> Result<(), BackendError> {
    store
        .replace_text_atomically_guarded(
            staging,
            destination,
            None,
            text,
            usize_limit_snapshot(limits)?,
        )
        .map_err(map_store)
}

fn parse_head(text: &str, limits: SyncLimits) -> Result<Head, BackendError> {
    if text.len() as u64 > limits.max_control_bytes() {
        return Err(invalid_remote());
    }
    let head: Head = parse_canonical(text)?;
    if head.schema_version != 1 {
        return Err(invalid_remote());
    }
    Ok(head)
}

fn parse_canonical<T>(text: &str) -> Result<T, BackendError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_str(text).map_err(|_| invalid_remote())?;
    if canonical(&value)? != text {
        return Err(invalid_remote());
    }
    Ok(value)
}

fn canonical(value: &impl Serialize) -> Result<String, BackendError> {
    let mut text = serde_json::to_string_pretty(value).map_err(|_| invalid_remote())?;
    text.push('\n');
    Ok(text)
}

fn head_revision(text: &str) -> Result<RemoteRevision, BackendError> {
    RemoteRevision::parse(format!(
        "filesystem:head:blake3:{}",
        blake3::hash(text.as_bytes()).to_hex()
    ))
    .map_err(|_| invalid_remote())
}

fn head_path(head: &Head, text: &str) -> Result<PortablePath, BackendError> {
    let revision = head_revision(text)?;
    let hex = revision
        .as_str()
        .rsplit(':')
        .next()
        .ok_or_else(invalid_remote)?;
    portable(&format!(
        "{CONTROL_ROOT}/heads/{:020}-{hex}.json",
        head.generation
    ))
}

fn snapshot_path(digest: &SnapshotDigest) -> Result<PortablePath, BackendError> {
    let hex = digest
        .as_str()
        .rsplit(':')
        .next()
        .ok_or_else(invalid_remote)?;
    portable(&format!("{CONTROL_ROOT}/snapshots/{hex}.json"))
}

fn stage_prefix(id: &PublicationId) -> Result<PortablePath, BackendError> {
    let hex = id.as_str().rsplit(':').next().ok_or_else(intent_invalid)?;
    portable(&format!("{CONTROL_ROOT}/staging/{hex}"))
}

fn remote_object_path(descriptor: &ObjectDescriptor) -> Result<PortablePath, BackendError> {
    joined(&portable(CONTROL_ROOT)?, descriptor.root().as_str())
}

fn joined(prefix: &PortablePath, suffix: &str) -> Result<PortablePath, BackendError> {
    portable(&format!("{}/{suffix}", prefix.as_str()))
}

fn portable(value: &str) -> Result<PortablePath, BackendError> {
    PortablePath::parse(value.to_owned()).map_err(|_| invalid_remote())
}

fn absent_revision() -> RemoteRevision {
    RemoteRevision::parse(ABSENT_REVISION).expect("compiled absent revision is valid")
}

fn capture_limits(limits: SyncLimits) -> CaptureLimits {
    CaptureLimits {
        max_files: limits.max_components(),
        max_file_bytes: limits.max_object_bytes(),
        max_total_bytes: limits.max_object_bytes(),
    }
}

fn usize_limit(limits: SyncLimits) -> Result<usize, BackendError> {
    usize::try_from(limits.max_control_bytes()).map_err(|_| invalid_remote())
}

fn usize_limit_snapshot(limits: SyncLimits) -> Result<usize, BackendError> {
    usize::try_from(limits.max_snapshot_bytes()).map_err(|_| invalid_remote())
}

fn map_store(_: crate::ObjectMutationError) -> BackendError {
    BackendError::new(
        "sync_backend.filesystem_io",
        "filesystem backend operation failed safely",
    )
}
const fn invalid_remote() -> BackendError {
    BackendError::new(
        "sync_backend.invalid_remote",
        "filesystem remote authority is invalid",
    )
}
const fn stale() -> BackendError {
    BackendError::new(
        "sync_backend.remote_stale",
        "filesystem remote revision changed",
    )
}
const fn intent_invalid() -> BackendError {
    BackendError::new(
        "sync_backend.intent_invalid",
        "publication intent is invalid",
    )
}
const fn object_mismatch() -> BackendError {
    BackendError::new(
        "sync_backend.object_mismatch",
        "publication objects do not match snapshot",
    )
}
const fn generation_overflow() -> BackendError {
    BackendError::new(
        "sync_backend.generation_overflow",
        "backend generation cannot advance",
    )
}
const fn history_exceeded() -> BackendError {
    BackendError::new(
        "sync_backend.history_exceeded",
        "backend history exceeds the request limit",
    )
}

const fn control_budget_exceeded() -> BackendError {
    BackendError::new(
        "sync_backend.control_budget_exceeded",
        "backend control data exceeds the request limit",
    )
}

const fn snapshot_budget_exceeded() -> BackendError {
    BackendError::new(
        "sync_backend.snapshot_budget_exceeded",
        "backend snapshot history exceeds the request limit",
    )
}

const fn object_budget_exceeded() -> BackendError {
    BackendError::new(
        "sync_backend.object_budget_exceeded",
        "backend objects exceed the request limit",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{EnvironmentManifest, Profile, ProfileId, SchemaVersion};

    use super::*;

    fn empty_snapshot() -> PortableSnapshotV1 {
        PortableSnapshotV1::new(
            EnvironmentManifest {
                schema_version: SchemaVersion::V1,
                assets: BTreeMap::new(),
                packs: BTreeMap::new(),
                profiles: BTreeMap::new(),
                required_bindings: BTreeSet::new(),
            },
            BTreeSet::new(),
            SyncLimits::default(),
        )
        .unwrap()
    }

    fn publication(byte: char) -> PublicationId {
        PublicationId::parse(format!(
            "publication:blake3:{}",
            byte.to_string().repeat(64)
        ))
        .unwrap()
    }

    fn populated_snapshot() -> (PortableSnapshotV1, Vec<VerifiedObjectEnvelope>) {
        let (skill, _, _) = crate::adoption::tests::ready_plan();
        let extension = crate::native_extension_adoption::tests::ready_plan();
        let skill_asset = skill.asset();
        let portable = skill_asset.portable.as_ref().unwrap();
        let skill_native = skill_asset
            .native_variants
            .get(skill.origin_harness())
            .unwrap();
        let extension_native = &extension.asset().native_variants[&kitrove_model::HarnessId::Pi];
        let objects = vec![
            VerifiedObjectEnvelope::portable(
                portable.root.clone(),
                skill.portable_object().clone(),
            )
            .unwrap(),
            VerifiedObjectEnvelope::native(
                skill_native.root.clone(),
                skill.native_object().clone(),
            )
            .unwrap(),
            VerifiedObjectEnvelope::native_extension(
                extension_native.root.clone(),
                extension.native_object().clone(),
            )
            .unwrap(),
        ];
        let mut manifest = skill.proposed_manifest().clone();
        manifest
            .assets
            .insert(extension.asset().id.clone(), extension.asset().clone());
        manifest.refresh_pack_revisions().unwrap();
        let descriptors = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        (
            PortableSnapshotV1::new(manifest, descriptors, SyncLimits::default()).unwrap(),
            objects,
        )
    }

    fn constrained_limits(
        control_bytes: u64,
        object_count: usize,
        object_bytes: u64,
        total_object_bytes: u64,
        history: usize,
    ) -> SyncLimits {
        SyncLimits::new(
            16 * 1024 * 1024,
            control_bytes,
            4 * 1024 * 1024,
            4 * 1024 * 1024,
            object_count,
            object_bytes,
            total_object_bytes,
            128,
            4096,
            history,
        )
        .unwrap()
    }

    struct FilesystemContractFixture {
        backend: FilesystemSyncBackend,
        _root: tempfile::TempDir,
    }

    impl crate::sync_backend::tests::BackendContractFixture for FilesystemContractFixture {
        type Backend = FilesystemSyncBackend;

        fn backend(&self) -> &Self::Backend {
            &self.backend
        }

        fn assert_exact_fetch_and_immutable_rules(&self) {
            exact_object_fetch_reuse_and_conflicting_immutable_content_are_fail_closed();
        }

        fn assert_aba_and_selected_history_rules(&self) {
            later_same_snapshot_head_preserves_prior_publication_proof();
            valid_alternate_branch_excluding_the_intent_is_uncertain();
        }

        fn assert_publication_interruption_rules(&self) {
            every_publication_commit_checkpoint_reconciles_from_selected_authority_only();
        }

        fn assert_alias_and_hostile_filesystem_rules(&self) {
            lexical_root_aliases_share_one_remote_key();
            #[cfg(unix)]
            {
                link_aliased_remote_root_is_refused();
                hostile_control_symlink_is_refused_without_following_it();
                hostile_pointer_symlink_and_special_file_are_refused_without_disclosure();
            }
            #[cfg(windows)]
            windows_reparse_root_and_device_namespace_are_refused();
        }

        fn assert_aggregate_limit_rules(&self) {
            inspection_charges_the_complete_selected_head_chain_to_one_control_budget();
            inspection_refuses_before_following_history_beyond_the_head_budget();
            publication_refuses_count_and_aggregate_object_budget_exhaustion_before_staging();
        }

        fn assert_redaction_rules(&self) {
            inspection_of_absent_remote_is_mutation_free();
            #[cfg(unix)]
            hostile_pointer_symlink_and_special_file_are_refused_without_disclosure();
        }
    }

    #[test]
    fn inspection_of_absent_remote_is_mutation_free() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let backend = FilesystemSyncBackend::open(&canonical_root).unwrap();
        let observed = backend.inspect(SyncLimits::default()).unwrap();

        assert!(observed.snapshot().is_none());
        assert_eq!(observed.revision(), &absent_revision());
        assert!(!root.path().join(CONTROL_ROOT).exists());
        assert!(!format!("{backend:?}").contains(canonical_root.to_string_lossy().as_ref()));
    }

    #[test]
    fn satisfies_shared_backend_contract() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let backend = FilesystemSyncBackend::open(&canonical_root).unwrap();
        crate::sync_backend::tests::assert_backend_contract(&FilesystemContractFixture {
            backend,
            _root: root,
        });
    }

    #[test]
    fn initialized_read_session_holds_shared_lock_without_mutating_absent_remote() {
        let limits = SyncLimits::default();
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let backend = FilesystemSyncBackend::open(&canonical_root).unwrap();
        let read = backend.begin_read(limits).unwrap();
        assert!(!root.path().join(CONTROL_ROOT).exists());
        drop(read);

        let mut apply = backend.begin_apply(limits).unwrap();
        let snapshot = empty_snapshot();
        let intent = apply
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        apply.publish(&intent, &snapshot, &[], limits).unwrap();
        drop(apply);

        let read = backend.begin_read(limits).unwrap();
        assert!(backend.begin_apply(limits).is_err());
        drop(read);
        assert!(backend.begin_apply(limits).is_ok());
    }

    #[test]
    fn read_session_returns_complete_verified_snapshot_history_newest_first() {
        let limits = SyncLimits::default();
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let snapshot = empty_snapshot();
        let mut expected = absent_revision();
        for marker in ['a', 'b'] {
            let mut apply = backend.begin_apply(limits).unwrap();
            let intent = apply
                .prepare_publication(&expected, &publication(marker), &snapshot, &[], limits)
                .unwrap();
            let PublicationStatus::Published(revision) =
                apply.publish(&intent, &snapshot, &[], limits).unwrap()
            else {
                panic!("test publication must commit");
            };
            expected = revision;
        }

        let mut read = backend.begin_read(limits).unwrap();
        let history = read.inspect_history(limits).unwrap();
        assert_eq!(history.snapshots().len(), 2);
        assert_eq!(history.snapshots()[0].revision(), &expected);
        assert_eq!(
            history.snapshots()[0].snapshot().snapshot_digest(),
            snapshot.snapshot_digest()
        );
    }

    #[test]
    fn snapshot_history_uses_one_aggregate_byte_budget() {
        let limits = SyncLimits::default();
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let first = empty_snapshot();
        let mut manifest = first.manifest().clone();
        let profile_id = ProfileId::parse("workstation").unwrap();
        manifest.profiles.insert(
            profile_id.clone(),
            Profile {
                id: profile_id,
                extends: None,
                assets: BTreeSet::new(),
                targets: BTreeSet::new(),
            },
        );
        let second = PortableSnapshotV1::new(manifest, BTreeSet::new(), limits).unwrap();
        let mut expected = absent_revision();
        for (marker, snapshot) in [('a', &first), ('b', &second)] {
            let mut apply = backend.begin_apply(limits).unwrap();
            let intent = apply
                .prepare_publication(&expected, &publication(marker), snapshot, &[], limits)
                .unwrap();
            let PublicationStatus::Published(revision) =
                apply.publish(&intent, snapshot, &[], limits).unwrap()
            else {
                panic!("test publication must commit");
            };
            expected = revision;
        }
        let first_json = first.to_json(limits).unwrap();
        let second_json = second.to_json(limits).unwrap();
        let snapshot_bytes = (first_json.len() + second_json.len() - 1) as u64;
        let manifest_bytes = first
            .manifest_toml()
            .len()
            .max(second.manifest_toml().len()) as u64;
        let lock_bytes = first.lock_json().len().max(second.lock_json().len()) as u64;
        let constrained = SyncLimits::new(
            snapshot_bytes,
            limits.max_control_bytes(),
            manifest_bytes,
            lock_bytes,
            limits.max_object_count(),
            limits.max_object_bytes(),
            limits.max_total_object_bytes(),
            limits.max_conflicts(),
            limits.max_components(),
            2,
        )
        .unwrap();

        let error = backend
            .begin_read(constrained)
            .unwrap()
            .inspect_history(constrained)
            .unwrap_err();

        assert_eq!(error.code(), "sync_backend.snapshot_budget_exceeded");
    }

    #[test]
    fn snapshot_history_refuses_an_incomplete_immutable_object_catalog() {
        let limits = SyncLimits::default();
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let (snapshot, objects) = populated_snapshot();
        let mut apply = backend.begin_apply(limits).unwrap();
        let intent = apply
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();
        apply.publish(&intent, &snapshot, &objects, limits).unwrap();
        drop(apply);
        let missing = root.path().join(
            remote_object_path(objects[0].descriptor())
                .unwrap()
                .as_str(),
        );
        std::fs::rename(&missing, root.path().join("removed-test-object")).unwrap();

        let error = backend
            .begin_read(limits)
            .unwrap()
            .inspect_history(limits)
            .unwrap_err();

        assert_eq!(error.code(), "sync_backend.filesystem_io");
    }

    #[test]
    fn lexical_root_aliases_share_one_remote_key() {
        let root = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(root.path()).unwrap();
        let direct = FilesystemSyncBackend::open(&canonical).unwrap();
        let dotted = FilesystemSyncBackend::open(&canonical.join(".")).unwrap();

        assert_eq!(direct.remote_key(), dotted.remote_key());
    }

    #[cfg(unix)]
    #[test]
    fn link_aliased_remote_root_is_refused() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("REMOTE-ROOT-CANARY");
        let alias = parent.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();

        let error = FilesystemSyncBackend::open(&alias).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert_eq!(error.code(), "sync_backend.filesystem_io");
        assert!(!rendered.contains("REMOTE-ROOT-CANARY"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_root_and_device_namespace_are_refused() {
        use std::os::windows::fs::symlink_dir;

        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        let alias = parent.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        symlink_dir(&real, &alias).unwrap();

        assert!(FilesystemSyncBackend::open(&alias).is_err());
        assert!(FilesystemSyncBackend::open(Path::new(r"\\.\NUL")).is_err());
    }

    #[test]
    fn conditional_publication_round_trips_and_reconciles_positive_history() {
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();

        assert_eq!(
            session.publish(&intent, &snapshot, &[], limits).unwrap(),
            PublicationStatus::Published(intent.proposed_revision().clone())
        );
        assert_eq!(
            session.reconcile(&intent, limits).unwrap(),
            PublicationStatus::Published(intent.proposed_revision().clone())
        );
        drop(session);

        let observed = backend.inspect(limits).unwrap();
        assert_eq!(observed.revision(), intent.proposed_revision());
        assert_eq!(observed.snapshot(), Some(&snapshot));
    }

    #[test]
    fn later_same_snapshot_head_preserves_prior_publication_proof() {
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let first = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&first, &snapshot, &[], limits).unwrap();
        let second = session
            .prepare_publication(
                first.proposed_revision(),
                &publication('b'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&second, &snapshot, &[], limits).unwrap();

        assert_eq!(
            session.reconcile(&first, limits).unwrap(),
            PublicationStatus::Published(first.proposed_revision().clone())
        );
        assert_ne!(first.proposed_revision(), second.proposed_revision());
    }

    #[test]
    fn stale_intent_cannot_replace_the_selected_pointer() {
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let winner = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        let stale_intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('b'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&winner, &snapshot, &[], limits).unwrap();

        assert_eq!(
            session
                .publish(&stale_intent, &snapshot, &[], limits)
                .unwrap(),
            PublicationStatus::Uncertain
        );
        assert_eq!(
            session.inspect(limits).unwrap().revision(),
            winner.proposed_revision()
        );
    }

    #[test]
    fn every_publication_commit_checkpoint_reconciles_from_selected_authority_only() {
        let limits = SyncLimits::default();
        for target in [
            PublishCheckpoint::BeforeHeadInstall,
            PublishCheckpoint::AfterHeadInstall,
            PublishCheckpoint::BeforePointerReplace,
            PublishCheckpoint::AfterPointerReplace,
        ] {
            let root = tempfile::tempdir().unwrap();
            let backend =
                FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
            let snapshot = empty_snapshot();
            let mut session = backend.begin_apply(limits).unwrap();
            let intent = session
                .prepare_publication(
                    &absent_revision(),
                    &publication('d'),
                    &snapshot,
                    &[],
                    limits,
                )
                .unwrap();
            let error = session
                .publish_with_checkpoints(&intent, &snapshot, &[], limits, |checkpoint| {
                    if checkpoint == target {
                        Err(test_interrupted())
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert_eq!(error.code(), "sync_backend.test_interrupted");

            if target == PublishCheckpoint::AfterPointerReplace {
                assert_eq!(
                    session.reconcile(&intent, limits).unwrap(),
                    PublicationStatus::Published(intent.proposed_revision().clone())
                );
                assert_eq!(
                    session.inspect(limits).unwrap().revision(),
                    intent.proposed_revision()
                );
            } else {
                assert_eq!(
                    session.reconcile(&intent, limits).unwrap(),
                    PublicationStatus::Ready
                );
                assert_eq!(
                    session.publish(&intent, &snapshot, &[], limits).unwrap(),
                    PublicationStatus::Published(intent.proposed_revision().clone())
                );
            }
        }
    }

    #[test]
    fn valid_alternate_branch_excluding_the_intent_is_uncertain() {
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let excluded = session
            .prepare_publication(
                &absent_revision(),
                &publication('e'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        let selected = session
            .prepare_publication(
                &absent_revision(),
                &publication('f'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&selected, &snapshot, &[], limits).unwrap();

        assert_eq!(
            session.reconcile(&excluded, limits).unwrap(),
            PublicationStatus::Uncertain
        );
        assert_eq!(
            session.inspect(limits).unwrap().revision(),
            selected.proposed_revision()
        );
    }

    #[test]
    fn inspection_charges_the_complete_selected_head_chain_to_one_control_budget() {
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let first = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&first, &snapshot, &[], limits).unwrap();
        let second = session
            .prepare_publication(
                first.proposed_revision(),
                &publication('b'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        session.publish(&second, &snapshot, &[], limits).unwrap();
        drop(session);

        let control = root.path().join(CONTROL_ROOT);
        let mut lengths = vec![
            std::fs::metadata(control.join("current.json"))
                .unwrap()
                .len(),
        ];
        lengths.extend(
            std::fs::read_dir(control.join("heads"))
                .unwrap()
                .map(|entry| entry.unwrap().metadata().unwrap().len()),
        );
        let aggregate = lengths.iter().sum::<u64>();
        let largest = *lengths.iter().max().unwrap();
        assert!(aggregate > largest);
        let constrained = constrained_limits(aggregate - 1, 1, 1, 1, 8);
        let error = backend.inspect(constrained).unwrap_err();

        assert_eq!(error.code(), "sync_backend.control_budget_exceeded");
    }

    #[test]
    fn inspection_refuses_before_following_history_beyond_the_head_budget() {
        let limits = SyncLimits::default();
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let backend = FilesystemSyncBackend::open(&canonical_root).unwrap();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let first = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        let PublicationStatus::Published(first_revision) =
            session.publish(&first, &snapshot, &[], limits).unwrap()
        else {
            panic!("first publication must succeed");
        };
        let second = session
            .prepare_publication(&first_revision, &publication('b'), &snapshot, &[], limits)
            .unwrap();
        session.publish(&second, &snapshot, &[], limits).unwrap();
        drop(session);

        let limited = constrained_limits(
            limits.max_control_bytes(),
            limits.max_object_count(),
            limits.max_object_bytes(),
            limits.max_total_object_bytes(),
            1,
        );
        let error = backend.inspect(limited).unwrap_err();
        assert_eq!(error.code(), "sync_backend.history_exceeded");
    }

    #[test]
    fn publication_refuses_before_selecting_an_unreadable_history_generation() {
        let limits = constrained_limits(4 * 1024 * 1024, 1, 1, 1, 2);
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let backend = FilesystemSyncBackend::open(&canonical_root).unwrap();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let first = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();
        let PublicationStatus::Published(first_revision) =
            session.publish(&first, &snapshot, &[], limits).unwrap()
        else {
            panic!("first publication must succeed");
        };
        let second = session
            .prepare_publication(&first_revision, &publication('b'), &snapshot, &[], limits)
            .unwrap();
        let PublicationStatus::Published(second_revision) =
            session.publish(&second, &snapshot, &[], limits).unwrap()
        else {
            panic!("second publication must succeed");
        };

        let error = session
            .prepare_publication(&second_revision, &publication('c'), &snapshot, &[], limits)
            .unwrap_err();

        assert_eq!(error.code(), "sync_backend.history_exceeded");
        assert_eq!(
            session.inspect(limits).unwrap().revision(),
            &second_revision
        );
    }

    #[cfg(unix)]
    #[test]
    fn empty_publication_refuses_when_the_opened_remote_root_is_replaced() {
        let limits = SyncLimits::default();
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("remote");
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let backend = FilesystemSyncBackend::open(&root).unwrap();
        let snapshot = empty_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('e'),
                &snapshot,
                &[],
                limits,
            )
            .unwrap();

        let displaced = parent.path().join("displaced");
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let error = session
            .publish(&intent, &snapshot, &[], limits)
            .unwrap_err();

        assert_eq!(error.code(), "sync_backend.filesystem_io");
        assert!(!displaced.join(".kitrove-sync/current.json").exists());
        assert!(!root.join(".kitrove-sync/current.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn fetch_refuses_when_the_opened_remote_root_is_replaced() {
        let limits = SyncLimits::default();
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("remote");
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let backend = FilesystemSyncBackend::open(&root).unwrap();
        let (snapshot, objects) = populated_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('a'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();
        session
            .publish(&intent, &snapshot, &objects, limits)
            .unwrap();
        drop(session);

        let displaced = parent.path().join("displaced");
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("REPLACEMENT-ROOT-CANARY"), "do not read").unwrap();

        let error = backend
            .fetch_object(objects[0].descriptor(), limits)
            .unwrap_err();
        assert_eq!(error.code(), "sync_backend.filesystem_io");
        assert_eq!(
            std::fs::read_to_string(root.join("REPLACEMENT-ROOT-CANARY")).unwrap(),
            "do not read"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publication_refuses_replacement_root_with_exact_decoy_objects() {
        let limits = SyncLimits::default();
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("remote");
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let backend = FilesystemSyncBackend::open(&root).unwrap();
        let (snapshot, objects) = populated_snapshot();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('d'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();

        let displaced = parent.path().join("displaced");
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();
        let decoy = ObjectStore::open(&root).unwrap();
        let stage = stage_prefix(&publication('d')).unwrap();
        for object in &objects {
            let staging = joined(&stage, object.descriptor().root().as_str()).unwrap();
            let destination = remote_object_path(object.descriptor()).unwrap();
            match object {
                VerifiedObjectEnvelope::Portable { object, .. } => {
                    decoy
                        .stage_portable(&staging, object, capture_limits(limits))
                        .unwrap();
                    decoy
                        .stage_portable(&destination, object, capture_limits(limits))
                        .unwrap();
                }
                VerifiedObjectEnvelope::Native { object, .. } => {
                    decoy
                        .stage_native(&staging, object, capture_limits(limits))
                        .unwrap();
                    decoy
                        .stage_native(&destination, object, capture_limits(limits))
                        .unwrap();
                }
                VerifiedObjectEnvelope::NativeExtension { object, .. } => {
                    decoy
                        .stage_native_extension(&staging, object, capture_limits(limits))
                        .unwrap();
                    decoy
                        .stage_native_extension(&destination, object, capture_limits(limits))
                        .unwrap();
                }
                VerifiedObjectEnvelope::Document { object, .. } => {
                    object
                        .stage(&decoy, &staging, capture_limits(limits))
                        .unwrap();
                    object
                        .stage(&decoy, &destination, capture_limits(limits))
                        .unwrap();
                }
            }
        }
        let error = session
            .publish(&intent, &snapshot, &objects, limits)
            .unwrap_err();

        assert_eq!(error.code(), "sync_backend.filesystem_io");
        assert!(backend.inspect(limits).is_err());
        assert!(!displaced.join(".kitrove-sync/current.json").exists());
        assert!(!root.join(".kitrove-sync/current.json").exists());
    }

    #[test]
    fn publication_refuses_count_and_aggregate_object_budget_exhaustion_before_staging() {
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let (snapshot, objects) = populated_snapshot();
        let largest = objects
            .iter()
            .map(|object| object.descriptor().encoded_len())
            .max()
            .unwrap();
        let total = objects
            .iter()
            .map(|object| object.descriptor().encoded_len())
            .sum::<u64>();
        assert!(total > largest);

        for limits in [
            constrained_limits(4 * 1024 * 1024, 1, largest, total, 8),
            constrained_limits(4 * 1024 * 1024, objects.len(), largest, total - 1, 8),
        ] {
            let mut session = backend.begin_apply(limits).unwrap();
            let error = session
                .prepare_publication(
                    &absent_revision(),
                    &publication('c'),
                    &snapshot,
                    &objects,
                    limits,
                )
                .unwrap_err();
            assert_eq!(error.code(), "sync_backend.object_budget_exceeded");
            assert!(!root.path().join(CONTROL_ROOT).join("staging").exists());
        }
    }

    #[test]
    fn exact_object_fetch_reuse_and_conflicting_immutable_content_are_fail_closed() {
        let limits = SyncLimits::default();
        let (snapshot, objects) = populated_snapshot();

        let reusable_root = tempfile::tempdir().unwrap();
        let reusable =
            FilesystemSyncBackend::open(&std::fs::canonicalize(reusable_root.path()).unwrap())
                .unwrap();
        let mut session = reusable.begin_apply(limits).unwrap();
        let first = session
            .prepare_publication(
                &absent_revision(),
                &publication('1'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();
        session
            .publish(&first, &snapshot, &objects, limits)
            .unwrap();
        for object in &objects {
            assert_eq!(
                session.fetch_object(object.descriptor(), limits).unwrap(),
                *object
            );
        }
        let second = session
            .prepare_publication(
                first.proposed_revision(),
                &publication('2'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();
        assert_eq!(
            session
                .publish(&second, &snapshot, &objects, limits)
                .unwrap(),
            PublicationStatus::Published(second.proposed_revision().clone())
        );

        let conflicting_root = tempfile::tempdir().unwrap();
        let conflicting =
            FilesystemSyncBackend::open(&std::fs::canonicalize(conflicting_root.path()).unwrap())
                .unwrap();
        let destination = conflicting_root
            .path()
            .join(CONTROL_ROOT)
            .join(objects[0].descriptor().root().as_str());
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::write(
            destination.join("unexpected-canary"),
            "HOSTILE-OBJECT-CANARY",
        )
        .unwrap();
        let mut session = conflicting.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('3'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();
        let error = session
            .publish(&intent, &snapshot, &objects, limits)
            .unwrap_err();

        assert_eq!(error.code(), "sync_backend.filesystem_io");
        assert!(!error.to_string().contains("HOSTILE-OBJECT-CANARY"));
        assert!(session.inspect(limits).unwrap().snapshot().is_none());
        assert_eq!(
            std::fs::read_to_string(destination.join("unexpected-canary")).unwrap(),
            "HOSTILE-OBJECT-CANARY"
        );
    }

    #[test]
    fn fetch_refuses_a_stored_envelope_larger_than_its_declared_length() {
        let limits = SyncLimits::default();
        let (snapshot, objects) = populated_snapshot();
        let root = tempfile::tempdir().unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let mut session = backend.begin_apply(limits).unwrap();
        let intent = session
            .prepare_publication(
                &absent_revision(),
                &publication('4'),
                &snapshot,
                &objects,
                limits,
            )
            .unwrap();
        session
            .publish(&intent, &snapshot, &objects, limits)
            .unwrap();
        drop(session);

        let object = &objects[0];
        let (metadata_bytes, payload_bytes) = match object {
            VerifiedObjectEnvelope::Portable { object, .. } => (
                object.metadata_json().len() as u64,
                object
                    .tree()
                    .files
                    .values()
                    .map(|file| file.bytes.len() as u64)
                    .sum::<u64>(),
            ),
            VerifiedObjectEnvelope::Native { object, .. } => (
                object.metadata_json().len() as u64,
                object
                    .tree()
                    .files
                    .values()
                    .map(|file| file.bytes.len() as u64)
                    .sum::<u64>(),
            ),
            VerifiedObjectEnvelope::NativeExtension { object, .. } => (
                object.metadata_json().len() as u64,
                object
                    .tree()
                    .files
                    .values()
                    .map(|file| file.bytes.len() as u64)
                    .sum::<u64>(),
            ),
            VerifiedObjectEnvelope::Document { object, .. } => {
                (object.to_json().unwrap().len() as u64, 0)
            }
        };
        let stored_content_bytes = metadata_bytes + payload_bytes;
        assert!(stored_content_bytes > 1);
        let forged = ObjectDescriptor::new(
            object.descriptor().kind(),
            object.descriptor().root().clone(),
            object.descriptor().object_hash().clone(),
            stored_content_bytes - 1,
        )
        .unwrap();
        let fetch_limits = constrained_limits(
            limits.max_control_bytes(),
            1,
            forged.encoded_len(),
            forged.encoded_len(),
            limits.max_backend_history(),
        );

        let error = backend.fetch_object(&forged, fetch_limits).unwrap_err();

        assert_eq!(error.code(), "sync_backend.filesystem_io");
    }

    #[cfg(unix)]
    #[test]
    fn hostile_control_symlink_is_refused_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("current.json"), "HOSTILE-CANARY").unwrap();
        symlink(outside.path(), root.path().join(CONTROL_ROOT)).unwrap();
        let backend =
            FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
        let error = backend.inspect(SyncLimits::default()).unwrap_err();

        assert_eq!(error.code(), "sync_backend.filesystem_io");
        assert!(!error.to_string().contains("HOSTILE-CANARY"));
        assert_eq!(
            std::fs::read_to_string(outside.path().join("current.json")).unwrap(),
            "HOSTILE-CANARY"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hostile_pointer_symlink_and_special_file_are_refused_without_disclosure() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        for special in ["symlink", "socket"] {
            let root = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let control = root.path().join(CONTROL_ROOT);
            std::fs::create_dir(&control).unwrap();
            let pointer = control.join("current.json");
            let _listener = if special == "symlink" {
                let canary = outside.path().join("REMOTE-PATH-CANARY");
                std::fs::write(&canary, "REMOTE-CONTENT-CANARY").unwrap();
                symlink(&canary, &pointer).unwrap();
                None
            } else {
                Some(UnixListener::bind(&pointer).unwrap())
            };
            let backend =
                FilesystemSyncBackend::open(&std::fs::canonicalize(root.path()).unwrap()).unwrap();
            let error = backend.inspect(SyncLimits::default()).unwrap_err();
            let rendered = format!("{error:?} {error}");

            assert_eq!(error.code(), "sync_backend.filesystem_io");
            assert!(!rendered.contains("REMOTE-PATH-CANARY"));
            assert!(!rendered.contains("REMOTE-CONTENT-CANARY"));
        }
    }

    const fn test_interrupted() -> BackendError {
        BackendError::new(
            "sync_backend.test_interrupted",
            "backend test interrupted at a durable boundary",
        )
    }
}
