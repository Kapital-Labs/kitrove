use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::path::Path;

use kitrove_agent_skills::{CaptureLimits, CapturedFile, CapturedTree, FileMode, hash_tree};
use kitrove_model::{
    ContentHash, EnvironmentManifest, PortablePath, RemoteKey, RemoteRevision, SyncBasePointer,
    SyncBaseRecord, SyncLimits,
};

use crate::guarded_control::{self, GuardedControlError};
use crate::object_mutation::guarded_backup_path;
use crate::sync_backend::VerifiedDocumentObject;
use crate::{ObjectStore, PortableSnapshotV1, SyncBaseInput, VerifiedObjectEnvelope};

/// One complete verified immutable retained-base generation.
#[derive(Clone, Eq, PartialEq)]
pub struct RetainedSyncBase {
    generation: ContentHash,
    input: SyncBaseInput,
    objects: Vec<VerifiedObjectEnvelope>,
}

impl RetainedSyncBase {
    #[must_use]
    pub const fn generation(&self) -> &ContentHash {
        &self.generation
    }

    #[must_use]
    pub const fn input(&self) -> &SyncBaseInput {
        &self.input
    }

    #[must_use]
    pub fn objects(&self) -> &[VerifiedObjectEnvelope] {
        &self.objects
    }

    /// Consumes the retained generation without cloning immutable payloads.
    #[must_use]
    pub fn into_parts(self) -> (SyncBaseInput, Vec<VerifiedObjectEnvelope>) {
        (self.input, self.objects)
    }
}

impl Debug for RetainedSyncBase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedSyncBase")
            .field("generation", &self.generation)
            .field("objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

/// Capability-scoped local retained-base storage.
pub struct SyncBaseStore {
    store: ObjectStore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaseCheckpoint {
    BeforePointerReplace,
    AfterPointerReplace,
}

impl SyncBaseStore {
    /// Opens an existing machine-local state root without mutation.
    pub fn open(root: &Path) -> Result<Self, SyncBaseStoreError> {
        Ok(Self {
            store: ObjectStore::open_private_state(root).map_err(map_store)?,
        })
    }

    /// Derives retained-base authority from an already-open private mutation capability.
    pub(crate) fn from_private_state_store(
        store: &ObjectStore,
    ) -> Result<Self, SyncBaseStoreError> {
        Ok(Self {
            store: store
                .try_clone_private_state_for_mutation()
                .map_err(map_store)?,
        })
    }

    /// Opens or creates the state root as part of an authorized apply.
    pub fn open_or_create(root: &Path) -> Result<Self, SyncBaseStoreError> {
        Ok(Self {
            store: ObjectStore::open_or_create_private_state(root).map_err(map_store)?,
        })
    }

    /// Inspects and fully verifies the selected generation, if any.
    pub fn inspect(
        &self,
        remote_key: &RemoteKey,
        limits: SyncLimits,
    ) -> Result<Option<RetainedSyncBase>, SyncBaseStoreError> {
        let pointer_path = pointer_path(remote_key)?;
        let Some(pointer_text) = self
            .store
            .read_text(&pointer_path, control_limit(limits)?)
            .map_err(map_store)?
        else {
            return Ok(None);
        };
        let pointer = SyncBasePointer::from_json(&pointer_text, limits).map_err(|_| invalid())?;
        if pointer.remote_key() != remote_key {
            return Err(invalid());
        }
        self.inspect_generation(remote_key, pointer.generation(), limits)
            .map(Some)
    }

    /// Reports whether a selected base pointer exists without loading its object payloads.
    pub fn has_selected_base(
        &self,
        remote_key: &RemoteKey,
        limits: SyncLimits,
    ) -> Result<bool, SyncBaseStoreError> {
        let pointer_path = pointer_path(remote_key)?;
        let Some(pointer_text) = self
            .store
            .read_text(&pointer_path, control_limit(limits)?)
            .map_err(map_store)?
        else {
            return Ok(false);
        };
        let pointer = SyncBasePointer::from_json(&pointer_text, limits).map_err(|_| invalid())?;
        if pointer.remote_key() != remote_key {
            return Err(invalid());
        }
        Ok(true)
    }

    /// Installs a complete immutable generation and then replaces its single selector.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &self,
        remote_key: &RemoteKey,
        expected_prior: Option<&ContentHash>,
        snapshot: &PortableSnapshotV1,
        backend_revision: &RemoteRevision,
        objects: &[VerifiedObjectEnvelope],
        plan_digest: &ContentHash,
        limits: SyncLimits,
    ) -> Result<RetainedSyncBase, SyncBaseStoreError> {
        self.commit_with_checkpoints(
            remote_key,
            expected_prior,
            snapshot,
            backend_revision,
            objects,
            plan_digest,
            limits,
            |_| Ok(()),
        )
    }

    pub(crate) fn reconcile_interrupted_pointer(
        &self,
        remote_key: &RemoteKey,
        expected_prior: Option<&ContentHash>,
        proposed: &ContentHash,
        plan_digest: &ContentHash,
        limits: SyncLimits,
    ) -> Result<(), SyncBaseStoreError> {
        let staging = pointer_stage_path(remote_key, plan_digest)?;
        let backup = guarded_backup_path(&staging).map_err(map_store)?;
        let max_bytes = control_limit(limits)?;
        let staged_text = self
            .store
            .read_text(&staging, max_bytes)
            .map_err(map_store)?;
        let backup_text = self
            .store
            .read_text(&backup, max_bytes)
            .map_err(map_store)?;
        if staged_text.is_none() && backup_text.is_none() {
            return Ok(());
        }
        let old_text = expected_prior
            .map(|generation| pointer_text(remote_key, generation))
            .transpose()?;
        let new_text = pointer_text(remote_key, proposed)?;
        let destination = pointer_path(remote_key)?;
        let destination_text = self
            .store
            .read_text(&destination, max_bytes)
            .map_err(map_store)?;
        let known_backup_shape = (destination_text.is_none()
            && staged_text.as_deref() == Some(new_text.as_str()))
            || (destination_text.as_deref() == Some(new_text.as_str()) && staged_text.is_none());
        if backup_text.is_some() && !known_backup_shape {
            return Err(stale());
        }
        let displaced_old = backup_text.is_none()
            && destination_text.as_deref() == Some(new_text.as_str())
            && staged_text.as_deref() == old_text.as_deref();
        guarded_control::reconcile_accepting_duplicate_new(
            &self.store,
            &staging,
            &destination,
            old_text
                .as_deref()
                .map(|text| ContentHash::digest(text.as_bytes()))
                .as_ref(),
            &ContentHash::digest(new_text.as_bytes()),
            max_bytes,
            stale,
        )
        .map_err(|error| match error {
            GuardedControlError::Storage(error) => map_store(error),
            GuardedControlError::Authority(error) => error,
        })?;
        if displaced_old {
            self.store
                .remove_regular_file_if_present(&staging)
                .map_err(map_store)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_with_checkpoints(
        &self,
        remote_key: &RemoteKey,
        expected_prior: Option<&ContentHash>,
        snapshot: &PortableSnapshotV1,
        backend_revision: &RemoteRevision,
        objects: &[VerifiedObjectEnvelope],
        plan_digest: &ContentHash,
        limits: SyncLimits,
        mut checkpoint: impl FnMut(BaseCheckpoint) -> Result<(), SyncBaseStoreError>,
    ) -> Result<RetainedSyncBase, SyncBaseStoreError> {
        let current = self.inspect(remote_key, limits)?;
        if current.as_ref().map(RetainedSyncBase::generation) != expected_prior {
            return Err(stale());
        }
        let record = SyncBaseRecord::new(
            remote_key.clone(),
            snapshot.snapshot_digest().clone(),
            snapshot.manifest_revision().clone(),
            backend_revision.clone(),
            snapshot.objects().clone(),
            limits,
        )
        .map_err(|_| invalid())?;
        let record_text = record.to_json(limits).map_err(|_| invalid())?;
        let generation = SyncBaseRecord::generation_id_for_json(&record_text);
        let supplied: BTreeSet<_> = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        if supplied != *snapshot.objects() || supplied.len() != objects.len() {
            return Err(invalid());
        }

        if self
            .inspect_generation(remote_key, &generation, limits)
            .is_err()
        {
            let stage = staging_path(remote_key, plan_digest)?;
            for object in objects {
                let path = joined(&stage, object.descriptor().root().as_str())?;
                match object {
                    VerifiedObjectEnvelope::Portable { object, .. } => self
                        .store
                        .stage_portable(&path, object, capture_limits(limits))
                        .map_err(map_store)
                        .map(|_| ())?,
                    VerifiedObjectEnvelope::Native { object, .. } => self
                        .store
                        .stage_native(&path, object, capture_limits(limits))
                        .map_err(map_store)
                        .map(|_| ())?,
                    VerifiedObjectEnvelope::NativeExtension { object, .. } => self
                        .store
                        .stage_native_extension(&path, object, capture_limits(limits))
                        .map_err(map_store)
                        .map(|_| ())?,
                    VerifiedObjectEnvelope::Document { object, .. } => object
                        .stage(&self.store, &path, capture_limits(limits))
                        .map_err(map_store)?,
                };
            }
            self.store
                .stage_text(
                    &joined(&stage, "base.json")?,
                    &record_text,
                    control_limit(limits)?,
                )
                .map_err(map_store)?;
            self.store
                .stage_text(
                    &joined(&stage, "base-manifest.toml")?,
                    snapshot.manifest_toml(),
                    manifest_limit(limits)?,
                )
                .map_err(map_store)?;
            verify_generation_tree(&self.store, &stage, &record_text, snapshot, objects, limits)?;
            let destination = generation_path(remote_key, &generation)?;
            self.store
                .install_directory_noreplace(&stage, &destination)
                .map_err(map_store)?;
        }
        let retained = self.inspect_generation(remote_key, &generation, limits)?;
        let new_pointer_text = pointer_text(remote_key, &generation)?;
        let expected_text = current
            .as_ref()
            .map(|value| pointer_text(remote_key, value.generation()))
            .transpose()?;
        checkpoint(BaseCheckpoint::BeforePointerReplace)?;
        self.store
            .replace_text_atomically_guarded(
                &pointer_stage_path(remote_key, plan_digest)?,
                &pointer_path(remote_key)?,
                expected_text.as_deref(),
                &new_pointer_text,
                control_limit(limits)?,
            )
            .map_err(|_| stale())?;
        checkpoint(BaseCheckpoint::AfterPointerReplace)?;
        Ok(retained)
    }

    fn inspect_generation(
        &self,
        remote_key: &RemoteKey,
        generation: &ContentHash,
        limits: SyncLimits,
    ) -> Result<RetainedSyncBase, SyncBaseStoreError> {
        let root = generation_path(remote_key, generation)?;
        let record_text = self
            .store
            .read_text(&joined(&root, "base.json")?, control_limit(limits)?)
            .map_err(map_store)?
            .ok_or_else(invalid)?;
        if SyncBaseRecord::generation_id_for_json(&record_text) != *generation {
            return Err(invalid());
        }
        let record = SyncBaseRecord::from_json(&record_text, limits).map_err(budget_or_invalid)?;
        if record.remote_key() != remote_key {
            return Err(invalid());
        }
        let manifest_text = self
            .store
            .read_text(
                &joined(&root, "base-manifest.toml")?,
                manifest_limit(limits)?,
            )
            .map_err(map_store)?
            .ok_or_else(invalid)?;
        let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| invalid())?;
        if manifest.to_toml().map_err(|_| invalid())? != manifest_text {
            return Err(invalid());
        }
        let snapshot = PortableSnapshotV1::new(manifest, record.objects().clone(), limits)
            .map_err(|_| invalid())?;
        if snapshot.snapshot_digest() != record.snapshot_digest()
            || snapshot.manifest_revision() != record.manifest_revision()
        {
            return Err(invalid());
        }
        let mut objects = Vec::new();
        for descriptor in record.objects() {
            let path = joined(&root, descriptor.root().as_str())?;
            let object = match descriptor.kind() {
                kitrove_model::SnapshotObjectKind::PortableSkillTree => {
                    VerifiedObjectEnvelope::portable(
                        descriptor.root().clone(),
                        self.store
                            .load_portable_bounded(
                                &path,
                                capture_limits(limits),
                                descriptor.encoded_len(),
                            )
                            .map_err(map_store)?,
                    )
                }
                kitrove_model::SnapshotObjectKind::NativeSkillObject => {
                    VerifiedObjectEnvelope::native(
                        descriptor.root().clone(),
                        self.store
                            .load_native_bounded(
                                &path,
                                capture_limits(limits),
                                descriptor.encoded_len(),
                            )
                            .map_err(map_store)?,
                    )
                }
                kitrove_model::SnapshotObjectKind::NativeExtensionObject => {
                    VerifiedObjectEnvelope::native_extension(
                        descriptor.root().clone(),
                        self.store
                            .load_native_extension_bounded(
                                &path,
                                capture_limits(limits),
                                descriptor.encoded_len(),
                            )
                            .map_err(map_store)?,
                    )
                }
                kind @ (kitrove_model::SnapshotObjectKind::PortableInstruction
                | kitrove_model::SnapshotObjectKind::NativeInstruction
                | kitrove_model::SnapshotObjectKind::PortablePromptCommand
                | kitrove_model::SnapshotObjectKind::NativePromptCommand
                | kitrove_model::SnapshotObjectKind::PortableAgent
                | kitrove_model::SnapshotObjectKind::NativeAgent
                | kitrove_model::SnapshotObjectKind::PortableMcp
                | kitrove_model::SnapshotObjectKind::NativeMcp) => {
                    VerifiedObjectEnvelope::document(
                        descriptor.root().clone(),
                        VerifiedDocumentObject::load(
                            &self.store,
                            &path,
                            kind,
                            capture_limits(limits),
                            descriptor.encoded_len(),
                        )
                        .map_err(map_store)?,
                    )
                }
            }
            .map_err(|_| invalid())?;
            if object.descriptor() != descriptor {
                return Err(invalid());
            }
            objects.push(object);
        }
        verify_generation_tree(
            &self.store,
            &root,
            &record_text,
            &snapshot,
            &objects,
            limits,
        )?;
        Ok(RetainedSyncBase {
            generation: generation.clone(),
            input: SyncBaseInput::new(snapshot, record.backend_revision().clone()),
            objects,
        })
    }
}

impl Debug for SyncBaseStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncBaseStore")
            .field("root", &"[redacted]")
            .finish()
    }
}

fn pointer_text(
    remote_key: &RemoteKey,
    generation: &ContentHash,
) -> Result<String, SyncBaseStoreError> {
    SyncBasePointer::new(remote_key.clone(), generation.clone())
        .to_json()
        .map_err(|_| invalid())
}

/// Stable redacted retained-base failure.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncBaseStoreError {
    code: &'static str,
    message: &'static str,
}

impl SyncBaseStoreError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl Debug for SyncBaseStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncBaseStoreError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for SyncBaseStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SyncBaseStoreError {}

fn verify_generation_tree(
    store: &ObjectStore,
    root: &PortablePath,
    record: &str,
    snapshot: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
    limits: SyncLimits,
) -> Result<(), SyncBaseStoreError> {
    let expected = expected_tree(record, snapshot, objects)?;
    let actual = store
        .capture_directory(root, generation_capture_limits(limits))
        .map_err(map_store)?;
    if actual != expected {
        return Err(invalid());
    }
    Ok(())
}

fn expected_tree(
    record: &str,
    snapshot: &PortableSnapshotV1,
    objects: &[VerifiedObjectEnvelope],
) -> Result<CapturedTree, SyncBaseStoreError> {
    let mut files = BTreeMap::from([
        (
            PortablePath::parse("base.json").expect("fixed path"),
            regular(record.as_bytes().to_vec()),
        ),
        (
            PortablePath::parse("base-manifest.toml").expect("fixed path"),
            regular(snapshot.manifest_toml().as_bytes().to_vec()),
        ),
    ]);
    let empty_tree = CapturedTree {
        hash: hash_tree(&BTreeMap::new()),
        files: BTreeMap::new(),
    };
    for envelope in objects {
        let (metadata, tree) = match envelope {
            VerifiedObjectEnvelope::Portable { object, .. } => {
                (object.metadata_json(), object.tree())
            }
            VerifiedObjectEnvelope::Native { object, .. } => {
                (object.metadata_json(), object.tree())
            }
            VerifiedObjectEnvelope::NativeExtension { object, .. } => {
                (object.metadata_json(), object.tree())
            }
            VerifiedObjectEnvelope::Document { object, .. } => {
                (object.to_json().map_err(|_| invalid())?, &empty_tree)
            }
        };
        let prefix = envelope.descriptor().root().as_str();
        insert_file(
            &mut files,
            &format!("{prefix}/metadata.json"),
            regular(metadata.into_bytes()),
        )?;
        for (path, file) in &tree.files {
            insert_file(
                &mut files,
                &format!("{prefix}/payload/{}", path.as_str()),
                regular(file.bytes.clone()),
            )?;
        }
    }
    Ok(CapturedTree {
        hash: hash_tree(&files),
        files,
    })
}

fn insert_file(
    files: &mut BTreeMap<PortablePath, CapturedFile>,
    path: &str,
    file: CapturedFile,
) -> Result<(), SyncBaseStoreError> {
    if files
        .insert(PortablePath::parse(path).map_err(|_| invalid())?, file)
        .is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

fn regular(bytes: Vec<u8>) -> CapturedFile {
    CapturedFile {
        mode: FileMode::Regular,
        bytes,
    }
}

fn budget_or_invalid(error: kitrove_model::ValidationError) -> SyncBaseStoreError {
    if matches!(
        error.code(),
        "sync_objects.count_exceeded"
            | "sync_objects.object_bytes_exceeded"
            | "sync_objects.total_bytes_exceeded"
    ) {
        return SyncBaseStoreError {
            code: "sync_base.object_budget_exceeded",
            message: "the selected retained base exceeds the remaining request object budget",
        };
    }
    invalid()
}

fn remote_hex(remote: &RemoteKey) -> Result<&str, SyncBaseStoreError> {
    remote.as_str().rsplit(':').next().ok_or_else(invalid)
}
fn hash_hex(hash: &ContentHash) -> Result<&str, SyncBaseStoreError> {
    hash.as_str().rsplit(':').next().ok_or_else(invalid)
}
fn pointer_path(remote: &RemoteKey) -> Result<PortablePath, SyncBaseStoreError> {
    PortablePath::parse(format!("sync/{}/base-current.json", remote_hex(remote)?))
        .map_err(|_| invalid())
}
fn generation_path(
    remote: &RemoteKey,
    generation: &ContentHash,
) -> Result<PortablePath, SyncBaseStoreError> {
    PortablePath::parse(format!(
        "sync/{}/bases/{}",
        remote_hex(remote)?,
        hash_hex(generation)?
    ))
    .map_err(|_| invalid())
}
fn staging_path(
    remote: &RemoteKey,
    plan: &ContentHash,
) -> Result<PortablePath, SyncBaseStoreError> {
    PortablePath::parse(format!(
        "sync/{}/staging/{}/base",
        remote_hex(remote)?,
        hash_hex(plan)?
    ))
    .map_err(|_| invalid())
}
fn pointer_stage_path(
    remote: &RemoteKey,
    plan: &ContentHash,
) -> Result<PortablePath, SyncBaseStoreError> {
    PortablePath::parse(format!(
        "sync/{}/staging/{}/base-current.json",
        remote_hex(remote)?,
        hash_hex(plan)?
    ))
    .map_err(|_| invalid())
}
fn joined(root: &PortablePath, suffix: &str) -> Result<PortablePath, SyncBaseStoreError> {
    PortablePath::parse(format!("{}/{suffix}", root.as_str())).map_err(|_| invalid())
}
fn capture_limits(limits: SyncLimits) -> CaptureLimits {
    CaptureLimits {
        max_files: limits.max_components(),
        max_file_bytes: limits.max_object_bytes(),
        max_total_bytes: limits.max_object_bytes(),
    }
}
fn generation_capture_limits(limits: SyncLimits) -> CaptureLimits {
    CaptureLimits {
        max_files: limits
            .max_components()
            .saturating_add(limits.max_object_count())
            .saturating_add(2),
        max_file_bytes: limits
            .max_object_bytes()
            .max(limits.max_control_bytes())
            .max(limits.max_manifest_bytes()),
        max_total_bytes: limits
            .max_total_object_bytes()
            .saturating_add(limits.max_control_bytes())
            .saturating_add(limits.max_manifest_bytes()),
    }
}
fn control_limit(limits: SyncLimits) -> Result<usize, SyncBaseStoreError> {
    usize::try_from(limits.max_control_bytes()).map_err(|_| invalid())
}
fn manifest_limit(limits: SyncLimits) -> Result<usize, SyncBaseStoreError> {
    usize::try_from(limits.max_manifest_bytes()).map_err(|_| invalid())
}
fn map_store(_: crate::ObjectMutationError) -> SyncBaseStoreError {
    invalid()
}
const fn invalid() -> SyncBaseStoreError {
    SyncBaseStoreError {
        code: "sync.base_invalid",
        message: "retained synchronization base is invalid",
    }
}
const fn stale() -> SyncBaseStoreError {
    SyncBaseStoreError {
        code: "sync.base_stale",
        message: "retained synchronization base changed",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{EnvironmentManifest, SchemaVersion};

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

    fn remote() -> RemoteKey {
        RemoteKey::parse(format!("remote:blake3:{}", "a".repeat(64))).unwrap()
    }

    fn plan(byte: char) -> ContentHash {
        ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn absent_private_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap().join("state");
        (temporary, root)
    }

    #[test]
    fn inspection_store_refuses_commit_while_mutation_store_can_commit() {
        let (_temporary, root) = absent_private_root();
        drop(SyncBaseStore::open_or_create(&root).unwrap());
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();

        let inspection = SyncBaseStore::open(&root).unwrap();
        let error = inspection
            .commit(
                &remote(),
                None,
                &snapshot,
                &RemoteRevision::parse("revision-1").unwrap(),
                &[],
                &plan('b'),
                limits,
            )
            .unwrap_err();
        assert_eq!(error.code(), "sync.base_invalid");
        assert!(!root.join("sync").exists());

        let private_store = ObjectStore::open_private_state_for_mutation(&root).unwrap();
        SyncBaseStore::from_private_state_store(&private_store)
            .unwrap()
            .commit(
                &remote(),
                None,
                &snapshot,
                &RemoteRevision::parse("revision-1").unwrap(),
                &[],
                &plan('b'),
                limits,
            )
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn derived_mutation_store_does_not_follow_a_replaced_root_name() {
        let temporary = tempfile::tempdir().unwrap();
        let temporary_root = std::fs::canonicalize(temporary.path()).unwrap();
        let root = temporary_root.join("state");
        std::fs::create_dir(&root).unwrap();
        let private_store = ObjectStore::open_or_create_private_state(&root).unwrap();
        let displaced = temporary_root.join("displaced-state");
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let bases = SyncBaseStore::from_private_state_store(&private_store).unwrap();
        let error = bases
            .commit(
                &remote(),
                None,
                &empty_snapshot(),
                &RemoteRevision::parse("revision-1").unwrap(),
                &[],
                &plan('b'),
                SyncLimits::default(),
            )
            .unwrap_err();

        assert_eq!(error.code(), "sync.base_invalid");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&displaced).unwrap().count(), 0);
    }

    #[test]
    fn immutable_generations_distinguish_repeated_snapshot_revisions() {
        let (_temporary, root) = absent_private_root();
        let store = SyncBaseStore::open_or_create(&root).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        assert!(store.inspect(&remote(), limits).unwrap().is_none());

        let first = store
            .commit(
                &remote(),
                None,
                &snapshot,
                &RemoteRevision::parse("revision-1").unwrap(),
                &[],
                &plan('b'),
                limits,
            )
            .unwrap();
        let second = store
            .commit(
                &remote(),
                Some(first.generation()),
                &snapshot,
                &RemoteRevision::parse("revision-2").unwrap(),
                &[],
                &plan('c'),
                limits,
            )
            .unwrap();

        assert_ne!(first.generation(), second.generation());
        assert_eq!(store.inspect(&remote(), limits).unwrap().unwrap(), second);
        assert!(
            root.join(
                generation_path(&remote(), first.generation())
                    .unwrap()
                    .as_str()
            )
            .is_dir()
        );
        assert!(
            root.join(
                generation_path(&remote(), second.generation())
                    .unwrap()
                    .as_str()
            )
            .is_dir()
        );
    }

    #[test]
    fn base_pointer_replacement_is_recoverable_on_both_sides() {
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        for target in [
            BaseCheckpoint::BeforePointerReplace,
            BaseCheckpoint::AfterPointerReplace,
        ] {
            let (_temporary, root) = absent_private_root();
            let store = SyncBaseStore::open_or_create(&root).unwrap();
            let first = store
                .commit(
                    &remote(),
                    None,
                    &snapshot,
                    &RemoteRevision::parse("revision-1").unwrap(),
                    &[],
                    &plan('b'),
                    limits,
                )
                .unwrap();
            let error = store
                .commit_with_checkpoints(
                    &remote(),
                    Some(first.generation()),
                    &snapshot,
                    &RemoteRevision::parse("revision-2").unwrap(),
                    &[],
                    &plan('c'),
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
            assert_eq!(error.code(), "sync.base_test_interrupted");

            let selected = store.inspect(&remote(), limits).unwrap().unwrap();
            let second = if target == BaseCheckpoint::BeforePointerReplace {
                assert_eq!(selected.generation(), first.generation());
                store
                    .commit(
                        &remote(),
                        Some(first.generation()),
                        &snapshot,
                        &RemoteRevision::parse("revision-2").unwrap(),
                        &[],
                        &plan('c'),
                        limits,
                    )
                    .unwrap()
            } else {
                assert_eq!(
                    selected.input().backend_revision(),
                    &RemoteRevision::parse("revision-2").unwrap()
                );
                selected
            };
            assert_ne!(first.generation(), second.generation());
            assert!(
                root.join(
                    generation_path(&remote(), first.generation())
                        .unwrap()
                        .as_str()
                )
                .is_dir()
            );
        }
    }

    #[test]
    fn stale_pointer_and_extra_generation_bytes_fail_closed() {
        let (_temporary, root) = absent_private_root();
        let store = SyncBaseStore::open_or_create(&root).unwrap();
        let limits = SyncLimits::default();
        let snapshot = empty_snapshot();
        let retained = store
            .commit(
                &remote(),
                None,
                &snapshot,
                &RemoteRevision::parse("revision-1").unwrap(),
                &[],
                &plan('b'),
                limits,
            )
            .unwrap();
        let stale_generation = ContentHash::parse(format!("blake3:{}", "d".repeat(64))).unwrap();
        assert_eq!(
            store
                .commit(
                    &remote(),
                    Some(&stale_generation),
                    &snapshot,
                    &RemoteRevision::parse("revision-2").unwrap(),
                    &[],
                    &plan('c'),
                    limits,
                )
                .unwrap_err()
                .code(),
            "sync.base_stale"
        );

        let generation = generation_path(&remote(), retained.generation()).unwrap();
        std::fs::write(root.join(generation.as_str()).join("unexpected"), b"canary").unwrap();
        let error = store.inspect(&remote(), limits).unwrap_err();
        assert_eq!(error.code(), "sync.base_invalid");
        assert!(!error.to_string().contains("canary"));
    }

    #[test]
    fn retained_object_metadata_cannot_exceed_its_declared_envelope_allowance() {
        let (_temporary, root) = absent_private_root();
        let store = SyncBaseStore::open_or_create(&root).unwrap();
        let limits = SyncLimits::default();
        let (snapshot, objects) = populated_snapshot();
        let retained = store
            .commit(
                &remote(),
                None,
                &snapshot,
                &RemoteRevision::parse("revision-1").unwrap(),
                &objects,
                &plan('e'),
                limits,
            )
            .unwrap();
        let descriptor = objects[0].descriptor();
        let generation = generation_path(&remote(), retained.generation()).unwrap();
        let metadata = root
            .join(generation.as_str())
            .join(descriptor.root().as_str())
            .join("metadata.json");
        std::fs::write(
            metadata,
            vec![b'x'; usize::try_from(descriptor.encoded_len() + 1).unwrap()],
        )
        .unwrap();

        let error = store.inspect(&remote(), limits).unwrap_err();

        assert_eq!(error.code(), "sync.base_invalid");
    }

    #[test]
    fn base_pointer_reconciles_every_guarded_replacement_window() {
        #[derive(Clone, Copy, Debug)]
        enum Window {
            FallbackBeforeDestination,
            FallbackWithDestination,
            AtomicExchange,
        }

        for window in [
            Window::FallbackBeforeDestination,
            Window::FallbackWithDestination,
            Window::AtomicExchange,
        ] {
            let (_temporary, root) = absent_private_root();
            let store = SyncBaseStore::open_or_create(&root).unwrap();
            let limits = SyncLimits::default();
            let prior = ContentHash::digest(b"prior-base-generation");
            let proposed = ContentHash::digest(b"proposed-base-generation");
            let plan = plan('f');
            let destination = pointer_path(&remote()).unwrap();
            let staging = pointer_stage_path(&remote(), &plan).unwrap();
            let backup = guarded_backup_path(&staging).unwrap();
            let old_text = pointer_text(&remote(), &prior).unwrap();
            let new_text = pointer_text(&remote(), &proposed).unwrap();
            store
                .store
                .stage_text(&destination, &old_text, control_limit(limits).unwrap())
                .unwrap();
            store
                .store
                .stage_text(&staging, &new_text, control_limit(limits).unwrap())
                .unwrap();
            match window {
                Window::FallbackBeforeDestination => {
                    std::fs::rename(root.join(destination.as_str()), root.join(backup.as_str()))
                        .unwrap();
                }
                Window::FallbackWithDestination => {
                    std::fs::rename(root.join(destination.as_str()), root.join(backup.as_str()))
                        .unwrap();
                    std::fs::rename(root.join(staging.as_str()), root.join(destination.as_str()))
                        .unwrap();
                }
                Window::AtomicExchange => {
                    std::fs::write(root.join(destination.as_str()), &new_text).unwrap();
                    std::fs::write(root.join(staging.as_str()), &old_text).unwrap();
                }
            }

            store
                .reconcile_interrupted_pointer(&remote(), Some(&prior), &proposed, &plan, limits)
                .unwrap();

            let expected = match window {
                Window::FallbackBeforeDestination => &old_text,
                Window::FallbackWithDestination | Window::AtomicExchange => &new_text,
            };
            assert_eq!(
                store
                    .store
                    .read_text(&destination, control_limit(limits).unwrap())
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
            assert!(!root.join(backup.as_str()).exists());
            if matches!(window, Window::FallbackBeforeDestination) {
                assert_eq!(
                    store
                        .store
                        .read_text(&staging, control_limit(limits).unwrap())
                        .unwrap()
                        .as_deref(),
                    Some(new_text.as_str())
                );
            } else {
                assert!(!root.join(staging.as_str()).exists(), "{window:?}");
            }
        }
    }

    const fn test_interrupted() -> SyncBaseStoreError {
        SyncBaseStoreError {
            code: "sync.base_test_interrupted",
            message: "base test interrupted at a durable boundary",
        }
    }
}
