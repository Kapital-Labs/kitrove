use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{
    ContentHash, ObjectDescriptor, RemoteRevision, SyncConflict, SyncConflictCode, SyncLimits,
};

use crate::merge::validate_manifest_object_risk;
use crate::{
    PortableSnapshotV1, RemoteSnapshot, TierOneCapabilities, VerifiedSkillObjectCatalog,
    merge_manifests,
};

/// Relationship between the merged snapshot and the two observed sides.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncDisposition {
    Publish,
    Receive,
    Merge,
    EstablishBase,
    Unchanged,
}

/// Exact retained-base merge input loaded from one complete local generation.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncBaseInput {
    snapshot: PortableSnapshotV1,
    backend_revision: RemoteRevision,
}

impl SyncBaseInput {
    #[must_use]
    pub const fn new(snapshot: PortableSnapshotV1, backend_revision: RemoteRevision) -> Self {
        Self {
            snapshot,
            backend_revision,
        }
    }

    #[must_use]
    pub const fn snapshot(&self) -> &PortableSnapshotV1 {
        &self.snapshot
    }

    #[must_use]
    pub const fn backend_revision(&self) -> &RemoteRevision {
        &self.backend_revision
    }
}

impl Debug for SyncBaseInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncBaseInput")
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

/// Confirmable pure synchronization plan over exact snapshot preconditions.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncPlan {
    disposition: SyncDisposition,
    local: PortableSnapshotV1,
    base: Option<SyncBaseInput>,
    remote_revision: RemoteRevision,
    remote_snapshot: Option<PortableSnapshotV1>,
    merged: PortableSnapshotV1,
    upload: BTreeSet<ObjectDescriptor>,
    download: BTreeSet<ObjectDescriptor>,
    digest: ContentHash,
}

impl SyncPlan {
    #[must_use]
    pub const fn disposition(&self) -> SyncDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn local(&self) -> &PortableSnapshotV1 {
        &self.local
    }

    #[must_use]
    pub const fn base(&self) -> Option<&SyncBaseInput> {
        self.base.as_ref()
    }

    #[must_use]
    pub const fn remote_revision(&self) -> &RemoteRevision {
        &self.remote_revision
    }

    #[must_use]
    pub const fn remote_snapshot(&self) -> Option<&PortableSnapshotV1> {
        self.remote_snapshot.as_ref()
    }

    #[must_use]
    pub const fn merged(&self) -> &PortableSnapshotV1 {
        &self.merged
    }

    #[must_use]
    pub const fn upload(&self) -> &BTreeSet<ObjectDescriptor> {
        &self.upload
    }

    #[must_use]
    pub const fn download(&self) -> &BTreeSet<ObjectDescriptor> {
        &self.download
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for SyncPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncPlan")
            .field("disposition", &self.disposition)
            .field("local", &self.local.snapshot_digest())
            .field("base_present", &self.base.is_some())
            .field(
                "remote_present",
                &self.remote_snapshot.as_ref().map(|_| true).unwrap_or(false),
            )
            .field("merged", &self.merged.snapshot_digest())
            .field("upload", &self.upload.len())
            .field("download", &self.download.len())
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// Pure planning outcome; blocked outcomes carry no merged authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncPlanOutcome {
    Ready(Box<SyncPlan>),
    Blocked(Vec<SyncConflict>),
}

/// Stable content- and revision-redacted planning failure.
#[derive(Clone, Eq, PartialEq)]
pub struct SyncPlanningError {
    code: &'static str,
    message: &'static str,
}

impl SyncPlanningError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for SyncPlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncPlanningError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for SyncPlanningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for SyncPlanningError {}

/// Plans bootstrap or conservative three-way synchronization without mutation.
pub fn plan_sync(
    local: PortableSnapshotV1,
    base: Option<SyncBaseInput>,
    remote: RemoteSnapshot,
    catalog: &VerifiedSkillObjectCatalog,
    capabilities: &TierOneCapabilities,
    limits: SyncLimits,
) -> Result<SyncPlanOutcome, SyncPlanningError> {
    validate_manifest_object_risk(local.manifest(), catalog, limits).map_err(|_| invalid_plan())?;
    if let Some(base) = &base {
        validate_manifest_object_risk(base.snapshot().manifest(), catalog, limits)
            .map_err(|_| invalid_plan())?;
    }
    if let Some(snapshot) = remote.snapshot() {
        validate_manifest_object_risk(snapshot.manifest(), catalog, limits)
            .map_err(|_| invalid_plan())?;
    }
    let remote_revision = remote.revision().clone();
    let remote_snapshot = remote.snapshot().cloned();
    let (merged, disposition) = match (&base, &remote_snapshot) {
        (None, None) if manifest_empty(local.manifest()) => {
            return Err(planning_error(
                "sync.nothing_to_sync",
                "local and remote portable authority are both empty",
            ));
        }
        (None, None) => (local.clone(), SyncDisposition::Publish),
        (None, Some(remote)) if manifest_empty(local.manifest()) => {
            (remote.clone(), SyncDisposition::Receive)
        }
        (None, Some(remote)) if remote.snapshot_digest() == local.snapshot_digest() => {
            (local.clone(), SyncDisposition::EstablishBase)
        }
        (None, Some(_)) => {
            return Ok(SyncPlanOutcome::Blocked(vec![SyncConflict {
                code: SyncConflictCode::BootstrapAmbiguous,
                subject: kitrove_model::SyncConflictSubject::Bootstrap,
            }]));
        }
        (Some(_), None) => {
            return Err(planning_error(
                "sync.remote_history_missing",
                "a retained base requires present remote authority",
            ));
        }
        (Some(base), Some(remote)) => {
            if base.backend_revision() == &remote_revision
                && base.snapshot().snapshot_digest() != remote.snapshot_digest()
            {
                return Err(invalid_plan());
            }
            let result = merge_manifests(
                base.snapshot().manifest(),
                local.manifest(),
                remote.manifest(),
                catalog,
                capabilities,
                limits,
            )
            .map_err(|_| invalid_plan())?;
            if !result.conflicts().is_empty() {
                return Ok(SyncPlanOutcome::Blocked(result.conflicts().to_vec()));
            }
            let manifest = result.merged_manifest().cloned().ok_or_else(invalid_plan)?;
            let descriptors = merged_descriptors(&manifest, [&local, base.snapshot(), remote])?;
            let merged = PortableSnapshotV1::new(manifest, descriptors, limits)
                .map_err(|_| invalid_plan())?;
            let disposition = disposition(&local, remote, &merged);
            (merged, disposition)
        }
    };

    let remote_objects = remote_snapshot
        .as_ref()
        .map(PortableSnapshotV1::objects)
        .cloned()
        .unwrap_or_default();
    let upload = merged
        .objects()
        .difference(&remote_objects)
        .cloned()
        .collect();
    let download = merged
        .objects()
        .difference(local.objects())
        .cloned()
        .collect();
    let digest = plan_digest(
        disposition,
        &local,
        base.as_ref(),
        &remote_revision,
        remote_snapshot.as_ref(),
        &merged,
        &upload,
        &download,
        limits,
    )?;
    Ok(SyncPlanOutcome::Ready(Box::new(SyncPlan {
        disposition,
        local,
        base,
        remote_revision,
        remote_snapshot,
        merged,
        upload,
        download,
        digest,
    })))
}

fn disposition(
    local: &PortableSnapshotV1,
    remote: &PortableSnapshotV1,
    merged: &PortableSnapshotV1,
) -> SyncDisposition {
    let local_changed = local.snapshot_digest() != merged.snapshot_digest();
    let remote_changed = remote.snapshot_digest() != merged.snapshot_digest();
    match (local_changed, remote_changed) {
        (false, false) => SyncDisposition::Unchanged,
        (false, true) => SyncDisposition::Publish,
        (true, false) => SyncDisposition::Receive,
        (true, true) => SyncDisposition::Merge,
    }
}

fn merged_descriptors<'a>(
    manifest: &kitrove_model::EnvironmentManifest,
    snapshots: impl IntoIterator<Item = &'a PortableSnapshotV1>,
) -> Result<BTreeSet<ObjectDescriptor>, SyncPlanningError> {
    let mut available = BTreeMap::new();
    for snapshot in snapshots {
        for descriptor in snapshot.objects() {
            match available.insert(descriptor.root().clone(), descriptor.clone()) {
                Some(prior) if prior != *descriptor => return Err(invalid_plan()),
                _ => {}
            }
        }
    }
    let mut selected = BTreeSet::new();
    for asset in manifest.assets.values() {
        if let Some(portable) = &asset.portable {
            selected.insert(
                available
                    .get(&portable.root)
                    .filter(|value| value.object_hash() == &portable.object_hash)
                    .cloned()
                    .ok_or_else(invalid_plan)?,
            );
        }
        for native in asset.native_variants.values() {
            selected.insert(
                available
                    .get(&native.root)
                    .filter(|value| value.object_hash() == &native.object_hash)
                    .cloned()
                    .ok_or_else(invalid_plan)?,
            );
        }
    }
    Ok(selected)
}

#[allow(clippy::too_many_arguments)]
fn plan_digest(
    disposition: SyncDisposition,
    local: &PortableSnapshotV1,
    base: Option<&SyncBaseInput>,
    remote_revision: &RemoteRevision,
    remote: Option<&PortableSnapshotV1>,
    merged: &PortableSnapshotV1,
    upload: &BTreeSet<ObjectDescriptor>,
    download: &BTreeSet<ObjectDescriptor>,
    limits: SyncLimits,
) -> Result<ContentHash, SyncPlanningError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kitrove-sync-plan-v1\0");
    write(&mut hasher, disposition_tag(disposition));
    write(&mut hasher, b"local");
    write(
        &mut hasher,
        local
            .to_json(limits)
            .map_err(|_| invalid_plan())?
            .as_bytes(),
    );
    match base {
        Some(base) => {
            write(&mut hasher, b"base-present");
            write(
                &mut hasher,
                base.snapshot()
                    .to_json(limits)
                    .map_err(|_| invalid_plan())?
                    .as_bytes(),
            );
            write(&mut hasher, base.backend_revision().as_str().as_bytes());
        }
        None => write(&mut hasher, b"base-absent"),
    }
    write(&mut hasher, b"remote-revision");
    write(&mut hasher, remote_revision.as_str().as_bytes());
    match remote {
        Some(remote) => {
            write(&mut hasher, b"remote-present");
            write(
                &mut hasher,
                remote
                    .to_json(limits)
                    .map_err(|_| invalid_plan())?
                    .as_bytes(),
            );
        }
        None => write(&mut hasher, b"remote-absent"),
    }
    write(&mut hasher, b"merged");
    write(
        &mut hasher,
        merged
            .to_json(limits)
            .map_err(|_| invalid_plan())?
            .as_bytes(),
    );
    write(&mut hasher, b"upload");
    for descriptor in upload {
        write(
            &mut hasher,
            &serde_json::to_vec(descriptor).map_err(|_| invalid_plan())?,
        );
    }
    write(&mut hasher, b"download");
    for descriptor in download {
        write(
            &mut hasher,
            &serde_json::to_vec(descriptor).map_err(|_| invalid_plan())?,
        );
    }
    Ok(
        ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex()))
            .expect("BLAKE3 produces a valid content hash"),
    )
}

const fn disposition_tag(disposition: SyncDisposition) -> &'static [u8] {
    match disposition {
        SyncDisposition::Publish => b"publish",
        SyncDisposition::Receive => b"receive",
        SyncDisposition::Merge => b"merge",
        SyncDisposition::EstablishBase => b"establish-base",
        SyncDisposition::Unchanged => b"unchanged",
    }
}

fn write(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn manifest_empty(manifest: &kitrove_model::EnvironmentManifest) -> bool {
    manifest.assets.is_empty()
        && manifest.packs.is_empty()
        && manifest.profiles.is_empty()
        && manifest.required_bindings.is_empty()
}

const fn planning_error(code: &'static str, message: &'static str) -> SyncPlanningError {
    SyncPlanningError { code, message }
}

const fn invalid_plan() -> SyncPlanningError {
    planning_error(
        "sync.plan_invalid",
        "synchronization inputs cannot produce a valid bounded plan",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VerifiedObjectEnvelope;
    use crate::adoption::tests::{capabilities, empty_manifest};
    use kitrove_agent_skills::{CapturedFile, FileMode, StoredSkillTree, hash_tree};
    use kitrove_model::{ObjectDescriptor, SnapshotObjectKind};

    fn snapshot(manifest: kitrove_model::EnvironmentManifest) -> PortableSnapshotV1 {
        let mut descriptors = BTreeSet::new();
        for asset in manifest.assets.values() {
            if let Some(portable) = &asset.portable {
                descriptors.insert(
                    ObjectDescriptor::new(
                        SnapshotObjectKind::PortableSkillTree,
                        portable.root.clone(),
                        portable.object_hash.clone(),
                        1,
                    )
                    .unwrap(),
                );
            }
            for native in asset.native_variants.values() {
                descriptors.insert(
                    ObjectDescriptor::new(
                        SnapshotObjectKind::NativeSkillObject,
                        native.root.clone(),
                        native.object_hash.clone(),
                        1,
                    )
                    .unwrap(),
                );
            }
        }
        PortableSnapshotV1::new(manifest, descriptors, SyncLimits::default()).unwrap()
    }

    fn empty() -> PortableSnapshotV1 {
        snapshot(empty_manifest())
    }

    fn populated() -> PortableSnapshotV1 {
        let mut manifest = empty_manifest();
        manifest.required_bindings =
            BTreeSet::from([kitrove_model::BindingName::parse("review").unwrap()]);
        snapshot(manifest)
    }

    fn catalog() -> VerifiedSkillObjectCatalog {
        VerifiedSkillObjectCatalog::new([], []).unwrap()
    }

    #[test]
    fn bootstrap_publish_receive_and_base_establishment_are_exact() {
        let limits = SyncLimits::default();
        let populated = populated();
        let absent = RemoteRevision::parse("filesystem:absent:v1").unwrap();
        let published = plan_sync(
            populated.clone(),
            None,
            RemoteSnapshot::absent(absent),
            &catalog(),
            &capabilities(),
            limits,
        )
        .unwrap();
        let SyncPlanOutcome::Ready(published) = published else {
            panic!("non-empty local bootstrap must publish");
        };
        assert_eq!(published.disposition(), SyncDisposition::Publish);
        assert_eq!(published.upload(), populated.objects());

        let revision = RemoteRevision::parse("REMOTE-REVISION-CANARY").unwrap();
        let received = plan_sync(
            empty(),
            None,
            RemoteSnapshot::present(revision.clone(), populated.clone()),
            &catalog(),
            &capabilities(),
            limits,
        )
        .unwrap();
        let SyncPlanOutcome::Ready(received) = received else {
            panic!("empty local bootstrap must receive");
        };
        assert_eq!(received.disposition(), SyncDisposition::Receive);
        assert_eq!(received.download(), populated.objects());
        assert!(!format!("{received:?}").contains(revision.as_str()));

        let establish = plan_sync(
            populated.clone(),
            None,
            RemoteSnapshot::present(revision, populated),
            &catalog(),
            &capabilities(),
            limits,
        )
        .unwrap();
        let SyncPlanOutcome::Ready(establish) = establish else {
            panic!("identical bootstrap must establish a base");
        };
        assert_eq!(establish.disposition(), SyncDisposition::EstablishBase);
        assert!(establish.upload().is_empty());
        assert!(establish.download().is_empty());
    }

    #[test]
    fn ambiguous_bootstrap_and_missing_remote_history_never_create_a_plan() {
        let limits = SyncLimits::default();
        let populated = populated();
        let revision = RemoteRevision::parse("remote-1").unwrap();
        let ambiguous = plan_sync(
            populated.clone(),
            None,
            RemoteSnapshot::present(revision.clone(), empty()),
            &catalog(),
            &capabilities(),
            limits,
        )
        .unwrap();
        let SyncPlanOutcome::Blocked(conflicts) = ambiguous else {
            panic!("distinct bootstrap must block");
        };
        assert_eq!(conflicts[0].code, SyncConflictCode::BootstrapAmbiguous);

        let base = SyncBaseInput::new(populated.clone(), revision);
        let error = plan_sync(
            populated,
            Some(base),
            RemoteSnapshot::absent(RemoteRevision::parse("absent").unwrap()),
            &catalog(),
            &capabilities(),
            limits,
        )
        .unwrap_err();
        assert_eq!(error.code(), "sync.remote_history_missing");
    }

    #[test]
    fn empty_absent_bootstrap_is_a_nonmutating_refusal() {
        let error = plan_sync(
            empty(),
            None,
            RemoteSnapshot::absent(RemoteRevision::parse("absent").unwrap()),
            &catalog(),
            &capabilities(),
            SyncLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "sync.nothing_to_sync");
    }

    #[test]
    fn bootstrap_publish_and_receive_reject_credential_objects() {
        let limits = SyncLimits::default();
        let (adoption, _, _) = crate::adoption::tests::ready_plan();
        let mut tree = adoption.portable_object().tree().clone();
        tree.files.insert(
            kitrove_model::PortablePath::parse(".env").unwrap(),
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"SYNC-CREDENTIAL-CANARY".to_vec(),
            },
        );
        tree.hash = hash_tree(&tree.files);
        let hostile = StoredSkillTree::new(tree).unwrap();
        let mut manifest = adoption.proposed_manifest().clone();
        let asset = manifest.assets.get_mut(&adoption.asset().id).unwrap();
        asset.portable.as_mut().unwrap().object_hash = hostile.tree().hash.clone();
        asset.refresh_content_hash();
        let portable = VerifiedObjectEnvelope::portable(
            asset.portable.as_ref().unwrap().root.clone(),
            hostile.clone(),
        )
        .unwrap();
        let native_component = asset
            .native_variants
            .get(adoption.origin_harness())
            .unwrap();
        let native = VerifiedObjectEnvelope::native(
            native_component.root.clone(),
            adoption.native_object().clone(),
        )
        .unwrap();
        let descriptors = [portable.descriptor().clone(), native.descriptor().clone()]
            .into_iter()
            .collect();
        let hostile_snapshot = PortableSnapshotV1::new(manifest, descriptors, limits).unwrap();
        let catalog =
            VerifiedSkillObjectCatalog::new([hostile], [adoption.native_object().clone()]).unwrap();

        let publish_error = plan_sync(
            hostile_snapshot.clone(),
            None,
            RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
            &catalog,
            &capabilities(),
            limits,
        )
        .unwrap_err();
        assert_eq!(publish_error.code(), "sync.plan_invalid");
        assert!(!format!("{publish_error:?} {publish_error}").contains("SYNC-CREDENTIAL-CANARY"));

        let receive_error = plan_sync(
            empty(),
            None,
            RemoteSnapshot::present(
                RemoteRevision::parse("filesystem:credential-canary").unwrap(),
                hostile_snapshot,
            ),
            &catalog,
            &capabilities(),
            limits,
        )
        .unwrap_err();
        assert_eq!(receive_error.code(), "sync.plan_invalid");
        assert!(!format!("{receive_error:?} {receive_error}").contains("SYNC-CREDENTIAL-CANARY"));
    }
}
