//! Selective, one-time import from an already verified distribution head.
use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    AssetId, ContentHash, EnvironmentManifest, Lockfile, ObjectDescriptor, Revision,
};

use crate::pack_distribution::{PackDistributionError, error};
use crate::pack_rollback_plan::{pack_closure, pack_graft_plan_digest, required_snapshot_objects};
use crate::{VerifiedRemoteHistory, derive_lockfile, derive_manifest_revision};

/// Immutable authority for a collision-refusing graft. No local trust is imported.
#[derive(Clone)]
pub struct CollectionImportPlan {
    pub(crate) required_objects: BTreeSet<ObjectDescriptor>,
    pub(crate) proposed_manifest: EnvironmentManifest,
    pub(crate) proposed_lock: Lockfile,
    pub(crate) base_manifest_revision: Revision,
    pub(crate) proposed_manifest_revision: Revision,
    pub(crate) digest: ContentHash,
}

impl std::fmt::Debug for CollectionImportPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CollectionImportPlan")
            .field("objects", &self.required_objects.len())
            .finish_non_exhaustive()
    }
}

impl CollectionImportPlan {
    #[must_use]
    pub fn required_objects(&self) -> &BTreeSet<ObjectDescriptor> {
        &self.required_objects
    }
    #[must_use]
    pub const fn proposed_manifest(&self) -> &EnvironmentManifest {
        &self.proposed_manifest
    }
    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

/// Selects assets and complete pack closures, excluding all unrelated remote records.
/// Differing local identities refuse the entire plan before any mutation.
pub fn plan_collection_import(
    current: &EnvironmentManifest,
    history: &VerifiedRemoteHistory,
    selected: &BTreeSet<AssetId>,
) -> Result<CollectionImportPlan, PackDistributionError> {
    let invalid = || {
        error(
            "collection.import_invalid",
            "collection import requires valid bounded authority and a nonempty exact selection",
        )
    };
    current.validate().map_err(|_| invalid())?;
    if selected.is_empty() {
        return Err(invalid());
    }
    let head = history.snapshots().first().ok_or_else(invalid)?;
    let snapshot = head.snapshot();
    let remote = snapshot.manifest();
    remote.validate().map_err(|_| invalid())?;
    let mut closure = BTreeSet::new();
    for id in selected {
        if remote.assets.contains_key(id) {
            closure.insert(id.clone());
        } else if remote.packs.contains_key(id) {
            closure.extend(pack_closure(remote, id).map_err(|_| invalid())?);
        } else {
            return Err(invalid());
        }
    }
    let conflict = || {
        error(
            "collection.identity_conflict",
            "a selected item differs from an existing local identity; nothing was imported",
        )
    };
    let mut proposed = current.clone();
    for id in &closure {
        if let Some(asset) = remote.assets.get(id) {
            if proposed.packs.contains_key(id)
                || proposed.assets.get(id).is_some_and(|old| old != asset)
            {
                return Err(conflict());
            }
            proposed
                .required_bindings
                .extend(asset.required_bindings.iter().cloned());
            proposed.assets.insert(id.clone(), asset.clone());
        } else if let Some(pack) = remote.packs.get(id) {
            if proposed.assets.contains_key(id)
                || proposed.packs.get(id).is_some_and(|old| old != pack)
            {
                return Err(conflict());
            }
            proposed
                .required_bindings
                .extend(pack.required_bindings.iter().cloned());
            proposed.packs.insert(id.clone(), pack.clone());
        } else {
            return Err(invalid());
        }
    }
    proposed.refresh_pack_revisions().map_err(|_| invalid())?;
    proposed.validate().map_err(|_| invalid())?;
    for id in &closure {
        if remote.assets.get(id) != proposed.assets.get(id)
            || remote.packs.get(id) != proposed.packs.get(id)
        {
            return Err(invalid());
        }
    }
    let base_manifest_revision = derive_manifest_revision(current).map_err(|_| invalid())?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed).map_err(|_| invalid())?;
    let proposed_lock = derive_lockfile(&proposed).map_err(|_| invalid())?;
    let required_objects = required_snapshot_objects(snapshot, &closure).map_err(|_| invalid())?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"kitrove-collection-selection-v1\0");
    for value in std::iter::once(head.revision().as_str())
        .chain(std::iter::once(snapshot.snapshot_digest().as_str()))
        .chain(selected.iter().map(AssetId::as_str))
    {
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    let selection =
        ContentHash::parse(format!("blake3:{}", hash.finalize())).map_err(|_| invalid())?;
    let digest = pack_graft_plan_digest(
        b"kitrove-collection-import-plan-v1\0",
        &selection,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
        &required_objects,
        &BTreeMap::new(),
    )
    .map_err(|_| invalid())?;
    Ok(CollectionImportPlan {
        required_objects,
        proposed_manifest: proposed,
        proposed_lock,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PortableSnapshotV1;
    use kitrove_model::{RemoteRevision, SchemaVersion, SyncLimits};
    use std::sync::Arc;

    fn empty() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    fn history(revision: &str) -> VerifiedRemoteHistory {
        VerifiedRemoteHistory::new(
            vec![(
                RemoteRevision::parse(revision).unwrap(),
                Arc::new(
                    PortableSnapshotV1::new(
                        crate::pack_creation::tests::manifest(),
                        BTreeSet::new(),
                        SyncLimits::default(),
                    )
                    .unwrap(),
                ),
            )],
            SyncLimits::default(),
        )
        .unwrap()
    }

    fn selection(names: &[&str]) -> BTreeSet<AssetId> {
        names
            .iter()
            .map(|name| AssetId::parse(*name).unwrap())
            .collect()
    }

    #[test]
    fn selects_one_asset_or_complete_pack_without_unrelated_items() {
        let remote = history("test:head");
        let single = plan_collection_import(&empty(), &remote, &selection(&["alpha"])).unwrap();
        assert_eq!(single.proposed_manifest.assets.len(), 1);
        assert!(single.proposed_manifest.packs.is_empty());
        let pack = plan_collection_import(&empty(), &remote, &selection(&["left"])).unwrap();
        assert_eq!(
            pack.proposed_manifest.assets,
            single.proposed_manifest.assets
        );
        assert_eq!(pack.proposed_manifest.packs.len(), 1);
        assert_ne!(single.digest, pack.digest);
        // Identical local items can be retained, unlike differing collisions.
        let again =
            plan_collection_import(&single.proposed_manifest, &remote, &selection(&["alpha"]))
                .unwrap();
        assert_eq!(again.proposed_manifest, single.proposed_manifest);
        let combined =
            plan_collection_import(&single.proposed_manifest, &remote, &selection(&["beta"]))
                .unwrap();
        assert_eq!(combined.proposed_manifest.assets.len(), 2);
        assert_eq!(
            combined.proposed_manifest.assets[&AssetId::parse("alpha").unwrap()],
            single.proposed_manifest.assets[&AssetId::parse("alpha").unwrap()]
        );
    }

    #[test]
    fn rejects_unknown_empty_or_conflicting_selection_and_binds_remote_revision() {
        let remote = history("test:head");
        for names in [vec![], vec!["missing"]] {
            assert!(plan_collection_import(&empty(), &remote, &selection(&names)).is_err());
        }
        let plan = plan_collection_import(&empty(), &remote, &selection(&["alpha"])).unwrap();
        let changed_revision =
            plan_collection_import(&empty(), &history("test:other"), &selection(&["alpha"]))
                .unwrap();
        assert_ne!(plan.digest, changed_revision.digest);
        let mut local = plan.proposed_manifest;
        let alpha = local
            .assets
            .get_mut(&AssetId::parse("alpha").unwrap())
            .unwrap();
        alpha.kind = kitrove_model::AssetKind::Command;
        alpha.refresh_content_hash();
        let before = local.clone();
        assert_eq!(
            plan_collection_import(&local, &remote, &selection(&["alpha"]))
                .unwrap_err()
                .code(),
            "collection.identity_conflict"
        );
        assert_eq!(local, before);
    }

    #[test]
    fn commit_requires_exact_objects_and_fresh_local_authority() {
        use crate::{VerifiedObjectEnvelope, commit_collection_import};
        use kitrove_agent_skills::CaptureLimits;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let current = empty();
        // Match initialized control-file ownership, including an elevated Windows
        // test runner whose ambient file creator may otherwise select another owner.
        let store = crate::ObjectStore::open(&root).unwrap();
        for (path, contents) in [
            ("kitrove.toml", current.to_toml().unwrap()),
            (
                "kitrove.lock.json",
                derive_lockfile(&current).unwrap().to_json().unwrap(),
            ),
        ] {
            store
                .stage_text(
                    &kitrove_model::PortablePath::parse(path).unwrap(),
                    &contents,
                    1 << 20,
                )
                .unwrap();
        }
        // Later writes deliberately change only fixture contents, retaining the
        // initialized ownership while exercising stale-manifest refusal.
        let write_controls = |manifest: &EnvironmentManifest| {
            std::fs::write(root.join("kitrove.toml"), manifest.to_toml().unwrap()).unwrap();
            std::fs::write(
                root.join("kitrove.lock.json"),
                derive_lockfile(manifest).unwrap().to_json().unwrap(),
            )
            .unwrap();
        };
        let (adoption, _, _) = crate::adoption::tests::ready_plan();
        let asset = adoption.asset().clone();
        let objects = vec![
            VerifiedObjectEnvelope::portable(
                asset.portable.as_ref().unwrap().root.clone(),
                adoption.portable_object().clone(),
            )
            .unwrap(),
            VerifiedObjectEnvelope::native(
                asset.native_variants[adoption.origin_harness()]
                    .root
                    .clone(),
                adoption.native_object().clone(),
            )
            .unwrap(),
        ];
        let mut remote = empty();
        remote.assets.insert(asset.id.clone(), asset.clone());
        let limits = SyncLimits::default();
        let history = VerifiedRemoteHistory::new(
            vec![(
                RemoteRevision::parse("test:verified-import").unwrap(),
                Arc::new(
                    PortableSnapshotV1::new(
                        remote,
                        objects.iter().map(|o| o.descriptor().clone()).collect(),
                        limits,
                    )
                    .unwrap(),
                ),
            )],
            limits,
        )
        .unwrap();
        let plan = plan_collection_import(&current, &history, &BTreeSet::from([asset.id])).unwrap();
        assert!(commit_collection_import(&plan, &[], &root, CaptureLimits::default()).is_err());
        let duplicate = vec![objects[0].clone(), objects[1].clone(), objects[0].clone()];
        assert!(
            commit_collection_import(&plan, &duplicate, &root, CaptureLimits::default()).is_err()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("kitrove.toml")).unwrap(),
            current.to_toml().unwrap()
        );
        let changed = crate::pack_creation::tests::manifest();
        write_controls(&changed);
        assert!(
            commit_collection_import(&plan, &objects, &root, CaptureLimits::default()).is_err()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("kitrove.toml")).unwrap(),
            changed.to_toml().unwrap()
        );
        write_controls(&current);
        commit_collection_import(&plan, &objects, &root, CaptureLimits::default()).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("kitrove.toml")).unwrap(),
            plan.proposed_manifest().to_toml().unwrap()
        );
    }
}
