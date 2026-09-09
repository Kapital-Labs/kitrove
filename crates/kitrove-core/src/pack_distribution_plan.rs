use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use kitrove_model::{
    AssetId, ContentHash, EnvironmentManifest, Lockfile, ObjectDescriptor, Revision,
};

use crate::pack_creation::affected_pack_revisions;
use crate::pack_distribution::{PackDistributionError, error};
use crate::pack_rollback_plan::{pack_closure, pack_graft_plan_digest, required_snapshot_objects};
use crate::{
    PackDistributionSelection, PackRevisionChange, derive_lockfile, derive_manifest_revision,
};

/// One selective, non-executing pack adoption from verified distribution authority.
#[derive(Clone, Eq, PartialEq)]
pub struct PackDistributionPlan {
    selection: PackDistributionSelection,
    affected_packs: BTreeMap<AssetId, PackRevisionChange>,
    required_objects: BTreeSet<ObjectDescriptor>,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl PackDistributionPlan {
    #[must_use]
    pub const fn selection(&self) -> &PackDistributionSelection {
        &self.selection
    }

    #[must_use]
    pub const fn affected_packs(&self) -> &BTreeMap<AssetId, PackRevisionChange> {
        &self.affected_packs
    }

    #[must_use]
    pub const fn required_objects(&self) -> &BTreeSet<ObjectDescriptor> {
        &self.required_objects
    }

    #[must_use]
    pub const fn proposed_manifest(&self) -> &EnvironmentManifest {
        &self.proposed_manifest
    }

    #[must_use]
    pub const fn proposed_lock(&self) -> &Lockfile {
        &self.proposed_lock
    }

    #[must_use]
    pub const fn base_manifest_revision(&self) -> &Revision {
        &self.base_manifest_revision
    }

    #[must_use]
    pub const fn proposed_manifest_revision(&self) -> &Revision {
        &self.proposed_manifest_revision
    }

    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

impl Debug for PackDistributionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackDistributionPlan")
            .field("affected_packs", &self.affected_packs.len())
            .field("required_objects", &self.required_objects.len())
            .finish_non_exhaustive()
    }
}

/// Plans an atomic import of one complete pack closure from verified head authority.
pub fn plan_pack_distribution_adoption(
    current: &EnvironmentManifest,
    selection: &PackDistributionSelection,
) -> Result<PackDistributionPlan, PackDistributionError> {
    current.validate().map_err(|_| manifest_invalid())?;
    let distributed = selection.snapshot().manifest();
    distributed.validate().map_err(|_| history_invalid())?;
    if current.assets.contains_key(selection.pack_id())
        || current.packs.contains_key(selection.pack_id())
    {
        return Err(identity_conflict());
    }
    let distributed_pack = distributed
        .packs
        .get(selection.pack_id())
        .ok_or_else(pack_missing)?;
    if &distributed_pack.content_hash != selection.target_revision() {
        return Err(history_invalid());
    }

    let closure = pack_closure(distributed, selection.pack_id()).map_err(map_rollback_error)?;
    let mut proposed = current.clone();
    for id in &closure {
        if let Some(asset) = distributed.assets.get(id) {
            if proposed.packs.contains_key(id)
                || proposed
                    .assets
                    .get(id)
                    .is_some_and(|existing| existing != asset)
            {
                return Err(identity_conflict());
            }
            proposed
                .required_bindings
                .extend(asset.required_bindings.iter().cloned());
            proposed.assets.insert(id.clone(), asset.clone());
        } else if let Some(pack) = distributed.packs.get(id) {
            if proposed.assets.contains_key(id)
                || proposed
                    .packs
                    .get(id)
                    .is_some_and(|existing| existing != pack)
            {
                return Err(identity_conflict());
            }
            proposed
                .required_bindings
                .extend(pack.required_bindings.iter().cloned());
            proposed.packs.insert(id.clone(), pack.clone());
        } else {
            return Err(history_invalid());
        }
    }
    proposed
        .refresh_pack_revisions()
        .map_err(|_| proposed_manifest_invalid())?;
    proposed
        .validate()
        .map_err(|_| proposed_manifest_invalid())?;
    for id in &closure {
        if distributed.assets.get(id) != proposed.assets.get(id)
            || distributed.packs.get(id) != proposed.packs.get(id)
        {
            return Err(proposed_manifest_invalid());
        }
    }

    let base_manifest_revision =
        derive_manifest_revision(current).map_err(|_| manifest_invalid())?;
    let proposed_lock = derive_lockfile(&proposed).map_err(|_| proposed_lock_invalid())?;
    let proposed_manifest_revision =
        derive_manifest_revision(&proposed).map_err(|_| proposed_manifest_invalid())?;
    let required_objects =
        required_snapshot_objects(selection.snapshot(), &closure).map_err(map_rollback_error)?;
    let affected_packs = affected_pack_revisions(current, &proposed);
    let digest = plan_digest(
        selection,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
        &required_objects,
        &affected_packs,
    )?;
    Ok(PackDistributionPlan {
        selection: selection.clone(),
        affected_packs,
        required_objects,
        proposed_manifest: proposed,
        proposed_lock,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })
}

fn plan_digest(
    selection: &PackDistributionSelection,
    base: &Revision,
    proposed: &Revision,
    lock: &Lockfile,
    objects: &BTreeSet<ObjectDescriptor>,
    affected: &BTreeMap<AssetId, PackRevisionChange>,
) -> Result<ContentHash, PackDistributionError> {
    pack_graft_plan_digest(
        b"kitrove-pack-distribution-plan-v1\0",
        selection.digest(),
        base,
        proposed,
        lock,
        objects,
        affected,
    )
    .map_err(|_| plan_invalid())
}

fn map_rollback_error(_: crate::PackRollbackError) -> PackDistributionError {
    history_invalid()
}

const fn history_invalid() -> PackDistributionError {
    error(
        "pack_adopt.history_invalid",
        "pack adoption requires one complete verified distribution snapshot",
    )
}

const fn pack_missing() -> PackDistributionError {
    error(
        "pack_adopt.pack_missing",
        "the selected pack is absent from current distribution authority",
    )
}

const fn identity_conflict() -> PackDistributionError {
    error(
        "pack_adopt.identity_conflict",
        "the distribution conflicts with existing portable identity",
    )
}

const fn manifest_invalid() -> PackDistributionError {
    error(
        "pack_adopt.manifest_invalid",
        "pack adoption requires valid current portable authority",
    )
}

const fn proposed_manifest_invalid() -> PackDistributionError {
    error(
        "pack_adopt.proposed_manifest_invalid",
        "the distributed pack cannot form valid proposed portable authority",
    )
}

const fn proposed_lock_invalid() -> PackDistributionError {
    error(
        "pack_adopt.proposed_lock_invalid",
        "the distributed pack cannot form a valid generated lock",
    )
}

const fn plan_invalid() -> PackDistributionError {
    error(
        "pack_adopt.plan_invalid",
        "the distributed pack cannot form deterministic adoption authority",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kitrove_model::{RemoteRevision, SchemaVersion, SyncLimits};

    use super::*;
    use crate::{PortableSnapshotV1, VerifiedRemoteHistory, select_pack_distribution};

    fn empty_manifest() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    #[test]
    fn imports_only_the_selected_complete_closure_and_refuses_identity_collision() {
        let distributed = crate::pack_creation::tests::manifest();
        let pack_id = AssetId::parse("left").unwrap();
        let snapshot = Arc::new(
            PortableSnapshotV1::new(distributed.clone(), BTreeSet::new(), SyncLimits::default())
                .unwrap(),
        );
        let history = VerifiedRemoteHistory::new(
            vec![(RemoteRevision::parse("test:head").unwrap(), snapshot)],
            SyncLimits::default(),
        )
        .unwrap();
        let selection = select_pack_distribution(&history, &pack_id).unwrap();

        let plan = plan_pack_distribution_adoption(&empty_manifest(), &selection).unwrap();

        assert!(plan.proposed_manifest().packs.contains_key(&pack_id));
        assert!(
            plan.proposed_manifest()
                .assets
                .contains_key(&AssetId::parse("alpha").unwrap())
        );
        assert!(
            !plan
                .proposed_manifest()
                .packs
                .contains_key(&AssetId::parse("right").unwrap())
        );
        assert!(
            !plan
                .proposed_manifest()
                .assets
                .contains_key(&AssetId::parse("beta").unwrap())
        );
        assert!(plan.required_objects().is_empty());
        assert_eq!(
            plan_pack_distribution_adoption(plan.proposed_manifest(), &selection)
                .unwrap_err()
                .code(),
            "pack_adopt.identity_conflict"
        );
    }
}
