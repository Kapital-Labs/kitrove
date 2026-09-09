use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

use kitrove_model::{
    AssetId, ContentClass, ContentHash, EnvironmentManifest, Lockfile, ObjectDescriptor, Revision,
    SnapshotObjectKind,
};

use crate::pack_creation::affected_pack_revisions;
use crate::{
    PackRevisionChange, PackRollbackError, PackRollbackSelection, PortableSnapshotV1,
    derive_lockfile, derive_manifest_revision,
};

/// A selective exact-history pack rollback proposal over current portable authority.
#[derive(Clone, Eq, PartialEq)]
pub struct PackRollbackPlan {
    selection: PackRollbackSelection,
    affected_packs: BTreeMap<AssetId, PackRevisionChange>,
    required_objects: BTreeSet<ObjectDescriptor>,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl PackRollbackPlan {
    #[must_use]
    pub const fn selection(&self) -> &PackRollbackSelection {
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

    pub fn ensure_manifest_fresh(
        &self,
        manifest: &EnvironmentManifest,
    ) -> Result<(), PackRollbackError> {
        if derive_manifest_revision(manifest).ok().as_ref() == Some(&self.base_manifest_revision) {
            Ok(())
        } else {
            Err(manifest_stale())
        }
    }
}

impl Debug for PackRollbackPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackRollbackPlan")
            .field("affected_packs", &self.affected_packs.len())
            .field("required_objects", &self.required_objects.len())
            .finish_non_exhaustive()
    }
}

/// Grafts one selected historical pack closure into current authority without restoring unrelated
/// historical records.
pub fn plan_pack_rollback(
    current: &EnvironmentManifest,
    selection: &PackRollbackSelection,
) -> Result<PackRollbackPlan, PackRollbackError> {
    current.validate().map_err(|_| manifest_invalid())?;
    let historical = selection.snapshot().manifest();
    historical.validate().map_err(|_| history_invalid())?;
    let current_pack = current
        .packs
        .get(selection.pack_id())
        .ok_or_else(pack_missing)?;
    if &current_pack.content_hash != selection.current_revision() {
        return Err(expected_current_mismatch());
    }
    let historical_pack = historical
        .packs
        .get(selection.pack_id())
        .ok_or_else(target_missing)?;
    if &historical_pack.content_hash != selection.target_revision() {
        return Err(target_missing());
    }

    let current_closure = pack_closure(current, selection.pack_id())?;
    let historical_closure = pack_closure(historical, selection.pack_id())?;
    let mut proposed = current.clone();
    for id in &historical_closure {
        if let Some(historical_asset) = historical.assets.get(id) {
            if current.packs.contains_key(id)
                || (!current_closure.contains(id)
                    && current
                        .assets
                        .get(id)
                        .is_some_and(|asset| asset != historical_asset))
            {
                return Err(identity_collision());
            }
            if current.assets.get(id) != Some(historical_asset)
                && historical_asset.content_class == ContentClass::Executable
            {
                return Err(executable_transition());
            }
            proposed
                .required_bindings
                .extend(historical_asset.required_bindings.iter().cloned());
            proposed.assets.insert(id.clone(), historical_asset.clone());
        } else if let Some(historical_pack) = historical.packs.get(id) {
            if current.assets.contains_key(id)
                || (!current_closure.contains(id)
                    && current
                        .packs
                        .get(id)
                        .is_some_and(|pack| pack != historical_pack))
            {
                return Err(identity_collision());
            }
            if current.packs.get(id) != Some(historical_pack)
                && historical_pack.content_class == ContentClass::Executable
            {
                return Err(executable_transition());
            }
            proposed
                .required_bindings
                .extend(historical_pack.required_bindings.iter().cloned());
            proposed.packs.insert(id.clone(), historical_pack.clone());
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
    for id in &historical_closure {
        if historical.assets.get(id) != proposed.assets.get(id)
            || historical.packs.get(id) != proposed.packs.get(id)
        {
            return Err(proposed_manifest_invalid());
        }
    }
    if proposed
        .packs
        .get(selection.pack_id())
        .is_none_or(|pack| &pack.content_hash != selection.target_revision())
    {
        return Err(proposed_manifest_invalid());
    }

    let base_manifest_revision =
        derive_manifest_revision(current).map_err(|_| manifest_invalid())?;
    let proposed_lock = derive_lockfile(&proposed).map_err(|_| proposed_lock_invalid())?;
    let proposed_manifest_revision =
        derive_manifest_revision(&proposed).map_err(|_| proposed_manifest_invalid())?;
    let required_objects = required_snapshot_objects(selection.snapshot(), &historical_closure)?;
    let affected_packs = affected_pack_revisions(current, &proposed);
    let digest = rollback_plan_digest(
        selection,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
        &required_objects,
        &affected_packs,
    )?;
    Ok(PackRollbackPlan {
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

pub(crate) fn pack_closure(
    manifest: &EnvironmentManifest,
    pack_id: &AssetId,
) -> Result<BTreeSet<AssetId>, PackRollbackError> {
    let components = crate::pack_inspection::resolve_pack_components(
        manifest,
        &BTreeSet::from([pack_id.clone()]),
    )
    .map_err(|error| {
        if error.code() == "pack.application_limit" {
            application_limit()
        } else {
            history_invalid()
        }
    })?;
    Ok(std::iter::once(pack_id.clone())
        .chain(
            components
                .into_iter()
                .map(|component| component.id().clone()),
        )
        .collect())
}

pub(crate) fn required_snapshot_objects(
    snapshot: &PortableSnapshotV1,
    closure: &BTreeSet<AssetId>,
) -> Result<BTreeSet<ObjectDescriptor>, PackRollbackError> {
    let roots: BTreeSet<_> = closure
        .iter()
        .filter_map(|id| snapshot.manifest().assets.get(id))
        .flat_map(|asset| {
            asset
                .portable
                .iter()
                .map(|content| &content.root)
                .chain(asset.native_variants.values().map(|content| &content.root))
        })
        .collect();
    let objects: BTreeSet<_> = snapshot
        .objects()
        .iter()
        .filter(|descriptor| roots.contains(descriptor.root()))
        .cloned()
        .collect();
    if objects.len() != roots.len() {
        return Err(history_invalid());
    }
    Ok(objects)
}

fn rollback_plan_digest(
    selection: &PackRollbackSelection,
    base: &Revision,
    proposed: &Revision,
    lock: &Lockfile,
    objects: &BTreeSet<ObjectDescriptor>,
    affected: &BTreeMap<AssetId, PackRevisionChange>,
) -> Result<ContentHash, PackRollbackError> {
    pack_graft_plan_digest(
        b"kitrove-pack-rollback-plan-v1\0",
        selection.digest(),
        base,
        proposed,
        lock,
        objects,
        affected,
    )
    .map_err(|_| plan_invalid())
}

pub(crate) fn pack_graft_plan_digest(
    domain: &[u8],
    selection_digest: &ContentHash,
    base: &Revision,
    proposed: &Revision,
    lock: &Lockfile,
    objects: &BTreeSet<ObjectDescriptor>,
    affected: &BTreeMap<AssetId, PackRevisionChange>,
) -> Result<ContentHash, ()> {
    let lock = lock.to_json().map_err(|_| ())?;
    let lock_digest = ContentHash::digest(lock.as_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for value in [
        selection_digest.as_str(),
        base.as_str(),
        proposed.as_str(),
        lock_digest.as_str(),
    ] {
        write_record(&mut hasher, value);
    }
    hasher.update(&(objects.len() as u64).to_be_bytes());
    for object in objects {
        hasher.update(&[snapshot_kind_tag(object.kind())]);
        write_record(&mut hasher, object.root().as_str());
        write_record(&mut hasher, object.object_hash().as_str());
        hasher.update(&object.encoded_len().to_be_bytes());
    }
    hasher.update(&(affected.len() as u64).to_be_bytes());
    for (id, change) in affected {
        write_record(&mut hasher, id.as_str());
        match change.prior() {
            Some(prior) => {
                hasher.update(&[1]);
                write_record(&mut hasher, prior.as_str());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        write_record(&mut hasher, change.proposed().as_str());
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex())).map_err(|_| ())
}

pub(crate) const fn snapshot_kind_tag(kind: SnapshotObjectKind) -> u8 {
    match kind {
        SnapshotObjectKind::PortableSkillTree => 0,
        SnapshotObjectKind::NativeSkillObject => 1,
        SnapshotObjectKind::NativeExtensionObject => 2,
        SnapshotObjectKind::PortableInstruction => 3,
        SnapshotObjectKind::NativeInstruction => 4,
        SnapshotObjectKind::PortablePromptCommand => 5,
        SnapshotObjectKind::NativePromptCommand => 6,
        SnapshotObjectKind::PortableAgent => 7,
        SnapshotObjectKind::NativeAgent => 8,
        SnapshotObjectKind::PortableMcp => 9,
        SnapshotObjectKind::NativeMcp => 10,
    }
}

fn write_record(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

const fn error(code: &'static str, message: &'static str) -> PackRollbackError {
    PackRollbackError::new(code, message)
}

const fn history_invalid() -> PackRollbackError {
    error(
        "pack_rollback.history_invalid",
        "pack rollback requires one bounded verified linear snapshot history",
    )
}

const fn pack_missing() -> PackRollbackError {
    error(
        "pack_rollback.pack_missing",
        "the selected pack is absent from current remote authority",
    )
}

const fn target_missing() -> PackRollbackError {
    error(
        "pack_rollback.target_missing",
        "the selected pack revision is absent from verified older history",
    )
}

const fn expected_current_mismatch() -> PackRollbackError {
    error(
        "pack_rollback.expected_prior_mismatch",
        "the selected pack no longer matches --expected-prior",
    )
}

const fn manifest_invalid() -> PackRollbackError {
    error(
        "pack_rollback.manifest_invalid",
        "pack rollback requires valid current portable authority",
    )
}

const fn manifest_stale() -> PackRollbackError {
    error(
        "pack_rollback.manifest_stale",
        "manifest authority changed after pack rollback was planned",
    )
}

const fn identity_collision() -> PackRollbackError {
    error(
        "pack_rollback.identity_collision",
        "historical pack closure collides with unrelated current authority",
    )
}

const fn application_limit() -> PackRollbackError {
    error(
        "pack_rollback.application_limit",
        "pack rollback closure exceeds the configured traversal limit",
    )
}

const fn executable_transition() -> PackRollbackError {
    error(
        "pack_rollback.executable_transition",
        "pack rollback cannot introduce a changed executable component without explicit policy",
    )
}

const fn proposed_manifest_invalid() -> PackRollbackError {
    error(
        "pack_rollback.proposed_manifest_invalid",
        "the historical pack closure does not form valid selective authority",
    )
}

const fn proposed_lock_invalid() -> PackRollbackError {
    error(
        "pack_rollback.proposed_lock_invalid",
        "the generated rollback lock authority is invalid",
    )
}

const fn plan_invalid() -> PackRollbackError {
    error(
        "pack_rollback.plan_invalid",
        "the pack rollback plan identity is invalid",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kitrove_model::{RemoteRevision, SyncLimits};

    use super::*;
    use crate::{VerifiedRemoteHistory, plan_pack_creation, select_pack_rollback_snapshot};

    fn snapshot(
        manifest: EnvironmentManifest,
        marker: &str,
    ) -> (RemoteRevision, Arc<PortableSnapshotV1>) {
        (
            RemoteRevision::parse(format!("test:{marker}")).unwrap(),
            Arc::new(
                PortableSnapshotV1::new(manifest, BTreeSet::new(), SyncLimits::default()).unwrap(),
            ),
        )
    }

    fn selection(
        current: EnvironmentManifest,
        historical: EnvironmentManifest,
        pack_id: &AssetId,
    ) -> PackRollbackSelection {
        let expected = current.packs[pack_id].content_hash.clone();
        let target = historical.packs[pack_id].content_hash.clone();
        let history = VerifiedRemoteHistory::new(
            vec![
                snapshot(current, "current"),
                snapshot(historical, "historical"),
            ],
            SyncLimits::default(),
        )
        .unwrap();
        select_pack_rollback_snapshot(&history, pack_id, &expected, &target).unwrap()
    }

    #[test]
    fn restores_only_the_historical_closure_and_rederives_parents() {
        let created = plan_pack_creation(
            &crate::pack_creation::tests::manifest(),
            AssetId::parse("tooling").unwrap(),
            BTreeSet::from([
                AssetId::parse("left").unwrap(),
                AssetId::parse("right").unwrap(),
            ]),
        )
        .unwrap();
        let historical = created.proposed_manifest().clone();
        let mut current = historical.clone();
        let alpha = AssetId::parse("alpha").unwrap();
        let beta = AssetId::parse("beta").unwrap();
        current.assets.get_mut(&alpha).unwrap().content_class = ContentClass::AgentActive;
        current
            .assets
            .get_mut(&alpha)
            .unwrap()
            .refresh_content_hash();
        current.assets.get_mut(&beta).unwrap().content_class = ContentClass::AgentActive;
        current
            .assets
            .get_mut(&beta)
            .unwrap()
            .refresh_content_hash();
        current.refresh_pack_revisions().unwrap();
        let left = AssetId::parse("left").unwrap();
        let right = AssetId::parse("right").unwrap();
        let tooling = AssetId::parse("tooling").unwrap();
        let selection = selection(current.clone(), historical.clone(), &left);

        let plan = plan_pack_rollback(&current, &selection).unwrap();

        assert_eq!(
            plan.proposed_manifest().assets[&alpha],
            historical.assets[&alpha]
        );
        assert_eq!(
            plan.proposed_manifest().assets[&beta],
            current.assets[&beta]
        );
        assert_eq!(
            plan.proposed_manifest().packs[&right],
            current.packs[&right]
        );
        assert_eq!(
            plan.proposed_manifest().packs[&left].content_hash,
            historical.packs[&left].content_hash
        );
        assert_ne!(
            plan.proposed_manifest().packs[&tooling].content_hash,
            historical.packs[&tooling].content_hash
        );
        assert_eq!(
            plan.affected_packs().keys().collect::<BTreeSet<_>>(),
            BTreeSet::from([&left, &tooling])
        );
        assert!(plan.required_objects().is_empty());
        assert!(plan.ensure_manifest_fresh(&current).is_ok());
        let debug = format!("{plan:?}");
        for secret in [
            left.as_str(),
            plan.digest().as_str(),
            plan.selection().snapshot_digest().as_str(),
        ] {
            assert!(!debug.contains(secret));
        }
        assert_eq!(
            plan.ensure_manifest_fresh(&historical).unwrap_err().code(),
            "pack_rollback.manifest_stale"
        );
    }

    #[test]
    fn refuses_unrelated_identity_collisions_and_executable_transitions() {
        let current = crate::pack_creation::tests::manifest();
        let left = AssetId::parse("left").unwrap();
        let alpha = AssetId::parse("alpha").unwrap();
        let beta = AssetId::parse("beta").unwrap();

        let mut colliding_history = current.clone();
        colliding_history.packs.get_mut(&left).unwrap().members = BTreeMap::from([(
            beta.clone(),
            colliding_history.assets[&beta].content_hash.clone(),
        )]);
        colliding_history.refresh_pack_revisions().unwrap();
        let mut colliding_current = current.clone();
        colliding_current
            .assets
            .get_mut(&beta)
            .unwrap()
            .content_class = ContentClass::AgentActive;
        colliding_current
            .assets
            .get_mut(&beta)
            .unwrap()
            .refresh_content_hash();
        colliding_current.refresh_pack_revisions().unwrap();
        let collision_selection = selection(colliding_current.clone(), colliding_history, &left);
        assert_eq!(
            plan_pack_rollback(&colliding_current, &collision_selection)
                .unwrap_err()
                .code(),
            "pack_rollback.identity_collision"
        );

        let mut executable_history = current.clone();
        executable_history
            .assets
            .get_mut(&alpha)
            .unwrap()
            .content_class = ContentClass::Executable;
        executable_history
            .assets
            .get_mut(&alpha)
            .unwrap()
            .refresh_content_hash();
        executable_history.refresh_pack_revisions().unwrap();
        let executable_selection = selection(current.clone(), executable_history, &left);
        assert_eq!(
            plan_pack_rollback(&current, &executable_selection)
                .unwrap_err()
                .code(),
            "pack_rollback.executable_transition"
        );
    }

    #[test]
    fn binds_every_historical_closure_object_required_by_the_plan() {
        let (adoption, _, _) = crate::adoption::tests::ready_plan();
        let mut historical = crate::pack_creation::tests::manifest();
        let alpha = AssetId::parse("alpha").unwrap();
        let left = AssetId::parse("left").unwrap();
        let mut asset = adoption.asset().clone();
        asset.id = alpha.clone();
        let binding = kitrove_model::BindingName::parse("rollback_test").unwrap();
        asset.required_bindings.insert(binding.clone());
        asset.refresh_content_hash();
        historical.assets.insert(alpha.clone(), asset.clone());
        historical.required_bindings.insert(binding.clone());
        historical.refresh_pack_revisions().unwrap();
        let portable = asset.portable.as_ref().unwrap();
        let native = &asset.native_variants[adoption.origin_harness()];
        let objects = [
            crate::VerifiedObjectEnvelope::portable(
                portable.root.clone(),
                adoption.portable_object().clone(),
            )
            .unwrap(),
            crate::VerifiedObjectEnvelope::native(
                native.root.clone(),
                adoption.native_object().clone(),
            )
            .unwrap(),
        ];
        let descriptors: BTreeSet<_> = objects
            .iter()
            .map(|object| object.descriptor().clone())
            .collect();
        let mut current = historical.clone();
        current
            .assets
            .get_mut(&alpha)
            .unwrap()
            .required_bindings
            .remove(&binding);
        current.required_bindings.remove(&binding);
        current
            .assets
            .get_mut(&alpha)
            .unwrap()
            .refresh_content_hash();
        current.refresh_pack_revisions().unwrap();
        let limits = SyncLimits::default();
        let expected = current.packs[&left].content_hash.clone();
        let target = historical.packs[&left].content_hash.clone();
        let history = VerifiedRemoteHistory::new(
            vec![
                (
                    RemoteRevision::parse("test:current-objects").unwrap(),
                    Arc::new(
                        PortableSnapshotV1::new(current.clone(), descriptors.clone(), limits)
                            .unwrap(),
                    ),
                ),
                (
                    RemoteRevision::parse("test:historical-objects").unwrap(),
                    Arc::new(
                        PortableSnapshotV1::new(historical, descriptors.clone(), limits).unwrap(),
                    ),
                ),
            ],
            limits,
        )
        .unwrap();
        let selection = select_pack_rollback_snapshot(&history, &left, &expected, &target).unwrap();

        let plan = plan_pack_rollback(&current, &selection).unwrap();

        assert_eq!(plan.required_objects(), &descriptors);
        assert!(
            plan.proposed_manifest()
                .required_bindings
                .contains(&binding)
        );
    }
}
