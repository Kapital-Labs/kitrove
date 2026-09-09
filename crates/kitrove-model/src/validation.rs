use std::collections::{BTreeMap, BTreeSet};

use crate::portable::{
    MAX_PACK_GRAPH_DEPTH, PackMemberMetadata, derive_pack_fields, validate_pack_graph_depth,
    validate_pack_member_budget,
};
use crate::{AssetId, EnvironmentManifest, Lockfile, ProfileId, ValidationError};

/// Cross-record validation implemented by persisted roots.
pub trait Validate {
    /// Verifies invariants that Serde's type checks cannot express.
    fn validate(&self) -> Result<(), ValidationError>;
}

impl Validate for EnvironmentManifest {
    fn validate(&self) -> Result<(), ValidationError> {
        for (id, asset) in &self.assets {
            if id != &asset.id {
                return Err(ValidationError::new(
                    "manifest.asset_key_mismatch",
                    format!("asset map key {id} does not match embedded id {}", asset.id),
                ));
            }
            if asset.kind == crate::AssetKind::Pack {
                return Err(ValidationError::new(
                    "manifest.pack_in_asset_map",
                    format!("pack {id} must be declared in the first-class packs map"),
                ));
            }
            for binding in &asset.required_bindings {
                if !self.required_bindings.contains(binding) {
                    return Err(ValidationError::new(
                        "manifest.undeclared_binding",
                        format!("asset {id} requires undeclared binding {binding}"),
                    ));
                }
            }
            for (harness, variant) in &asset.native_variants {
                if harness != &variant.harness {
                    return Err(ValidationError::new(
                        "manifest.native_variant_key_mismatch",
                        format!(
                            "native variant key {harness} does not match embedded harness {}",
                            variant.harness
                        ),
                    ));
                }
            }
            for (provenance_id, provenance) in &asset.provenance {
                if provenance_id != &provenance.provenance_id() {
                    return Err(ValidationError::new(
                        "manifest.provenance_key_mismatch",
                        "asset provenance map key does not match the complete provenance identity",
                    ));
                }
            }
            let mut referenced_provenance = BTreeSet::new();
            if let Some(portable) = &asset.portable {
                referenced_provenance.insert(portable.provenance.clone());
            }
            referenced_provenance.extend(
                asset
                    .native_variants
                    .values()
                    .map(|variant| variant.provenance.clone()),
            );
            if referenced_provenance
                .iter()
                .any(|id| !asset.provenance.contains_key(id))
            {
                return Err(ValidationError::new(
                    "manifest.provenance_missing",
                    "an asset component references missing provenance",
                ));
            }
            if asset
                .provenance
                .keys()
                .any(|id| !referenced_provenance.contains(id))
            {
                return Err(ValidationError::new(
                    "manifest.provenance_unreferenced",
                    "an asset contains unreferenced provenance",
                ));
            }
            if asset.content_hash != asset.expected_content_hash() {
                return Err(ValidationError::new(
                    "manifest.asset_content_hash_mismatch",
                    "asset content hash does not match its complete revision",
                ));
            }
        }

        validate_pack_member_budget(&self.packs, "manifest.pack_member_limit_exceeded")?;
        for (id, pack) in &self.packs {
            if id != &pack.id {
                return Err(ValidationError::new(
                    "manifest.pack_key_mismatch",
                    format!("pack map key {id} does not match embedded id {}", pack.id),
                ));
            }
            if self.assets.contains_key(id) {
                return Err(ValidationError::new(
                    "manifest.duplicate_identity",
                    format!("{id} is declared as both an asset and a pack"),
                ));
            }
            for binding in &pack.required_bindings {
                if !self.required_bindings.contains(binding) {
                    return Err(ValidationError::new(
                        "manifest.undeclared_binding",
                        format!("pack {id} requires undeclared binding {binding}"),
                    ));
                }
            }
            if pack.members.is_empty() {
                return Err(ValidationError::new(
                    "manifest.pack_empty",
                    "a pack requires at least one exact member revision",
                ));
            }
            for member in pack.members.keys() {
                if !self.assets.contains_key(member) && !self.packs.contains_key(member) {
                    return Err(ValidationError::new(
                        "manifest.unknown_pack_member",
                        "a pack references an unknown member",
                    ));
                }
            }
        }
        validate_pack_graph_depth(
            &self.packs,
            "manifest.pack_depth_limit_exceeded",
            "manifest.pack_cycle",
        )?;
        reject_pack_cycles(self)?;
        validate_pack_revisions(self)?;

        for (id, profile) in &self.profiles {
            if id != &profile.id {
                return Err(ValidationError::new(
                    "manifest.profile_key_mismatch",
                    format!(
                        "profile map key {id} does not match embedded id {}",
                        profile.id
                    ),
                ));
            }
            if let Some(parent) = &profile.extends {
                if !self.profiles.contains_key(parent) {
                    return Err(ValidationError::new(
                        "manifest.unknown_profile_parent",
                        format!("profile {id} extends unknown profile {parent}"),
                    ));
                }
            }
            for asset in &profile.assets {
                if !self.assets.contains_key(asset) && !self.packs.contains_key(asset) {
                    return Err(ValidationError::new(
                        "manifest.unknown_profile_asset",
                        format!("profile {id} references unknown asset or pack {asset}"),
                    ));
                }
            }
        }
        reject_profile_cycles(self)
    }
}

fn reject_pack_cycles(manifest: &EnvironmentManifest) -> Result<(), ValidationError> {
    fn visit(
        id: &AssetId,
        manifest: &EnvironmentManifest,
        visiting: &mut BTreeSet<AssetId>,
        visited: &mut BTreeSet<AssetId>,
        depth: usize,
    ) -> Result<(), ValidationError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.clone()) {
            return Err(ValidationError::new(
                "manifest.pack_cycle",
                format!("pack dependency cycle reaches {id}"),
            ));
        }
        if depth > MAX_PACK_GRAPH_DEPTH {
            return Err(ValidationError::new(
                "manifest.pack_depth_limit_exceeded",
                "pack dependency graph exceeds the compiled depth limit",
            ));
        }
        if let Some(pack) = manifest.packs.get(id) {
            for member in pack.members.keys() {
                if manifest.packs.contains_key(member) {
                    visit(member, manifest, visiting, visited, depth + 1)?;
                }
            }
        }
        visiting.remove(id);
        visited.insert(id.clone());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in manifest.packs.keys() {
        visit(id, manifest, &mut visiting, &mut visited, 1)?;
    }
    Ok(())
}

fn reject_profile_cycles(manifest: &EnvironmentManifest) -> Result<(), ValidationError> {
    fn visit(
        id: &ProfileId,
        manifest: &EnvironmentManifest,
        visiting: &mut BTreeSet<ProfileId>,
        visited: &mut BTreeSet<ProfileId>,
    ) -> Result<(), ValidationError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.clone()) {
            return Err(ValidationError::new(
                "manifest.profile_cycle",
                format!("profile inheritance cycle reaches {id}"),
            ));
        }
        if let Some(parent) = manifest
            .profiles
            .get(id)
            .and_then(|profile| profile.extends.as_ref())
        {
            visit(parent, manifest, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id.clone());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in manifest.profiles.keys() {
        visit(id, manifest, &mut visiting, &mut visited)?;
    }
    Ok(())
}

impl Validate for Lockfile {
    fn validate(&self) -> Result<(), ValidationError> {
        for (id, asset) in &self.assets {
            if id != &asset.id {
                return Err(ValidationError::new(
                    "lockfile.asset_key_mismatch",
                    format!("asset map key {id} does not match embedded id {}", asset.id),
                ));
            }
            if asset.kind == crate::AssetKind::Pack {
                return Err(ValidationError::new(
                    "lockfile.pack_in_asset_map",
                    format!("pack {id} must be declared in the first-class packs map"),
                ));
            }
            if asset
                .portable_provenance
                .as_ref()
                .is_some_and(|provenance| !asset.provenance.contains_key(provenance))
                || asset
                    .native_provenance
                    .values()
                    .any(|provenance| !asset.provenance.contains_key(provenance))
            {
                return Err(ValidationError::new(
                    "lockfile.provenance_missing",
                    "a locked component references missing provenance",
                ));
            }
            let referenced = asset
                .portable_provenance
                .iter()
                .chain(asset.native_provenance.values())
                .collect::<BTreeSet<_>>();
            if asset
                .provenance
                .iter()
                .any(|(id, record)| id != &record.provenance_id() || !referenced.contains(id))
            {
                return Err(ValidationError::new(
                    "lockfile.provenance_invalid",
                    "locked provenance is mismatched or unreferenced",
                ));
            }
        }
        validate_locked_pack_member_budget(self)?;
        for (id, pack) in &self.packs {
            if id != &pack.id {
                return Err(ValidationError::new(
                    "lockfile.pack_key_mismatch",
                    format!("pack map key {id} does not match embedded id {}", pack.id),
                ));
            }
            if self.assets.contains_key(id) {
                return Err(ValidationError::new(
                    "lockfile.duplicate_identity",
                    format!("{id} is locked as both an asset and a pack"),
                ));
            }
            if pack.members.is_empty() {
                return Err(ValidationError::new(
                    "lockfile.pack_empty",
                    "a locked pack requires at least one exact member revision",
                ));
            }
            for (member, revision) in &pack.members {
                if !self.assets.contains_key(member) && !self.packs.contains_key(member) {
                    return Err(ValidationError::new(
                        "lockfile.unknown_pack_member",
                        "a locked pack references an unknown member",
                    ));
                }
                let expected = self
                    .assets
                    .get(member)
                    .map(|asset| &asset.content_hash)
                    .or_else(|| self.packs.get(member).map(|pack| &pack.content_hash))
                    .expect("locked member existence was checked");
                if revision != expected {
                    return Err(ValidationError::new(
                        "lockfile.pack_member_revision_mismatch",
                        "a locked pack member revision does not match locked authority",
                    ));
                }
            }
        }
        validate_locked_pack_graph_depth(self)?;
        reject_lockfile_pack_cycles(self)
    }
}

fn reject_lockfile_pack_cycles(lockfile: &Lockfile) -> Result<(), ValidationError> {
    fn visit(
        id: &AssetId,
        lockfile: &Lockfile,
        visiting: &mut BTreeSet<AssetId>,
        visited: &mut BTreeSet<AssetId>,
        depth: usize,
    ) -> Result<(), ValidationError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.clone()) {
            return Err(ValidationError::new(
                "lockfile.pack_cycle",
                format!("locked pack dependency cycle reaches {id}"),
            ));
        }
        if depth > MAX_PACK_GRAPH_DEPTH {
            return Err(ValidationError::new(
                "lockfile.pack_depth_limit_exceeded",
                "locked pack dependency graph exceeds the compiled depth limit",
            ));
        }
        if let Some(pack) = lockfile.packs.get(id) {
            for member in pack.members.keys() {
                if lockfile.packs.contains_key(member) {
                    visit(member, lockfile, visiting, visited, depth + 1)?;
                }
            }
        }
        visiting.remove(id);
        visited.insert(id.clone());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in lockfile.packs.keys() {
        visit(id, lockfile, &mut visiting, &mut visited, 1)?;
    }
    Ok(())
}

fn validate_locked_pack_member_budget(lockfile: &Lockfile) -> Result<(), ValidationError> {
    let count = lockfile.packs.values().try_fold(0_usize, |count, pack| {
        count.checked_add(pack.members.len()).ok_or_else(|| {
            ValidationError::new(
                "lockfile.pack_member_limit_exceeded",
                "locked pack member graph exceeds the compiled limit",
            )
        })
    })?;
    if count > crate::portable::MAX_PACK_MEMBER_EDGES {
        return Err(ValidationError::new(
            "lockfile.pack_member_limit_exceeded",
            "locked pack member graph exceeds the compiled limit",
        ));
    }
    Ok(())
}

fn validate_locked_pack_graph_depth(lockfile: &Lockfile) -> Result<(), ValidationError> {
    fn height(
        id: &AssetId,
        lockfile: &Lockfile,
        visiting: &mut BTreeSet<AssetId>,
        memo: &mut BTreeMap<AssetId, usize>,
        depth: usize,
    ) -> Result<usize, ValidationError> {
        if depth > MAX_PACK_GRAPH_DEPTH {
            return Err(ValidationError::new(
                "lockfile.pack_depth_limit_exceeded",
                "locked pack dependency graph exceeds the compiled depth limit",
            ));
        }
        if let Some(height) = memo.get(id) {
            if depth.saturating_sub(1).saturating_add(*height) > MAX_PACK_GRAPH_DEPTH {
                return Err(ValidationError::new(
                    "lockfile.pack_depth_limit_exceeded",
                    "locked pack dependency graph exceeds the compiled depth limit",
                ));
            }
            return Ok(*height);
        }
        if !visiting.insert(id.clone()) {
            return Err(ValidationError::new(
                "lockfile.pack_cycle",
                "locked pack dependency graph contains a cycle",
            ));
        }
        let mut result = 1_usize;
        if let Some(pack) = lockfile.packs.get(id) {
            for member in pack
                .members
                .keys()
                .filter(|member| lockfile.packs.contains_key(*member))
            {
                result = result
                    .max(height(member, lockfile, visiting, memo, depth + 1)?.saturating_add(1));
                if result > MAX_PACK_GRAPH_DEPTH {
                    return Err(ValidationError::new(
                        "lockfile.pack_depth_limit_exceeded",
                        "locked pack dependency graph exceeds the compiled depth limit",
                    ));
                }
            }
        }
        visiting.remove(id);
        memo.insert(id.clone(), result);
        Ok(result)
    }

    let mut visiting = BTreeSet::new();
    let mut memo = BTreeMap::new();
    for id in lockfile.packs.keys() {
        height(id, lockfile, &mut visiting, &mut memo, 1)?;
    }
    Ok(())
}

fn validate_pack_revisions(manifest: &EnvironmentManifest) -> Result<(), ValidationError> {
    for pack in manifest.packs.values() {
        let mut members = Vec::with_capacity(pack.members.len());
        for (member, revision) in &pack.members {
            if let Some(asset) = manifest.assets.get(member) {
                if revision != &asset.content_hash {
                    return Err(ValidationError::new(
                        "manifest.pack_member_revision_mismatch",
                        "a pack member revision does not match asset authority",
                    ));
                }
                members.push(PackMemberMetadata {
                    id: member.clone(),
                    revision: revision.clone(),
                    compatibility: asset.compatibility.clone(),
                    content_class: asset.content_class,
                    required_bindings: asset.required_bindings.clone(),
                });
            } else if let Some(nested) = manifest.packs.get(member) {
                if revision != &nested.content_hash {
                    return Err(ValidationError::new(
                        "manifest.pack_member_revision_mismatch",
                        "a pack member revision does not match nested pack authority",
                    ));
                }
                members.push(PackMemberMetadata {
                    id: member.clone(),
                    revision: revision.clone(),
                    compatibility: nested.compatibility.clone(),
                    content_class: nested.content_class,
                    required_bindings: nested.required_bindings.clone(),
                });
            }
        }
        let derived = derive_pack_fields(&members)?;
        if pack.compatibility != derived.compatibility {
            return Err(ValidationError::new(
                "manifest.pack_compatibility_mismatch",
                "pack compatibility is not the exact member aggregate",
            ));
        }
        if pack.content_class != derived.content_class {
            return Err(ValidationError::new(
                "manifest.pack_content_class_mismatch",
                "pack content class is not the exact member maximum",
            ));
        }
        if pack.required_bindings != derived.required_bindings {
            return Err(ValidationError::new(
                "manifest.pack_bindings_mismatch",
                "pack binding requirements are not the exact member union",
            ));
        }
        if pack.content_hash != pack.expected_content_hash() {
            return Err(ValidationError::new(
                "manifest.pack_content_hash_mismatch",
                "pack content hash does not match its complete aggregate revision",
            ));
        }
    }
    Ok(())
}
