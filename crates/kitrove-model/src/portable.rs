use std::collections::{BTreeMap, BTreeSet};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    Asset, AssetId, BindingName, ContentClass, ContentHash, Fidelity, FidelityEvidence,
    FidelityReason, FidelityResult, HarnessId, LockedAsset, LockedPack, Pack, ProfileId, Validate,
    ValidationError,
};

pub(crate) const MAX_PACK_MEMBER_EDGES: usize = 4096;
pub(crate) const MAX_PACK_GRAPH_DEPTH: usize = 64;

pub(crate) fn validate_pack_member_budget(
    packs: &BTreeMap<AssetId, Pack>,
    member_code: &'static str,
) -> Result<(), ValidationError> {
    let count = packs.values().try_fold(0_usize, |count, pack| {
        count.checked_add(pack.members.len()).ok_or_else(|| {
            ValidationError::new(member_code, "pack member graph exceeds the compiled limit")
        })
    })?;
    if count > MAX_PACK_MEMBER_EDGES {
        return Err(ValidationError::new(
            member_code,
            "pack member graph exceeds the compiled limit",
        ));
    }
    Ok(())
}

pub(crate) fn validate_pack_graph_depth(
    packs: &BTreeMap<AssetId, Pack>,
    depth_code: &'static str,
    cycle_code: &'static str,
) -> Result<(), ValidationError> {
    fn height(
        id: &AssetId,
        packs: &BTreeMap<AssetId, Pack>,
        visiting: &mut BTreeSet<AssetId>,
        memo: &mut BTreeMap<AssetId, usize>,
        depth: usize,
        depth_code: &'static str,
        cycle_code: &'static str,
    ) -> Result<usize, ValidationError> {
        if depth > MAX_PACK_GRAPH_DEPTH {
            return Err(ValidationError::new(
                depth_code,
                "pack dependency graph exceeds the compiled depth limit",
            ));
        }
        if let Some(height) = memo.get(id) {
            if depth.saturating_sub(1).saturating_add(*height) > MAX_PACK_GRAPH_DEPTH {
                return Err(ValidationError::new(
                    depth_code,
                    "pack dependency graph exceeds the compiled depth limit",
                ));
            }
            return Ok(*height);
        }
        if !visiting.insert(id.clone()) {
            return Err(ValidationError::new(
                cycle_code,
                "pack dependency graph contains a cycle",
            ));
        }
        let mut result = 1_usize;
        if let Some(pack) = packs.get(id) {
            for member in pack
                .members
                .keys()
                .filter(|member| packs.contains_key(*member))
            {
                result = result.max(
                    height(
                        member,
                        packs,
                        visiting,
                        memo,
                        depth + 1,
                        depth_code,
                        cycle_code,
                    )?
                    .saturating_add(1),
                );
                if result > MAX_PACK_GRAPH_DEPTH {
                    return Err(ValidationError::new(
                        depth_code,
                        "pack dependency graph exceeds the compiled depth limit",
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
    for id in packs.keys() {
        height(
            id,
            packs,
            &mut visiting,
            &mut memo,
            1,
            depth_code,
            cycle_code,
        )?;
    }
    Ok(())
}

/// The only portable schema version currently accepted by Kitrove.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaVersion {
    V1,
}

impl Serialize for SchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(1)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u32::deserialize(deserializer)? {
            1 => Ok(Self::V1),
            version => Err(D::Error::custom(format!(
                "unsupported schema version {version}"
            ))),
        }
    }
}

/// A portable selection of assets and target harnesses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: ProfileId,
    pub extends: Option<ProfileId>,
    #[serde(default)]
    pub assets: BTreeSet<AssetId>,
    #[serde(default)]
    pub targets: BTreeSet<HarnessId>,
}

/// The desired portable capability environment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentManifest {
    pub schema_version: SchemaVersion,
    #[serde(default)]
    pub assets: BTreeMap<AssetId, Asset>,
    #[serde(default)]
    pub packs: BTreeMap<AssetId, Pack>,
    #[serde(default)]
    pub profiles: BTreeMap<ProfileId, Profile>,
    #[serde(default)]
    pub required_bindings: BTreeSet<crate::BindingName>,
}

/// The generated, deterministic immutable source resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    pub schema_version: SchemaVersion,
    #[serde(default)]
    pub assets: BTreeMap<AssetId, LockedAsset>,
    #[serde(default)]
    pub packs: BTreeMap<AssetId, LockedPack>,
}

impl EnvironmentManifest {
    /// Re-derives every nested pack from exact member revisions in dependency order.
    pub fn refresh_pack_revisions(&mut self) -> Result<(), ValidationError> {
        fn refresh(
            manifest: &mut EnvironmentManifest,
            id: &AssetId,
            visiting: &mut BTreeSet<AssetId>,
            visited: &mut BTreeSet<AssetId>,
            depth: usize,
        ) -> Result<(), ValidationError> {
            if visited.contains(id) {
                return Ok(());
            }
            if depth > MAX_PACK_GRAPH_DEPTH {
                return Err(ValidationError::new(
                    "manifest.pack_depth_limit_exceeded",
                    "pack dependency graph exceeds the compiled depth limit",
                ));
            }
            if !visiting.insert(id.clone()) {
                return Err(ValidationError::new(
                    "manifest.pack_cycle",
                    "pack dependency graph contains a cycle",
                ));
            }
            let member_ids: Vec<_> = manifest
                .packs
                .get(id)
                .ok_or_else(|| {
                    ValidationError::new("manifest.pack_missing", "selected pack is missing")
                })?
                .members
                .keys()
                .cloned()
                .collect();
            if member_ids.is_empty() {
                return Err(ValidationError::new(
                    "manifest.pack_empty",
                    "a pack requires at least one exact member revision",
                ));
            }
            for member in &member_ids {
                if manifest.packs.contains_key(member) {
                    refresh(manifest, member, visiting, visited, depth + 1)?;
                }
            }
            let mut members = Vec::with_capacity(member_ids.len());
            for member in member_ids {
                if let Some(asset) = manifest.assets.get(&member) {
                    if asset.content_hash != asset.expected_content_hash() {
                        return Err(ValidationError::new(
                            "manifest.pack_member_invalid",
                            "a pack member asset has invalid revision authority",
                        ));
                    }
                    members.push(PackMemberMetadata {
                        id: member,
                        revision: asset.content_hash.clone(),
                        compatibility: asset.compatibility.clone(),
                        content_class: asset.content_class,
                        required_bindings: asset.required_bindings.clone(),
                    });
                } else if let Some(pack) = manifest.packs.get(&member) {
                    members.push(PackMemberMetadata {
                        id: member,
                        revision: pack.content_hash.clone(),
                        compatibility: pack.compatibility.clone(),
                        content_class: pack.content_class,
                        required_bindings: pack.required_bindings.clone(),
                    });
                } else {
                    return Err(ValidationError::new(
                        "manifest.unknown_pack_member",
                        "a pack references an unknown member",
                    ));
                }
            }
            let derived = derive_pack_fields(&members)?;
            let pack = manifest
                .packs
                .get_mut(id)
                .expect("selected pack remains present while refreshing");
            pack.members = members
                .into_iter()
                .map(|member| (member.id, member.revision))
                .collect();
            pack.compatibility = derived.compatibility;
            pack.content_class = derived.content_class;
            pack.required_bindings = derived.required_bindings;
            pack.refresh_content_hash();
            visiting.remove(id);
            visited.insert(id.clone());
            Ok(())
        }

        validate_pack_member_budget(&self.packs, "manifest.pack_member_limit_exceeded")?;
        validate_pack_graph_depth(
            &self.packs,
            "manifest.pack_depth_limit_exceeded",
            "manifest.pack_cycle",
        )?;
        let ids: Vec<_> = self.packs.keys().cloned().collect();
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for id in ids {
            refresh(self, &id, &mut visiting, &mut visited, 1)?;
        }
        self.validate()
    }

    /// Parses and validates a strict portable TOML manifest.
    pub fn from_toml(input: &str) -> Result<Self, ValidationError> {
        let value: Self = toml::from_str(input).map_err(|error| {
            let location = error
                .span()
                .map(|span| format!(" at bytes {}..{}", span.start, span.end))
                .unwrap_or_default();
            ValidationError::new(
                "manifest.invalid_toml",
                format!("{}{location}", error.message()),
            )
        })?;
        value.validate()?;
        Ok(value)
    }

    /// Validates and deterministically serializes portable TOML.
    pub fn to_toml(&self) -> Result<String, ValidationError> {
        self.validate()?;
        let mut encoded = toml::to_string_pretty(self)
            .map_err(|error| ValidationError::new("manifest.serialize", error.to_string()))?;
        if !encoded.ends_with('\n') {
            encoded.push('\n');
        }
        Ok(encoded)
    }

    /// Verifies cross-record manifest invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        Validate::validate(self)
    }
}

#[derive(Clone)]
pub(crate) struct PackMemberMetadata {
    pub(crate) id: AssetId,
    pub(crate) revision: ContentHash,
    pub(crate) compatibility: BTreeMap<HarnessId, FidelityResult>,
    pub(crate) content_class: ContentClass,
    pub(crate) required_bindings: BTreeSet<BindingName>,
}

pub(crate) struct DerivedPackFields {
    pub(crate) compatibility: BTreeMap<HarnessId, FidelityResult>,
    pub(crate) content_class: ContentClass,
    pub(crate) required_bindings: BTreeSet<BindingName>,
}

pub(crate) fn derive_pack_fields(
    members: &[PackMemberMetadata],
) -> Result<DerivedPackFields, ValidationError> {
    if members.is_empty() {
        return Err(ValidationError::new(
            "manifest.pack_empty",
            "a pack requires at least one exact member revision",
        ));
    }
    let content_class = members
        .iter()
        .map(|member| member.content_class)
        .max()
        .expect("non-empty pack has one content class");
    let required_bindings = members
        .iter()
        .flat_map(|member| member.required_bindings.iter().cloned())
        .collect();
    let harnesses: BTreeSet<_> = members
        .iter()
        .flat_map(|member| member.compatibility.keys().cloned())
        .collect();
    let mut compatibility = BTreeMap::new();
    for harness in harnesses {
        let mut selected = Fidelity::Native;
        let mut missing = false;
        let mut blocked = BTreeSet::new();
        let mut harness_versions = Vec::with_capacity(members.len());
        for member in members {
            match member.compatibility.get(&harness) {
                Some(result) => {
                    selected = selected.max(result.fidelity());
                    blocked.extend(result.blocked_requirements().iter().cloned());
                    harness_versions.push(result.harness_version().map(str::to_owned));
                }
                None => {
                    selected = selected.max(Fidelity::Unsupported);
                    missing = true;
                    harness_versions.push(None);
                }
            }
        }
        let harness_version = harness_versions
            .first()
            .cloned()
            .filter(|first| harness_versions.iter().all(|candidate| candidate == first))
            .flatten();
        let evidence = vec![FidelityEvidence::new(
            "pack.aggregate",
            format!("{} exact member revisions", members.len()),
        )];
        let result = match selected {
            Fidelity::Native | Fidelity::Portable | Fidelity::Adapted => FidelityResult::exact(
                selected,
                evidence,
                "kitrove-pack-aggregate/v1",
                harness_version,
            ),
            Fidelity::Partial => FidelityResult::new(
                selected,
                vec![FidelityReason::new(
                    "pack.member_partial",
                    "at least one pack member has partial target fidelity",
                )],
                evidence,
                vec![],
                "kitrove-pack-aggregate/v1",
                harness_version,
            ),
            Fidelity::Unsupported => FidelityResult::new(
                selected,
                vec![FidelityReason::new(
                    if missing {
                        "pack.member_fidelity_missing"
                    } else {
                        "pack.member_unsupported"
                    },
                    if missing {
                        "at least one pack member lacks target fidelity evidence"
                    } else {
                        "at least one pack member is unsupported on the target"
                    },
                )],
                evidence,
                vec![],
                "kitrove-pack-aggregate/v1",
                harness_version,
            ),
            Fidelity::Blocked => FidelityResult::new(
                selected,
                vec![FidelityReason::new(
                    "pack.member_blocked",
                    "at least one pack member is blocked by a local requirement",
                )],
                evidence,
                blocked.into_iter().collect(),
                "kitrove-pack-aggregate/v1",
                harness_version,
            ),
        }?;
        compatibility.insert(harness, result);
    }
    Ok(DerivedPackFields {
        compatibility,
        content_class,
        required_bindings,
    })
}

impl Lockfile {
    /// Parses and validates a strict generated JSON lockfile.
    pub fn from_json(input: &str) -> Result<Self, ValidationError> {
        let value: Self = serde_json::from_str(input)
            .map_err(|error| ValidationError::new("lockfile.invalid_json", error.to_string()))?;
        value.validate()?;
        Ok(value)
    }

    /// Validates and deterministically serializes generated JSON.
    pub fn to_json(&self) -> Result<String, ValidationError> {
        self.validate()?;
        let mut encoded = serde_json::to_string_pretty(self)
            .map_err(|error| ValidationError::new("lockfile.serialize", error.to_string()))?;
        encoded.push('\n');
        Ok(encoded)
    }

    /// Verifies cross-record lockfile invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        Validate::validate(self)
    }
}
