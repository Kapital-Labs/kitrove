use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{AssetId, AssetKind, ContentHash, EnvironmentManifest, Pack};

const MAX_PACK_APPLICATION_GRAPH_VISITS: usize = 4096;
const MAX_PACK_APPLICATION_MEMBERSHIPS: usize = 4096;

/// The kind of one unique component reachable from a pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackComponentKind {
    Asset(AssetKind),
    Pack,
}

/// One unique component and every direct pack that contains it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackComponent {
    id: AssetId,
    revision: ContentHash,
    kind: PackComponentKind,
    direct: bool,
    parents: BTreeSet<AssetId>,
}

impl PackComponent {
    #[must_use]
    pub const fn id(&self) -> &AssetId {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> &ContentHash {
        &self.revision
    }

    #[must_use]
    pub const fn kind(&self) -> PackComponentKind {
        self.kind
    }

    #[must_use]
    pub const fn is_direct(&self) -> bool {
        self.direct
    }

    #[must_use]
    pub const fn parents(&self) -> &BTreeSet<AssetId> {
        &self.parents
    }
}

/// A validated pack plus its bounded, deduplicated transitive component graph.
#[derive(Clone, Eq, PartialEq)]
pub struct PackInspection {
    pack: Pack,
    components: Vec<PackComponent>,
}

impl Debug for PackInspection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackInspection")
            .field("pack_id", &self.pack.id)
            .field("component_count", &self.components.len())
            .finish_non_exhaustive()
    }
}

impl PackInspection {
    #[must_use]
    pub const fn pack(&self) -> &Pack {
        &self.pack
    }

    #[must_use]
    pub fn components(&self) -> &[PackComponent] {
        &self.components
    }
}

/// A fail-closed pack inspection error with a stable public code.
#[derive(Clone, Eq, PartialEq)]
pub struct PackInspectionError {
    code: &'static str,
    message: &'static str,
}

impl PackInspectionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for PackInspectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackInspectionError")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl Display for PackInspectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for PackInspectionError {}

/// Inspects one pack without reading objects or mutating portable or local state.
pub fn inspect_pack(
    manifest: &EnvironmentManifest,
    pack_id: &AssetId,
) -> Result<PackInspection, PackInspectionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    let pack = manifest
        .packs
        .get(pack_id)
        .ok_or_else(pack_missing)?
        .clone();
    let roots = BTreeSet::from([pack_id.clone()]);
    let components = resolve_pack_components(manifest, &roots)?;
    Ok(PackInspection { pack, components })
}

/// Resolves one or more packs to their deduplicated leaf assets.
pub fn resolve_pack_assets(
    manifest: &EnvironmentManifest,
    roots: &BTreeSet<AssetId>,
) -> Result<BTreeSet<AssetId>, PackInspectionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    resolve_pack_components(manifest, roots).map(|components| {
        components
            .into_iter()
            .filter_map(|component| {
                matches!(component.kind, PackComponentKind::Asset(_)).then_some(component.id)
            })
            .collect()
    })
}

/// Resolves each selected pack to its own leaf assets under one request-global work bound.
pub fn resolve_pack_asset_memberships(
    manifest: &EnvironmentManifest,
    roots: &BTreeSet<AssetId>,
) -> Result<BTreeMap<AssetId, BTreeSet<AssetId>>, PackInspectionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    let mut memberships = roots
        .iter()
        .cloned()
        .map(|root| (root, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut pending = roots
        .iter()
        .cloned()
        .map(|root| (root.clone(), root))
        .collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    let mut membership_count = 0usize;
    while let Some((root, pack_id)) = pending.pop_first() {
        if !visited.insert((root.clone(), pack_id.clone())) {
            continue;
        }
        if visited.len() > MAX_PACK_APPLICATION_GRAPH_VISITS {
            return Err(application_limit());
        }
        let pack = manifest.packs.get(&pack_id).ok_or_else(pack_missing)?;
        for member_id in pack.members.keys() {
            if manifest.assets.contains_key(member_id) {
                if memberships
                    .get_mut(&root)
                    .ok_or_else(invalid_manifest)?
                    .insert(member_id.clone())
                {
                    membership_count = membership_count.saturating_add(1);
                    if membership_count > MAX_PACK_APPLICATION_MEMBERSHIPS {
                        return Err(application_limit());
                    }
                }
            } else if manifest.packs.contains_key(member_id) {
                pending.insert((root.clone(), member_id.clone()));
            } else {
                return Err(invalid_manifest());
            }
        }
    }
    Ok(memberships)
}

pub(crate) fn resolve_pack_components(
    manifest: &EnvironmentManifest,
    roots: &BTreeSet<AssetId>,
) -> Result<Vec<PackComponent>, PackInspectionError> {
    let mut pending = roots.clone();
    let mut visited_packs = BTreeSet::new();
    let mut components = BTreeMap::<AssetId, PackComponent>::new();

    while let Some(parent_id) = pending.pop_first() {
        if !visited_packs.insert(parent_id.clone()) {
            continue;
        }
        let parent = manifest.packs.get(&parent_id).ok_or_else(pack_missing)?;
        for (member_id, revision) in &parent.members {
            let (kind, actual_revision) = if let Some(asset) = manifest.assets.get(member_id) {
                (PackComponentKind::Asset(asset.kind), &asset.content_hash)
            } else if let Some(pack) = manifest.packs.get(member_id) {
                pending.insert(member_id.clone());
                (PackComponentKind::Pack, &pack.content_hash)
            } else {
                return Err(invalid_manifest());
            };
            if actual_revision != revision {
                return Err(invalid_manifest());
            }
            let component = components
                .entry(member_id.clone())
                .or_insert_with(|| PackComponent {
                    id: member_id.clone(),
                    revision: revision.clone(),
                    kind,
                    direct: false,
                    parents: BTreeSet::new(),
                });
            if component.revision != *revision || component.kind != kind {
                return Err(invalid_manifest());
            }
            component.direct |= roots.contains(&parent_id);
            component.parents.insert(parent_id.clone());
        }
    }

    Ok(components.into_values().collect())
}

const fn invalid_manifest() -> PackInspectionError {
    PackInspectionError {
        code: "pack.manifest_invalid",
        message: "pack inspection requires a valid environment manifest",
    }
}

const fn pack_missing() -> PackInspectionError {
    PackInspectionError {
        code: "pack.missing",
        message: "the selected pack is not present in the environment",
    }
}

const fn application_limit() -> PackInspectionError {
    PackInspectionError {
        code: "pack.application_limit",
        message: "selected pack ownership exceeds the request-global traversal limit",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{
        Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, Pack,
        PortablePath, Revision, SchemaVersion, Source,
    };

    use super::{
        PackComponentKind, inspect_pack, resolve_pack_asset_memberships, resolve_pack_assets,
    };

    fn asset(id: &str, kind: AssetKind) -> Asset {
        let mut asset = Asset {
            id: AssetId::parse(id).unwrap(),
            kind,
            content_hash: ContentHash::digest(b"pending-pack-inspection-asset"),
            provenance: BTreeMap::new(),
            portable: None,
            native_variants: BTreeMap::new(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        };
        asset.refresh_content_hash();
        asset
    }

    fn pack(id: &str, members: &[&str]) -> Pack {
        Pack {
            id: AssetId::parse(id).unwrap(),
            source: Source::Local {
                path: PortablePath::parse(format!("packs/{id}")).unwrap(),
            },
            revision: Revision::parse(format!("local:{id}")).unwrap(),
            exact_source_hash: ContentHash::digest(id.as_bytes()),
            content_hash: ContentHash::digest(b"pending-pack-inspection-pack"),
            members: members
                .iter()
                .map(|member| {
                    (
                        AssetId::parse(*member).unwrap(),
                        ContentHash::digest(b"pending-pack-inspection-member"),
                    )
                })
                .collect(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        }
    }

    fn nested_manifest() -> EnvironmentManifest {
        let assets: BTreeMap<_, _> = [
            asset("alpha", AssetKind::Skill),
            asset("beta", AssetKind::Command),
        ]
        .into_iter()
        .map(|asset| (asset.id.clone(), asset))
        .collect();
        let inner = pack("inner", &["alpha", "beta"]);
        let outer = pack("outer", &["alpha", "inner"]);
        let mut manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets,
            packs: BTreeMap::from([(inner.id.clone(), inner), (outer.id.clone(), outer)]),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };
        manifest.refresh_pack_revisions().unwrap();
        manifest
    }

    #[test]
    fn nested_components_are_unique_ordered_and_retain_every_parent() {
        let manifest = nested_manifest();
        let inspection = inspect_pack(&manifest, &AssetId::parse("outer").unwrap()).unwrap();

        let ids: Vec<_> = inspection
            .components()
            .iter()
            .map(|component| component.id().as_str())
            .collect();
        assert_eq!(ids, ["alpha", "beta", "inner"]);

        let alpha = &inspection.components()[0];
        assert_eq!(alpha.kind(), PackComponentKind::Asset(AssetKind::Skill));
        assert!(alpha.is_direct());
        assert_eq!(
            alpha
                .parents()
                .iter()
                .map(AssetId::as_str)
                .collect::<Vec<_>>(),
            ["inner", "outer"]
        );
        assert!(!inspection.components()[1].is_direct());
        assert_eq!(inspection.components()[2].kind(), PackComponentKind::Pack);
    }

    #[test]
    fn pack_assets_are_deduplicated_across_nested_roots() {
        let manifest = nested_manifest();
        let roots = BTreeSet::from([
            AssetId::parse("inner").unwrap(),
            AssetId::parse("outer").unwrap(),
        ]);

        let assets = resolve_pack_assets(&manifest, &roots).unwrap();

        assert_eq!(
            assets.iter().map(AssetId::as_str).collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
    }

    #[test]
    fn per_root_memberships_preserve_overlapping_pack_ownership() {
        let manifest = nested_manifest();
        let inner = AssetId::parse("inner").unwrap();
        let outer = AssetId::parse("outer").unwrap();
        let memberships = resolve_pack_asset_memberships(
            &manifest,
            &BTreeSet::from([inner.clone(), outer.clone()]),
        )
        .unwrap();

        assert_eq!(
            memberships[&inner]
                .iter()
                .map(AssetId::as_str)
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(memberships[&inner], memberships[&outer]);
    }

    #[test]
    fn missing_pack_and_invalid_manifest_fail_closed() {
        let manifest = nested_manifest();
        let missing = AssetId::parse("missing").unwrap();
        let error = inspect_pack(&manifest, &missing).unwrap_err();
        assert_eq!(error.code(), "pack.missing");
        let error = resolve_pack_assets(&manifest, &BTreeSet::from([missing])).unwrap_err();
        assert_eq!(error.code(), "pack.missing");

        let mut invalid = manifest;
        invalid
            .packs
            .get_mut(&AssetId::parse("outer").unwrap())
            .unwrap()
            .members
            .clear();
        let error = inspect_pack(&invalid, &AssetId::parse("outer").unwrap()).unwrap_err();
        assert_eq!(error.code(), "pack.manifest_invalid");
    }

    #[test]
    fn inspection_debug_is_structural_and_omits_source_authority() {
        let manifest = nested_manifest();
        let inspection = inspect_pack(&manifest, &AssetId::parse("outer").unwrap()).unwrap();
        let debug = format!("{inspection:?}");

        assert!(debug.contains("pack_id"));
        assert!(debug.contains("component_count"));
        assert!(!debug.contains("packs/outer"));
        assert!(!debug.contains(inspection.pack().exact_source_hash.as_str()));
    }
}
