use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_model::{AssetId, EnvironmentManifest, HarnessId, ProfileId};

use crate::pack_inspection::resolve_pack_assets;

/// The complete portable selection produced by one profile and its ancestors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProfile {
    pub profile_id: ProfileId,
    pub assets: BTreeSet<AssetId>,
    pub targets: BTreeSet<HarnessId>,
}

/// A fail-closed profile resolution error with a stable public code.
#[derive(Clone, Eq, PartialEq)]
pub struct ProfileResolutionError {
    code: &'static str,
    message: &'static str,
}

impl ProfileResolutionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for ProfileResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileResolutionError")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

impl Display for ProfileResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for ProfileResolutionError {}

/// Resolves inherited profile selections and expands nested packs to materializable leaf assets.
pub fn resolve_profile(
    manifest: &EnvironmentManifest,
    profile_id: &ProfileId,
) -> Result<ResolvedProfile, ProfileResolutionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;

    let mut selected = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut visited_profiles = BTreeSet::new();
    let mut current = Some(profile_id);
    while let Some(id) = current {
        if !visited_profiles.insert(id.clone()) {
            return Err(invalid_manifest());
        }
        let profile = manifest.profiles.get(id).ok_or_else(profile_missing)?;
        selected.extend(profile.assets.iter().cloned());
        targets.extend(profile.targets.iter().cloned());
        current = profile.extends.as_ref();
    }

    let mut assets = BTreeSet::new();
    let mut pack_roots = BTreeSet::new();
    for id in selected {
        if manifest.assets.contains_key(&id) {
            assets.insert(id);
        } else if manifest.packs.contains_key(&id) {
            pack_roots.insert(id);
        } else {
            return Err(invalid_manifest());
        }
    }
    assets.extend(resolve_pack_assets(manifest, &pack_roots).map_err(|_| invalid_manifest())?);

    Ok(ResolvedProfile {
        profile_id: profile_id.clone(),
        assets,
        targets,
    })
}

const fn invalid_manifest() -> ProfileResolutionError {
    ProfileResolutionError {
        code: "profile.manifest_invalid",
        message: "profile resolution requires a valid environment manifest",
    }
}

const fn profile_missing() -> ProfileResolutionError {
    ProfileResolutionError {
        code: "profile.missing",
        message: "the selected profile is not present in the environment",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use kitrove_model::{
        Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, HarnessId, Pack,
        PortablePath, Profile, ProfileId, Revision, SchemaVersion, Source,
    };

    use super::resolve_profile;

    fn asset(id: &str) -> Asset {
        let mut asset = Asset {
            id: AssetId::parse(id).unwrap(),
            kind: AssetKind::Skill,
            content_hash: ContentHash::digest(b"pending-profile-test-asset"),
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
            content_hash: ContentHash::digest(b"pending-profile-test-pack"),
            members: members
                .iter()
                .map(|member| {
                    (
                        AssetId::parse(*member).unwrap(),
                        ContentHash::digest(b"pending-profile-test-member"),
                    )
                })
                .collect(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        }
    }

    #[test]
    fn inheritance_unions_targets_and_expands_nested_packs_to_leaf_assets() {
        let assets: BTreeMap<_, _> = ["alpha", "beta", "gamma"]
            .into_iter()
            .map(|id| {
                let asset = asset(id);
                (asset.id.clone(), asset)
            })
            .collect();
        let inner = pack("inner", &["alpha", "beta"]);
        let outer = pack("outer", &["inner", "gamma"]);
        let base_id = ProfileId::parse("base").unwrap();
        let child_id = ProfileId::parse("child").unwrap();
        let mut manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets,
            packs: BTreeMap::from([(inner.id.clone(), inner), (outer.id.clone(), outer)]),
            profiles: BTreeMap::from([
                (
                    base_id.clone(),
                    Profile {
                        id: base_id.clone(),
                        extends: None,
                        assets: BTreeSet::from([AssetId::parse("outer").unwrap()]),
                        targets: BTreeSet::from([HarnessId::Claude]),
                    },
                ),
                (
                    child_id.clone(),
                    Profile {
                        id: child_id.clone(),
                        extends: Some(base_id),
                        assets: BTreeSet::from([AssetId::parse("beta").unwrap()]),
                        targets: BTreeSet::from([HarnessId::Codex]),
                    },
                ),
            ]),
            required_bindings: BTreeSet::new(),
        };
        manifest.refresh_pack_revisions().unwrap();

        let resolved = resolve_profile(&manifest, &child_id).unwrap();

        assert_eq!(
            resolved.assets,
            ["alpha", "beta", "gamma"]
                .into_iter()
                .map(|id| AssetId::parse(id).unwrap())
                .collect()
        );
        assert_eq!(
            resolved.targets,
            BTreeSet::from([HarnessId::Claude, HarnessId::Codex])
        );
    }

    #[test]
    fn missing_profile_has_a_stable_error() {
        let manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };

        let error = resolve_profile(&manifest, &ProfileId::parse("missing").unwrap()).unwrap_err();

        assert_eq!(error.code(), "profile.missing");
    }
}
