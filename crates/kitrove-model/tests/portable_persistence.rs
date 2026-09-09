use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    Asset, AssetId, AssetKind, ComponentProvenance, ContentClass, ContentHash, EnvironmentManifest,
    Fidelity, FidelityReason, FidelityResult, HarnessId, LockedPack, Lockfile, NativeVariant, Pack,
    PortableContent, PortablePath, Profile, ProfileId, RepositoryUrl, ResolvedSource, Revision,
    SchemaVersion, Source,
};

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).expect("test hash")
}

fn source() -> Source {
    Source::Git {
        repository: RepositoryUrl::parse("https://example.test/capabilities.git")
            .expect("repository URL"),
        subdirectory: Some(PortablePath::parse("skills/review").expect("portable path")),
    }
}

fn skill(id: &str, byte: char) -> Asset {
    let id = AssetId::parse(id).expect("asset id");
    let content_hash = hash(byte);
    let mut compatibility = BTreeMap::new();
    compatibility.insert(
        HarnessId::Claude,
        FidelityResult::new(
            Fidelity::Partial,
            vec![FidelityReason::new(
                "frontmatter.omitted",
                "one native metadata field remains only in the Claude variant",
            )],
            vec![kitrove_model::FidelityEvidence::new(
                "fixture.matrix",
                "fixture records one omitted metadata field",
            )],
            vec![],
            "claude-adapter/1",
            Some("2.0.0".to_owned()),
        )
        .expect("partial fidelity has a reason"),
    );
    let provenance = ComponentProvenance::new(
        source(),
        Revision::parse("git:0123456789abcdef").expect("revision"),
        content_hash.clone(),
        None,
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    let mut native_variants = BTreeMap::new();
    native_variants.insert(
        HarnessId::Claude,
        NativeVariant {
            harness: HarnessId::Claude,
            format: "claude-skill/v1".to_owned(),
            root: PortablePath::parse(format!("assets/{id}/native/claude")).expect("root"),
            object_hash: content_hash.clone(),
            content_class: ContentClass::AgentActive,
            provenance: provenance_id.clone(),
        },
    );
    let mut asset = Asset {
        id: id.clone(),
        kind: AssetKind::Skill,
        content_hash: content_hash.clone(),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: PortablePath::parse(format!("assets/{id}/portable")).expect("root"),
            object_hash: content_hash,
            provenance: provenance_id,
        }),
        native_variants,
        compatibility,
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    asset
}

fn manifest() -> EnvironmentManifest {
    let alpha = skill("alpha", 'a');
    let beta = skill("beta", 'b');
    let mut assets = BTreeMap::new();
    assets.insert(beta.id.clone(), beta);
    assets.insert(alpha.id.clone(), alpha);

    let pack_id = AssetId::parse("review-pack").expect("pack id");
    let pack_members = assets
        .iter()
        .map(|(id, asset)| (id.clone(), asset.content_hash.clone()))
        .collect();
    let packs = BTreeMap::from([(
        pack_id.clone(),
        Pack {
            id: pack_id,
            source: source(),
            revision: Revision::parse("git:0123456789abcdef").expect("revision"),
            exact_source_hash: hash('c'),
            content_hash: hash('c'),
            members: pack_members,
            compatibility: BTreeMap::new(),
            content_class: ContentClass::AgentActive,
            required_bindings: BTreeSet::new(),
        },
    )]);

    let profile_id = ProfileId::parse("default").expect("profile id");
    let profiles = BTreeMap::from([(
        profile_id.clone(),
        Profile {
            id: profile_id,
            extends: None,
            assets: BTreeSet::from([AssetId::parse("review-pack").expect("pack id")]),
            targets: BTreeSet::from([HarnessId::Claude, HarnessId::Codex]),
        },
    )]);

    let mut manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets,
        packs,
        profiles,
        required_bindings: BTreeSet::new(),
    };
    manifest
        .refresh_pack_revisions()
        .expect("refresh pack aggregate");
    manifest
}

#[test]
fn environment_manifest_round_trips_deterministically() {
    let manifest = manifest();
    let encoded = manifest.to_toml().expect("serialize manifest");
    let decoded = EnvironmentManifest::from_toml(&encoded).expect("deserialize manifest");

    assert_eq!(decoded, manifest);
    assert_eq!(decoded.to_toml().expect("serialize again"), encoded);
    assert!(encoded.find("[assets.alpha]") < encoded.find("[assets.beta]"));
}

#[test]
fn native_variants_and_fidelity_reasons_survive_round_trip() {
    let encoded = manifest().to_toml().expect("serialize manifest");
    let decoded = EnvironmentManifest::from_toml(&encoded).expect("deserialize manifest");
    let alpha = &decoded.assets[&AssetId::parse("alpha").expect("asset id")];

    assert!(alpha.native_variants.contains_key(&HarnessId::Claude));
    assert_eq!(alpha.compatibility[&HarnessId::Claude].reasons().len(), 1);
}

#[test]
fn portable_schema_rejects_unknown_and_credential_like_fields() {
    let unknown = "schema_version = 1\nsecret_value = 'canary'\n";
    let credential = "schema_version = 1\napi_key = 'canary'\n";

    assert!(EnvironmentManifest::from_toml(unknown).is_err());
    let error = EnvironmentManifest::from_toml(credential).expect_err("credential field");
    assert!(
        !error.to_string().contains("canary"),
        "parser errors must not echo rejected secret values"
    );
}

#[test]
fn portable_schema_rejects_duplicate_asset_tables() {
    let duplicate = r#"
schema_version = 1

[assets.review]
id = "review"

[assets.review]
id = "review"
"#;
    assert!(EnvironmentManifest::from_toml(duplicate).is_err());
}

fn lockfile(asset_order: [&str; 2]) -> Lockfile {
    let mut assets = BTreeMap::new();
    for id in asset_order {
        let id = AssetId::parse(id).expect("asset id");
        let (revision, content_hash) = match id.as_str() {
            "alpha" => ("git:0000000000000000", hash('d')),
            "beta" => ("git:0000000000000001", hash('e')),
            unexpected => panic!("unexpected fixture asset {unexpected}"),
        };
        let provenance = ComponentProvenance::new(
            source(),
            Revision::parse(revision).expect("revision"),
            content_hash.clone(),
            None,
        )
        .unwrap();
        let provenance_id = provenance.provenance_id();
        assets.insert(
            id.clone(),
            kitrove_model::LockedAsset {
                id,
                kind: AssetKind::Skill,
                content_hash,
                portable_provenance: Some(provenance_id.clone()),
                native_provenance: BTreeMap::new(),
                provenance: BTreeMap::from([(provenance_id, provenance)]),
                compatibility: BTreeMap::new(),
            },
        );
    }
    let members = assets
        .iter()
        .map(|(id, asset)| (id.clone(), asset.content_hash.clone()))
        .collect();
    Lockfile {
        schema_version: SchemaVersion::V1,
        assets,
        packs: BTreeMap::from([(
            AssetId::parse("review-pack").expect("pack id"),
            LockedPack {
                id: AssetId::parse("review-pack").expect("pack id"),
                resolved_source: ResolvedSource {
                    source: source(),
                    revision: Revision::parse("git:pack000000000001").expect("revision"),
                    content_hash: hash('f'),
                },
                content_hash: hash('0'),
                members,
                compatibility: BTreeMap::new(),
            },
        )]),
    }
}

#[test]
fn lockfile_serialization_is_ordered_and_repeatable() {
    let first = lockfile(["alpha", "beta"]);
    let second = lockfile(["beta", "alpha"]);

    let first_json = first.to_json().expect("serialize first lockfile");
    assert_eq!(first_json, first.to_json().expect("serialize repeatedly"));
    assert!(first_json.find("\"alpha\"") < first_json.find("\"beta\""));
    assert_eq!(
        first_json,
        second.to_json().expect("serialize second lockfile")
    );

    let decoded = Lockfile::from_json(&first_json).expect("deserialize lockfile");
    assert_eq!(decoded, first);
    assert!(
        decoded
            .packs
            .contains_key(&AssetId::parse("review-pack").expect("pack id"))
    );
    assert_eq!(first, second, "insertion order is not semantic");
}

#[test]
fn lockfile_rejects_pack_cycles() {
    let mut lockfile = lockfile(["alpha", "beta"]);
    let first_id = AssetId::parse("review-pack").expect("pack id");
    let second_id = AssetId::parse("nested-pack").expect("pack id");
    lockfile
        .packs
        .get_mut(&first_id)
        .expect("first pack")
        .members
        .insert(second_id.clone(), hash('1'));
    lockfile.packs.insert(
        second_id.clone(),
        LockedPack {
            id: second_id,
            resolved_source: ResolvedSource {
                source: source(),
                revision: Revision::parse("git:pack000000000002").expect("revision"),
                content_hash: hash('1'),
            },
            content_hash: hash('2'),
            members: BTreeMap::from([(first_id, hash('0'))]),
            compatibility: BTreeMap::new(),
        },
    );

    assert!(lockfile.to_json().is_err(), "pack cycles must not persist");
}

#[test]
fn lockfile_rejects_empty_pack() {
    let mut lockfile = lockfile(["alpha", "beta"]);
    lockfile
        .packs
        .get_mut(&AssetId::parse("review-pack").expect("pack id"))
        .expect("pack")
        .members
        .clear();

    assert_eq!(
        lockfile.validate().unwrap_err().code(),
        "lockfile.pack_empty"
    );
}

#[test]
fn lockfile_refuses_pack_graphs_beyond_the_compiled_member_budget() {
    let mut lockfile = lockfile(["alpha", "beta"]);
    lockfile
        .packs
        .get_mut(&AssetId::parse("review-pack").expect("pack id"))
        .expect("pack")
        .members = (0..=4096)
        .map(|index| {
            (
                AssetId::parse(format!("member-{index:04}")).expect("asset id"),
                hash('f'),
            )
        })
        .collect();

    assert_eq!(
        lockfile.validate().unwrap_err().code(),
        "lockfile.pack_member_limit_exceeded"
    );
}

#[test]
fn lockfile_refuses_excessive_pack_nesting_independent_of_key_order() {
    let mut lockfile = lockfile(["alpha", "beta"]);
    let alpha = AssetId::parse("alpha").expect("asset id");
    let alpha_revision = lockfile.assets[&alpha].content_hash.clone();
    for index in (0..64).rev() {
        let (member, revision) = if index == 63 {
            (alpha.clone(), alpha_revision.clone())
        } else {
            (
                AssetId::parse(format!("a-nested-pack-{:02}", index + 1)).expect("pack id"),
                hash('1'),
            )
        };
        let id = AssetId::parse(format!("a-nested-pack-{index:02}")).expect("pack id");
        lockfile.packs.insert(
            id.clone(),
            LockedPack {
                id,
                resolved_source: ResolvedSource {
                    source: source(),
                    revision: Revision::parse("git:pack-depth-fixture").expect("revision"),
                    content_hash: hash('1'),
                },
                content_hash: hash('1'),
                members: BTreeMap::from([(member, revision)]),
                compatibility: BTreeMap::new(),
            },
        );
    }
    let outer = AssetId::parse("z-outer-pack").expect("pack id");
    lockfile.packs.insert(
        outer.clone(),
        LockedPack {
            id: outer,
            resolved_source: ResolvedSource {
                source: source(),
                revision: Revision::parse("git:pack-depth-fixture").expect("revision"),
                content_hash: hash('1'),
            },
            content_hash: hash('1'),
            members: BTreeMap::from([(
                AssetId::parse("a-nested-pack-00").expect("pack id"),
                hash('1'),
            )]),
            compatibility: BTreeMap::new(),
        },
    );

    assert_eq!(
        lockfile.validate().unwrap_err().code(),
        "lockfile.pack_depth_limit_exceeded"
    );
}

#[test]
fn lockfile_accepts_exact_member_and_depth_boundaries() {
    let mut wide = lockfile(["alpha", "beta"]);
    let alpha = AssetId::parse("alpha").expect("asset id");
    let alpha_revision = wide.assets[&alpha].content_hash.clone();
    wide.packs = (0..4096)
        .map(|index| {
            let id = AssetId::parse(format!("boundary-pack-{index:04}")).expect("pack id");
            (
                id.clone(),
                LockedPack {
                    id,
                    resolved_source: ResolvedSource {
                        source: source(),
                        revision: Revision::parse("git:pack-boundary").expect("revision"),
                        content_hash: hash('1'),
                    },
                    content_hash: hash('1'),
                    members: BTreeMap::from([(alpha.clone(), alpha_revision.clone())]),
                    compatibility: BTreeMap::new(),
                },
            )
        })
        .collect();
    wide.validate().unwrap();

    let mut deep = lockfile(["alpha", "beta"]);
    deep.packs.clear();
    for index in (0..64).rev() {
        let (member, revision) = if index == 63 {
            (alpha.clone(), alpha_revision.clone())
        } else {
            (
                AssetId::parse(format!("depth-pack-{:02}", index + 1)).expect("pack id"),
                hash('1'),
            )
        };
        let id = AssetId::parse(format!("depth-pack-{index:02}")).expect("pack id");
        deep.packs.insert(
            id.clone(),
            LockedPack {
                id,
                resolved_source: ResolvedSource {
                    source: source(),
                    revision: Revision::parse("git:pack-depth").expect("revision"),
                    content_hash: hash('1'),
                },
                content_hash: hash('1'),
                members: BTreeMap::from([(member, revision)]),
                compatibility: BTreeMap::new(),
            },
        );
    }
    deep.validate().unwrap();
}

#[test]
fn lockfile_maximum_budget_graphs_refuse_before_unbounded_recursion() {
    fn graph(cyclic: bool) -> Lockfile {
        let mut lockfile = lockfile(["alpha", "beta"]);
        let alpha = AssetId::parse("alpha").expect("asset id");
        let alpha_revision = lockfile.assets[&alpha].content_hash.clone();
        lockfile.packs.clear();
        for index in (0..4096).rev() {
            let (member, revision) = if index == 4095 {
                if cyclic {
                    (
                        AssetId::parse("hostile-pack-0000").expect("pack id"),
                        hash('1'),
                    )
                } else {
                    (alpha.clone(), alpha_revision.clone())
                }
            } else {
                (
                    AssetId::parse(format!("hostile-pack-{:04}", index + 1)).expect("pack id"),
                    hash('1'),
                )
            };
            let id = AssetId::parse(format!("hostile-pack-{index:04}")).expect("pack id");
            lockfile.packs.insert(
                id.clone(),
                LockedPack {
                    id,
                    resolved_source: ResolvedSource {
                        source: source(),
                        revision: Revision::parse("git:pack-hostile").expect("revision"),
                        content_hash: hash('1'),
                    },
                    content_hash: hash('1'),
                    members: BTreeMap::from([(member, revision)]),
                    compatibility: BTreeMap::new(),
                },
            );
        }
        lockfile
    }

    for lockfile in [graph(false), graph(true)] {
        assert_eq!(
            lockfile.validate().unwrap_err().code(),
            "lockfile.pack_depth_limit_exceeded"
        );
    }
}
