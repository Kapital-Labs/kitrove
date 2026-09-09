use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    Asset, AssetId, AssetKind, ComponentProvenance, ContentClass, ContentHash, EnvironmentManifest,
    HarnessId, NativeVariant, Pack, PortableContent, PortablePath, Profile, ProfileId, Revision,
    SchemaVersion, Source,
};

fn id(value: &str) -> AssetId {
    AssetId::parse(value).expect("asset id")
}

fn profile_id(value: &str) -> ProfileId {
    ProfileId::parse(value).expect("profile id")
}

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).expect("hash")
}

fn source() -> Source {
    Source::Local {
        path: PortablePath::parse("sources/review").expect("portable path"),
    }
}

fn asset(asset_id: &str) -> Asset {
    let mut asset = Asset {
        id: id(asset_id),
        kind: AssetKind::Skill,
        content_hash: hash('a'),
        provenance: BTreeMap::new(),
        portable: None,
        native_variants: BTreeMap::new(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    asset
}

fn pack(pack_id: &str, members: &[&str]) -> Pack {
    Pack {
        id: id(pack_id),
        source: source(),
        revision: Revision::parse("local:1").expect("revision"),
        exact_source_hash: hash('b'),
        content_hash: hash('b'),
        members: members
            .iter()
            .copied()
            .map(|member| (id(member), hash('c')))
            .collect(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    }
}

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(id("review"), asset("review"))]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    }
}

#[test]
fn manifest_rejects_asset_key_identity_mismatch() {
    let mut manifest = manifest();
    let review = manifest.assets.remove(&id("review")).expect("review asset");
    manifest.assets.insert(id("other"), review);

    let error = manifest.validate().expect_err("key mismatch must fail");
    assert_eq!(error.code(), "manifest.asset_key_mismatch");
}

#[test]
fn manifest_rejects_native_variant_key_mismatch() {
    let mut manifest = manifest();
    let provenance = ComponentProvenance::new(
        source(),
        Revision::parse("local:1").expect("revision"),
        hash('d'),
        None,
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    manifest
        .assets
        .get_mut(&id("review"))
        .unwrap()
        .provenance
        .insert(provenance_id.clone(), provenance);
    manifest
        .assets
        .get_mut(&id("review"))
        .expect("review asset")
        .native_variants
        .insert(
            HarnessId::Claude,
            NativeVariant {
                harness: HarnessId::Codex,
                format: "codex-skill/v1".to_owned(),
                root: PortablePath::parse("assets/review/native/codex").expect("path"),
                object_hash: hash('c'),
                content_class: ContentClass::AgentActive,
                provenance: provenance_id,
            },
        );

    let error = manifest.validate().expect_err("harness mismatch must fail");
    assert_eq!(error.code(), "manifest.native_variant_key_mismatch");
}

#[test]
fn manifest_requires_exactly_the_provenance_referenced_by_components() {
    let component_provenance = ComponentProvenance::new(
        source(),
        Revision::parse("local:1").unwrap(),
        hash('c'),
        None,
    )
    .unwrap();
    let component_id = component_provenance.provenance_id();
    let mut complete = asset("review");
    complete
        .provenance
        .insert(component_id.clone(), component_provenance.clone());
    complete.portable = Some(PortableContent {
        format: "agent-skills/v1".to_owned(),
        root: PortablePath::parse("assets/review/portable").unwrap(),
        object_hash: hash('d'),
        provenance: component_id.clone(),
    });
    complete.refresh_content_hash();

    let mut missing = complete.clone();
    missing.provenance.clear();
    let missing_manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(id("review"), missing)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    assert_eq!(
        missing_manifest.validate().unwrap_err().code(),
        "manifest.provenance_missing"
    );

    let extra = ComponentProvenance::new(
        source(),
        Revision::parse("local:2").unwrap(),
        hash('e'),
        None,
    )
    .unwrap();
    let mut unreferenced = complete.clone();
    unreferenced.provenance.insert(extra.provenance_id(), extra);
    let unreferenced_manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(id("review"), unreferenced)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    assert_eq!(
        unreferenced_manifest.validate().unwrap_err().code(),
        "manifest.provenance_unreferenced"
    );

    let wrong_key = ComponentProvenance::new(
        source(),
        Revision::parse("local:wrong-key").unwrap(),
        hash('f'),
        None,
    )
    .unwrap()
    .provenance_id();
    let mut mismatched = complete;
    mismatched.provenance = BTreeMap::from([(wrong_key, component_provenance)]);
    let mismatched_manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(id("review"), mismatched)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    assert_eq!(
        mismatched_manifest.validate().unwrap_err().code(),
        "manifest.provenance_key_mismatch"
    );
}

#[test]
fn manifest_rejects_duplicate_identity_across_assets_and_packs() {
    let mut manifest = manifest();
    manifest
        .packs
        .insert(id("review"), pack("review", &["review"]));

    let error = manifest
        .validate()
        .expect_err("duplicate identity must fail");
    assert_eq!(error.code(), "manifest.duplicate_identity");
}

#[test]
fn manifest_rejects_pack_kind_in_the_plain_asset_map() {
    let mut manifest = manifest();
    manifest.assets.get_mut(&id("review")).expect("asset").kind = AssetKind::Pack;

    let error = manifest
        .validate()
        .expect_err("pack kind must use pack map");
    assert_eq!(error.code(), "manifest.pack_in_asset_map");
}

#[test]
fn manifest_rejects_undeclared_asset_bindings() {
    let mut manifest = manifest();
    manifest
        .assets
        .get_mut(&id("review"))
        .expect("asset")
        .required_bindings
        .insert(kitrove_model::BindingName::parse("token").expect("binding"));

    let error = manifest
        .validate()
        .expect_err("binding must be declared globally");
    assert_eq!(error.code(), "manifest.undeclared_binding");
}

#[test]
fn manifest_rejects_missing_pack_member() {
    let mut manifest = manifest();
    manifest
        .packs
        .insert(id("bundle"), pack("bundle", &["missing"]));

    let error = manifest.validate().expect_err("missing member must fail");
    assert_eq!(error.code(), "manifest.unknown_pack_member");
}

#[test]
fn manifest_rejects_empty_pack() {
    let mut manifest = manifest();
    manifest.packs.insert(id("bundle"), pack("bundle", &[]));

    let error = manifest.validate().expect_err("empty pack must fail");
    assert_eq!(error.code(), "manifest.pack_empty");
}

#[test]
fn manifest_rejects_pack_cycles() {
    let mut manifest = manifest();
    manifest.packs.insert(id("alpha"), pack("alpha", &["beta"]));
    manifest.packs.insert(id("beta"), pack("beta", &["alpha"]));

    let error = manifest.validate().expect_err("pack cycle must fail");
    assert_eq!(error.code(), "manifest.pack_cycle");
}

#[test]
fn manifest_rejects_profile_cycles() {
    let mut manifest = manifest();
    manifest.profiles.insert(
        profile_id("work"),
        Profile {
            id: profile_id("work"),
            extends: Some(profile_id("base")),
            assets: BTreeSet::new(),
            targets: BTreeSet::new(),
        },
    );
    manifest.profiles.insert(
        profile_id("base"),
        Profile {
            id: profile_id("base"),
            extends: Some(profile_id("work")),
            assets: BTreeSet::new(),
            targets: BTreeSet::new(),
        },
    );

    let error = manifest.validate().expect_err("profile cycle must fail");
    assert_eq!(error.code(), "manifest.profile_cycle");
}

#[test]
fn manifest_accepts_acyclic_pack_and_profile_graphs() {
    let mut manifest = manifest();
    manifest
        .packs
        .insert(id("inner"), pack("inner", &["review"]));
    manifest
        .packs
        .insert(id("outer"), pack("outer", &["inner"]));
    manifest.profiles.insert(
        profile_id("base"),
        Profile {
            id: profile_id("base"),
            extends: None,
            assets: BTreeSet::from([id("inner")]),
            targets: BTreeSet::from([HarnessId::Claude]),
        },
    );
    manifest.profiles.insert(
        profile_id("work"),
        Profile {
            id: profile_id("work"),
            extends: Some(profile_id("base")),
            assets: BTreeSet::from([id("outer")]),
            targets: BTreeSet::from([HarnessId::Codex]),
        },
    );

    manifest
        .refresh_pack_revisions()
        .expect("acyclic graph is valid");
}
