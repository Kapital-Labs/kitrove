use super::*;
use kitrove_model::{HarnessId, HarnessScope, PortableContent, PortablePath};

#[test]
fn authored_verified_distribution_preserves_mode() {
    let original = super::tests::manifest();
    let base = plan_authored_pack_creation(&original, id("suite"), members("alpha")).unwrap();
    let local = plan_pack_update(
        base.proposed_manifest(),
        id("suite"),
        base.pack().content_hash.clone(),
        BTreeSet::from([id("alpha"), id("beta")]),
    )
    .unwrap();
    let remote = plan_pack_update(
        base.proposed_manifest(),
        id("suite"),
        base.pack().content_hash.clone(),
        BTreeSet::from([id("alpha"), id("right")]),
    )
    .unwrap();
    assert_ne!(local.digest(), remote.digest());
    let manifest = remote.proposed_manifest();
    assert_eq!(manifest.packs[&id("suite")].members.len(), 2);
    assert_eq!(manifest.packs[&id("suite")].source, Source::AuthoredPack);
    let history = crate::VerifiedRemoteHistory::new(
        vec![(
            kitrove_model::RemoteRevision::parse("test:authored").unwrap(),
            std::sync::Arc::new(
                crate::PortableSnapshotV1::new(
                    manifest.clone(),
                    BTreeSet::new(),
                    kitrove_model::SyncLimits::default(),
                )
                .unwrap(),
            ),
        )],
        kitrove_model::SyncLimits::default(),
    )
    .unwrap();
    let selection = crate::select_pack_distribution(&history, &id("suite")).unwrap();
    let mut empty = original;
    empty.assets.clear();
    empty.packs.clear();
    let imported = crate::plan_pack_distribution_adoption(&empty, &selection).unwrap();
    assert_eq!(
        imported.proposed_manifest().packs[&id("suite")],
        manifest.packs[&id("suite")]
    );
    for (id, asset) in &imported.proposed_manifest().assets {
        assert_eq!(asset, &manifest.assets[id]);
    }
}

fn id(value: &str) -> AssetId {
    AssetId::parse(value).unwrap()
}
fn members(value: &str) -> BTreeSet<AssetId> {
    BTreeSet::from([id(value)])
}

fn native_manifest() -> EnvironmentManifest {
    let mut manifest = super::tests::manifest();
    let provenance = ComponentProvenance::new(
        Source::Harness {
            harness: HarnessId::parse("claude").unwrap(),
            origin: PortablePath::parse("skills/alpha").unwrap(),
        },
        Revision::parse("observation:alpha").unwrap(),
        ContentHash::digest(b"native"),
        Some(HarnessScope::User),
    )
    .unwrap();
    let asset = manifest.assets.get_mut(&id("alpha")).unwrap();
    asset.portable = Some(PortableContent {
        format: "agent-skills-v1".to_owned(),
        root: PortablePath::parse("alpha").unwrap(),
        object_hash: ContentHash::digest(b"object"),
        provenance: provenance.provenance_id(),
    });
    asset
        .provenance
        .insert(provenance.provenance_id(), provenance);
    asset.refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();
    manifest
}

#[test]
fn authored_preserves_native_members_and_roundtrips_without_distribution_claim() {
    let original = native_manifest();
    assert_eq!(
        plan_pack_creation(&original, id("suite"), members("alpha"))
            .unwrap_err()
            .code(),
        "pack_create.source_mismatch"
    );
    let plan = plan_authored_pack_creation(
        &original,
        id("suite"),
        BTreeSet::from([id("alpha"), id("right")]),
    )
    .unwrap();
    assert_eq!(plan.pack().source, Source::AuthoredPack);
    assert_eq!(plan.proposed_manifest().assets, original.assets);
    for (key, pack) in &original.packs {
        assert_eq!(&plan.proposed_manifest().packs[key], pack);
    }
    let decoded =
        EnvironmentManifest::from_toml(&plan.proposed_manifest().to_toml().unwrap()).unwrap();
    assert_eq!(&decoded, plan.proposed_manifest());
    assert_eq!(
        crate::derive_lockfile(&decoded).unwrap(),
        *plan.proposed_lock()
    );
    assert_eq!(
        plan_pack_creation(&decoded, id("upstream"), members("suite"))
            .unwrap_err()
            .code(),
        "pack_create.source_mismatch"
    );
    let nested = plan_authored_pack_creation(&decoded, id("nested"), members("suite")).unwrap();
    let updated = plan_pack_update(
        nested.proposed_manifest(),
        id("suite"),
        plan.pack().content_hash.clone(),
        members("right"),
    )
    .unwrap();
    assert_eq!(updated.pack().source, Source::AuthoredPack);
    assert_eq!(updated.proposed_manifest().assets, original.assets);
    assert!(updated.affected_packs().contains_key(&id("nested")));
    assert_ne!(updated.digest(), plan.digest());
}

#[test]
fn authored_declaration_cannot_be_forged_or_used_as_component_provenance() {
    let original = native_manifest();
    let plan = plan_authored_pack_creation(&original, id("suite"), members("alpha")).unwrap();
    for revision in [false, true] {
        let mut tampered = plan.proposed_manifest().clone();
        let pack = tampered.packs.get_mut(&id("suite")).unwrap();
        if revision {
            pack.revision = Revision::parse("forged").unwrap();
        } else {
            pack.exact_source_hash = ContentHash::digest(b"forged");
        }
        pack.refresh_content_hash();
        assert!(tampered.validate().is_err());
        assert!(crate::derive_lockfile(&tampered).is_err());
        let mut lock = plan.proposed_lock().clone();
        let source = &mut lock.packs.get_mut(&id("suite")).unwrap().resolved_source;
        if revision {
            source.revision = Revision::parse("forged").unwrap();
        } else {
            source.content_hash = ContentHash::digest(b"forged");
        }
        assert!(lock.validate().is_err());
    }
    assert!(
        ComponentProvenance::new(
            Source::AuthoredPack,
            Revision::parse("authored-pack-v1").unwrap(),
            ContentHash::digest(b"claim"),
            None
        )
        .is_err()
    );
    assert!(plan_authored_pack_creation(&original, id("suite"), members("missing")).is_err());
    assert!(plan_authored_pack_creation(&original, id("suite"), members("suite")).is_err());
    assert!(plan_authored_pack_creation(&original, id("alpha"), members("right")).is_err());
}
