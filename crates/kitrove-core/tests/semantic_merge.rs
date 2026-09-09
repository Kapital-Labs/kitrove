use std::collections::{BTreeMap, BTreeSet};

use kitrove_adapter_api::CapabilityMatrix;
use kitrove_agent_skills::{
    CapturedFile, CapturedTree, FileMode, NativeSkillObject, SkillSourceLayout, StoredSkillTree,
    hash_tree,
};
use kitrove_core::{
    TierOneCapabilities, VerifiedSkillObjectCatalog, derive_lockfile, merge_manifests,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, ComponentProvenance, ContentClass, ContentHash,
    EnvironmentManifest, Fidelity, HarnessId, NativeVariant, Pack, PortableContent, PortablePath,
    RepositoryUrl, Revision, SchemaVersion, Source, SyncConflictCode, SyncConflictSubject,
    SyncLimits,
};

fn capabilities() -> TierOneCapabilities {
    TierOneCapabilities::new(
        [
            HarnessId::Claude,
            HarnessId::Codex,
            HarnessId::Pi,
            HarnessId::OpenCode,
        ]
        .into_iter()
        .map(|harness| {
            (
                harness,
                CapabilityMatrix::portable_agent_skills(
                    "merge-test/1",
                    "test target accepts canonical Agent Skills packages",
                ),
            )
        })
        .collect(),
    )
    .unwrap()
}

fn tree(marker: &str, native_hook: bool) -> CapturedTree {
    let hook = if native_hook { "hooks: enabled\n" } else { "" };
    let bytes = format!("---\nname: review\ndescription: Review carefully\n{hook}---\n{marker}\n")
        .into_bytes();
    let files = BTreeMap::from([(
        PortablePath::parse("SKILL.md").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes,
        },
    )]);
    CapturedTree {
        hash: hash_tree(&files),
        files,
    }
}

fn portable(marker: &str) -> StoredSkillTree {
    StoredSkillTree::new(tree(marker, false)).unwrap()
}

fn native(marker: &str, hook: bool) -> NativeSkillObject {
    NativeSkillObject::new(
        SkillSourceLayout::Directory,
        "SKILL.md",
        "review",
        tree(marker, hook),
    )
    .unwrap()
}

fn provenance(marker: &str, exact_hash: &ContentHash) -> ComponentProvenance {
    ComponentProvenance::new(
        Source::Git {
            repository: RepositoryUrl::parse("https://example.test/review.git").unwrap(),
            subdirectory: Some(PortablePath::parse("skills/review").unwrap()),
        },
        Revision::parse(format!("git:{marker}")).unwrap(),
        exact_hash.clone(),
        None,
    )
    .unwrap()
}

fn asset(
    portable: (&StoredSkillTree, &ComponentProvenance),
    native: (&NativeSkillObject, &ComponentProvenance),
) -> Asset {
    let portable_provenance = portable.1.provenance_id();
    let native_provenance = native.1.provenance_id();
    let provenance = BTreeMap::from([
        (portable_provenance.clone(), portable.1.clone()),
        (native_provenance.clone(), native.1.clone()),
    ]);
    let mut asset = Asset {
        id: AssetId::parse("review").unwrap(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"pending"),
        provenance,
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: PortablePath::parse("assets/review/portable").unwrap(),
            object_hash: portable.0.tree().hash.clone(),
            provenance: portable_provenance,
        }),
        native_variants: BTreeMap::from([(
            HarnessId::Claude,
            NativeVariant {
                harness: HarnessId::Claude,
                format: "kitrove-native-skill-object/v1".to_owned(),
                root: PortablePath::parse("assets/review/native/claude").unwrap(),
                object_hash: native.0.hash().clone(),
                content_class: ContentClass::DataOnly,
                provenance: native_provenance,
            },
        )]),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    asset
}

fn manifest(asset: Asset) -> EnvironmentManifest {
    EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(asset.id.clone(), asset)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    }
}

fn with_pack(mut manifest: EnvironmentManifest, members: &[&str]) -> EnvironmentManifest {
    let pack_id = AssetId::parse("review-pack").unwrap();
    manifest.packs.insert(
        pack_id.clone(),
        Pack {
            id: pack_id,
            source: Source::Git {
                repository: RepositoryUrl::parse("https://example.test/review-pack.git").unwrap(),
                subdirectory: None,
            },
            revision: Revision::parse("git:pack-base").unwrap(),
            exact_source_hash: ContentHash::digest(b"pack-base-source"),
            content_hash: ContentHash::digest(b"pending-pack"),
            members: members
                .iter()
                .map(|member| {
                    (
                        AssetId::parse(*member).unwrap(),
                        ContentHash::digest(b"pending-member"),
                    )
                })
                .collect(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        },
    );
    manifest.refresh_pack_revisions().unwrap();
    manifest
}

fn rename_asset(mut asset: Asset, id: &str) -> Asset {
    asset.id = AssetId::parse(id).unwrap();
    asset.portable.as_mut().unwrap().root =
        PortablePath::parse(format!("assets/{id}/portable")).unwrap();
    asset
        .native_variants
        .get_mut(&HarnessId::Claude)
        .unwrap()
        .root = PortablePath::parse(format!("assets/{id}/native/claude")).unwrap();
    asset.refresh_content_hash();
    asset
}

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
fn independent_portable_and_native_changes_merge_with_exact_provenance() {
    let p1 = portable("portable one");
    let p2 = portable("portable two");
    let n1 = native("native one", false);
    let n2 = native("native two", true);
    let prov1 = provenance("base", &n1.tree().hash);
    let prov2 = provenance("local", &p2.tree().hash);
    let prov3 = provenance("remote", &n2.tree().hash);
    let base = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let local = manifest(asset((&p2, &prov2), (&n1, &prov1)));
    let remote = manifest(asset((&p1, &prov1), (&n2, &prov3)));
    let catalog =
        VerifiedSkillObjectCatalog::new([p1.clone(), p2.clone()], [n1.clone(), n2.clone()])
            .unwrap();

    let result = merge_manifests(
        &base,
        &local,
        &remote,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    let merged = result.merged_manifest().unwrap();
    let merged_asset = &merged.assets[&AssetId::parse("review").unwrap()];

    assert!(result.conflicts().is_empty());
    assert_eq!(
        merged_asset.portable.as_ref().unwrap().object_hash,
        p2.tree().hash
    );
    assert_eq!(
        merged_asset.native_variants[&HarnessId::Claude].object_hash,
        *n2.hash()
    );
    assert_eq!(
        merged_asset
            .provenance
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([prov2.provenance_id(), prov3.provenance_id()])
    );
    assert_eq!(merged_asset.content_class, ContentClass::Executable);
    assert_eq!(
        merged_asset.native_variants[&HarnessId::Claude].content_class,
        ContentClass::Executable
    );
    assert_eq!(
        merged_asset.compatibility[&HarnessId::Claude].fidelity(),
        Fidelity::Native
    );
    assert_eq!(
        merged_asset.compatibility[&HarnessId::Codex].fidelity(),
        Fidelity::Partial
    );
    assert_eq!(
        result.merged_lock().unwrap(),
        &derive_lockfile(merged).unwrap()
    );
}

#[test]
fn divergent_same_component_returns_data_without_merged_authority() {
    let p1 = portable("base");
    let p2 = portable("local");
    let p3 = portable("remote");
    let n1 = native("native", false);
    let prov1 = provenance("base", &p1.tree().hash);
    let prov2 = provenance("local", &p2.tree().hash);
    let prov3 = provenance("remote", &p3.tree().hash);
    let base = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let local = manifest(asset((&p2, &prov2), (&n1, &prov1)));
    let remote = manifest(asset((&p3, &prov3), (&n1, &prov1)));
    let catalog = VerifiedSkillObjectCatalog::new([], []).unwrap();

    let result = merge_manifests(
        &base,
        &local,
        &remote,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();

    assert!(!result.is_ready());
    assert!(result.merged_lock().is_none());
    assert_eq!(result.conflicts().len(), 1);
    assert_eq!(
        result.conflicts()[0].code,
        SyncConflictCode::DivergentComponent
    );
    assert!(matches!(
        result.conflicts()[0].subject,
        SyncConflictSubject::Portable { .. }
    ));
}

#[test]
fn conflict_order_is_component_stable_and_the_limit_refuses_before_overflow() {
    let p1 = portable("base");
    let p2 = portable("local");
    let p3 = portable("remote");
    let n1 = native("native base", false);
    let n2 = native("native local", false);
    let n3 = native("native remote", false);
    let prov1 = provenance("base", &p1.tree().hash);
    let prov2 = provenance("local", &p2.tree().hash);
    let prov3 = provenance("remote", &p3.tree().hash);
    let base = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let local = manifest(asset((&p2, &prov2), (&n2, &prov2)));
    let remote = manifest(asset((&p3, &prov3), (&n3, &prov3)));
    let catalog = VerifiedSkillObjectCatalog::new([], []).unwrap();

    let result = merge_manifests(
        &base,
        &local,
        &remote,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(result.conflicts().len(), 2);
    assert!(matches!(
        result.conflicts()[0].subject,
        SyncConflictSubject::Portable { .. }
    ));
    assert!(matches!(
        result.conflicts()[1].subject,
        SyncConflictSubject::Native { .. }
    ));

    let one_conflict = SyncLimits::new(
        256 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4096,
        16 * 1024 * 1024,
        240 * 1024 * 1024,
        1,
        65_536,
        4096,
    )
    .unwrap();
    assert_eq!(
        merge_manifests(
            &base,
            &local,
            &remote,
            &catalog,
            &capabilities(),
            one_conflict,
        )
        .unwrap_err()
        .code(),
        "sync_merge.conflict_limit_exceeded"
    );
}

#[test]
fn independent_additions_cannot_exceed_the_request_global_component_limit() {
    let p1 = portable("shared portable");
    let n1 = native("shared native", false);
    let prov1 = provenance("shared", &p1.tree().hash);
    let local = manifest(rename_asset(asset((&p1, &prov1), (&n1, &prov1)), "local"));
    let remote = manifest(rename_asset(asset((&p1, &prov1), (&n1, &prov1)), "remote"));
    let catalog = VerifiedSkillObjectCatalog::new([p1], [n1]).unwrap();
    let three_components = SyncLimits::new(
        256 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4096,
        16 * 1024 * 1024,
        240 * 1024 * 1024,
        1024,
        3,
        4096,
    )
    .unwrap();

    assert_eq!(
        merge_manifests(
            &empty_manifest(),
            &local,
            &remote,
            &catalog,
            &capabilities(),
            three_components,
        )
        .unwrap_err()
        .code(),
        "sync_merge.component_limit_exceeded"
    );
}

#[test]
fn deletion_is_an_explicit_nonmutating_conflict() {
    let p1 = portable("base");
    let n1 = native("native", false);
    let prov1 = provenance("base", &p1.tree().hash);
    let base = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let local = empty_manifest();
    let catalog = VerifiedSkillObjectCatalog::new([p1], [n1]).unwrap();

    let deletion = merge_manifests(
        &base,
        &local,
        &base,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(
        deletion.conflicts()[0].code,
        SyncConflictCode::DeletionUnsupported
    );
}

#[test]
fn independent_pack_member_additions_and_source_change_merge_then_rederive() {
    let portable = portable("shared");
    let native = native("shared", false);
    let provenance = provenance("shared", &portable.tree().hash);
    let mut review = asset((&portable, &provenance), (&native, &provenance));
    let token = BindingName::parse("review-token").unwrap();
    review.required_bindings.insert(token.clone());
    review.refresh_content_hash();
    let mut base = manifest(review.clone());
    base.required_bindings.insert(token.clone());
    let base = with_pack(base, &["review"]);

    let mut local = base.clone();
    let local_asset = rename_asset(review.clone(), "local-member");
    local.assets.insert(local_asset.id.clone(), local_asset);
    let local_pack = local.packs.values_mut().next().unwrap();
    local_pack.members.insert(
        AssetId::parse("local-member").unwrap(),
        ContentHash::digest(b"pending"),
    );
    local_pack.revision = Revision::parse("git:pack-local").unwrap();
    local_pack.exact_source_hash = ContentHash::digest(b"pack-local-source");
    local.refresh_pack_revisions().unwrap();

    let mut remote = base.clone();
    let remote_asset = rename_asset(review, "remote-member");
    remote.assets.insert(remote_asset.id.clone(), remote_asset);
    remote.packs.values_mut().next().unwrap().members.insert(
        AssetId::parse("remote-member").unwrap(),
        ContentHash::digest(b"pending"),
    );
    remote.refresh_pack_revisions().unwrap();

    let result = merge_manifests(
        &base,
        &local,
        &remote,
        &VerifiedSkillObjectCatalog::new([portable], [native]).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    let merged = result.merged_manifest().unwrap();
    let pack = &merged.packs[&AssetId::parse("review-pack").unwrap()];
    assert_eq!(pack.members.len(), 3);
    assert_eq!(pack.revision, Revision::parse("git:pack-local").unwrap());
    for (member, revision) in &pack.members {
        assert_eq!(revision, &merged.assets[member].content_hash);
    }
    assert_eq!(pack.content_hash, pack.expected_content_hash());
    assert_eq!(pack.required_bindings, BTreeSet::from([token.clone()]));
    assert_eq!(
        merged.assets[&AssetId::parse("review").unwrap()].required_bindings,
        BTreeSet::from([token])
    );
    assert_eq!(
        result.merged_lock().unwrap(),
        &derive_lockfile(merged).unwrap()
    );
}

#[test]
fn divergent_concurrent_pack_creation_has_no_merged_authority() {
    let portable = portable("shared");
    let native = native("shared", false);
    let provenance = provenance("shared", &portable.tree().hash);
    let review = asset((&portable, &provenance), (&native, &provenance));
    let extra = rename_asset(review.clone(), "extra");
    let mut base = manifest(review);
    base.assets.insert(extra.id.clone(), extra);
    let local = with_pack(base.clone(), &["review"]);
    let remote = with_pack(base.clone(), &["extra"]);

    let result = merge_manifests(
        &base,
        &local,
        &remote,
        &VerifiedSkillObjectCatalog::new([], []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(result.conflicts().len(), 1);
    assert_eq!(
        result.conflicts()[0].code,
        SyncConflictCode::DivergentComponent
    );
    assert!(matches!(
        result.conflicts()[0].subject,
        SyncConflictSubject::Pack { .. }
    ));
    assert!(result.merged_manifest().is_none());
    assert!(result.merged_lock().is_none());
}

#[test]
fn pack_member_deletion_and_divergent_source_are_nonmutating_conflicts() {
    let portable = portable("shared");
    let native = native("shared", false);
    let provenance = provenance("shared", &portable.tree().hash);
    let review = asset((&portable, &provenance), (&native, &provenance));
    let extra = rename_asset(review.clone(), "extra");
    let mut base = manifest(review);
    base.assets.insert(extra.id.clone(), extra);
    let base = with_pack(base, &["review", "extra"]);

    let mut deleted = base.clone();
    deleted
        .packs
        .values_mut()
        .next()
        .unwrap()
        .members
        .remove(&AssetId::parse("extra").unwrap());
    deleted.refresh_pack_revisions().unwrap();
    let deletion = merge_manifests(
        &base,
        &deleted,
        &base,
        &VerifiedSkillObjectCatalog::new([], []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(
        deletion.conflicts()[0].code,
        SyncConflictCode::DeletionUnsupported
    );
    assert!(matches!(
        deletion.conflicts()[0].subject,
        SyncConflictSubject::Pack { .. }
    ));

    let mut local = base.clone();
    let local_pack = local.packs.values_mut().next().unwrap();
    local_pack.revision = Revision::parse("git:pack-local").unwrap();
    local_pack.refresh_content_hash();
    let mut remote = base.clone();
    let remote_pack = remote.packs.values_mut().next().unwrap();
    remote_pack.revision = Revision::parse("git:pack-remote").unwrap();
    remote_pack.refresh_content_hash();
    let divergence = merge_manifests(
        &base,
        &local,
        &remote,
        &VerifiedSkillObjectCatalog::new([], []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(
        divergence.conflicts()[0].code,
        SyncConflictCode::DivergentComponent
    );
    assert!(divergence.merged_manifest().is_none());
}

#[test]
fn same_pack_member_divergence_has_no_pack_or_merged_authority() {
    let p1 = portable("base");
    let p2 = portable("local");
    let p3 = portable("remote");
    let native = native("native", false);
    let prov1 = provenance("base", &p1.tree().hash);
    let prov2 = provenance("local", &p2.tree().hash);
    let prov3 = provenance("remote", &p3.tree().hash);
    let base = with_pack(
        manifest(asset((&p1, &prov1), (&native, &prov1))),
        &["review"],
    );
    let local = with_pack(
        manifest(asset((&p2, &prov2), (&native, &prov1))),
        &["review"],
    );
    let remote = with_pack(
        manifest(asset((&p3, &prov3), (&native, &prov1))),
        &["review"],
    );

    let result = merge_manifests(
        &base,
        &local,
        &remote,
        &VerifiedSkillObjectCatalog::new([], []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(result.conflicts().len(), 1);
    assert!(matches!(
        result.conflicts()[0].subject,
        SyncConflictSubject::Portable { .. }
    ));
    assert!(result.merged_manifest().is_none());
    assert!(result.merged_lock().is_none());
}

#[test]
fn pack_member_edges_share_the_request_global_component_budget() {
    let portable = portable("shared");
    let native = native("shared", false);
    let provenance = provenance("shared", &portable.tree().hash);
    let review = asset((&portable, &provenance), (&native, &provenance));
    let extra = rename_asset(review.clone(), "extra");
    let mut manifest = manifest(review);
    manifest.assets.insert(extra.id.clone(), extra);
    manifest = with_pack(manifest, &["review", "extra"]);
    let template = manifest.packs.values().next().unwrap().clone();
    manifest.packs.clear();
    for index in 0..7 {
        let mut pack = template.clone();
        pack.id = AssetId::parse(format!("review-pack-{index}")).unwrap();
        manifest.packs.insert(pack.id.clone(), pack);
    }
    manifest.refresh_pack_revisions().unwrap();

    let limits = SyncLimits::new(
        256 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4096,
        16 * 1024 * 1024,
        240 * 1024 * 1024,
        1024,
        13,
        4096,
    )
    .unwrap();
    assert_eq!(
        merge_manifests(
            &manifest,
            &manifest,
            &manifest,
            &VerifiedSkillObjectCatalog::new([], []).unwrap(),
            &capabilities(),
            limits,
        )
        .unwrap_err()
        .code(),
        "sync_merge.component_limit_exceeded"
    );
}

#[test]
fn pack_member_budget_is_charged_before_deletion_or_divergence_conflicts() {
    let portable = portable("shared");
    let native = native("shared", false);
    let provenance = provenance("shared", &portable.tree().hash);
    let review = asset((&portable, &provenance), (&native, &provenance));
    let extra = rename_asset(review.clone(), "extra");
    let mut plain = manifest(review);
    plain.assets.insert(extra.id.clone(), extra);
    let base = with_pack(plain.clone(), &["review", "extra"]);
    let mut deleted = base.clone();
    deleted
        .packs
        .get_mut(&AssetId::parse("review-pack").unwrap())
        .unwrap()
        .members
        .remove(&AssetId::parse("extra").unwrap());
    deleted.refresh_pack_revisions().unwrap();

    let limits = SyncLimits::new(
        256 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4096,
        16 * 1024 * 1024,
        240 * 1024 * 1024,
        1024,
        8,
        4096,
    )
    .unwrap();
    assert_eq!(
        merge_manifests(
            &base,
            &deleted,
            &base,
            &VerifiedSkillObjectCatalog::new([], []).unwrap(),
            &capabilities(),
            limits,
        )
        .unwrap_err()
        .code(),
        "sync_merge.component_limit_exceeded"
    );

    let local = with_pack(plain.clone(), &["review"]);
    let remote = with_pack(plain.clone(), &["extra"]);
    assert_eq!(
        merge_manifests(
            &plain,
            &local,
            &remote,
            &VerifiedSkillObjectCatalog::new([], []).unwrap(),
            &capabilities(),
            limits,
        )
        .unwrap_err()
        .code(),
        "sync_merge.component_limit_exceeded"
    );
}

#[test]
fn identical_addition_coalesces_and_binding_sets_merge_independently() {
    let p1 = portable("added");
    let n1 = native("added", false);
    let prov1 = provenance("added", &p1.tree().hash);
    let added = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let mut local = added.clone();
    let mut remote = added.clone();
    local
        .required_bindings
        .insert(BindingName::parse("local_binding").unwrap());
    remote
        .required_bindings
        .insert(BindingName::parse("remote_binding").unwrap());
    let catalog = VerifiedSkillObjectCatalog::new([p1], [n1]).unwrap();

    let result = merge_manifests(
        &empty_manifest(),
        &local,
        &remote,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    let merged = result.merged_manifest().unwrap();
    assert_eq!(merged.assets.len(), 1);
    assert_eq!(
        merged.required_bindings,
        BTreeSet::from([
            BindingName::parse("local_binding").unwrap(),
            BindingName::parse("remote_binding").unwrap(),
        ])
    );
}

#[test]
fn missing_verified_object_blocks_derivation_without_echoing_identifiers() {
    let p1 = portable("base");
    let n1 = native("native", false);
    let prov1 = provenance("base", &p1.tree().hash);
    let base = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let error = merge_manifests(
        &base,
        &base,
        &base,
        &VerifiedSkillObjectCatalog::new([], []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap_err();

    assert_eq!(error.code(), "sync_merge.object_missing");
    assert!(!error.to_string().contains("review"));
    assert!(!format!("{error:?}").contains("review"));
}

#[test]
fn decoded_objects_remain_subject_to_merge_request_byte_limits() {
    let p1 = portable("bounded portable");
    let n1 = native("bounded native", false);
    let prov1 = provenance("bounded", &p1.tree().hash);
    let base = manifest(asset((&p1, &prov1), (&n1, &prov1)));
    let catalog = VerifiedSkillObjectCatalog::new([p1], [n1]).unwrap();
    let one_object_byte = SyncLimits::new(
        256 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4 * 1024 * 1024,
        4096,
        1,
        240 * 1024 * 1024,
        1024,
        65_536,
        4096,
    )
    .unwrap();

    assert_eq!(
        merge_manifests(
            &base,
            &base,
            &base,
            &catalog,
            &capabilities(),
            one_object_byte,
        )
        .unwrap_err()
        .code(),
        "sync_objects.object_bytes_exceeded"
    );
}

#[test]
fn portable_secret_metadata_is_rejected_without_echoing_the_canary() {
    let canary = "DO_NOT_ECHO_PORTABLE_MERGE_SECRET_19f4";
    let bytes = format!(
        "---\nname: review\ndescription: Review carefully\nmetadata:\n  access_token: {canary}\n---\nbody\n"
    )
    .into_bytes();
    let files = BTreeMap::from([(
        PortablePath::parse("SKILL.md").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes,
        },
    )]);
    let secret_portable = StoredSkillTree::new(CapturedTree {
        hash: hash_tree(&files),
        files,
    })
    .unwrap();
    let n1 = native("native", false);
    let prov = provenance("secret-portable", &secret_portable.tree().hash);
    let manifest = manifest(asset((&secret_portable, &prov), (&n1, &prov)));
    let catalog = VerifiedSkillObjectCatalog::new([secret_portable], [n1]).unwrap();

    let error = merge_manifests(
        &manifest,
        &manifest,
        &manifest,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "sync_merge.portable_document_invalid");
    assert!(!error.to_string().contains(canary));
    assert!(!format!("{error:?}").contains(canary));
}

#[test]
fn native_secret_metadata_is_rejected_during_derived_risk_recomputation() {
    let canary = "DO_NOT_ECHO_MERGE_SECRET_73d1";
    let p1 = portable("portable");
    let secret_bytes = format!(
        "---\nname: review\ndescription: Review carefully\nmetadata:\n  api_key: {canary}\n---\nbody\n"
    )
    .into_bytes();
    let files = BTreeMap::from([(
        PortablePath::parse("SKILL.md").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: secret_bytes,
        },
    )]);
    let secret_native = NativeSkillObject::new(
        SkillSourceLayout::Directory,
        "SKILL.md",
        "review",
        CapturedTree {
            hash: hash_tree(&files),
            files,
        },
    )
    .unwrap();
    let prov = provenance("secret", secret_native.hash());
    let manifest = manifest(asset((&p1, &prov), (&secret_native, &prov)));
    let catalog = VerifiedSkillObjectCatalog::new([p1], [secret_native]).unwrap();

    let error = merge_manifests(
        &manifest,
        &manifest,
        &manifest,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "sync_merge.derived_risk_invalid");
    assert!(!error.to_string().contains(canary));
}
