use std::collections::BTreeMap;
use std::fs;

use kitrove_adapter_api::{CapabilityMatrix, RootId, RootTier};
use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, StoredSkillTree, hash_tree};
use kitrove_core::{
    CapturedNativeExtension, NativeExtensionDisposition, NativeExtensionLayout,
    NativeExtensionObservation, PortableSnapshotV1, RemoteSnapshot, TierOneCapabilities,
    VerifiedObjectEnvelope, VerifiedSkillObjectCatalog, commit_native_extension_plan,
    derive_lockfile, guard_asset_materialization, merge_manifests, plan_native_extension_adoption,
    plan_native_extension_update, plan_sync,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, BlockedRequirement, ComponentProvenance, ContentClass, ContentHash,
    Fidelity, HarnessId, HarnessScope, PortableContent, PortablePath, RemoteRevision,
    RepositoryUrl, Revision, Source, SyncConflictCode, SyncConflictSubject, SyncLimits,
};
use kitrove_testkit::portable_manifest;

fn observation(bytes: &[u8]) -> NativeExtensionObservation {
    observation_with_id(bytes, "review")
}

fn observation_with_id(bytes: &[u8], native_id: &str) -> NativeExtensionObservation {
    let source_name = format!("{native_id}.ts");
    let files = BTreeMap::from([(
        PortablePath::parse(source_name.clone()).unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: bytes.to_vec(),
        },
    )]);
    let exact = CapturedTree {
        hash: hash_tree(&files),
        files,
    };
    NativeExtensionObservation::new(
        HarnessScope::User,
        RootTier::User,
        RootId::parse("pi.user.native.extensions").unwrap(),
        15,
        PortablePath::parse(source_name.clone()).unwrap(),
        native_id,
        CapturedNativeExtension {
            layout: NativeExtensionLayout::Standalone,
            entrypoint: source_name,
            exact,
            content_class: ContentClass::Executable,
        },
    )
    .unwrap()
}

fn asset_id() -> AssetId {
    AssetId::parse("native-review").unwrap()
}

fn empty_manifest() -> kitrove_model::EnvironmentManifest {
    let mut manifest = portable_manifest();
    manifest.assets.clear();
    manifest.packs.clear();
    manifest.profiles.clear();
    manifest.required_bindings.clear();
    manifest
}

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
                    "native-extension-merge-test/1",
                    "test target accepts canonical Agent Skills packages",
                ),
            )
        })
        .collect(),
    )
    .unwrap()
}

#[cfg(target_os = "macos")]
fn temporary_directory() -> tempfile::TempDir {
    tempfile::tempdir_in("/private/tmp").unwrap()
}

#[cfg(not(target_os = "macos"))]
fn temporary_directory() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn portable_skill() -> (Asset, StoredSkillTree) {
    let files = BTreeMap::from([(
        PortablePath::parse("SKILL.md").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes:
                b"---\nname: portable-review\ndescription: Portable review skill\n---\nReview.\n"
                    .to_vec(),
        },
    )]);
    let object = StoredSkillTree::new(CapturedTree {
        hash: hash_tree(&files),
        files,
    })
    .unwrap();
    let provenance = ComponentProvenance::new(
        Source::Git {
            repository: RepositoryUrl::parse("https://example.test/portable-review.git").unwrap(),
            subdirectory: None,
        },
        Revision::parse("git:portable-review").unwrap(),
        object.tree().hash.clone(),
        None,
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: AssetId::parse("portable-review").unwrap(),
        kind: AssetKind::Skill,
        content_hash: ContentHash::digest(b"pending"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: PortablePath::parse("assets/portable-review/portable").unwrap(),
            object_hash: object.tree().hash.clone(),
            provenance: provenance_id,
        }),
        native_variants: BTreeMap::new(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::AgentActive,
        required_bindings: Default::default(),
    };
    asset.refresh_content_hash();
    (asset, object)
}

#[test]
fn adoption_preserves_before_trust_without_mutating_input_authority() {
    let manifest = portable_manifest();
    let plan = plan_native_extension_adoption(
        &observation(b"export default {};\n"),
        Some(asset_id()),
        &manifest,
    )
    .unwrap();
    assert_eq!(plan.asset().id, asset_id());
    assert_eq!(
        plan.asset().compatibility[&HarnessId::Pi].blocked_requirements(),
        &[BlockedRequirement::ExecutableTrust]
    );
    assert_eq!(manifest, portable_manifest());
    assert!(!format!("{plan:?}").contains("export default"));
}

#[test]
fn adoption_infers_a_valid_native_id_or_requires_an_explicit_asset_id() {
    let inferred = plan_native_extension_adoption(
        &observation(b"export default {};\n"),
        None,
        &empty_manifest(),
    )
    .unwrap();
    assert_eq!(inferred.asset().id.as_str(), "review");

    let invalid = observation_with_id(b"export default {};\n", "Review");
    assert_eq!(
        plan_native_extension_adoption(&invalid, None, &empty_manifest())
            .unwrap_err()
            .code(),
        "native_extension.asset_id_required"
    );
    assert_eq!(
        plan_native_extension_adoption(&invalid, Some(asset_id()), &empty_manifest())
            .unwrap()
            .asset()
            .id,
        asset_id()
    );
}

#[test]
fn project_extension_provenance_is_trust_neutral_and_exactly_verifiable() {
    let captured = observation(b"export default {};\n").captured().clone();
    for trust_tag in ["trusted", "declined", "unknown"] {
        assert_eq!(
            NativeExtensionObservation::new(
                HarnessScope::Project,
                RootTier::Project,
                RootId::parse(format!("pi.project.native.extensions.{trust_tag}")).unwrap(),
                35,
                PortablePath::parse("review.ts").unwrap(),
                "review",
                captured.clone(),
            )
            .unwrap_err()
            .code(),
            "native_extension.observation_invalid"
        );
    }
    let observed = NativeExtensionObservation::new(
        HarnessScope::Project,
        RootTier::Project,
        RootId::parse("pi.project.native.extensions").unwrap(),
        35,
        PortablePath::parse("review.ts").unwrap(),
        "review",
        captured,
    )
    .unwrap();
    let plan =
        plan_native_extension_adoption(&observed, Some(asset_id()), &empty_manifest()).unwrap();
    let provenance = plan.asset().provenance.values().next().unwrap();
    assert!(matches!(
        provenance.source(),
        Source::Harness { harness: HarnessId::Pi, origin }
            if origin.as_str()
                == "observations/pi/project/pi.project.native.extensions/review.ts"
    ));
    assert!(
        !plan
            .proposed_manifest()
            .to_toml()
            .unwrap()
            .contains("trusted")
    );
    assert!(
        !plan
            .proposed_manifest()
            .to_toml()
            .unwrap()
            .contains("declined")
    );
    assert!(
        !plan
            .proposed_manifest()
            .to_toml()
            .unwrap()
            .contains("unknown")
    );

    let native = &plan.asset().native_variants[&HarnessId::Pi];
    let envelope =
        VerifiedObjectEnvelope::native_extension(native.root.clone(), plan.native_object().clone())
            .unwrap();
    let snapshot = PortableSnapshotV1::new(
        plan.proposed_manifest().clone(),
        [envelope.descriptor().clone()].into_iter().collect(),
        SyncLimits::default(),
    )
    .unwrap();
    let catalog =
        VerifiedSkillObjectCatalog::new_with_extensions([], [], [plan.native_object().clone()])
            .unwrap();
    plan_sync(
        snapshot,
        None,
        RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
}

#[test]
fn observation_refuses_nested_sources_and_standalone_entrypoint_substitution() {
    let directory_files = BTreeMap::from([(
        PortablePath::parse("index.ts").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: b"export default {};\n".to_vec(),
        },
    )]);
    assert_eq!(
        NativeExtensionObservation::new(
            HarnessScope::User,
            RootTier::User,
            RootId::parse("pi.user.native.extensions").unwrap(),
            15,
            PortablePath::parse("nested/review").unwrap(),
            "nested/review",
            CapturedNativeExtension {
                layout: NativeExtensionLayout::Directory,
                entrypoint: "index.ts".to_owned(),
                exact: CapturedTree {
                    hash: hash_tree(&directory_files),
                    files: directory_files,
                },
                content_class: ContentClass::Executable,
            },
        )
        .unwrap_err()
        .code(),
        "native_extension.observation_invalid"
    );

    let standalone_files = BTreeMap::from([(
        PortablePath::parse("other.ts").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: b"export default {};\n".to_vec(),
        },
    )]);
    assert_eq!(
        NativeExtensionObservation::new(
            HarnessScope::User,
            RootTier::User,
            RootId::parse("pi.user.native.extensions").unwrap(),
            15,
            PortablePath::parse("review.ts").unwrap(),
            "review",
            CapturedNativeExtension {
                layout: NativeExtensionLayout::Standalone,
                entrypoint: "other.ts".to_owned(),
                exact: CapturedTree {
                    hash: hash_tree(&standalone_files),
                    files: standalone_files,
                },
                content_class: ContentClass::Executable,
            },
        )
        .unwrap_err()
        .code(),
        "native_extension.observation_invalid"
    );
}

#[test]
fn sync_rejects_a_forged_native_extension_compatibility_matrix() {
    let plan = plan_native_extension_adoption(
        &observation(b"export default {};\n"),
        Some(asset_id()),
        &empty_manifest(),
    )
    .unwrap();
    let mut manifest = plan.proposed_manifest().clone();
    let asset = manifest.assets.get_mut(&asset_id()).unwrap();
    asset.compatibility.remove(&HarnessId::Claude);
    asset.refresh_content_hash();

    let root = plan.asset().native_variants[&HarnessId::Pi].root.clone();
    let envelope =
        VerifiedObjectEnvelope::native_extension(root, plan.native_object().clone()).unwrap();
    let snapshot = PortableSnapshotV1::new(
        manifest,
        [envelope.descriptor().clone()].into_iter().collect(),
        SyncLimits::default(),
    )
    .unwrap();
    let catalog =
        VerifiedSkillObjectCatalog::new_with_extensions([], [], [plan.native_object().clone()])
            .unwrap();

    let error = plan_sync(
        snapshot,
        None,
        RemoteSnapshot::absent(RemoteRevision::parse("filesystem:absent:v1").unwrap()),
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), "sync.plan_invalid");
}

#[test]
fn first_adoption_is_native_only_and_truthfully_blocked_for_apply() {
    let manifest = portable_manifest();
    let plan = plan_native_extension_adoption(
        &observation(b"export default {};\n"),
        Some(asset_id()),
        &manifest,
    )
    .unwrap();
    assert_eq!(plan.disposition(), NativeExtensionDisposition::First);
    assert_eq!(plan.asset().kind, AssetKind::Extension);
    assert!(plan.asset().portable.is_none());
    assert_eq!(plan.asset().native_variants.len(), 1);
    assert_eq!(
        plan.asset().native_variants[&HarnessId::Pi].format,
        "kitrove-native-pi-extension-object/v1"
    );
    let pi = &plan.asset().compatibility[&HarnessId::Pi];
    assert_eq!(pi.fidelity(), Fidelity::Blocked);
    assert_eq!(
        pi.blocked_requirements(),
        &[BlockedRequirement::ExecutableTrust]
    );
    for harness in [HarnessId::Claude, HarnessId::Codex, HarnessId::OpenCode] {
        assert_eq!(
            plan.asset().compatibility[&harness].fidelity(),
            Fidelity::Unsupported
        );
    }
    assert!(plan.proposed_manifest().assets.contains_key(&asset_id()));
    let provenance = plan.asset().provenance.values().next().unwrap();
    let observed = observation(b"export default {};\n");
    assert_eq!(provenance.revision().as_str(), observed.identity().as_str());
    assert_eq!(
        provenance.exact_source_hash(),
        &observed.captured().exact.hash
    );
    assert_eq!(
        guard_asset_materialization(plan.proposed_manifest(), &asset_id())
            .unwrap_err()
            .code(),
        "apply.executable_trust_required"
    );
    assert!(!format!("{plan:?}").contains("export default"));
}

#[test]
fn repeated_adoption_is_idempotent_and_changed_content_requires_exact_prior_update() {
    let first_observation = observation(b"export default { version: 1 };\n");
    let first =
        plan_native_extension_adoption(&first_observation, Some(asset_id()), &portable_manifest())
            .unwrap();
    let current = first.proposed_manifest().clone();

    let repeated =
        plan_native_extension_adoption(&first_observation, Some(asset_id()), &current).unwrap();
    assert_eq!(
        repeated.disposition(),
        NativeExtensionDisposition::Idempotent
    );

    let changed = observation(b"export default { version: 2 };\n");
    assert_eq!(
        plan_native_extension_adoption(&changed, Some(asset_id()), &current)
            .unwrap_err()
            .code(),
        "native_extension.asset_conflict"
    );
    let prior = current.assets[&asset_id()].content_hash.clone();
    let update =
        plan_native_extension_update(&changed, asset_id(), prior.clone(), &current).unwrap();
    assert_eq!(update.disposition(), NativeExtensionDisposition::Update);
    assert_eq!(update.expected_prior(), Some(&prior));
    assert_ne!(update.asset().content_hash, prior);
    assert_ne!(
        update.asset().native_variants[&HarnessId::Pi].root,
        first.asset().native_variants[&HarnessId::Pi].root
    );

    let forged = ContentHash::digest(b"not-current");
    assert_eq!(
        plan_native_extension_update(&changed, asset_id(), forged, &current,)
            .unwrap_err()
            .code(),
        "native_extension.expected_prior_mismatch"
    );
}

#[test]
fn freshness_binds_both_exact_observation_and_manifest_revision() {
    let observed = observation(b"export default {};\n");
    let manifest = portable_manifest();
    let plan = plan_native_extension_adoption(&observed, Some(asset_id()), &manifest).unwrap();
    plan.ensure_fresh(&observed, &manifest).unwrap();
    assert_eq!(
        plan.ensure_fresh(&observation(b"changed\n"), &manifest)
            .unwrap_err()
            .code(),
        "native_extension.plan_stale"
    );
}

#[test]
fn semantic_sync_rederives_native_only_extension_without_portable_coercion() {
    let base = empty_manifest();
    let plan = plan_native_extension_adoption(
        &observation(b"export default {};\n"),
        Some(asset_id()),
        &base,
    )
    .unwrap();
    let local = plan.proposed_manifest().clone();
    let catalog =
        VerifiedSkillObjectCatalog::new_with_extensions([], [], [plan.native_object().clone()])
            .unwrap();

    let merged = merge_manifests(
        &base,
        &local,
        &base,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert!(
        merged.conflicts().is_empty(),
        "unexpected conflicts: {:?}",
        merged.conflicts()
    );
    let asset = &merged.merged_manifest().unwrap().assets[&asset_id()];
    assert_eq!(asset.kind, AssetKind::Extension);
    assert!(asset.portable.is_none());
    assert_eq!(asset.native_variants.len(), 1);
    assert_eq!(asset.content_hash, plan.asset().content_hash);
}

#[test]
fn commit_preserves_without_trust_then_uses_atomic_portable_transaction() {
    let temporary = temporary_directory();
    let root = temporary.path();
    let manifest = empty_manifest();
    let manifest_text = manifest.to_toml().unwrap();
    let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
    kitrove_testkit::owned_fixture::create(&root.join("kitrove.toml"), manifest_text.as_bytes());
    kitrove_testkit::owned_fixture::create(&root.join("kitrove.lock.json"), lock_text.as_bytes());
    let observed = observation(b"export default {};\n");
    let plan = plan_native_extension_adoption(&observed, Some(asset_id()), &manifest).unwrap();
    let native = &plan.asset().native_variants[&HarnessId::Pi];
    let envelope =
        VerifiedObjectEnvelope::native_extension(native.root.clone(), plan.native_object().clone())
            .unwrap();

    commit_native_extension_plan(
        root,
        &plan,
        &observed,
        &[],
        std::slice::from_ref(&envelope),
        SyncLimits::default(),
    )
    .unwrap();
    let committed = kitrove_model::EnvironmentManifest::from_toml(
        &fs::read_to_string(root.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(committed, *plan.proposed_manifest());
    assert!(
        root.join(native.root.as_str())
            .join("metadata.json")
            .is_file()
    );
    assert!(
        root.join(native.root.as_str())
            .join("payload/review.ts")
            .is_file()
    );

    let changed = observation(b"export default { version: 2 };\n");
    let expected_prior = committed.assets[&asset_id()].content_hash.clone();
    let update =
        plan_native_extension_update(&changed, asset_id(), expected_prior, &committed).unwrap();
    let updated_native = &update.asset().native_variants[&HarnessId::Pi];
    let updated_envelope = VerifiedObjectEnvelope::native_extension(
        updated_native.root.clone(),
        update.native_object().clone(),
    )
    .unwrap();
    commit_native_extension_plan(
        root,
        &update,
        &changed,
        &[envelope],
        &[updated_envelope],
        SyncLimits::default(),
    )
    .unwrap();
    let updated_manifest = kitrove_model::EnvironmentManifest::from_toml(
        &fs::read_to_string(root.join("kitrove.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(updated_manifest, *update.proposed_manifest());
    assert!(
        root.join(updated_native.root.as_str())
            .join("payload/review.ts")
            .is_file()
    );
}

#[test]
fn independent_skill_addition_and_extension_update_both_survive_semantic_merge() {
    let empty = empty_manifest();
    let first = plan_native_extension_adoption(
        &observation(b"export default { version: 1 };\n"),
        Some(asset_id()),
        &empty,
    )
    .unwrap();
    let base = first.proposed_manifest().clone();
    let (skill, skill_object) = portable_skill();
    let mut local = base.clone();
    local.assets.insert(skill.id.clone(), skill);
    let prior = base.assets[&asset_id()].content_hash.clone();
    let update = plan_native_extension_update(
        &observation(b"export default { version: 2 };\n"),
        asset_id(),
        prior,
        &base,
    )
    .unwrap();
    let remote = update.proposed_manifest().clone();
    let catalog = VerifiedSkillObjectCatalog::new_with_extensions(
        [skill_object],
        [],
        [
            first.native_object().clone(),
            update.native_object().clone(),
        ],
    )
    .unwrap();

    let merged = merge_manifests(
        &base,
        &local,
        &remote,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    let manifest = merged.merged_manifest().expect("independent changes merge");
    assert!(
        manifest
            .assets
            .contains_key(&AssetId::parse("portable-review").unwrap())
    );
    assert_eq!(
        manifest.assets[&asset_id()].native_variants[&HarnessId::Pi].object_hash,
        update.native_object().hash().clone()
    );
}

#[test]
fn identical_extension_updates_coalesce_to_one_authoritative_result() {
    let empty = empty_manifest();
    let first = plan_native_extension_adoption(
        &observation(b"export default { version: 1 };\n"),
        Some(asset_id()),
        &empty,
    )
    .unwrap();
    let base = first.proposed_manifest().clone();
    let prior = base.assets[&asset_id()].content_hash.clone();
    let update = plan_native_extension_update(
        &observation(b"export default { version: 2 };\n"),
        asset_id(),
        prior,
        &base,
    )
    .unwrap();
    let local = update.proposed_manifest().clone();
    let remote = local.clone();
    let catalog = VerifiedSkillObjectCatalog::new_with_extensions(
        [],
        [],
        [
            first.native_object().clone(),
            update.native_object().clone(),
        ],
    )
    .unwrap();

    let merged = merge_manifests(
        &base,
        &local,
        &remote,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert!(merged.conflicts().is_empty());
    assert_eq!(merged.merged_manifest(), Some(&local));
    assert!(merged.merged_lock().is_some());
}

#[test]
fn divergent_extension_updates_and_deletion_remain_explicit_nonmutating_conflicts() {
    let empty = empty_manifest();
    let first = plan_native_extension_adoption(
        &observation(b"export default { version: 1 };\n"),
        Some(asset_id()),
        &empty,
    )
    .unwrap();
    let base = first.proposed_manifest().clone();
    let prior = base.assets[&asset_id()].content_hash.clone();
    let local = plan_native_extension_update(
        &observation(b"export default { version: 2 };\n"),
        asset_id(),
        prior.clone(),
        &base,
    )
    .unwrap();
    let remote = plan_native_extension_update(
        &observation(b"export default { version: 3 };\n"),
        asset_id(),
        prior,
        &base,
    )
    .unwrap();
    let catalog = VerifiedSkillObjectCatalog::new_with_extensions(
        [],
        [],
        [
            first.native_object().clone(),
            local.native_object().clone(),
            remote.native_object().clone(),
        ],
    )
    .unwrap();
    let unchanged_base = base.clone();
    let unchanged_local = local.proposed_manifest().clone();
    let unchanged_remote = remote.proposed_manifest().clone();
    let divergent = merge_manifests(
        &base,
        local.proposed_manifest(),
        remote.proposed_manifest(),
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert!(divergent.merged_manifest().is_none());
    assert!(divergent.merged_lock().is_none());
    assert_eq!(
        divergent.conflicts(),
        &[kitrove_model::SyncConflict {
            code: SyncConflictCode::DivergentComponent,
            subject: SyncConflictSubject::Native {
                asset: asset_id(),
                harness: HarnessId::Pi,
            },
        }]
    );
    assert_eq!(base, unchanged_base);
    assert_eq!(local.proposed_manifest(), &unchanged_local);
    assert_eq!(remote.proposed_manifest(), &unchanged_remote);

    let deletion = merge_manifests(
        &base,
        &empty,
        &base,
        &catalog,
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert!(deletion.merged_manifest().is_none());
    assert!(deletion.merged_lock().is_none());
    assert_eq!(
        deletion.conflicts(),
        &[kitrove_model::SyncConflict {
            code: SyncConflictCode::DeletionUnsupported,
            subject: SyncConflictSubject::Native {
                asset: asset_id(),
                harness: HarnessId::Pi,
            },
        }]
    );
}
