use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, BlockedRequirement, ContentClass, ContentHash,
    EnvironmentManifest, Fidelity, FidelityEvidence, FidelityReason, FidelityResult, HarnessId,
    Pack, PortablePath, Revision, SchemaVersion, Source,
};

fn id(value: &str) -> AssetId {
    AssetId::parse(value).expect("asset id")
}

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).expect("content hash")
}

fn binding(value: &str) -> BindingName {
    BindingName::parse(value).expect("binding")
}

fn source(path: &str) -> Source {
    Source::Local {
        path: PortablePath::parse(path).expect("portable path"),
    }
}

fn exact(fidelity: Fidelity) -> FidelityResult {
    FidelityResult::exact(
        fidelity,
        vec![FidelityEvidence::new("fixture", "exact test evidence")],
        "fixture-adapter/v1",
        Some("1.0.0".to_owned()),
    )
    .expect("exact fidelity")
}

fn partial() -> FidelityResult {
    FidelityResult::new(
        Fidelity::Partial,
        vec![FidelityReason::new(
            "fixture.partial",
            "fixture intentionally models a partial member",
        )],
        vec![FidelityEvidence::new("fixture", "partial test evidence")],
        vec![],
        "fixture-adapter/v1",
        Some("1.0.0".to_owned()),
    )
    .expect("partial fidelity")
}

fn blocked(requirements: &[&str], harness_version: &str) -> FidelityResult {
    FidelityResult::new(
        Fidelity::Blocked,
        vec![FidelityReason::new(
            "fixture.blocked",
            "fixture intentionally models a blocked member",
        )],
        vec![FidelityEvidence::new("fixture", "blocked test evidence")],
        requirements
            .iter()
            .copied()
            .map(binding)
            .map(BlockedRequirement::binding)
            .collect(),
        "fixture-adapter/v1",
        Some(harness_version.to_owned()),
    )
    .expect("blocked fidelity")
}

fn asset(
    asset_id: &str,
    content_class: ContentClass,
    required_bindings: &[&str],
    compatibility: BTreeMap<HarnessId, FidelityResult>,
) -> Asset {
    let mut asset = Asset {
        id: id(asset_id),
        kind: AssetKind::Skill,
        content_hash: hash('0'),
        provenance: BTreeMap::new(),
        portable: None,
        native_variants: BTreeMap::new(),
        compatibility,
        content_class,
        required_bindings: required_bindings.iter().copied().map(binding).collect(),
    };
    asset.refresh_content_hash();
    asset
}

fn pack(pack_id: &str, members: &[&str]) -> Pack {
    Pack {
        id: id(pack_id),
        source: source("packs/review"),
        revision: Revision::parse("local:pack-1").expect("revision"),
        exact_source_hash: hash('a'),
        content_hash: hash('0'),
        members: members
            .iter()
            .copied()
            .map(|member| (id(member), hash('f')))
            .collect(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    }
}

type PackMutation = Box<dyn Fn(&mut Pack)>;

fn aggregate_manifest() -> EnvironmentManifest {
    let alpha = asset(
        "alpha",
        ContentClass::AgentActive,
        &["github-token"],
        BTreeMap::from([
            (HarnessId::Codex, exact(Fidelity::Native)),
            (HarnessId::Claude, exact(Fidelity::Portable)),
        ]),
    );
    let beta = asset(
        "beta",
        ContentClass::Executable,
        &["service-endpoint"],
        BTreeMap::from([(HarnessId::Codex, partial())]),
    );
    EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(alpha.id.clone(), alpha), (beta.id.clone(), beta)]),
        packs: BTreeMap::from([(id("review-pack"), pack("review-pack", &["alpha", "beta"]))]),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::from([binding("github-token"), binding("service-endpoint")]),
    }
}

#[test]
fn pack_revision_binds_every_aggregate_field_and_not_insertion_order() {
    let mut manifest = aggregate_manifest();
    manifest.refresh_pack_revisions().expect("refresh pack");
    let original = manifest.packs[&id("review-pack")].clone();
    let expected = original.expected_content_hash();

    let mut reversed = original.clone();
    reversed.members = original
        .members
        .iter()
        .rev()
        .map(|(member, revision)| (member.clone(), revision.clone()))
        .collect();
    assert_eq!(reversed.expected_content_hash(), expected);

    let mutations: Vec<PackMutation> = vec![
        Box::new(|pack| pack.id = id("other-pack")),
        Box::new(|pack| pack.source = source("packs/other")),
        Box::new(|pack| pack.revision = Revision::parse("local:pack-2").unwrap()),
        Box::new(|pack| pack.exact_source_hash = hash('b')),
        Box::new(|pack| {
            pack.members.insert(id("alpha"), hash('c'));
        }),
        Box::new(|pack| {
            pack.compatibility.clear();
        }),
        Box::new(|pack| pack.content_class = ContentClass::DataOnly),
        Box::new(|pack| {
            pack.required_bindings.insert(binding("extra-binding"));
        }),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(changed.expected_content_hash(), expected);
    }
}

#[test]
fn refresh_derives_exact_members_weakest_fidelity_class_and_bindings() {
    let mut manifest = aggregate_manifest();
    manifest.refresh_pack_revisions().expect("refresh pack");
    let pack = &manifest.packs[&id("review-pack")];

    assert_eq!(
        pack.members[&id("alpha")],
        manifest.assets[&id("alpha")].content_hash
    );
    assert_eq!(
        pack.members[&id("beta")],
        manifest.assets[&id("beta")].content_hash
    );
    assert_eq!(
        pack.compatibility[&HarnessId::Codex].fidelity(),
        Fidelity::Partial
    );
    assert_eq!(
        pack.compatibility[&HarnessId::Claude].fidelity(),
        Fidelity::Unsupported
    );
    assert_eq!(pack.content_class, ContentClass::Executable);
    assert_eq!(
        pack.required_bindings,
        BTreeSet::from([binding("github-token"), binding("service-endpoint")])
    );
    assert_eq!(pack.content_hash, pack.expected_content_hash());
}

#[test]
fn refresh_unions_blocked_requirements_and_retains_only_agreed_harness_version() {
    let alpha = asset(
        "alpha",
        ContentClass::DataOnly,
        &[],
        BTreeMap::from([(HarnessId::Codex, blocked(&["alpha-token"], "1.0.0"))]),
    );
    let beta = asset(
        "beta",
        ContentClass::DataOnly,
        &[],
        BTreeMap::from([(HarnessId::Codex, blocked(&["beta-token"], "1.0.0"))]),
    );
    let mut manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(alpha.id.clone(), alpha), (beta.id.clone(), beta)]),
        packs: BTreeMap::from([(id("blocked-pack"), pack("blocked-pack", &["alpha", "beta"]))]),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    manifest.refresh_pack_revisions().unwrap();
    let result = &manifest.packs[&id("blocked-pack")].compatibility[&HarnessId::Codex];
    assert_eq!(result.fidelity(), Fidelity::Blocked);
    assert_eq!(
        result.blocked_requirements(),
        &[
            BlockedRequirement::binding(binding("alpha-token")),
            BlockedRequirement::binding(binding("beta-token")),
        ]
    );
    assert_eq!(result.harness_version(), Some("1.0.0"));

    manifest
        .assets
        .get_mut(&id("beta"))
        .unwrap()
        .compatibility
        .insert(HarnessId::Codex, blocked(&["beta-token"], "2.0.0"));
    manifest
        .assets
        .get_mut(&id("beta"))
        .unwrap()
        .refresh_content_hash();
    manifest.refresh_pack_revisions().unwrap();
    assert_eq!(
        manifest.packs[&id("blocked-pack")].compatibility[&HarnessId::Codex].harness_version(),
        None
    );
}

#[test]
fn nested_packs_refresh_in_dependency_order() {
    let mut manifest = aggregate_manifest();
    manifest
        .packs
        .insert(id("outer-pack"), pack("outer-pack", &["review-pack"]));
    manifest
        .refresh_pack_revisions()
        .expect("refresh nested packs");

    let inner = &manifest.packs[&id("review-pack")];
    let outer = &manifest.packs[&id("outer-pack")];
    assert_eq!(outer.members[&inner.id], inner.content_hash);
    assert_eq!(
        outer.compatibility[&HarnessId::Codex].fidelity(),
        inner.compatibility[&HarnessId::Codex].fidelity()
    );
    assert_eq!(
        outer.compatibility[&HarnessId::Claude].fidelity(),
        inner.compatibility[&HarnessId::Claude].fidelity()
    );
    assert_eq!(outer.content_class, inner.content_class);
    assert_eq!(outer.required_bindings, inner.required_bindings);
}

#[test]
fn validation_rejects_pack_member_metadata_and_revision_tampering() {
    let mut manifest = aggregate_manifest();
    manifest.refresh_pack_revisions().expect("refresh pack");

    let mut wrong_member = manifest.clone();
    wrong_member
        .packs
        .get_mut(&id("review-pack"))
        .unwrap()
        .members
        .insert(id("alpha"), hash('d'));
    assert_eq!(
        wrong_member.validate().unwrap_err().code(),
        "manifest.pack_member_revision_mismatch"
    );

    let mut wrong_metadata = manifest.clone();
    wrong_metadata
        .packs
        .get_mut(&id("review-pack"))
        .unwrap()
        .compatibility
        .clear();
    assert_eq!(
        wrong_metadata.validate().unwrap_err().code(),
        "manifest.pack_compatibility_mismatch"
    );

    let mut wrong_hash = manifest;
    wrong_hash
        .packs
        .get_mut(&id("review-pack"))
        .unwrap()
        .content_hash = hash('e');
    assert_eq!(
        wrong_hash.validate().unwrap_err().code(),
        "manifest.pack_content_hash_mismatch"
    );
}

#[test]
fn refresh_and_validation_refuse_pack_graphs_beyond_the_compiled_member_budget() {
    let members = (0..=4096)
        .map(|index| (id(&format!("member-{index:04}")), hash('f')))
        .collect();
    let oversized = Pack {
        members,
        ..pack("oversized-pack", &["placeholder"])
    };
    let mut manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::from([(oversized.id.clone(), oversized)]),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };

    assert_eq!(
        manifest.validate().unwrap_err().code(),
        "manifest.pack_member_limit_exceeded"
    );
    assert_eq!(
        manifest.refresh_pack_revisions().unwrap_err().code(),
        "manifest.pack_member_limit_exceeded"
    );
}

#[test]
fn refresh_and_validation_refuse_excessive_pack_nesting() {
    let mut manifest = aggregate_manifest();
    for index in (0..64).rev() {
        let member = if index == 63 {
            "alpha".to_owned()
        } else {
            format!("a-nested-pack-{:02}", index + 1)
        };
        let pack_id = format!("a-nested-pack-{index:02}");
        manifest
            .packs
            .insert(id(&pack_id), pack(&pack_id, &[&member]));
    }
    manifest.packs.insert(
        id("z-outer-pack"),
        pack("z-outer-pack", &["a-nested-pack-00"]),
    );

    assert_eq!(
        manifest.refresh_pack_revisions().unwrap_err().code(),
        "manifest.pack_depth_limit_exceeded"
    );
    assert_eq!(
        manifest.validate().unwrap_err().code(),
        "manifest.pack_depth_limit_exceeded"
    );
}

#[test]
fn pack_graph_accepts_exact_member_and_depth_boundaries() {
    let alpha = asset("alpha", ContentClass::DataOnly, &[], BTreeMap::new());
    let mut wide = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(alpha.id.clone(), alpha.clone())]),
        packs: (0..4096)
            .map(|index| {
                let pack_id = format!("boundary-pack-{index:04}");
                (id(&pack_id), pack(&pack_id, &["alpha"]))
            })
            .collect(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    wide.refresh_pack_revisions().unwrap();
    wide.validate().unwrap();

    let mut deep = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(alpha.id.clone(), alpha)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    for index in (0..64).rev() {
        let member = if index == 63 {
            "alpha".to_owned()
        } else {
            format!("depth-pack-{:02}", index + 1)
        };
        let pack_id = format!("depth-pack-{index:02}");
        deep.packs.insert(id(&pack_id), pack(&pack_id, &[&member]));
    }
    deep.refresh_pack_revisions().unwrap();
    deep.validate().unwrap();
}

#[test]
fn maximum_budget_deep_and_cyclic_graphs_refuse_before_unbounded_recursion() {
    fn graph(cyclic: bool) -> EnvironmentManifest {
        let alpha = asset("alpha", ContentClass::DataOnly, &[], BTreeMap::new());
        let mut packs = BTreeMap::new();
        for index in (0..4096).rev() {
            let member = if index == 4095 {
                if cyclic {
                    "hostile-pack-0000".to_owned()
                } else {
                    "alpha".to_owned()
                }
            } else {
                format!("hostile-pack-{:04}", index + 1)
            };
            let pack_id = format!("hostile-pack-{index:04}");
            packs.insert(id(&pack_id), pack(&pack_id, &[&member]));
        }
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::from([(alpha.id.clone(), alpha)]),
            packs,
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    for mut manifest in [graph(false), graph(true)] {
        assert_eq!(
            manifest.validate().unwrap_err().code(),
            "manifest.pack_depth_limit_exceeded"
        );
        assert_eq!(
            manifest.refresh_pack_revisions().unwrap_err().code(),
            "manifest.pack_depth_limit_exceeded"
        );
    }
}
