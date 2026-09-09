use std::collections::{BTreeMap, BTreeSet};

use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, BlockedRequirement, ComponentProvenance, ContentClass,
    ContentHash, EnvironmentManifest, Fidelity, FidelityEvidence, FidelityReason, FidelityResult,
    HarnessId, HarnessScope, NativeVariant, PortableContent, PortablePath, Revision, SchemaVersion,
    Source,
};

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).unwrap()
}

fn fidelity(adapter_version: &str) -> FidelityResult {
    FidelityResult::new(
        Fidelity::Partial,
        vec![FidelityReason::new(
            "native.metadata",
            "one native field remains preserved",
        )],
        vec![FidelityEvidence::new(
            "fixture.asset-revision",
            "fixture proves the retained native field",
        )],
        vec![],
        adapter_version,
        Some("1.2.3".to_owned()),
    )
    .unwrap()
}

fn asset(reverse_maps: bool) -> Asset {
    let provenance = ComponentProvenance::new(
        Source::Harness {
            harness: HarnessId::Pi,
            origin: PortablePath::parse("pi/user/review.md").unwrap(),
        },
        Revision::parse("observation:review-v1").unwrap(),
        hash('e'),
        Some(HarnessScope::User),
    )
    .unwrap();
    let provenance_id = provenance.provenance_id();
    let variant = |harness, marker| NativeVariant {
        harness,
        format: format!("native-skill/{marker}"),
        root: PortablePath::parse(format!("assets/review/native/{marker}")).unwrap(),
        object_hash: hash(marker),
        content_class: ContentClass::AgentActive,
        provenance: provenance_id.clone(),
    };
    let variant_items = [
        (HarnessId::Claude, variant(HarnessId::Claude, 'c')),
        (HarnessId::Pi, variant(HarnessId::Pi, 'd')),
    ];
    let fidelity_items = [
        (HarnessId::Claude, fidelity("claude-adapter/1")),
        (HarnessId::Pi, fidelity("pi-adapter/1")),
    ];
    let indexes: [usize; 2] = if reverse_maps { [1, 0] } else { [0, 1] };
    let mut native_variants = BTreeMap::new();
    let mut compatibility = BTreeMap::new();
    for index in indexes {
        native_variants.insert(
            variant_items[index].0.clone(),
            variant_items[index].1.clone(),
        );
        compatibility.insert(
            fidelity_items[index].0.clone(),
            fidelity_items[index].1.clone(),
        );
    }

    Asset {
        id: AssetId::parse("review").unwrap(),
        kind: AssetKind::Skill,
        content_hash: hash('0'),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: PortablePath::parse("assets/review/portable").unwrap(),
            object_hash: hash('a'),
            provenance: provenance_id,
        }),
        native_variants,
        compatibility,
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::from([BindingName::parse("github_token").unwrap()]),
    }
}

fn replace_provenance(asset: &mut Asset, provenance: ComponentProvenance) {
    let id = provenance.provenance_id();
    asset.provenance = BTreeMap::from([(id.clone(), provenance)]);
    if let Some(portable) = &mut asset.portable {
        portable.provenance = id.clone();
    }
    for variant in asset.native_variants.values_mut() {
        variant.provenance = id.clone();
    }
}

#[test]
fn complete_asset_revision_has_a_stable_golden_hash() {
    let first = asset(false);
    let second = asset(true);

    assert_eq!(
        first.expected_content_hash(),
        second.expected_content_hash()
    );
    assert_eq!(
        first.expected_content_hash().as_str(),
        "blake3:e51ce15f1a42d77c1124b896ce060b929ec9dd981252e55b008aa585602b501e"
    );
}

#[test]
fn complete_asset_revision_changes_when_revision_bearing_fields_change() {
    let baseline = asset(false);
    let baseline_hash = baseline.expected_content_hash();
    let mut mutations = Vec::new();

    let mut value = baseline.clone();
    value.id = AssetId::parse("renamed").unwrap();
    mutations.push(value);

    let mut value = baseline.clone();
    value.kind = AssetKind::Instruction;
    mutations.push(value);

    let mut value = baseline.clone();
    replace_provenance(
        &mut value,
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Claude,
                origin: PortablePath::parse("claude/user/review").unwrap(),
            },
            Revision::parse("observation:review-v1").unwrap(),
            hash('e'),
            Some(HarnessScope::User),
        )
        .unwrap(),
    );
    mutations.push(value);

    let mut value = baseline.clone();
    replace_provenance(
        &mut value,
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Pi,
                origin: PortablePath::parse("pi/user/review.md").unwrap(),
            },
            Revision::parse("observation:review-v1").unwrap(),
            hash('f'),
            Some(HarnessScope::User),
        )
        .unwrap(),
    );
    mutations.push(value);

    let mut value = baseline.clone();
    replace_provenance(
        &mut value,
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Pi,
                origin: PortablePath::parse("pi/user/review.md").unwrap(),
            },
            Revision::parse("observation:review-v1").unwrap(),
            hash('e'),
            Some(HarnessScope::Project),
        )
        .unwrap(),
    );
    mutations.push(value);

    let mut value = baseline.clone();
    value.portable.as_mut().unwrap().provenance = ComponentProvenance::new(
        Source::Local {
            path: PortablePath::parse("imports/review").unwrap(),
        },
        Revision::parse("local:review-v1").unwrap(),
        hash('a'),
        None,
    )
    .unwrap()
    .provenance_id();
    mutations.push(value);

    let mut value = baseline.clone();
    replace_provenance(
        &mut value,
        ComponentProvenance::new(
            Source::Harness {
                harness: HarnessId::Pi,
                origin: PortablePath::parse("pi/user/review.md").unwrap(),
            },
            Revision::parse("observation:review-v2").unwrap(),
            hash('e'),
            Some(HarnessScope::User),
        )
        .unwrap(),
    );
    mutations.push(value);

    let mut value = baseline.clone();
    value.portable.as_mut().unwrap().object_hash = hash('b');
    mutations.push(value);

    let mut value = baseline.clone();
    value.portable.as_mut().unwrap().format = "agent-skills/v2".to_owned();
    mutations.push(value);

    let mut value = baseline.clone();
    value.portable.as_mut().unwrap().root = PortablePath::parse("objects/review").unwrap();
    mutations.push(value);

    let mut value = baseline.clone();
    value.portable = None;
    mutations.push(value);

    let mut value = baseline.clone();
    value
        .native_variants
        .get_mut(&HarnessId::Pi)
        .unwrap()
        .format = "native-skill/changed".to_owned();
    mutations.push(value);

    let mut value = baseline.clone();
    value.native_variants.get_mut(&HarnessId::Pi).unwrap().root =
        PortablePath::parse("objects/native/pi").unwrap();
    mutations.push(value);

    let mut value = baseline.clone();
    value
        .native_variants
        .get_mut(&HarnessId::Pi)
        .unwrap()
        .object_hash = hash('e');
    mutations.push(value);

    let mut value = baseline.clone();
    value
        .native_variants
        .get_mut(&HarnessId::Pi)
        .unwrap()
        .content_class = ContentClass::Executable;
    mutations.push(value);

    let mut value = baseline.clone();
    value
        .compatibility
        .insert(HarnessId::Pi, fidelity("pi-adapter/2"));
    mutations.push(value);

    let mut value = baseline.clone();
    value.compatibility.insert(
        HarnessId::Pi,
        FidelityResult::new(
            Fidelity::Unsupported,
            vec![FidelityReason::new(
                "layout.unsupported",
                "target rejects layout",
            )],
            vec![FidelityEvidence::new("fixture.changed", "changed evidence")],
            vec![],
            "pi-adapter/1",
            None,
        )
        .unwrap(),
    );
    mutations.push(value);

    let mut value = baseline.clone();
    value.content_class = ContentClass::Executable;
    mutations.push(value);

    let mut value = baseline.clone();
    value
        .required_bindings
        .insert(BindingName::parse("linear_token").unwrap());
    mutations.push(value);

    for mutation in mutations {
        assert_ne!(mutation.expected_content_hash(), baseline_hash);
    }

    let mut self_hash_only = baseline.clone();
    self_hash_only.content_hash = hash('f');
    assert_eq!(self_hash_only.expected_content_hash(), baseline_hash);
}

#[test]
fn manifest_rejects_a_stored_asset_revision_mismatch() {
    let mut valid_asset = asset(false);
    valid_asset.content_hash = valid_asset.expected_content_hash();
    let id = valid_asset.id.clone();
    let valid = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(id.clone(), valid_asset.clone())]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: valid_asset.required_bindings.clone(),
    };
    valid.validate().unwrap();

    let mut invalid = valid;
    invalid.assets.get_mut(&id).unwrap().content_hash = hash('f');
    let error = invalid.validate().unwrap_err();
    assert_eq!(error.code(), "manifest.asset_content_hash_mismatch");
    assert!(!error.to_string().contains("github_token"));

    let secret_shaped_id = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    let mut secret_shaped = asset(false);
    secret_shaped.id = AssetId::parse(secret_shaped_id).unwrap();
    secret_shaped.refresh_content_hash();
    secret_shaped.content_hash = hash('e');
    let secret_id = secret_shaped.id.clone();
    let manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::from([(secret_id, secret_shaped)]),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::from([BindingName::parse("github_token").unwrap()]),
    };
    let error = manifest.validate().unwrap_err();
    assert!(!error.to_string().contains(secret_shaped_id));
}

#[test]
fn complete_asset_revision_distinguishes_typed_blocked_requirements() {
    let blocked = |requirement| {
        FidelityResult::new(
            Fidelity::Blocked,
            vec![FidelityReason::new(
                "local.requirement",
                "a local requirement blocks materialization",
            )],
            vec![FidelityEvidence::new(
                "fixture",
                "typed blocked requirement",
            )],
            vec![requirement],
            "pi-adapter/1",
            None,
        )
        .unwrap()
    };
    let mut binding_asset = asset(false);
    binding_asset.compatibility.insert(
        HarnessId::Pi,
        blocked(BlockedRequirement::binding(
            BindingName::parse("token").unwrap(),
        )),
    );
    let mut executable_asset = binding_asset.clone();
    executable_asset
        .compatibility
        .insert(HarnessId::Pi, blocked(BlockedRequirement::ExecutableTrust));

    assert_ne!(
        binding_asset.expected_content_hash(),
        executable_asset.expected_content_hash()
    );
}

#[test]
fn checked_in_portable_fixture_uses_the_complete_asset_revision() {
    let manifest: EnvironmentManifest = toml::from_str(include_str!(
        "../../kitrove-testkit/fixtures/portable/kitrove.toml"
    ))
    .unwrap();
    let id = AssetId::parse("review").unwrap();
    let asset = &manifest.assets[&id];
    assert_eq!(
        asset.expected_content_hash().as_str(),
        "blake3:f96367a31752045a8b1e9e0e2c725b43db1179498ab29619dc2271f358eb8b97"
    );
    let pack = &manifest.packs[&AssetId::parse("review-pack").unwrap()];
    assert_eq!(
        pack.expected_content_hash().as_str(),
        "blake3:cd54269c6e4780dcad6edd4909cc9f5c4708170da36b1b34143a695873c1e9ee"
    );
}
