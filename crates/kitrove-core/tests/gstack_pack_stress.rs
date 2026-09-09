use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kitrove_adapter_api::{CapabilityMatrix, EvidenceRef, TargetPolicy};
use kitrove_agent_skills::{
    CapturedFile, CapturedTree, FileMode, SkillSourceLayout, StoredSkillTree, hash_tree,
};
use kitrove_core::{
    DestinationObservation, TierOneCapabilities, VerifiedSkillObjectCatalog, derive_lockfile,
    merge_manifests, plan_skill_apply,
};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, BindingResolver, ComponentProvenance, ContentClass,
    ContentHash, EnvironmentManifest, Fidelity, FidelityEvidence, FidelityReason, FidelityResult,
    HarnessId, HarnessScope, LocalState, MachineConfig, MachineId, Pack, PortableContent,
    PortablePath, RepositoryUrl, Revision, SchemaVersion, Source, SyncConflictCode,
    SyncConflictSubject, SyncLimits,
};

const GSTACK_COMMIT: &str = "394db326f2d3aaccd4804fe846b82aaa7d189dee";

const GSTACK_SKILL_PATHS: [&str; 59] = [
    "SKILL.md",
    "autoplan/SKILL.md",
    "benchmark-models/SKILL.md",
    "benchmark/SKILL.md",
    "browse/SKILL.md",
    "browser-skills/hackernews-frontpage/SKILL.md",
    "canary/SKILL.md",
    "careful/SKILL.md",
    "codex/SKILL.md",
    "context-restore/SKILL.md",
    "context-save/SKILL.md",
    "cso/SKILL.md",
    "design-consultation/SKILL.md",
    "design-html/SKILL.md",
    "design-review/SKILL.md",
    "design-shotgun/SKILL.md",
    "devex-review/SKILL.md",
    "diagram/SKILL.md",
    "document-generate/SKILL.md",
    "document-release/SKILL.md",
    "freeze/SKILL.md",
    "gstack-upgrade/SKILL.md",
    "guard/SKILL.md",
    "health/SKILL.md",
    "investigate/SKILL.md",
    "ios-clean/SKILL.md",
    "ios-design-review/SKILL.md",
    "ios-fix/SKILL.md",
    "ios-qa/SKILL.md",
    "ios-sync/SKILL.md",
    "land-and-deploy/SKILL.md",
    "landing-report/SKILL.md",
    "learn/SKILL.md",
    "make-pdf/SKILL.md",
    "office-hours/SKILL.md",
    "open-gstack-browser/SKILL.md",
    "openclaw/skills/gstack-openclaw-ceo-review/SKILL.md",
    "openclaw/skills/gstack-openclaw-investigate/SKILL.md",
    "openclaw/skills/gstack-openclaw-office-hours/SKILL.md",
    "openclaw/skills/gstack-openclaw-retro/SKILL.md",
    "pair-agent/SKILL.md",
    "plan-ceo-review/SKILL.md",
    "plan-design-review/SKILL.md",
    "plan-devex-review/SKILL.md",
    "plan-eng-review/SKILL.md",
    "plan-tune/SKILL.md",
    "qa-only/SKILL.md",
    "qa/SKILL.md",
    "retro/SKILL.md",
    "review/SKILL.md",
    "scrape/SKILL.md",
    "setup-browser-cookies/SKILL.md",
    "setup-deploy/SKILL.md",
    "setup-gbrain/SKILL.md",
    "ship/SKILL.md",
    "skillify/SKILL.md",
    "spec/SKILL.md",
    "sync-gbrain/SKILL.md",
    "unfreeze/SKILL.md",
];

fn member_id(path: &str) -> AssetId {
    let stem = path.strip_suffix("/SKILL.md").unwrap_or("root");
    AssetId::parse(format!("gstack-{}", stem.replace('/', "--"))).expect("synthetic member id")
}

fn exact(fidelity: Fidelity) -> FidelityResult {
    FidelityResult::exact(
        fidelity,
        vec![FidelityEvidence::new(
            "stress.synthetic",
            "pinned structural member evidence",
        )],
        "gstack-structure/v1",
        Some("1.0.0".to_owned()),
    )
    .expect("exact synthetic fidelity")
}

fn lossy(fidelity: Fidelity) -> FidelityResult {
    FidelityResult::new(
        fidelity,
        vec![FidelityReason::new(
            "stress.synthetic_loss",
            "synthetic member models a conservative target loss",
        )],
        vec![FidelityEvidence::new(
            "stress.synthetic",
            "pinned structural member evidence",
        )],
        vec![],
        "gstack-structure/v1",
        Some("1.0.0".to_owned()),
    )
    .expect("lossy synthetic fidelity")
}

fn member_object(path: &str) -> StoredSkillTree {
    let mode = if path == "ship/SKILL.md" {
        FileMode::Executable
    } else {
        FileMode::Regular
    };
    let files = BTreeMap::from([(
        PortablePath::parse("SKILL.md").unwrap(),
        CapturedFile {
            mode,
            bytes: format!(
                "---\nname: review\ndescription: Synthetic pinned structural member.\n---\n{path}\n"
            )
            .into_bytes(),
        },
    )]);
    StoredSkillTree::new(CapturedTree {
        hash: hash_tree(&files),
        files,
    })
    .unwrap()
}

fn member_provenance(object: &StoredSkillTree) -> ComponentProvenance {
    ComponentProvenance::new(
        Source::Git {
            repository: RepositoryUrl::parse("https://github.com/garrytan/gstack.git").unwrap(),
            subdirectory: None,
        },
        Revision::parse(format!("git:{GSTACK_COMMIT}")).unwrap(),
        object.tree().hash.clone(),
        None,
    )
    .unwrap()
}

fn stress_objects() -> Vec<StoredSkillTree> {
    GSTACK_SKILL_PATHS
        .iter()
        .map(|path| member_object(path))
        .collect()
}

fn stress_manifest(reverse: bool) -> EnvironmentManifest {
    let paths: Box<dyn Iterator<Item = &&str>> = if reverse {
        Box::new(GSTACK_SKILL_PATHS.iter().rev())
    } else {
        Box::new(GSTACK_SKILL_PATHS.iter())
    };
    let mut assets = BTreeMap::new();
    for path in paths {
        let index = GSTACK_SKILL_PATHS
            .iter()
            .position(|candidate| candidate == path)
            .expect("pinned path remains in the corpus");
        let id = member_id(path);
        let fidelity = match index % 4 {
            0 => exact(Fidelity::Native),
            1 => exact(Fidelity::Portable),
            2 => lossy(Fidelity::Partial),
            _ => lossy(Fidelity::Unsupported),
        };
        let mut asset = Asset {
            id: id.clone(),
            kind: AssetKind::Skill,
            content_hash: ContentHash::digest(b"pending-gstack-member"),
            provenance: {
                let object = member_object(path);
                let provenance = member_provenance(&object);
                BTreeMap::from([(provenance.provenance_id(), provenance)])
            },
            portable: {
                let object = member_object(path);
                let provenance = member_provenance(&object);
                Some(PortableContent {
                    format: "agent-skills/v1".to_owned(),
                    root: PortablePath::parse(format!("assets/{id}/portable")).unwrap(),
                    object_hash: object.tree().hash.clone(),
                    provenance: provenance.provenance_id(),
                })
            },
            native_variants: BTreeMap::new(),
            compatibility: BTreeMap::from([
                (HarnessId::Codex, fidelity),
                (HarnessId::Claude, exact(Fidelity::Native)),
            ]),
            content_class: if path == &"ship/SKILL.md" {
                ContentClass::Executable
            } else {
                ContentClass::AgentActive
            },
            required_bindings: BTreeSet::new(),
        };
        asset.refresh_content_hash();
        assets.insert(id, asset);
    }

    let pack_id = AssetId::parse("gstack-distribution").unwrap();
    let pack = Pack {
        id: pack_id.clone(),
        source: Source::Git {
            repository: RepositoryUrl::parse("https://github.com/garrytan/gstack.git").unwrap(),
            subdirectory: None,
        },
        revision: Revision::parse(format!("git:{GSTACK_COMMIT}")).unwrap(),
        exact_source_hash: ContentHash::digest(b"gstack-pinned-structural-corpus-v1"),
        content_hash: ContentHash::digest(b"pending-gstack-pack"),
        members: assets
            .keys()
            .cloned()
            .map(|id| (id, ContentHash::digest(b"pending-gstack-member-ref")))
            .collect(),
        compatibility: BTreeMap::new(),
        content_class: ContentClass::DataOnly,
        required_bindings: BTreeSet::new(),
    };
    let mut manifest = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets,
        packs: BTreeMap::from([(pack_id, pack)]),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    manifest.refresh_pack_revisions().unwrap();
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
                    "gstack-stress/1",
                    "synthetic stress target accepts canonical Agent Skills packages",
                ),
            )
        })
        .collect(),
    )
    .unwrap()
}

fn addon(id: &str, kind: AssetKind) -> (Asset, StoredSkillTree) {
    let object = member_object(id);
    let provenance = member_provenance(&object);
    let provenance_id = provenance.provenance_id();
    let mut asset = Asset {
        id: AssetId::parse(id).unwrap(),
        kind,
        content_hash: ContentHash::digest(b"pending-gstack-addon"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: "agent-skills/v1".to_owned(),
            root: PortablePath::parse(format!("assets/{id}/portable")).unwrap(),
            object_hash: object.tree().hash.clone(),
            provenance: provenance_id,
        }),
        native_variants: BTreeMap::new(),
        compatibility: BTreeMap::from([
            (HarnessId::Codex, exact(Fidelity::Native)),
            (HarnessId::Claude, exact(Fidelity::Native)),
        ]),
        content_class: ContentClass::AgentActive,
        required_bindings: BTreeSet::new(),
    };
    asset.refresh_content_hash();
    (asset, object)
}

fn add_pack_member(manifest: &mut EnvironmentManifest, asset: Asset) {
    let id = asset.id.clone();
    manifest.assets.insert(id.clone(), asset);
    manifest
        .packs
        .get_mut(&AssetId::parse("gstack-distribution").unwrap())
        .unwrap()
        .members
        .insert(id, ContentHash::digest(b"pending-gstack-addon-ref"));
    manifest.refresh_pack_revisions().unwrap();
}

fn target_policy() -> TargetPolicy {
    TargetPolicy {
        harness: HarnessId::Claude,
        scope: HarnessScope::User,
        policy_line: kitrove_adapter_api::PolicyLine::ClaudeCurrent,
        relative_root: PortablePath::parse(".claude/skills").unwrap(),
        layout: SkillSourceLayout::Directory,
        document_name: PortablePath::parse("SKILL.md").unwrap(),
        adapter_version: "gstack-stress/1",
        evidence: EvidenceRef::parse("claude.target.skills").unwrap(),
    }
}

fn local_state_text() -> String {
    LocalState {
        schema_version: SchemaVersion::V1,
        machine: MachineConfig {
            id: MachineId::parse("gstack-stress-machine").unwrap(),
            active_profile: None,
            enabled_targets: BTreeSet::new(),
            harness_roots: BTreeMap::new(),
        },
        bindings: BTreeMap::<BindingName, BindingResolver>::new(),
        receipts: BTreeMap::new(),
        pack_applications: BTreeMap::new(),
        trust: BTreeMap::new(),
        scans: Vec::new(),
    }
    .to_json()
    .unwrap()
}

#[cfg(not(windows))]
fn test_anchor() -> &'static Path {
    Path::new("/home/review")
}

#[cfg(windows)]
fn test_anchor() -> &'static Path {
    Path::new(r"C:\home\review")
}

#[test]
fn pinned_distribution_membership_is_exact_and_excludes_test_fixtures() {
    assert_eq!(GSTACK_SKILL_PATHS.len(), 59);
    assert!(
        GSTACK_SKILL_PATHS
            .iter()
            .all(|path| !path.starts_with("test/"))
    );
    assert_eq!(
        GSTACK_SKILL_PATHS
            .iter()
            .map(|path| member_id(path))
            .collect::<BTreeSet<_>>()
            .len(),
        59
    );
}

#[test]
fn pinned_distribution_pack_is_order_independent_and_has_a_golden_revision() {
    let forward = stress_manifest(false);
    let reverse = stress_manifest(true);
    let pack_id = AssetId::parse("gstack-distribution").unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(
        forward.packs[&pack_id].content_hash.as_str(),
        "blake3:5017bd12c367649fe458f7df86616299aa45019e7be516cf1212761552d47d75"
    );
}

#[test]
fn one_member_change_updates_the_pack_and_weakest_risk_is_retained() {
    let original = stress_manifest(false);
    let mut changed = original.clone();
    let member = member_id("review/SKILL.md");
    let asset = changed.assets.get_mut(&member).unwrap();
    asset.content_class = ContentClass::Executable;
    asset.refresh_content_hash();
    changed.refresh_pack_revisions().unwrap();
    let pack_id = AssetId::parse("gstack-distribution").unwrap();
    assert_ne!(
        changed.packs[&pack_id].content_hash,
        original.packs[&pack_id].content_hash
    );
    assert_eq!(
        changed.packs[&pack_id].content_class,
        ContentClass::Executable
    );
    assert_eq!(
        changed.packs[&pack_id].compatibility[&HarnessId::Codex].fidelity(),
        Fidelity::Unsupported
    );
    assert_eq!(
        changed.packs[&pack_id].compatibility[&HarnessId::Claude].fidelity(),
        Fidelity::Native
    );
    assert_eq!(
        changed.assets[&member_id("SKILL.md")].compatibility[&HarnessId::Codex].fidelity(),
        Fidelity::Native
    );
    assert_eq!(
        changed.assets[&member_id("benchmark-models/SKILL.md")].compatibility[&HarnessId::Codex]
            .fidelity(),
        Fidelity::Partial
    );
}

#[test]
fn exact_stress_lock_round_trips_and_refuses_a_member_revision_mismatch() {
    let manifest = stress_manifest(false);
    let lock = derive_lockfile(&manifest).unwrap();
    let json = lock.to_json().unwrap();
    assert_eq!(kitrove_model::Lockfile::from_json(&json).unwrap(), lock);
    let pack_id = AssetId::parse("gstack-distribution").unwrap();
    assert_eq!(lock.packs[&pack_id].members.len(), 59);

    let mut mismatched = lock;
    let revision = mismatched
        .packs
        .get_mut(&pack_id)
        .unwrap()
        .members
        .values_mut()
        .next()
        .unwrap();
    *revision = ContentHash::digest(b"mismatched-member-revision");
    assert_eq!(
        mismatched.validate().unwrap_err().code(),
        "lockfile.pack_member_revision_mismatch"
    );
}

#[test]
fn executable_member_in_the_stress_pack_is_refused_by_real_apply_planning() {
    let manifest = stress_manifest(false);
    let ship = member_id("ship/SKILL.md");
    assert_eq!(
        manifest.assets[&ship].content_class,
        ContentClass::Executable
    );
    assert_eq!(
        plan_skill_apply(
            &manifest,
            &ship,
            &member_object("ship/SKILL.md"),
            &target_policy(),
            test_anchor(),
            &local_state_text(),
            DestinationObservation::Absent,
        )
        .unwrap_err()
        .code(),
        "apply.executable_blocked"
    );
}

#[test]
fn stress_pack_merges_independent_members_and_refuses_same_member_divergence() {
    let base = stress_manifest(false);
    let mut local = base.clone();
    let (local_addon, local_object) = addon("gstack-local-addon", AssetKind::Skill);
    add_pack_member(&mut local, local_addon);
    let mut remote = base.clone();
    let (remote_addon, remote_object) = addon("gstack-remote-addon", AssetKind::Skill);
    add_pack_member(&mut remote, remote_addon);
    let mut objects = stress_objects();
    objects.extend([local_object, remote_object]);

    let merged = merge_manifests(
        &base,
        &local,
        &remote,
        &VerifiedSkillObjectCatalog::new(objects, []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    let manifest = merged.merged_manifest().unwrap();
    assert_eq!(
        manifest.packs[&AssetId::parse("gstack-distribution").unwrap()]
            .members
            .len(),
        61
    );
    assert_eq!(
        merged.merged_lock().unwrap(),
        &derive_lockfile(manifest).unwrap()
    );

    let mut local = base.clone();
    let (local_addon, shared_object) = addon("gstack-shared-addon", AssetKind::Skill);
    add_pack_member(&mut local, local_addon);
    let mut remote = base.clone();
    let (remote_addon, _) = addon("gstack-shared-addon", AssetKind::Instruction);
    add_pack_member(&mut remote, remote_addon);
    let mut objects = stress_objects();
    objects.push(shared_object);
    let conflicted = merge_manifests(
        &base,
        &local,
        &remote,
        &VerifiedSkillObjectCatalog::new(objects, []).unwrap(),
        &capabilities(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(conflicted.conflicts().len(), 1);
    assert_eq!(
        conflicted.conflicts()[0].code,
        SyncConflictCode::DivergentComponent
    );
    assert!(matches!(
        conflicted.conflicts()[0].subject,
        SyncConflictSubject::AssetKind { .. }
    ));
    assert!(conflicted.merged_manifest().is_none());
    assert!(conflicted.merged_lock().is_none());
}
