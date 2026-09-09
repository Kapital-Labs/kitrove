use std::collections::BTreeSet;

use kitrove_agent_skills::{CapturedFile, FileMode, NativeSkillObject, StoredSkillTree, hash_tree};
use kitrove_model::{
    BindingName, ContentHash, PublicationId, RemoteKey, RemoteRevision, SyncBaseRecord, SyncLimits,
};

use crate::adoption::tests::{capabilities, ready_plan};
use crate::sync_journal::SyncJournal;
use crate::{
    PortableSnapshotV1, PublicationIntent, RemoteSnapshot, SyncPlanOutcome, VerifiedObjectEnvelope,
    VerifiedSkillObjectCatalog, plan_sync,
};

const AUTHORED: &str = "D3-AUTHORED-CONTENT-CANARY-91a2";
const NATIVE_ID: &str = "d3-native-id-canary-82b3";
const OBJECT_BYTES: &str = "D3-RAW-OBJECT-BYTES-CANARY-73c4";
const SOURCE_PATH: &str = "/D3-ABSOLUTE-SOURCE-PATH-CANARY-64d5";
const REMOTE_PATH: &str = "/D3-REMOTE-PATH-CANARY-55e6";
const RECEIPT_DESTINATION: &str = "/D3-RECEIPT-DESTINATION-CANARY-46f7";
const BACKEND_REVISION: &str = "D3-BACKEND-REVISION-CANARY-37a8";
const PROPOSED_REVISION: &str = "D3-PROPOSED-REVISION-CANARY-28b9";
const PUBLICATION_INTENT: &str = "D3-PUBLICATION-INTENT-CANARY-19ca";
const SECRET: &str = "D3-SECRET-CANARY-0adb";

fn forbidden_public_canaries() -> [&'static str; 10] {
    [
        AUTHORED,
        NATIVE_ID,
        OBJECT_BYTES,
        SOURCE_PATH,
        REMOTE_PATH,
        RECEIPT_DESTINATION,
        BACKEND_REVISION,
        PROPOSED_REVISION,
        PUBLICATION_INTENT,
        SECRET,
    ]
}

fn assert_absent(surface: &str, canaries: &[&str]) {
    for canary in canaries {
        assert!(
            !surface.contains(canary),
            "canary leaked through bounded surface"
        );
    }
}

fn fixture() -> (
    PortableSnapshotV1,
    Vec<VerifiedObjectEnvelope>,
    VerifiedSkillObjectCatalog,
) {
    let limits = SyncLimits::default();
    let (adoption, _, _) = ready_plan();
    let mut tree = adoption.portable_object().tree().clone();
    tree.files.insert(
        kitrove_model::PortablePath::parse("authored.txt").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: AUTHORED.as_bytes().to_vec(),
        },
    );
    tree.files.insert(
        kitrove_model::PortablePath::parse("notes.md").unwrap(),
        CapturedFile {
            mode: FileMode::Regular,
            bytes: OBJECT_BYTES.as_bytes().to_vec(),
        },
    );
    tree.hash = hash_tree(&tree.files);
    let portable = StoredSkillTree::new(tree.clone()).unwrap();
    let native = NativeSkillObject::new(
        adoption.native_object().layout(),
        adoption.native_object().original_document_name(),
        NATIVE_ID,
        tree,
    )
    .unwrap();
    let mut manifest = adoption.proposed_manifest().clone();
    let asset = manifest.assets.get_mut(&adoption.asset().id).unwrap();
    asset.portable.as_mut().unwrap().object_hash = portable.tree().hash.clone();
    asset
        .native_variants
        .get_mut(adoption.origin_harness())
        .unwrap()
        .object_hash = native.hash().clone();
    asset.refresh_content_hash();
    let portable_envelope = VerifiedObjectEnvelope::portable(
        asset.portable.as_ref().unwrap().root.clone(),
        portable.clone(),
    )
    .unwrap();
    let native_envelope = VerifiedObjectEnvelope::native(
        asset
            .native_variants
            .get(adoption.origin_harness())
            .unwrap()
            .root
            .clone(),
        native.clone(),
    )
    .unwrap();
    let objects = vec![portable_envelope, native_envelope];
    let descriptors = objects
        .iter()
        .map(|object| object.descriptor().clone())
        .collect();
    let snapshot = PortableSnapshotV1::new(manifest, descriptors, limits).unwrap();
    let catalog = VerifiedSkillObjectCatalog::new([portable], [native]).unwrap();
    (snapshot, objects, catalog)
}

#[test]
fn d3_distinct_canary_allow_deny_matrix_covers_internal_and_public_surfaces() {
    let limits = SyncLimits::default();
    let (snapshot, objects, catalog) = fixture();
    crate::merge::validate_manifest_object_risk(snapshot.manifest(), &catalog, limits).unwrap();
    let snapshot_json = snapshot.to_json(limits).unwrap();
    assert_absent(&snapshot_json, &forbidden_public_canaries());

    let mut payload = String::new();
    for object in &objects {
        match object {
            VerifiedObjectEnvelope::Portable { object, .. } => {
                payload.push_str(&object.metadata_json());
                for file in object.tree().files.values() {
                    payload.push_str(std::str::from_utf8(&file.bytes).unwrap());
                }
            }
            VerifiedObjectEnvelope::Native { object, .. } => {
                payload.push_str(&object.metadata_json());
                for file in object.tree().files.values() {
                    payload.push_str(std::str::from_utf8(&file.bytes).unwrap());
                }
            }
            VerifiedObjectEnvelope::NativeExtension { object, .. } => {
                payload.push_str(&object.metadata_json());
                for file in object.tree().files.values() {
                    payload.push_str(std::str::from_utf8(&file.bytes).unwrap());
                }
            }
            VerifiedObjectEnvelope::Document { object, .. } => {
                payload.push_str(&object.to_json().unwrap());
            }
        }
    }
    for allowed in [AUTHORED, NATIVE_ID, OBJECT_BYTES] {
        assert!(payload.contains(allowed));
    }
    assert_absent(
        &payload,
        &[
            SOURCE_PATH,
            REMOTE_PATH,
            RECEIPT_DESTINATION,
            BACKEND_REVISION,
            PROPOSED_REVISION,
        ],
    );

    let SyncPlanOutcome::Ready(plan) = plan_sync(
        snapshot.clone(),
        None,
        RemoteSnapshot::absent(RemoteRevision::parse(BACKEND_REVISION).unwrap()),
        &catalog,
        &capabilities(),
        limits,
    )
    .unwrap() else {
        panic!("non-empty bootstrap must produce a plan");
    };
    assert_absent(&format!("{plan:?}"), &forbidden_public_canaries());

    let remote_key = RemoteKey::parse(format!("remote:blake3:{}", "b".repeat(64))).unwrap();
    let proposed = RemoteRevision::parse(PROPOSED_REVISION).unwrap();
    let intent =
        PublicationIntent::from_persisted(PUBLICATION_INTENT.to_owned(), proposed.clone(), limits)
            .unwrap();
    let publication =
        PublicationId::parse(format!("publication:blake3:{}", "c".repeat(64))).unwrap();
    let journal = SyncJournal::prepared(
        &plan,
        remote_key.clone(),
        Some((publication.clone(), &intent)),
        None,
        limits,
    )
    .unwrap();
    let journal_json = journal.to_json(limits).unwrap();
    for required in [BACKEND_REVISION, PROPOSED_REVISION, PUBLICATION_INTENT] {
        assert!(journal_json.contains(required));
    }
    assert!(journal_json.contains(publication.as_str()));
    assert_absent(
        &journal_json,
        &[
            AUTHORED,
            NATIVE_ID,
            OBJECT_BYTES,
            SOURCE_PATH,
            REMOTE_PATH,
            RECEIPT_DESTINATION,
            SECRET,
        ],
    );
    assert_absent(&format!("{journal:?}"), &forbidden_public_canaries());

    let base = SyncBaseRecord::new(
        remote_key,
        snapshot.snapshot_digest().clone(),
        snapshot.manifest_revision().clone(),
        RemoteRevision::parse(BACKEND_REVISION).unwrap(),
        snapshot.objects().clone(),
        limits,
    )
    .unwrap();
    let base_json = base.to_json(limits).unwrap();
    assert!(base_json.contains(BACKEND_REVISION));
    assert_absent(
        &base_json,
        &[
            AUTHORED,
            NATIVE_ID,
            OBJECT_BYTES,
            SOURCE_PATH,
            REMOTE_PATH,
            RECEIPT_DESTINATION,
            SECRET,
        ],
    );
    assert_absent(&format!("{base:?}"), &forbidden_public_canaries());

    let mut different = snapshot.manifest().clone();
    different.required_bindings = BTreeSet::from([BindingName::parse("matrix-conflict").unwrap()]);
    let different = PortableSnapshotV1::new(different, snapshot.objects().clone(), limits).unwrap();
    let SyncPlanOutcome::Blocked(conflicts) = plan_sync(
        snapshot,
        None,
        RemoteSnapshot::present(RemoteRevision::parse(PROPOSED_REVISION).unwrap(), different),
        &catalog,
        &capabilities(),
        limits,
    )
    .unwrap() else {
        panic!("distinct non-empty bootstrap must conflict");
    };
    let conflicts_json = serde_json::to_string(&conflicts).unwrap();
    assert_absent(&conflicts_json, &forbidden_public_canaries());
    assert_absent(&format!("{conflicts:?}"), &forbidden_public_canaries());

    let tiny = SyncLimits::new(8, 8, 4, 4, 1, 1, 1, 1, 1, 1).unwrap();
    let secret_error =
        PublicationIntent::from_persisted(SECRET.to_owned(), proposed, tiny).unwrap_err();
    assert_absent(&format!("{secret_error:?} {secret_error}"), &[SECRET]);
    assert_ne!(
        ContentHash::digest(SOURCE_PATH.as_bytes()),
        ContentHash::digest(REMOTE_PATH.as_bytes())
    );
}
