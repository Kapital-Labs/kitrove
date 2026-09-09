use std::collections::BTreeSet;

use kitrove_core::PortableSnapshotV1;
use kitrove_model::{
    BindingName, ContentHash, Lockfile, ObjectDescriptor, PortablePath, Revision,
    SnapshotObjectKind, SyncLimits,
};
use kitrove_testkit::portable_manifest;
use serde_json::Value;

fn object(bytes: u64) -> ObjectDescriptor {
    ObjectDescriptor::new(
        SnapshotObjectKind::PortableSkillTree,
        PortablePath::parse("assets/review/portable").unwrap(),
        ContentHash::parse(format!("blake3:{}", "a".repeat(64))).unwrap(),
        bytes,
    )
    .unwrap()
}

fn objects(bytes: u64) -> BTreeSet<ObjectDescriptor> {
    BTreeSet::from([object(bytes)])
}

fn encode(value: &Value) -> String {
    let mut encoded = serde_json::to_string_pretty(value).unwrap();
    encoded.push('\n');
    encoded
}

#[test]
fn canonical_snapshot_has_a_fixed_digest_and_round_trips_strictly() {
    let snapshot =
        PortableSnapshotV1::new(portable_manifest(), objects(128), SyncLimits::default()).unwrap();
    let encoded = snapshot.to_json(SyncLimits::default()).unwrap();
    let decoded = PortableSnapshotV1::from_json(&encoded, SyncLimits::default()).unwrap();

    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.manifest(), &portable_manifest());
    assert_eq!(decoded.objects(), &objects(128));
    assert_eq!(
        decoded.lock_digest(),
        &ContentHash::digest(decoded.lock_json().as_bytes())
    );
    assert_eq!(
        decoded.snapshot_digest().as_str(),
        "snapshot:blake3:1fbe566afabbdf12d91829f9b56f79bc4d9fb61a9e784be065cad90d66c4d90a"
    );
}

#[test]
fn digest_changes_with_manifest_authority_and_descriptor_length() {
    let base =
        PortableSnapshotV1::new(portable_manifest(), objects(128), SyncLimits::default()).unwrap();
    let length_changed =
        PortableSnapshotV1::new(portable_manifest(), objects(129), SyncLimits::default()).unwrap();
    let mut changed_manifest = portable_manifest();
    changed_manifest
        .required_bindings
        .insert(BindingName::parse("review_token").unwrap());
    let authority_changed =
        PortableSnapshotV1::new(changed_manifest, objects(128), SyncLimits::default()).unwrap();

    assert_ne!(base.snapshot_digest(), length_changed.snapshot_digest());
    assert_ne!(base.snapshot_digest(), authority_changed.snapshot_digest());
    assert_ne!(
        base.manifest_revision(),
        authority_changed.manifest_revision()
    );
}

#[test]
fn verification_rejects_every_derived_identity_or_lock_mismatch() {
    let snapshot =
        PortableSnapshotV1::new(portable_manifest(), objects(128), SyncLimits::default()).unwrap();
    let encoded = snapshot.to_json(SyncLimits::default()).unwrap();

    let mut revision: Value = serde_json::from_str(&encoded).unwrap();
    revision["manifest_revision"] = Value::String("manifest:forged".to_owned());
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&revision), SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.manifest_revision_mismatch"
    );

    let mut lock: Value = serde_json::from_str(&encoded).unwrap();
    let mut drifted_lock = Lockfile::from_json(lock["lock_json"].as_str().unwrap()).unwrap();
    drifted_lock
        .packs
        .values_mut()
        .next()
        .unwrap()
        .resolved_source
        .revision = Revision::parse("git:fedcba9876543210").unwrap();
    lock["lock_json"] = Value::String(drifted_lock.to_json().unwrap());
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&lock), SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.lock_mismatch"
    );

    let mut lock_digest: Value = serde_json::from_str(&encoded).unwrap();
    lock_digest["lock_digest"] = Value::String(format!("blake3:{}", "c".repeat(64)));
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&lock_digest), SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.lock_digest_mismatch"
    );

    let mut digest: Value = serde_json::from_str(&encoded).unwrap();
    digest["snapshot_digest"] = Value::String(format!("snapshot:blake3:{}", "d".repeat(64)));
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&digest), SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.digest_mismatch"
    );
}

#[test]
fn canonical_manifest_lock_and_outer_json_forms_are_mandatory() {
    let snapshot =
        PortableSnapshotV1::new(portable_manifest(), objects(128), SyncLimits::default()).unwrap();
    let encoded = snapshot.to_json(SyncLimits::default()).unwrap();

    let mut manifest: Value = serde_json::from_str(&encoded).unwrap();
    manifest["manifest_toml"] =
        Value::String(format!("{}\n", manifest["manifest_toml"].as_str().unwrap()));
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&manifest), SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.manifest_noncanonical"
    );

    let mut lock: Value = serde_json::from_str(&encoded).unwrap();
    lock["lock_json"] = Value::String(
        serde_json::to_string(
            &serde_json::from_str::<Value>(lock["lock_json"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&lock), SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.lock_noncanonical"
    );

    let minified =
        serde_json::to_string(&serde_json::from_str::<Value>(&encoded).unwrap()).unwrap();
    assert_eq!(
        PortableSnapshotV1::from_json(&minified, SyncLimits::default())
            .unwrap_err()
            .code(),
        "sync_snapshot.noncanonical"
    );
}

#[test]
fn object_catalog_must_be_complete_exact_unique_and_bounded() {
    let limits = SyncLimits::default();
    assert_eq!(
        PortableSnapshotV1::new(portable_manifest(), BTreeSet::new(), limits)
            .unwrap_err()
            .code(),
        "sync_snapshot.object_catalog_mismatch"
    );

    let wrong_hash = ObjectDescriptor::new(
        SnapshotObjectKind::PortableSkillTree,
        PortablePath::parse("assets/review/portable").unwrap(),
        ContentHash::parse(format!("blake3:{}", "b".repeat(64))).unwrap(),
        128,
    )
    .unwrap();
    assert_eq!(
        PortableSnapshotV1::new(portable_manifest(), BTreeSet::from([wrong_hash]), limits)
            .unwrap_err()
            .code(),
        "sync_snapshot.object_catalog_mismatch"
    );

    let extra = ObjectDescriptor::new(
        SnapshotObjectKind::PortableSkillTree,
        PortablePath::parse("assets/unreferenced/portable").unwrap(),
        ContentHash::parse(format!("blake3:{}", "c".repeat(64))).unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(
        PortableSnapshotV1::new(
            portable_manifest(),
            BTreeSet::from([object(128), extra]),
            limits,
        )
        .unwrap_err()
        .code(),
        "sync_snapshot.object_catalog_mismatch"
    );

    let snapshot = PortableSnapshotV1::new(portable_manifest(), objects(128), limits).unwrap();
    let mut duplicate: Value = serde_json::from_str(&snapshot.to_json(limits).unwrap()).unwrap();
    let repeated = duplicate["objects"][0].clone();
    duplicate["objects"].as_array_mut().unwrap().push(repeated);
    assert_eq!(
        PortableSnapshotV1::from_json(&encode(&duplicate), limits)
            .unwrap_err()
            .code(),
        "sync_objects.duplicate_descriptor"
    );

    let small_object_limit =
        SyncLimits::new(10_000, 10_000, 4096, 4096, 4, 64, 64, 4, 64, 4).expect("coherent limits");
    assert_eq!(
        PortableSnapshotV1::new(portable_manifest(), objects(65), small_object_limit)
            .unwrap_err()
            .code(),
        "sync_objects.object_bytes_exceeded"
    );
}

#[test]
fn malformed_or_extended_input_is_redacted_and_debug_is_structural() {
    let canary = "sk-ant-api03-DO_NOT_ECHO_SNAPSHOT_CANARY";
    let snapshot =
        PortableSnapshotV1::new(portable_manifest(), objects(128), SyncLimits::default()).unwrap();
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("assets/review/portable"));
    assert!(!debug.contains("example.test"));

    let encoded = snapshot.to_json(SyncLimits::default()).unwrap();
    let extended = encoded.replacen("{", &format!("{{\n  \"secret\": \"{canary}\","), 1);
    let error = PortableSnapshotV1::from_json(&extended, SyncLimits::default()).unwrap_err();
    assert_eq!(error.code(), "sync_snapshot.invalid_json");
    assert!(!error.to_string().contains(canary));
}
