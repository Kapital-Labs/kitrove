use std::collections::BTreeSet;

use kitrove_model::{
    AssetId, ContentHash, DEFAULT_MAX_SYNC_COMPONENTS, GitSyncLimits,
    MAX_SUPPORTED_SYNC_COMPONENTS, ObjectDescriptor, PortablePath, PublicationId, RemoteKey,
    RemoteRevision, Revision, SnapshotDigest, SnapshotObjectKind, SyncBaseRecord, SyncConflict,
    SyncConflictCode, SyncConflictSubject, SyncLimits,
};

const _: () = assert!(DEFAULT_MAX_SYNC_COMPONENTS <= MAX_SUPPORTED_SYNC_COMPONENTS);

fn hash(byte: char) -> ContentHash {
    ContentHash::parse(format!("blake3:{}", byte.to_string().repeat(64))).unwrap()
}

fn digest(prefix: &str, byte: char) -> String {
    format!("{prefix}{}", byte.to_string().repeat(64))
}

fn descriptor(root: &str, bytes: u64) -> ObjectDescriptor {
    ObjectDescriptor::new(
        SnapshotObjectKind::PortableSkillTree,
        PortablePath::parse(root).unwrap(),
        hash('c'),
        bytes,
    )
    .unwrap()
}

#[test]
fn sync_identity_parsers_are_exact_and_debug_is_redacted() {
    let snapshot = SnapshotDigest::parse(digest("snapshot:blake3:", 'a')).unwrap();
    let remote = RemoteKey::parse(digest("remote:blake3:", 'b')).unwrap();
    let publication = PublicationId::parse(digest("publication:blake3:", 'c')).unwrap();
    let revision_canary = "DO_NOT_ECHO_REMOTE_REVISION_31d9";
    let revision = RemoteRevision::parse(revision_canary).unwrap();

    assert!(format!("{snapshot:?}").contains("[redacted]"));
    assert!(format!("{remote:?}").contains("[redacted]"));
    assert!(format!("{publication:?}").contains("[redacted]"));
    assert!(!format!("{revision:?}").contains(revision_canary));
    assert!(SnapshotDigest::parse(digest("snapshot:blake3:", 'A')).is_err());
    assert!(RemoteKey::parse(digest("blake3:", 'b')).is_err());
    assert!(PublicationId::parse(digest("publication:blake3:", 'C')).is_err());
    assert!(RemoteRevision::parse("line\nbreak").is_err());
    assert!(RemoteRevision::parse("x".repeat(1025)).is_err());
}

#[test]
fn sync_limits_refuse_zero_and_inconsistent_budgets() {
    assert!(SyncLimits::new(10, 1, 4, 4, 1, 5, 5, 1, 1, 1).is_ok());
    assert!(SyncLimits::new(0, 1, 1, 1, 1, 1, 1, 1, 1, 1).is_err());
    assert!(SyncLimits::new(8, 1, 4, 4, 1, 6, 5, 1, 1, 1).is_err());
    assert!(SyncLimits::new(7, 1, 4, 4, 1, 1, 1, 1, 1, 1).is_err());
    assert!(SyncLimits::new(8, 1, 4, 4, 1, 1, 1, 1, 1, 0).is_err());
    assert!(SyncLimits::new(10, 1, 4, 4, 1, 5, 5, 1, MAX_SUPPORTED_SYNC_COMPONENTS, 1,).is_ok());
    assert!(
        SyncLimits::new(
            10,
            1,
            4,
            4,
            1,
            5,
            5,
            1,
            MAX_SUPPORTED_SYNC_COMPONENTS + 1,
            1,
        )
        .is_err()
    );
}

#[test]
fn git_sync_limits_are_explicit_bounded_and_replaceable() {
    let defaults = SyncLimits::default().git();
    assert_eq!(defaults.max_response_header_bytes(), 32 * 1024);
    assert_eq!(defaults.http_input_buffer_bytes(), 8 * 1024);
    assert_eq!(defaults.http_output_buffer_bytes(), 8 * 1024);
    assert_eq!(defaults.max_response_body_bytes(), 512 * 1024 * 1024);
    assert_eq!(defaults.max_request_body_bytes(), 384 * 1024 * 1024);
    assert_eq!(defaults.max_advertisement_bytes(), 4 * 1024 * 1024);
    assert_eq!(defaults.max_advertisement_refs(), 4096);
    assert_eq!(defaults.max_packet_lines(), 65_536);
    assert_eq!(defaults.max_received_pack_bytes(), 384 * 1024 * 1024);
    assert_eq!(defaults.max_decoded_objects(), 16_384);
    assert_eq!(defaults.max_decoded_object_bytes(), 32 * 1024 * 1024);
    assert_eq!(defaults.max_total_decoded_object_bytes(), 512 * 1024 * 1024);
    assert_eq!(defaults.max_delta_depth(), 64);
    assert_eq!(defaults.connect_timeout_ms(), 10_000);
    assert_eq!(defaults.response_header_timeout_ms(), 15_000);
    assert_eq!(defaults.body_read_timeout_ms(), 15_000);
    assert_eq!(defaults.exchange_deadline_ms(), 120_000);
    assert_eq!(defaults.operation_deadline_ms(), 300_000);

    let tiny = GitSyncLimits::new(1, 1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1).unwrap();
    assert_eq!(SyncLimits::default().with_git_limits(tiny).git(), tiny);
    assert!(GitSyncLimits::new(1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1).is_err());
    assert!(GitSyncLimits::new(1, 1, 1, 2, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1).is_err());
    assert!(GitSyncLimits::new(1, 1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1).is_err());
}

#[test]
fn local_base_round_trips_strictly_and_redacts_backend_evidence() {
    let revision_canary = "DO_NOT_ECHO_REMOTE_REVISION_f8ab";
    let base = SyncBaseRecord::new(
        RemoteKey::parse(digest("remote:blake3:", 'a')).unwrap(),
        SnapshotDigest::parse(digest("snapshot:blake3:", 'b')).unwrap(),
        Revision::parse(format!("manifest:blake3:{}", "c".repeat(64))).unwrap(),
        RemoteRevision::parse(revision_canary).unwrap(),
        BTreeSet::from([descriptor("objects/portable", 128)]),
        SyncLimits::default(),
    )
    .unwrap();
    let encoded = base.to_json(SyncLimits::default()).unwrap();
    let decoded = SyncBaseRecord::from_json(&encoded, SyncLimits::default()).unwrap();

    assert_eq!(decoded, base);
    assert!(!format!("{base:?}").contains(revision_canary));
    assert!(
        encoded.contains(revision_canary),
        "local evidence retains the opaque revision"
    );

    let unknown = encoded.replacen("{", "{\n  \"secret\": \"canary\",", 1);
    let error = SyncBaseRecord::from_json(&unknown, SyncLimits::default()).unwrap_err();
    assert_eq!(error.code(), "sync_base.invalid_json");
    assert!(!error.to_string().contains("canary"));
}

#[test]
fn local_base_refuses_duplicate_roots_and_object_budget_overflow() {
    let limits = SyncLimits::new(100, 10_000, 10, 10, 2, 8, 12, 1, 1, 1).unwrap();
    let common = (
        RemoteKey::parse(digest("remote:blake3:", 'a')).unwrap(),
        SnapshotDigest::parse(digest("snapshot:blake3:", 'b')).unwrap(),
        Revision::parse("manifest:1").unwrap(),
        RemoteRevision::parse("revision-1").unwrap(),
    );

    let duplicate_roots = BTreeSet::from([
        descriptor("objects/shared", 4),
        ObjectDescriptor::new(
            SnapshotObjectKind::NativeSkillObject,
            PortablePath::parse("objects/shared").unwrap(),
            hash('d'),
            4,
        )
        .unwrap(),
    ]);
    assert_eq!(
        SyncBaseRecord::new(
            common.0.clone(),
            common.1.clone(),
            common.2.clone(),
            common.3.clone(),
            duplicate_roots,
            limits,
        )
        .unwrap_err()
        .code(),
        "sync_objects.duplicate_root"
    );

    let overflow = BTreeSet::from([descriptor("objects/a", 7), descriptor("objects/b", 7)]);
    assert_eq!(
        SyncBaseRecord::new(common.0, common.1, common.2, common.3, overflow, limits)
            .unwrap_err()
            .code(),
        "sync_objects.total_bytes_exceeded"
    );
}

#[test]
fn conflicts_have_stable_compiled_messages_and_structural_debug() {
    let secret_shaped_id = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
    let conflict = SyncConflict {
        code: SyncConflictCode::DivergentComponent,
        subject: SyncConflictSubject::Portable {
            asset: AssetId::parse(secret_shaped_id).unwrap(),
        },
    };
    let debug = format!("{conflict:?}");

    assert_eq!(conflict.code.as_str(), "sync.divergent_component");
    assert_eq!(
        conflict.code.message(),
        "both sides changed the same semantic component"
    );
    assert!(!debug.contains(secret_shaped_id));
    assert!(debug.contains("[redacted]"));
}
