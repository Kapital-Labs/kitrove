use kitrove_core::{
    LockComparison, LockStatus, compare_lockfile, derive_lockfile, derive_manifest_revision,
};
use kitrove_model::{AssetId, ContentHash, Revision};
use kitrove_testkit::{portable_lockfile, portable_manifest};

#[test]
fn manifest_derives_the_checked_in_lockfile() {
    let manifest = portable_manifest();

    let derived = derive_lockfile(&manifest).expect("valid manifest derives a lockfile");

    assert_eq!(derived, portable_lockfile());
    assert_eq!(
        derived.to_json().expect("derived lock serializes"),
        portable_lockfile()
            .to_json()
            .expect("fixture lock serializes")
    );
}

#[test]
fn manifest_revision_is_canonical_and_changes_with_authority() {
    let manifest = portable_manifest();
    let revision = derive_manifest_revision(&manifest).unwrap();
    assert!(revision.as_str().starts_with("manifest:blake3:"));
    assert_eq!(revision.as_str().len(), 80);
    assert_eq!(derive_manifest_revision(&manifest).unwrap(), revision);

    let mut changed = manifest;
    changed
        .required_bindings
        .insert(kitrove_model::BindingName::parse("new_binding").expect("valid binding name"));
    assert_ne!(derive_manifest_revision(&changed).unwrap(), revision);
}

#[test]
fn comparison_distinguishes_missing_invalid_drift_and_in_sync() {
    let manifest = portable_manifest();
    let expected = derive_lockfile(&manifest).expect("derive expected lock");
    let expected_json = expected.to_json().expect("serialize expected lock");

    assert_eq!(
        compare_lockfile(&manifest, None).unwrap().status(),
        LockStatus::Missing
    );
    assert_eq!(
        compare_lockfile(&manifest, Some("not-json"))
            .unwrap()
            .status(),
        LockStatus::Invalid
    );

    let mut drifted = expected.clone();
    drifted
        .packs
        .get_mut(&AssetId::parse("review-pack").unwrap())
        .unwrap()
        .resolved_source
        .revision = Revision::parse("git:fedcba9876543210").unwrap();
    assert_eq!(
        compare_lockfile(
            &manifest,
            Some(&drifted.to_json().expect("serialize drifted lock"))
        )
        .unwrap()
        .status(),
        LockStatus::Drift
    );

    let comparison = compare_lockfile(&manifest, Some(&expected_json)).unwrap();
    assert_eq!(comparison.status(), LockStatus::InSync);
    assert_eq!(comparison.expected(), &expected);
}

#[test]
fn invalid_manifest_prevents_derivation_and_comparison() {
    let mut manifest = portable_manifest();
    manifest
        .assets
        .get_mut(&AssetId::parse("review").unwrap())
        .unwrap()
        .content_hash = ContentHash::parse(format!("blake3:{}", "d".repeat(64))).unwrap();

    assert_eq!(
        derive_lockfile(&manifest).unwrap_err().code(),
        "manifest.asset_content_hash_mismatch"
    );
    assert_eq!(
        compare_lockfile(&manifest, None).unwrap_err().code(),
        "manifest.asset_content_hash_mismatch"
    );
}

#[test]
fn lock_comparison_debug_is_structural_and_redacted() {
    let canary = "DO_NOT_ECHO_SECRET_SOURCE_9f41";
    let comparison = compare_lockfile(&portable_manifest(), Some(canary)).unwrap();
    let debug = format!("{comparison:?}");

    assert_eq!(comparison.status(), LockStatus::Invalid);
    assert!(!debug.contains(canary));
    assert!(debug.contains("Invalid"));
}

#[test]
fn comparison_owns_the_expected_repair_value_for_every_status() {
    let manifest = portable_manifest();
    let expected = derive_lockfile(&manifest).unwrap();

    for comparison in [
        compare_lockfile(&manifest, None).unwrap(),
        compare_lockfile(&manifest, Some("invalid")).unwrap(),
    ] {
        assert_eq!(comparison.expected(), &expected);
    }

    let _: LockComparison = compare_lockfile(&manifest, None).unwrap();
}
