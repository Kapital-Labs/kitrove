use super::*;

#[test]
#[ignore = "run explicitly under the dedicated unelevated Windows CI account"]
fn standard_user_local_release_intake() {
    assert!(!kitrove_windows_security::current_process_is_elevated().unwrap());
    let directory = crate::windows_test_support::destination_in(&std::env::current_dir().unwrap());
    let (_, material) = crate::test_support::replacement_releases_with_bytes(
        b"prior executable",
        b"candidate executable",
        crate::replacement_direction::ReplacementDirection::Upgrade,
    );
    let archive = directory
        .path()
        .join(material.executable().subject().spec().archive_name());
    let bundle = directory.path().join("attestation.json");
    for (path, bytes) in [
        (&archive, material.archive_bytes()),
        (&bundle, material.bundle_bytes()),
    ] {
        kitrove_windows_security::write_current_user_owned_file_for_tests(path, bytes).unwrap();
    }
    let expected = ExpectedReleaseIdentity::new(
        material.executable().subject().release_tag(),
        material.executable().subject().source_commit(),
    )
    .unwrap();
    let request = LocalReleaseRequest {
        archive: &archive,
        bundle: &bundle,
        expected: &expected,
        archive_sha256: material.executable().subject().archive_sha256(),
    };
    let observed = request
        .authenticate_with(|spec, archive_bytes, bundle_bytes, identity| {
            assert!(std::fs::write(&archive, b"competing archive writer").is_err());
            assert!(std::fs::write(&bundle, b"competing bundle writer").is_err());
            assert!(std::fs::rename(&archive, directory.path().join("displaced")).is_err());
            AuthenticatedRecoveryMaterial::from_test_archive(
                spec,
                archive_bytes,
                bundle_bytes,
                identity,
            )
            .map_err(|_| InstallerStageError::VerificationFailed)
        })
        .unwrap();
    assert_eq!(observed.archive_bytes(), material.archive_bytes());
    assert_eq!(observed.bundle_bytes(), material.bundle_bytes());
    assert_eq!(
        request.authenticate().err(),
        Some(ReleaseIntakeError::VerificationFailed)
    );
    assert_eq!(std::fs::read(&archive).unwrap(), material.archive_bytes());
    assert_eq!(std::fs::read(&bundle).unwrap(), material.bundle_bytes());
    let size = material.archive_bytes().len() as u64;
    assert!(RetainedArtifact::open(&archive, size).is_ok());
    assert!(RetainedArtifact::open(&archive, size - 1).is_err());
    std::fs::hard_link(&archive, directory.path().join("alias")).unwrap();
    assert_eq!(
        request.authenticate().err(),
        Some(ReleaseIntakeError::UnsafeInput)
    );
    assert_eq!(std::fs::read(&archive).unwrap(), material.archive_bytes());
}
