use sha2::{Digest as _, Sha256};

use crate::StagingInput;

#[cfg(unix)]
pub(crate) type TestDestination = tempfile::TempDir;
#[cfg(windows)]
pub(crate) type TestDestination = crate::windows_test_support::TestDestination;

pub(crate) const EMPTY_STATE: &[u8] =
    br#"{"schema_version":1,"machine":{"id":"test-machine","active_profile":null}}"#;

pub(crate) fn initialized_state(bytes: &[u8]) -> (TestDestination, std::path::PathBuf) {
    #[cfg(unix)]
    let parent = private_tempdir();
    #[cfg(windows)]
    let parent = crate::windows_test_support::destination();
    let path = parent.path().join("state");
    let (authority, guard) =
        kitrove_state_lifecycle::StateAuthority::initialize_absent(&path).unwrap();
    authority
        .exclusive_access(&guard)
        .unwrap()
        .create_initial_state(bytes)
        .unwrap();
    (parent, path)
}

pub(crate) fn prepared_stage(
    bytes: &[u8],
) -> (
    TestDestination,
    crate::StagedApplication,
    std::path::PathBuf,
) {
    #[cfg(unix)]
    let destination = private_tempdir();
    #[cfg(windows)]
    let destination = crate::windows_test_support::destination();
    #[cfg(unix)]
    let staged = crate::unix_staging::stage(destination.path(), &staging_input(bytes)).unwrap();
    #[cfg(windows)]
    let staged = crate::windows_staging::stage_after_security_preflight_for_tests(
        destination.path(),
        &staging_input(bytes),
    )
    .unwrap();
    let path = destination
        .path()
        .join(crate::INSTALLER_STATE_DIRECTORY)
        .join(staged.record.operation_id());
    (destination, staged, path)
}

#[cfg(unix)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    let user_directory = std::env::var_os("HOME").expect("test user directory");
    tempfile::Builder::new()
        .prefix(".kitrove-installer-test-")
        .tempdir_in(user_directory)
        .unwrap()
}

pub(crate) fn staging_input(bytes: &[u8]) -> StagingInput<'_> {
    let target = crate::compiled_release_target().unwrap();
    let spec = kitrove_release_policy::application_archive_for_target(target).unwrap();
    let manifest_bytes = kitrove_release_policy::render_release_manifest(
        spec,
        &semver::Version::new(1, 2, 3),
        Sha256::digest(bytes).into(),
        &[],
    )
    .unwrap();
    StagingInput {
        target,
        archive_name: spec.archive_name(),
        archive_sha256: [1; 32],
        executable_name: spec.executable_name(),
        executable_sha256: Sha256::digest(bytes).into(),
        executable_bytes: bytes,
        release_tag: "v1.2.3",
        release_version: "1.2.3".to_owned(),
        source_commit: "0123456789abcdef0123456789abcdef01234567",
        signer_identity: "https://github.com/Kapital-Labs/kitrove/.github/workflows/release.yml@refs/tags/v1.2.3",
        attestation_bundle_sha256: [2; 32],
        trust_root_sha256: kitrove_release_provenance::PINNED_SIGSTORE_TRUST_ROOT_SHA256,
        manifest: kitrove_release_policy::parse_release_manifest(spec, &manifest_bytes).unwrap(),
        manifest_sha256: Sha256::digest(&manifest_bytes).into(),
    }
}

#[cfg(all(unix, debug_assertions))]
pub(crate) fn upgrade_releases() -> (
    kitrove_release_provenance::AuthenticatedApplicationExecutable,
    kitrove_release_provenance::AuthenticatedRecoveryMaterial,
) {
    upgrade_releases_with_bytes(b"prior executable", b"candidate executable")
}

#[cfg(all(unix, debug_assertions))]
pub(crate) fn upgrade_releases_with_bytes(
    prior_bytes: &[u8],
    candidate_bytes: &[u8],
) -> (
    kitrove_release_provenance::AuthenticatedApplicationExecutable,
    kitrove_release_provenance::AuthenticatedRecoveryMaterial,
) {
    replacement_releases_with_bytes(
        prior_bytes,
        candidate_bytes,
        crate::replacement_direction::ReplacementDirection::Upgrade,
    )
}

#[cfg(debug_assertions)]
pub(crate) fn replacement_releases_with_bytes(
    prior_bytes: &[u8],
    candidate_bytes: &[u8],
    direction: crate::replacement_direction::ReplacementDirection,
) -> (
    kitrove_release_provenance::AuthenticatedApplicationExecutable,
    kitrove_release_provenance::AuthenticatedRecoveryMaterial,
) {
    use kitrove_release_provenance::{
        AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity,
    };
    let spec = kitrove_release_policy::application_archive_for_target(
        crate::compiled_release_target().unwrap(),
    )
    .unwrap();
    let prior_version = semver::Version::new(1, 2, 3);
    let prior_archive =
        crate::release_archive_fixture::archive(spec, &prior_version, prior_bytes, &[]);
    let prior_identity =
        ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567").unwrap();
    let candidate_archive = crate::release_archive_fixture::archive(
        spec,
        &semver::Version::new(1, 2, 4),
        candidate_bytes,
        &[prior_version],
    );
    let candidate_identity =
        ExpectedReleaseIdentity::new("v1.2.4", "0123456789abcdef0123456789abcdef01234567").unwrap();
    let (desired_archive, desired_identity, installed_archive, installed_identity) = match direction
    {
        crate::replacement_direction::ReplacementDirection::Upgrade => (
            &candidate_archive,
            &candidate_identity,
            &prior_archive,
            &prior_identity,
        ),
        crate::replacement_direction::ReplacementDirection::Rollback => (
            &prior_archive,
            &prior_identity,
            &candidate_archive,
            &candidate_identity,
        ),
    };
    let rollback = AuthenticatedRecoveryMaterial::from_test_archive(
        spec,
        installed_archive,
        b"synthetic test bundle",
        installed_identity,
    )
    .unwrap();
    let candidate = AuthenticatedApplicationExecutable::from_test_archive(
        spec,
        desired_archive,
        desired_identity,
    )
    .unwrap();
    (candidate, rollback)
}
