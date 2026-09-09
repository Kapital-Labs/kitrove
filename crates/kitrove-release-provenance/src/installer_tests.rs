use std::io::{Cursor, Write as _};

use kitrove_release_policy::{
    APPLICATION_RELEASE_MANIFEST_NAME, BINARY_COMPANIONS, INSTALLER_ARCHIVES,
    extract_installer_release, render_installer_manifest,
};
use semver::Version;

use super::*;

const EXECUTABLE: &[u8] = b"synthetic installer executable, never run";

fn expected() -> ExpectedReleaseIdentity {
    ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567").unwrap()
}

fn inspected(version: Version, digest: [u8; 32]) -> InspectedInstallerRelease {
    let spec = INSTALLER_ARCHIVES[3];
    let manifest = render_installer_manifest(spec, &version, digest).unwrap();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for name in BINARY_COMPANIONS
        .into_iter()
        .chain([spec.executable_name()])
    {
        let bytes: &[u8] = if name == spec.executable_name() {
            EXECUTABLE
        } else if name == APPLICATION_RELEASE_MANIFEST_NAME {
            &manifest
        } else {
            b"synthetic companion"
        };
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
    }
    let bytes = zip.finish().unwrap().into_inner();
    extract_installer_release(spec, &bytes).unwrap()
}

fn valid_inspected() -> InspectedInstallerRelease {
    inspected(Version::new(1, 2, 3), Sha256::digest(EXECUTABLE).into())
}

#[test]
fn installer_manifest_must_bind_version_and_executable_before_authentication() {
    for (archive, error) in [
        (
            inspected(Version::new(1, 2, 4), Sha256::digest(EXECUTABLE).into()),
            ReleaseManifestError::ReleaseVersionMismatch,
        ),
        (
            inspected(Version::new(1, 2, 3), [0; 32]),
            ReleaseManifestError::ExecutableDigestMismatch,
        ),
    ] {
        assert_eq!(
            verify_installer_archive_attestation(archive, &expected(), b"{}"),
            Err(InstallerVerificationError::Manifest(error))
        );
    }
}

#[test]
fn installer_verification_requires_real_bounded_provenance() {
    let oversized = vec![b' '; crate::APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES + 1];
    let unrelated = include_bytes!("../tests/fixtures/github-actions-public-slsa-v1.json");
    for (bundle, error) in [
        (b"{}".as_slice(), ReleaseAttestationError::InvalidBundle),
        (
            oversized.as_slice(),
            ReleaseAttestationError::BundleTooLarge,
        ),
        (
            unrelated.as_slice(),
            ReleaseAttestationError::VerificationFailed,
        ),
    ] {
        assert_eq!(
            verify_installer_archive_attestation(valid_inspected(), &expected(), bundle),
            Err(InstallerVerificationError::Attestation(error))
        );
    }
}

#[test]
fn authenticated_installer_retains_snapshot_and_redacts_executable_bytes() {
    // Private construction tests the result container, not cryptographic acceptance.
    // A real Kitrove release fixture remains a publication acceptance gate.
    let inspected = valid_inspected();
    let digest = inspected.archive_sha256();
    let authenticated = AuthenticatedInstallerExecutable {
        manifest: inspected
            .validate_manifest(expected().release_version())
            .unwrap(),
        inspected,
        expected: expected(),
        bundle_sha256: [1; 32],
    };
    assert_eq!(authenticated.spec(), INSTALLER_ARCHIVES[3]);
    assert_eq!(authenticated.archive_sha256(), digest);
    assert_eq!(authenticated.bytes(), EXECUTABLE);
    assert_eq!(authenticated.release_identity(), &expected());
    assert_eq!(authenticated.attestation_bundle_sha256(), [1; 32]);
    assert_eq!(
        authenticated.manifest().release_version(),
        &Version::new(1, 2, 3)
    );
    assert!(!format!("{authenticated:?}").contains("synthetic installer executable"));
}
