use kitrove_release_policy::INSTALLER_CONTAINERS;

use super::*;

fn expected() -> ExpectedReleaseIdentity {
    ExpectedReleaseIdentity::new("v1.2.3", "0123456789abcdef0123456789abcdef01234567").unwrap()
}

#[test]
fn image_bounds_are_checked_before_attestation() {
    let max = usize::try_from(APPLICATION_ARCHIVE_LIMITS.max_archive_bytes).unwrap();
    for size in [0, max + 1, usize::MAX] {
        assert_eq!(
            validate_image_size(size),
            Err(InstallerContainerVerificationError::InvalidImageSize)
        );
    }
    for size in [1, max] {
        assert_eq!(validate_image_size(size), Ok(()));
    }
    assert_eq!(
        verify_installer_container_attestation(INSTALLER_CONTAINERS[0], vec![], &expected(), b"{}"),
        Err(InstallerContainerVerificationError::InvalidImageSize)
    );
}

#[test]
fn both_images_require_real_bounded_release_provenance() {
    let oversized = vec![b' '; crate::APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES + 1];
    let unrelated = include_bytes!("../tests/fixtures/github-actions-public-slsa-v1.json");
    for spec in INSTALLER_CONTAINERS {
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
                verify_installer_container_attestation(
                    spec,
                    b"opaque synthetic image".to_vec(),
                    &expected(),
                    bundle
                ),
                Err(InstallerContainerVerificationError::Attestation(error))
            );
        }
    }
}

#[test]
fn authenticated_container_retains_exact_snapshot_without_executable_authority() {
    // Private construction exercises result storage, not cryptographic acceptance.
    // A real production Kitrove fixture remains a release acceptance gate.
    for spec in INSTALLER_CONTAINERS {
        let bytes = b"opaque synthetic image".to_vec();
        let image_sha256 = Sha256::digest(&bytes).into();
        let authenticated = AuthenticatedInstallerContainer {
            spec,
            bytes,
            image_sha256,
            expected: expected(),
            bundle_sha256: [1; 32],
        };
        assert_eq!(authenticated.spec(), spec);
        assert_eq!(authenticated.bytes(), b"opaque synthetic image");
        assert_eq!(authenticated.image_sha256(), image_sha256);
        assert_eq!(authenticated.release_identity(), &expected());
        assert_eq!(authenticated.attestation_bundle_sha256(), [1; 32]);
        assert!(!format!("{authenticated:?}").contains("opaque synthetic image"));
    }
}
