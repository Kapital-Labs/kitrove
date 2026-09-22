//! Authenticate opaque image bytes; never mount, parse or execute their payload.
use std::fmt;

use kitrove_release_policy::{APPLICATION_ARCHIVE_LIMITS, InstallerContainerSpec};
use sha2::{Digest as _, Sha256};

use crate::{ExpectedReleaseIdentity, ReleaseAttestationError, verify_release_attestation};

/// Exact image snapshot authenticated by the fixed release provenance policy.
/// This is neither native-signature/payload validation nor permission to execute.
/// The caller must independently trust the verifier before using downloaded images.
///
/// ```compile_fail
/// use kitrove_release_provenance::{AuthenticatedInstallerContainer, AuthenticatedApplicationExecutable};
/// fn application(image: AuthenticatedInstallerContainer) -> AuthenticatedApplicationExecutable {
///     image.into()
/// }
/// ```
///
/// ```compile_fail
/// use kitrove_release_provenance::{AuthenticatedInstallerContainer, AuthenticatedInstallerExecutable};
/// fn installer(image: AuthenticatedInstallerContainer) -> AuthenticatedInstallerExecutable {
///     image.into()
/// }
/// ```
#[derive(Eq, PartialEq)]
pub struct AuthenticatedInstallerContainer {
    spec: InstallerContainerSpec,
    bytes: Vec<u8>,
    image_sha256: [u8; 32],
    expected: ExpectedReleaseIdentity,
    bundle_sha256: [u8; 32],
}

impl fmt::Debug for AuthenticatedInstallerContainer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedInstallerContainer")
            .field("spec", &self.spec)
            .field("image_sha256", &self.image_sha256)
            .field("expected", &self.expected)
            .field("bundle_sha256", &self.bundle_sha256)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl AuthenticatedInstallerContainer {
    #[must_use]
    pub const fn spec(&self) -> InstallerContainerSpec {
        self.spec
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn image_sha256(&self) -> [u8; 32] {
        self.image_sha256
    }

    #[must_use]
    pub const fn release_identity(&self) -> &ExpectedReleaseIdentity {
        &self.expected
    }

    #[must_use]
    pub const fn attestation_bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerContainerVerificationError {
    InvalidImageSize,
    Attestation(ReleaseAttestationError),
}

impl fmt::Display for InstallerContainerVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidImageSize => {
                formatter.write_str("installer image is empty or exceeds its bound")
            }
            Self::Attestation(error) => {
                write!(formatter, "installer image attestation refused: {error}")
            }
        }
    }
}

impl std::error::Error for InstallerContainerVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidImageSize => None,
            Self::Attestation(error) => Some(error),
        }
    }
}

/// Authenticate one bounded, owned image snapshot without filesystem or network access.
/// The closed spec supplies the exact subject name; the digest is computed here,
/// never accepted from a sidecar. Native checks and embedded archive authentication
/// remain separate requirements before installer execution.
pub fn verify_installer_container_attestation(
    spec: InstallerContainerSpec,
    image_bytes: Vec<u8>,
    expected: &ExpectedReleaseIdentity,
    bundle_bytes: &[u8],
) -> Result<AuthenticatedInstallerContainer, InstallerContainerVerificationError> {
    validate_image_size(image_bytes.len())?;
    let image_sha256 = Sha256::digest(&image_bytes).into();
    verify_release_attestation(spec.image_name(), image_sha256, expected, bundle_bytes)
        .map_err(InstallerContainerVerificationError::Attestation)?;
    Ok(AuthenticatedInstallerContainer {
        spec,
        bytes: image_bytes,
        image_sha256,
        expected: expected.clone(),
        bundle_sha256: Sha256::digest(bundle_bytes).into(),
    })
}

pub(super) fn validate_image_size(size: usize) -> Result<(), InstallerContainerVerificationError> {
    if size == 0
        || u64::try_from(size)
            .ok()
            .filter(|size| *size <= APPLICATION_ARCHIVE_LIMITS.max_archive_bytes)
            .is_none()
    {
        return Err(InstallerContainerVerificationError::InvalidImageSize);
    }
    Ok(())
}

#[cfg(test)]
#[path = "installer_container_tests.rs"]
mod tests;
