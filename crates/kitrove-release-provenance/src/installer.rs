use std::fmt;

use kitrove_release_policy::{
    InspectedInstallerRelease, InstallerArchiveSpec, ParsedInstallerManifest, ReleaseManifestError,
};
use sha2::{Digest as _, Sha256};

use crate::{ExpectedReleaseIdentity, ReleaseAttestationError, verify_release_attestation};

/// Verified installer bytes, never application installation or rollback authority.
/// Authentication grants no filesystem ownership or permission to execute.
///
/// ```compile_fail
/// use kitrove_release_provenance::{AuthenticatedInstallerExecutable, AuthenticatedApplicationExecutable};
/// fn application(installer: AuthenticatedInstallerExecutable) -> AuthenticatedApplicationExecutable {
///     installer.into()
/// }
/// ```
#[derive(Eq, PartialEq)]
pub struct AuthenticatedInstallerExecutable {
    inspected: InspectedInstallerRelease,
    manifest: ParsedInstallerManifest,
    expected: ExpectedReleaseIdentity,
    bundle_sha256: [u8; 32],
}

impl fmt::Debug for AuthenticatedInstallerExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedInstallerExecutable")
            .field("spec", &self.spec())
            .field("expected", &self.expected)
            .field("archive_sha256", &self.archive_sha256())
            .field("bundle_sha256", &self.bundle_sha256)
            .field("bytes_len", &self.bytes().len())
            .finish()
    }
}

impl AuthenticatedInstallerExecutable {
    #[must_use]
    pub fn spec(&self) -> InstallerArchiveSpec {
        self.inspected.spec()
    }

    #[must_use]
    pub fn archive_sha256(&self) -> [u8; 32] {
        self.inspected.archive_sha256()
    }

    #[must_use]
    pub const fn manifest(&self) -> &ParsedInstallerManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn release_identity(&self) -> &ExpectedReleaseIdentity {
        &self.expected
    }

    #[must_use]
    pub const fn attestation_bundle_sha256(&self) -> [u8; 32] {
        self.bundle_sha256
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.inspected.executable_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerVerificationError {
    Manifest(ReleaseManifestError),
    Attestation(ReleaseAttestationError),
}

impl fmt::Display for InstallerVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => write!(formatter, "installer manifest refused: {error}"),
            Self::Attestation(error) => write!(formatter, "installer attestation refused: {error}"),
        }
    }
}

impl std::error::Error for InstallerVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Manifest(error) => error,
            Self::Attestation(error) => error,
        })
    }
}

/// Authenticate the same bounded archive snapshot that supplied the installer bytes.
/// This is offline verification, not download, extraction to disk, or execution.
pub fn verify_installer_archive_attestation(
    inspected: InspectedInstallerRelease,
    expected: &ExpectedReleaseIdentity,
    bundle_bytes: &[u8],
) -> Result<AuthenticatedInstallerExecutable, InstallerVerificationError> {
    let manifest = inspected
        .validate_manifest(expected.release_version())
        .map_err(InstallerVerificationError::Manifest)?;
    verify_release_attestation(
        inspected.spec().archive_name(),
        inspected.archive_sha256(),
        expected,
        bundle_bytes,
    )
    .map_err(InstallerVerificationError::Attestation)?;
    Ok(AuthenticatedInstallerExecutable {
        inspected,
        manifest,
        expected: expected.clone(),
        bundle_sha256: Sha256::digest(bundle_bytes).into(),
    })
}

#[cfg(test)]
#[path = "installer_tests.rs"]
mod tests;
