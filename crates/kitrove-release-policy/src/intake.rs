use std::fmt;

use semver::Version;
use sha2::{Digest, Sha256};

use crate::{
    APPLICATION_ARCHIVE_LIMITS, ApplicationArchiveShapeSummary, ApplicationArchiveSpec,
    ArchivePolicyError, ParsedReleaseManifest, ReleaseManifestError, parse_release_manifest,
};

/// Byte-bound structural evidence produced from one immutable archive snapshot.
///
/// The digest identifies the inspected bytes but does not authenticate their
/// release provenance. Only the later attestation boundary may do that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationArchiveIntake {
    spec: ApplicationArchiveSpec,
    archive_sha256: [u8; 32],
    archive_size: u64,
    executable_size: u64,
}

/// Structurally validated application files from one exact archive snapshot.
///
/// This evidence is still unauthenticated until its intake is matched to a
/// cryptographically verified release subject.
#[derive(Eq, PartialEq)]
pub struct InspectedApplicationRelease {
    intake: ApplicationArchiveIntake,
    executable_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
}

impl fmt::Debug for InspectedApplicationRelease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectedApplicationRelease")
            .field("intake", &self.intake)
            .field("executable_bytes_len", &self.executable_bytes.len())
            .field("manifest_bytes_len", &self.manifest_bytes.len())
            .finish()
    }
}

impl InspectedApplicationRelease {
    pub(crate) fn new(
        intake: ApplicationArchiveIntake,
        executable_bytes: Vec<u8>,
        manifest_bytes: Vec<u8>,
    ) -> Self {
        Self {
            intake,
            executable_bytes,
            manifest_bytes,
        }
    }

    #[must_use]
    pub const fn intake(&self) -> ApplicationArchiveIntake {
        self.intake
    }

    #[must_use]
    pub fn executable_bytes(&self) -> &[u8] {
        &self.executable_bytes
    }

    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    #[must_use]
    pub fn into_executable_bytes(self) -> Vec<u8> {
        self.executable_bytes
    }

    /// Validates compatibility claims against the other files in this same archive snapshot.
    pub fn validate_manifest(
        &self,
        expected_release_version: &Version,
    ) -> Result<ParsedReleaseManifest, ReleaseManifestError> {
        let manifest = parse_release_manifest(self.intake.spec, &self.manifest_bytes)?;
        if manifest.release_version() != expected_release_version {
            return Err(ReleaseManifestError::ReleaseVersionMismatch);
        }
        if manifest.executable_sha256() != <[u8; 32]>::from(Sha256::digest(&self.executable_bytes))
        {
            return Err(ReleaseManifestError::ExecutableDigestMismatch);
        }
        Ok(manifest)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ApplicationReleaseFile {
    Executable,
    Manifest,
}

#[derive(Default)]
pub(crate) struct CapturedApplicationRelease {
    executable: Option<Vec<u8>>,
    manifest: Option<Vec<u8>>,
}

impl CapturedApplicationRelease {
    pub(crate) fn capture(&mut self, file: ApplicationReleaseFile, bytes: Vec<u8>) {
        match file {
            ApplicationReleaseFile::Executable => self.executable = Some(bytes),
            ApplicationReleaseFile::Manifest => self.manifest = Some(bytes),
        }
    }

    pub(crate) fn into_inspected(
        self,
        intake: ApplicationArchiveIntake,
    ) -> Option<InspectedApplicationRelease> {
        Some(InspectedApplicationRelease::new(
            intake,
            self.executable?,
            self.manifest?,
        ))
    }
}

impl ApplicationArchiveIntake {
    pub(crate) fn from_validated_snapshot(
        spec: ApplicationArchiveSpec,
        archive_bytes: &[u8],
        shape: ApplicationArchiveShapeSummary,
    ) -> Result<Self, ArchiveIntakeError> {
        Ok(Self {
            spec,
            archive_sha256: Sha256::digest(archive_bytes).into(),
            archive_size: checked_archive_size(archive_bytes)?,
            executable_size: shape.executable_size(),
        })
    }

    #[must_use]
    pub const fn spec(self) -> ApplicationArchiveSpec {
        self.spec
    }

    #[must_use]
    pub const fn archive_sha256(self) -> [u8; 32] {
        self.archive_sha256
    }

    #[must_use]
    pub const fn archive_size(self) -> u64 {
        self.archive_size
    }

    #[must_use]
    pub const fn executable_size(self) -> u64 {
        self.executable_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveIntakeError {
    ArchiveTooLarge,
    InvalidZip,
    InvalidXz,
    InvalidTar,
    UnsupportedFormat,
    UnsupportedCompression,
    UnsupportedTarMetadata,
    Policy(ArchivePolicyError),
}

impl fmt::Display for ArchiveIntakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArchiveTooLarge => "release archive exceeds the compressed-size limit",
            Self::InvalidZip => "release ZIP is malformed or has a non-canonical envelope",
            Self::InvalidXz => "release XZ is malformed or has a non-canonical envelope",
            Self::InvalidTar => "release TAR is malformed or has a non-canonical envelope",
            Self::UnsupportedFormat => "release archive format does not match its target policy",
            Self::UnsupportedCompression => "release ZIP uses an unsupported compression method",
            Self::UnsupportedTarMetadata => "release TAR uses unsupported extended metadata",
            Self::Policy(_) => "release archive violates application archive policy",
        })
    }
}

impl std::error::Error for ArchiveIntakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ArchivePolicyError> for ArchiveIntakeError {
    fn from(error: ArchivePolicyError) -> Self {
        Self::Policy(error)
    }
}

pub(crate) fn checked_archive_size(bytes: &[u8]) -> Result<u64, ArchiveIntakeError> {
    u64::try_from(bytes.len())
        .ok()
        .filter(|size| *size <= APPLICATION_ARCHIVE_LIMITS.max_archive_bytes)
        .ok_or(ArchiveIntakeError::ArchiveTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{APPLICATION_ARCHIVES, render_release_manifest};

    #[test]
    fn manifest_validation_binds_version_and_executable_bytes() {
        let spec = APPLICATION_ARCHIVES[0];
        let executable = b"executable".to_vec();
        let version = Version::new(1, 2, 3);
        let manifest =
            render_release_manifest(spec, &version, Sha256::digest(&executable).into(), &[])
                .unwrap();
        let intake = ApplicationArchiveIntake {
            spec,
            archive_sha256: [0; 32],
            archive_size: 1,
            executable_size: executable.len() as u64,
        };
        let release = InspectedApplicationRelease::new(intake, executable, manifest);
        assert!(release.validate_manifest(&version).is_ok());
        assert_eq!(
            release.validate_manifest(&Version::new(1, 2, 4)),
            Err(ReleaseManifestError::ReleaseVersionMismatch)
        );

        let mismatched = InspectedApplicationRelease::new(
            intake,
            b"changed".to_vec(),
            release.manifest_bytes().to_vec(),
        );
        assert_eq!(
            mismatched.validate_manifest(&version),
            Err(ReleaseManifestError::ExecutableDigestMismatch)
        );
    }
}
