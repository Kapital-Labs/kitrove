use std::path::Path;

use kitrove_release_policy::{APPLICATION_ARCHIVE_LIMITS, ApplicationArchiveSpec};
use kitrove_release_provenance::{
    APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES, AuthenticatedRecoveryMaterial,
    ExpectedReleaseIdentity,
};
use sha2::{Digest as _, Sha256};

use crate::InstallerStageError;
use crate::staging_policy::OpenedLeaf;

#[cfg(unix)]
type ArtifactDirectory = crate::unix_staging::OpenedDestination;
#[cfg(windows)]
type ArtifactDirectory = kitrove_windows_security::ValidatedInstallDirectory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseIntakeError {
    UnsupportedPlatform,
    UnsafeInput,
    VerificationFailed,
    BundleSelection(kitrove_release_provenance::BundleSelectionError),
}

impl std::fmt::Display for ReleaseIntakeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "release intake is unsupported on this platform",
            Self::UnsafeInput => {
                "release inputs are unsafe, changed, missing or exceed their bounds"
            }
            Self::VerificationFailed => "release inputs do not satisfy authentication policy",
            Self::BundleSelection(error) => return error.fmt(formatter),
        })
    }
}

impl std::error::Error for ReleaseIntakeError {}

/// Exact local inputs; neither a path nor an asserted checksum authenticates executable bytes.
pub(crate) struct LocalReleaseRequest<'a> {
    pub(crate) archive: &'a Path,
    pub(crate) bundle: &'a Path,
    pub(crate) expected: &'a ExpectedReleaseIdentity,
    pub(crate) archive_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BundleArtifactKind {
    Application,
    Installer,
}

impl LocalReleaseRequest<'_> {
    pub(crate) fn authenticate(&self) -> Result<AuthenticatedRecoveryMaterial, ReleaseIntakeError> {
        self.authenticate_with(verify_material)
    }

    fn authenticate_with(
        &self,
        verify: impl FnOnce(
            ApplicationArchiveSpec,
            &[u8],
            &[u8],
            &ExpectedReleaseIdentity,
        ) -> Result<AuthenticatedRecoveryMaterial, InstallerStageError>,
    ) -> Result<AuthenticatedRecoveryMaterial, ReleaseIntakeError> {
        let target = crate::compiled_release_target()
            .map_err(|_| ReleaseIntakeError::UnsupportedPlatform)?;
        let spec = kitrove_release_policy::application_archive_for_target(target)
            .map_err(|_| ReleaseIntakeError::UnsupportedPlatform)?;
        self.with_inputs(
            spec.archive_name(),
            APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES,
            |archive, bundle| {
                verify(spec, archive, bundle, self.expected)
                    .map_err(|_| ReleaseIntakeError::VerificationFailed)
            },
        )
    }

    pub(crate) fn select_bundle(
        &self,
        kind: BundleArtifactKind,
    ) -> Result<String, ReleaseIntakeError> {
        let target = crate::compiled_release_target()
            .map_err(|_| ReleaseIntakeError::UnsupportedPlatform)?;
        let application = kitrove_release_policy::application_archive_for_target(target)
            .map_err(|_| ReleaseIntakeError::UnsupportedPlatform)?;
        let installer = kitrove_release_policy::installer_archive_for_target(target)
            .map_err(|_| ReleaseIntakeError::UnsupportedPlatform)?;
        let name = match kind {
            BundleArtifactKind::Application => application.archive_name(),
            BundleArtifactKind::Installer => installer.archive_name(),
        };
        self.with_inputs(
            name,
            kitrove_release_provenance::ATTESTATION_COLLECTION_MAX_BYTES,
            |archive, collection| {
                let selected = match kind {
                    BundleArtifactKind::Application => {
                        let inspected = kitrove_release_policy::extract_application_release(
                            application,
                            archive,
                        )
                        .map_err(|_| ReleaseIntakeError::VerificationFailed)?;
                        inspected
                            .validate_manifest(self.expected.release_version())
                            .map_err(|_| ReleaseIntakeError::VerificationFailed)?;
                        kitrove_release_provenance::select_application_attestation_bundle(
                            inspected.intake(),
                            self.expected,
                            collection,
                        )
                    }
                    BundleArtifactKind::Installer => {
                        let inspected =
                            kitrove_release_policy::extract_installer_release(installer, archive)
                                .map_err(|_| ReleaseIntakeError::VerificationFailed)?;
                        kitrove_release_provenance::select_installer_attestation_bundle(
                            &inspected,
                            self.expected,
                            collection,
                        )
                    }
                }
                .map_err(ReleaseIntakeError::BundleSelection)?;
                String::from_utf8(selected).map_err(|_| ReleaseIntakeError::VerificationFailed)
            },
        )
    }

    fn with_inputs<T>(
        &self,
        archive_name: &str,
        bundle_maximum: usize,
        inspect: impl FnOnce(&[u8], &[u8]) -> Result<T, ReleaseIntakeError>,
    ) -> Result<T, ReleaseIntakeError> {
        if self.archive.file_name().and_then(|name| name.to_str()) != Some(archive_name) {
            return Err(ReleaseIntakeError::UnsafeInput);
        }
        let archive =
            RetainedArtifact::open(self.archive, APPLICATION_ARCHIVE_LIMITS.max_archive_bytes)
                .map_err(|_| ReleaseIntakeError::UnsafeInput)?;
        let bundle = RetainedArtifact::open(self.bundle, bundle_maximum as u64)
            .map_err(|_| ReleaseIntakeError::UnsafeInput)?;
        if <[u8; 32]>::from(Sha256::digest(&archive.bytes)) != self.archive_sha256 {
            return Err(ReleaseIntakeError::VerificationFailed);
        }
        let material = inspect(&archive.bytes, &bundle.bytes)?;
        // Only these retained bytes are authenticated and returned. A later stage never
        // reopens a user-selected archive path to obtain executable contents.
        archive
            .revalidate()
            .map_err(|_| ReleaseIntakeError::UnsafeInput)?;
        bundle
            .revalidate()
            .map_err(|_| ReleaseIntakeError::UnsafeInput)?;
        Ok(material)
    }
}

/// Shared offline policy for downloaded local inputs and privately retained rollback kits.
pub(crate) fn verify_material(
    spec: ApplicationArchiveSpec,
    archive: &[u8],
    bundle: &[u8],
    expected: &ExpectedReleaseIdentity,
) -> Result<AuthenticatedRecoveryMaterial, InstallerStageError> {
    let inspected = kitrove_release_policy::inspect_application_archive(spec, archive)
        .map_err(|_| InstallerStageError::VerificationFailed)?;
    let subject = kitrove_release_provenance::verify_application_archive_attestation(
        inspected, expected, bundle,
    )
    .map_err(|_| InstallerStageError::VerificationFailed)?;
    subject
        .authenticate_recovery_material(archive, bundle)
        .map_err(|_| InstallerStageError::VerificationFailed)
}

struct RetainedArtifact {
    parent: ArtifactDirectory,
    name: String,
    leaf: OpenedLeaf,
    bytes: Vec<u8>,
    #[cfg(unix)]
    mode: u32,
}

impl RetainedArtifact {
    fn open(path: &Path, maximum: u64) -> Result<Self, InstallerStageError> {
        let path = std::path::absolute(path).map_err(|_| InstallerStageError::UnsafeState)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(InstallerStageError::UnsafeState)?
            .to_owned();
        let parent_path = path.parent().ok_or(InstallerStageError::UnsafeState)?;
        #[cfg(unix)]
        let parent = crate::unix_staging::open_destination(parent_path)?;
        #[cfg(windows)]
        let parent = kitrove_windows_security::validate_install_directory(parent_path)
            .map_err(|_| InstallerStageError::UnsafeState)?;
        #[cfg(unix)]
        let mode = {
            use cap_std::fs::PermissionsExt as _;
            let mode = parent
                .directory()
                .symlink_metadata(&name)
                .map_err(|_| InstallerStageError::UnsafeState)?
                .permissions()
                .mode()
                & 0o7777;
            // Downloaded data may be readable, but must not be executable or writable
            // by other principals. No chmod or ACL repair is performed during intake.
            if !matches!(mode, 0o400 | 0o440 | 0o444 | 0o600 | 0o640 | 0o644) {
                return Err(InstallerStageError::UnsafeState);
            }
            mode
        };
        #[cfg(unix)]
        let leaf = crate::unix_recovery::open_bounded_private_file(
            parent.directory(),
            &name,
            mode,
            maximum,
        )?;
        #[cfg(windows)]
        let leaf = crate::windows_recovery::open_bounded_private_file(
            parent
                .directory()
                .map_err(|_| InstallerStageError::UnsafeState)?,
            std::ffi::OsStr::new(&name),
            maximum,
        )?;
        let size = usize::try_from(leaf.size).map_err(|_| InstallerStageError::UnsafeState)?;
        #[cfg(unix)]
        let bytes = crate::unix_staging::read_bounded_file(&leaf.file, size)?;
        #[cfg(windows)]
        let bytes = crate::windows_recovery::read_bounded_file(&leaf.file, size)?;
        let artifact = Self {
            parent,
            name,
            leaf,
            bytes,
            #[cfg(unix)]
            mode,
        };
        artifact.revalidate()?;
        Ok(artifact)
    }

    fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.revalidate_identity()?;
        let size = usize::try_from(self.leaf.size).map_err(|_| InstallerStageError::UnsafeState)?;
        #[cfg(unix)]
        let current = crate::unix_staging::read_bounded_file(&self.leaf.file, size)?;
        #[cfg(windows)]
        let current = crate::windows_recovery::read_bounded_file(&self.leaf.file, size)?;
        if self.bytes.len() != size || current != self.bytes {
            return Err(InstallerStageError::UnsafeState);
        }
        self.revalidate_identity()
    }

    fn revalidate_identity(&self) -> Result<(), InstallerStageError> {
        #[cfg(unix)]
        {
            crate::unix_staging::revalidate_destination(&self.parent)?;
            crate::unix_staging::require_named_file_identity(
                self.parent.directory(),
                &self.name,
                &self.leaf.file,
                self.leaf.identity,
                self.mode,
                self.leaf.size,
            )
        }
        #[cfg(windows)]
        {
            self.parent
                .revalidate()
                .map_err(|_| InstallerStageError::UnsafeState)?;
            kitrove_windows_security::inspect_private_single_link_file(&self.leaf.file)
                .map_err(|_| InstallerStageError::UnsafeState)?;
            crate::windows_staging::require_identity(&self.leaf.file, self.leaf.identity)?;
            crate::windows_staging::require_named_file_identity(
                self.parent
                    .directory()
                    .map_err(|_| InstallerStageError::UnsafeState)?,
                std::ffi::OsStr::new(&self.name),
                self.leaf.identity,
                false,
            )
        }
    }
}

#[cfg(all(unix, debug_assertions))]
#[cfg(test)]
#[path = "release_intake_tests.rs"]
mod tests;

#[cfg(all(windows, debug_assertions))]
#[cfg(test)]
#[path = "windows_release_intake_tests.rs"]
mod windows_tests;
