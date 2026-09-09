use crate::{
    ApplicationArchiveSpec, ArchiveFormat, ArchiveIntakeError, InspectedApplicationRelease,
    ParsedInstallerManifest, ReleaseManifestError, UnsupportedReleaseTarget,
};

#[cfg(test)]
#[path = "installer_archive_tests.rs"]
mod tests;

/// A closed installer catalog entry, never an application replacement spec.
///
/// ```compile_fail
/// use kitrove_release_policy::{INSTALLER_ARCHIVES, inspect_application_archive};
/// let _ = inspect_application_archive(INSTALLER_ARCHIVES[0], &[]);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerArchiveSpec(ApplicationArchiveSpec);

impl InstallerArchiveSpec {
    #[must_use]
    pub const fn target(self) -> &'static str {
        self.0.target()
    }
    #[must_use]
    pub const fn archive_name(self) -> &'static str {
        self.0.archive_name()
    }
    #[must_use]
    pub const fn archive_root(self) -> Option<&'static str> {
        self.0.archive_root()
    }
    #[must_use]
    pub const fn executable_name(self) -> &'static str {
        self.0.executable_name()
    }
    #[must_use]
    pub const fn format(self) -> ArchiveFormat {
        self.0.format()
    }
}

const fn installer_spec(
    index: usize,
    archive_name: &'static str,
    archive_root: Option<&'static str>,
) -> InstallerArchiveSpec {
    let application = crate::APPLICATION_ARCHIVES[index];
    InstallerArchiveSpec(ApplicationArchiveSpec {
        target: application.target(),
        archive_name,
        archive_root,
        executable_name: match application.format() {
            ArchiveFormat::TarXz => "kitrove-installer",
            ArchiveFormat::Zip => "kitrove-installer.exe",
        },
        format: application.format(),
    })
}

pub const INSTALLER_ARCHIVES: [InstallerArchiveSpec; 4] = [
    installer_spec(
        0,
        "kitrove-installer-aarch64-apple-darwin.tar.xz",
        Some("kitrove-installer-aarch64-apple-darwin"),
    ),
    installer_spec(
        1,
        "kitrove-installer-x86_64-apple-darwin.tar.xz",
        Some("kitrove-installer-x86_64-apple-darwin"),
    ),
    installer_spec(
        2,
        "kitrove-installer-x86_64-unknown-linux-gnu.tar.xz",
        Some("kitrove-installer-x86_64-unknown-linux-gnu"),
    ),
    installer_spec(3, "kitrove-installer-x86_64-pc-windows-msvc.zip", None),
];

pub fn installer_archive_for_target(
    target: &str,
) -> Result<InstallerArchiveSpec, UnsupportedReleaseTarget> {
    INSTALLER_ARCHIVES
        .into_iter()
        .find(|spec| spec.target() == target)
        .ok_or(UnsupportedReleaseTarget)
}

/// Structurally inspected bytes, not authenticated installer or application authority.
/// No application intake/spec is exposed from the shared internal layout representation.
#[derive(Debug, Eq, PartialEq)]
pub struct InspectedInstallerRelease {
    inner: InspectedApplicationRelease,
}

impl InspectedInstallerRelease {
    #[must_use]
    pub fn spec(&self) -> InstallerArchiveSpec {
        InstallerArchiveSpec(self.inner.intake().spec())
    }
    #[must_use]
    pub fn archive_sha256(&self) -> [u8; 32] {
        self.inner.intake().archive_sha256()
    }
    #[must_use]
    pub fn executable_bytes(&self) -> &[u8] {
        self.inner.executable_bytes()
    }
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        self.inner.manifest_bytes()
    }

    pub fn validate_manifest(
        &self,
        expected_version: &semver::Version,
    ) -> Result<ParsedInstallerManifest, ReleaseManifestError> {
        use sha2::{Digest as _, Sha256};
        let manifest = crate::parse_installer_manifest(self.spec(), self.manifest_bytes())?;
        if manifest.release_version() != expected_version {
            return Err(ReleaseManifestError::ReleaseVersionMismatch);
        }
        if manifest.executable_sha256() != <[u8; 32]>::from(Sha256::digest(self.executable_bytes()))
        {
            return Err(ReleaseManifestError::ExecutableDigestMismatch);
        }
        Ok(manifest)
    }
}

pub fn extract_installer_release(
    spec: InstallerArchiveSpec,
    bytes: &[u8],
) -> Result<InspectedInstallerRelease, ArchiveIntakeError> {
    // Reuse only the strict layout/stream decoder. Application manifest validation and
    // public application intake are not exposed through this installer-only wrapper.
    crate::extract_application_release(spec.0, bytes)
        .map(|inner| InspectedInstallerRelease { inner })
}
