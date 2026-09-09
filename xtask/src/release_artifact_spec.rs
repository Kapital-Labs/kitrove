use std::path::Path;

use kitrove_release_policy::{
    ApplicationArchiveSpec, ArchiveFormat, InstallerArchiveSpec, application_archive_for_target,
    extract_application_release, extract_installer_release, installer_archive_for_target,
    render_installer_manifest, render_release_manifest,
};
use semver::Version;
#[cfg(test)]
use sha2::{Digest as _, Sha256};

/// Publication-only routing. Application and installer authentication types stay separate.
#[derive(Clone, Copy)]
pub(super) enum ReleaseArchiveSpec {
    Application(ApplicationArchiveSpec),
    Installer(InstallerArchiveSpec),
}

impl ReleaseArchiveSpec {
    pub(super) fn resolve(archive: &Path, target: &str) -> Result<Self, String> {
        let application =
            application_archive_for_target(target).map_err(|error| error.to_string())?;
        let installer = installer_archive_for_target(target).map_err(|error| error.to_string())?;
        [Self::Application(application), Self::Installer(installer)].into_iter()
            .find(|spec| archive.file_name().and_then(|name| name.to_str()) == Some(spec.archive_name()))
            .ok_or_else(|| format!("archive name must exactly match a reviewed application or installer archive for {target}"))
    }

    pub(super) fn archive_name(self) -> &'static str {
        match self {
            Self::Application(spec) => spec.archive_name(),
            Self::Installer(spec) => spec.archive_name(),
        }
    }
    pub(super) fn archive_root(self) -> Option<&'static str> {
        match self {
            Self::Application(spec) => spec.archive_root(),
            Self::Installer(spec) => spec.archive_root(),
        }
    }
    pub(super) fn executable_name(self) -> &'static str {
        match self {
            Self::Application(spec) => spec.executable_name(),
            Self::Installer(spec) => spec.executable_name(),
        }
    }
    pub(super) fn format(self) -> ArchiveFormat {
        match self {
            Self::Application(spec) => spec.format(),
            Self::Installer(spec) => spec.format(),
        }
    }

    #[cfg(test)]
    pub(super) fn prepare_manifest(
        self,
        bytes: &[u8],
        version: &Version,
        compatibility: &Path,
    ) -> Result<Vec<u8>, String> {
        let digest = Sha256::digest(self.executable_bytes(bytes)?).into();
        self.render_manifest(digest, version, compatibility)
    }

    pub(super) fn executable_bytes(self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Application(spec) => extract_application_release(spec, bytes)
                .map(|release| release.executable_bytes().to_vec()),
            Self::Installer(spec) => extract_installer_release(spec, bytes)
                .map(|release| release.executable_bytes().to_vec()),
        }
        .map_err(|error| format!("release archive is not structurally valid: {error}"))
    }

    pub(super) fn render_manifest(
        self,
        digest: [u8; 32],
        version: &Version,
        compatibility: &Path,
    ) -> Result<Vec<u8>, String> {
        // Installer manifests make no application compatibility claims. The legacy
        // command's compatibility argument applies only to application archives.
        match self {
            Self::Application(spec) => render_release_manifest(
                spec,
                version,
                digest,
                &super::load_predecessors(compatibility, version)?,
            ),
            Self::Installer(spec) => render_installer_manifest(spec, version, digest),
        }
        .map_err(|error| format!("cannot render release manifest: {error}"))
    }

    pub(super) fn verify(self, bytes: &[u8], version: &Version) -> Result<(), String> {
        let archive_error = |error| format!("prepared release archive is invalid: {error}");
        match self {
            Self::Application(spec) => extract_application_release(spec, bytes)
                .map_err(archive_error)?
                .validate_manifest(version)
                .map(|_| ()),
            Self::Installer(spec) => extract_installer_release(spec, bytes)
                .map_err(archive_error)?
                .validate_manifest(version)
                .map(|_| ()),
        }
        .map_err(|error| format!("prepared release manifest is invalid: {error}"))
    }
}
