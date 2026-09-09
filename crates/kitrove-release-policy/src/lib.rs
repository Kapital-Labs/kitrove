#![forbid(unsafe_code)]

use std::fmt;

mod entry_policy;
mod installer_archive;
mod installer_manifest;
mod intake;
mod release_manifest;
mod tar_xz_intake;
mod zip_intake;

pub use entry_policy::{
    ApplicationArchiveShapeSummary, ArchiveEntryKind, ArchiveEntrySummary, ArchivePolicyError,
    validate_application_archive_entry_summaries,
};
pub use installer_archive::{
    INSTALLER_ARCHIVES, InspectedInstallerRelease, InstallerArchiveSpec, extract_installer_release,
    installer_archive_for_target,
};
pub use installer_manifest::{
    ParsedInstallerManifest, parse_installer_manifest, render_installer_manifest,
};
pub use intake::{ApplicationArchiveIntake, ArchiveIntakeError, InspectedApplicationRelease};
pub use release_manifest::{
    APPLICATION_RELEASE_MANIFEST_MAX_BYTES, ApplicationStateSchema, LifecycleLockProtocol,
    ParsedReleaseManifest, RELEASE_MANIFEST_MAX_ROLLBACK_PREDECESSORS,
    RELEASE_MANIFEST_MAX_VERSION_BYTES, ReleaseManifestError, parse_release_manifest,
    render_release_manifest,
};
pub use tar_xz_intake::inspect_tar_xz_application_archive;
pub use zip_intake::inspect_zip_application_archive;

pub fn inspect_application_archive(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
) -> Result<ApplicationArchiveIntake, ArchiveIntakeError> {
    match spec.format() {
        ArchiveFormat::TarXz => inspect_tar_xz_application_archive(spec, archive_bytes),
        ArchiveFormat::Zip => inspect_zip_application_archive(spec, archive_bytes),
    }
}

pub fn extract_application_release(
    spec: ApplicationArchiveSpec,
    archive_bytes: &[u8],
) -> Result<InspectedApplicationRelease, ArchiveIntakeError> {
    match spec.format() {
        ArchiveFormat::TarXz => {
            tar_xz_intake::extract_tar_xz_application_release(spec, archive_bytes)
        }
        ArchiveFormat::Zip => zip_intake::extract_zip_application_release(spec, archive_bytes),
    }
}

pub const APPLICATION_RELEASE_MANIFEST_NAME: &str = "kitrove-release.json";

pub const BINARY_COMPANIONS: [&str; 6] = [
    "README.md",
    "CHANGELOG.md",
    "LICENSE.md",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    APPLICATION_RELEASE_MANIFEST_NAME,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    pub max_archive_bytes: u64,
    pub max_tar_stream_bytes: u64,
    pub max_xz_blocks: u64,
    pub max_xz_decoder_memory_bytes: u64,
    pub max_xz_dictionary_bytes: u64,
    pub max_xz_index_bytes: u64,
    pub max_zip_central_directory_bytes: u64,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_path_bytes: usize,
    pub max_component_bytes: usize,
}

pub const APPLICATION_ARCHIVE_LIMITS: ArchiveLimits = ArchiveLimits {
    max_archive_bytes: 256 * 1024 * 1024,
    max_tar_stream_bytes: 512 * 1024 * 1024 + 10_000 * 1024,
    max_xz_blocks: 1024,
    max_xz_decoder_memory_bytes: 96 * 1024 * 1024,
    max_xz_dictionary_bytes: 64 * 1024 * 1024,
    max_xz_index_bytes: 32 * 1024,
    max_zip_central_directory_bytes: 16 * 1024 * 1024,
    max_entries: 10_000,
    max_entry_bytes: 128 * 1024 * 1024,
    max_expanded_bytes: 512 * 1024 * 1024,
    max_path_bytes: 4_096,
    max_component_bytes: 255,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    TarXz,
    Zip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationArchiveSpec {
    target: &'static str,
    archive_name: &'static str,
    archive_root: Option<&'static str>,
    executable_name: &'static str,
    format: ArchiveFormat,
}

impl ApplicationArchiveSpec {
    #[must_use]
    pub const fn target(self) -> &'static str {
        self.target
    }

    #[must_use]
    pub const fn archive_name(self) -> &'static str {
        self.archive_name
    }

    #[must_use]
    pub const fn archive_root(self) -> Option<&'static str> {
        self.archive_root
    }

    #[must_use]
    pub const fn executable_name(self) -> &'static str {
        self.executable_name
    }

    #[must_use]
    pub const fn format(self) -> ArchiveFormat {
        self.format
    }
}

pub const APPLICATION_ARCHIVES: [ApplicationArchiveSpec; 4] = [
    ApplicationArchiveSpec {
        target: "aarch64-apple-darwin",
        archive_name: "kitrove-cli-aarch64-apple-darwin.tar.xz",
        archive_root: Some("kitrove-cli-aarch64-apple-darwin"),
        executable_name: "kitrove",
        format: ArchiveFormat::TarXz,
    },
    ApplicationArchiveSpec {
        target: "x86_64-apple-darwin",
        archive_name: "kitrove-cli-x86_64-apple-darwin.tar.xz",
        archive_root: Some("kitrove-cli-x86_64-apple-darwin"),
        executable_name: "kitrove",
        format: ArchiveFormat::TarXz,
    },
    ApplicationArchiveSpec {
        target: "x86_64-unknown-linux-gnu",
        archive_name: "kitrove-cli-x86_64-unknown-linux-gnu.tar.xz",
        archive_root: Some("kitrove-cli-x86_64-unknown-linux-gnu"),
        executable_name: "kitrove",
        format: ArchiveFormat::TarXz,
    },
    ApplicationArchiveSpec {
        target: "x86_64-pc-windows-msvc",
        archive_name: "kitrove-cli-x86_64-pc-windows-msvc.zip",
        archive_root: None,
        executable_name: "kitrove.exe",
        format: ArchiveFormat::Zip,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedReleaseTarget;

impl fmt::Display for UnsupportedReleaseTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unsupported release target")
    }
}

impl std::error::Error for UnsupportedReleaseTarget {}

pub fn application_archive_for_target(
    target: &str,
) -> Result<ApplicationArchiveSpec, UnsupportedReleaseTarget> {
    APPLICATION_ARCHIVES
        .iter()
        .copied()
        .find(|spec| spec.target == target)
        .ok_or(UnsupportedReleaseTarget)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        APPLICATION_ARCHIVE_LIMITS, APPLICATION_ARCHIVES, APPLICATION_RELEASE_MANIFEST_MAX_BYTES,
        APPLICATION_RELEASE_MANIFEST_NAME, ArchiveFormat, BINARY_COMPANIONS,
        application_archive_for_target,
    };

    #[test]
    fn release_archive_catalog_is_exact_and_collision_free() {
        let targets = APPLICATION_ARCHIVES
            .iter()
            .map(|spec| spec.target())
            .collect::<BTreeSet<_>>();
        let archives = APPLICATION_ARCHIVES
            .iter()
            .map(|spec| spec.archive_name())
            .collect::<BTreeSet<_>>();
        let roots = APPLICATION_ARCHIVES
            .iter()
            .filter_map(|spec| spec.archive_root())
            .collect::<BTreeSet<_>>();

        assert_eq!(targets.len(), APPLICATION_ARCHIVES.len());
        assert_eq!(archives.len(), APPLICATION_ARCHIVES.len());
        assert_eq!(roots.len(), APPLICATION_ARCHIVES.len() - 1);
        assert_eq!(
            APPLICATION_ARCHIVES
                .iter()
                .filter(|spec| spec.format() == ArchiveFormat::Zip)
                .count(),
            1
        );
    }

    #[test]
    fn release_target_lookup_fails_closed() {
        for spec in APPLICATION_ARCHIVES {
            assert_eq!(application_archive_for_target(spec.target()), Ok(spec));
        }
        for unsupported in [
            "",
            "AARCH64-APPLE-DARWIN",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-gnu",
        ] {
            assert_eq!(
                application_archive_for_target(unsupported),
                Err(super::UnsupportedReleaseTarget)
            );
        }
    }

    #[test]
    fn executable_names_match_platform_archive_policy() {
        for spec in APPLICATION_ARCHIVES {
            match spec.format() {
                ArchiveFormat::TarXz => {
                    assert_eq!(spec.executable_name(), "kitrove");
                    assert!(spec.archive_root().is_some());
                }
                ArchiveFormat::Zip => {
                    assert_eq!(spec.executable_name(), "kitrove.exe");
                    assert_eq!(spec.archive_root(), None);
                }
            }
        }
    }

    #[test]
    fn rust_catalog_matches_canonical_publication_policy() {
        let policy: serde_json::Value =
            serde_json::from_str(include_str!("../../../release/release-policy.json")).unwrap();
        let observed = policy["application_archives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["target"].as_str().unwrap(),
                    entry["archive"].as_str().unwrap(),
                    entry["root"].as_str(),
                    entry["executable"].as_str().unwrap(),
                    entry["format"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let expected = APPLICATION_ARCHIVES
            .iter()
            .map(|spec| {
                (
                    spec.target(),
                    spec.archive_name(),
                    spec.archive_root(),
                    spec.executable_name(),
                    match spec.format() {
                        ArchiveFormat::TarXz => "tar.xz",
                        ArchiveFormat::Zip => "zip",
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(observed, expected);
        assert_eq!(
            policy["binary_companions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|name| name.as_str().unwrap())
                .collect::<Vec<_>>(),
            BINARY_COMPANIONS
        );
        assert_eq!(
            policy["limits"]["max_archive_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_archive_bytes
        );
        assert_eq!(
            policy["limits"]["max_tar_stream_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_tar_stream_bytes
        );
        assert_eq!(
            policy["limits"]["max_xz_blocks"],
            APPLICATION_ARCHIVE_LIMITS.max_xz_blocks
        );
        assert_eq!(
            policy["limits"]["max_xz_decoder_memory_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_xz_decoder_memory_bytes
        );
        assert_eq!(
            policy["limits"]["max_xz_dictionary_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_xz_dictionary_bytes
        );
        assert_eq!(
            policy["limits"]["max_xz_index_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_xz_index_bytes
        );
        assert_eq!(
            policy["limits"]["max_zip_central_directory_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_zip_central_directory_bytes
        );
        assert_eq!(
            policy["limits"]["max_entries"],
            APPLICATION_ARCHIVE_LIMITS.max_entries
        );
        assert_eq!(
            policy["limits"]["max_entry_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_entry_bytes
        );
        assert_eq!(
            policy["limits"]["max_expanded_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_expanded_bytes
        );
        assert_eq!(
            policy["limits"]["max_path_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_path_bytes
        );
        assert_eq!(
            policy["limits"]["max_component_bytes"],
            APPLICATION_ARCHIVE_LIMITS.max_component_bytes
        );
        assert_eq!(
            policy["release_manifest"]["name"],
            APPLICATION_RELEASE_MANIFEST_NAME
        );
        assert_eq!(
            policy["release_manifest"]["max_bytes"],
            APPLICATION_RELEASE_MANIFEST_MAX_BYTES
        );
    }
}
