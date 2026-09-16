//! Closed packaging policy, not authenticated installer or application authority.
use crate::{INSTALLER_ARCHIVES, InstallerArchiveSpec, UnsupportedReleaseTarget};

/// A Mac bootstrap container has no conversion to an application archive spec.
/// Its embedded archive remains subject to separate installer authentication.
///
/// ```compile_fail
/// use kitrove_release_policy::{ApplicationArchiveSpec, INSTALLER_CONTAINERS};
/// let application: ApplicationArchiveSpec = INSTALLER_CONTAINERS[0].into();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerContainerSpec {
    installer: InstallerArchiveSpec,
    image_name: &'static str,
}

impl InstallerContainerSpec {
    #[must_use]
    pub const fn target(self) -> &'static str {
        self.installer.target()
    }

    #[must_use]
    pub const fn image_name(self) -> &'static str {
        self.image_name
    }

    #[must_use]
    pub const fn installer_archive(self) -> InstallerArchiveSpec {
        self.installer
    }
}

pub const INSTALLER_CONTAINERS: [InstallerContainerSpec; 2] = [
    InstallerContainerSpec {
        installer: INSTALLER_ARCHIVES[0],
        image_name: "kitrove-installer-aarch64-apple-darwin.dmg",
    },
    InstallerContainerSpec {
        installer: INSTALLER_ARCHIVES[1],
        image_name: "kitrove-installer-x86_64-apple-darwin.dmg",
    },
];

pub fn installer_container_for_target(
    target: &str,
) -> Result<InstallerContainerSpec, UnsupportedReleaseTarget> {
    INSTALLER_CONTAINERS
        .iter()
        .copied()
        .find(|spec| spec.target() == target)
        .ok_or(UnsupportedReleaseTarget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::APPLICATION_ARCHIVES;

    #[test]
    fn container_catalog_matches_policy_without_archive_authority() {
        let policy: serde_json::Value =
            serde_json::from_str(include_str!("../../../release/release-policy.json")).unwrap();
        let expected: Vec<_> = INSTALLER_CONTAINERS
            .iter()
            .map(|spec| {
                assert_eq!(installer_container_for_target(spec.target()), Ok(*spec));
                assert!(
                    !APPLICATION_ARCHIVES
                        .iter()
                        .any(|archive| { archive.archive_name() == spec.image_name() })
                );
                assert!(
                    !INSTALLER_ARCHIVES
                        .iter()
                        .any(|archive| { archive.archive_name() == spec.image_name() })
                );
                serde_json::json!({
                    "target": spec.target(),
                    "image": spec.image_name(),
                    "installer_archive": spec.installer_archive().archive_name(),
                })
            })
            .collect();
        assert_eq!(policy["installer_containers"], serde_json::json!(expected));
        assert_ne!(
            INSTALLER_CONTAINERS[0].image_name(),
            INSTALLER_CONTAINERS[1].image_name()
        );
    }

    #[test]
    fn container_targets_are_exact_and_mac_only() {
        for target in [
            "",
            "AARCH64-APPLE-DARWIN",
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-apple-darwin.dmg",
        ] {
            assert_eq!(
                installer_container_for_target(target),
                Err(UnsupportedReleaseTarget)
            );
        }
    }
}
