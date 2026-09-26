//! Non-executable installer preparation; never application replacement authority.
use std::ffi::OsStr;
use std::path::Path;

#[cfg(unix)]
use cap_std::fs::{Dir, File};
#[cfg(windows)]
use std::fs::File;
#[cfg(windows)]
type Dir = File;
use kitrove_release_provenance::AuthenticatedInstallerExecutable;
use sha2::{Digest as _, Sha256};

#[cfg(unix)]
use crate::unix_staging as native;
#[cfg(windows)]
#[path = "installer_payload_windows.rs"]
mod native;
use crate::{InstallerStageError, NativeFileIdentity};

const DIRECTORY: &str = ".kitrove-installer-bootstrap";
const PAYLOAD: &str = "installer.payload";
#[cfg(target_os = "macos")]
const EXECUTABLE: &str = "kitrove-installer";

/// Retained published installer, never application replacement authority.
/// No automatic execution occurs. Dropping it preserves the published files.
#[cfg(target_os = "macos")]
pub struct PublishedInstallerPayload {
    staged: StagedInstallerPayload,
}

#[cfg(target_os = "macos")]
impl PublishedInstallerPayload {
    /// Freshly check the retained namespace, permissions and authenticated bytes.
    /// This does not make later pathname execution race-free or authenticate a new process.
    pub fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.staged
            .retained
            .revalidate_named(self.staged.authenticated.bytes(), EXECUTABLE, 0o700)
    }
}

/// Retains authenticated installer data, not a runnable installer or install permit.
/// Dropping this value closes handles but preserves all staged files.
///
/// ```compile_fail
/// use kitrove_installer::{StagedInstallerPayload, StagedApplication};
/// fn application(payload: StagedInstallerPayload) -> StagedApplication {
///     payload.into()
/// }
/// ```
pub struct StagedInstallerPayload {
    retained: RetainedPayload,
    authenticated: AuthenticatedInstallerExecutable,
}

impl StagedInstallerPayload {
    /// Fresh native verification followed by no-overwrite publication in the owned
    /// private directory. Consumes staging authority; does not execute the result.
    /// Failure preserves partial evidence, which may already have executable mode.
    /// Never infer completion from the filename after a failure or interruption.
    #[cfg(target_os = "macos")]
    pub fn publish_native(self) -> Result<PublishedInstallerPayload, InstallerStageError> {
        self.verify_native_signature()?;
        self.retained.publish(self.authenticated.bytes())?;
        let published = PublishedInstallerPayload { staged: self };
        published.revalidate()?;
        Ok(published)
    }

    /// Rechecks retained ancestry, names, private permissions, identities and bytes.
    /// Success grants no permission to execute, publish or replace a binary.
    pub fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.retained.revalidate(self.authenticated.bytes())
    }

    /// Inspect the authenticated Mac payload through a bounded, verified self helper.
    /// The executing verifier must already be independently trusted and implement
    /// the installer's fixed helper dispatch. No downloaded payload is executed.
    /// Success is a point-in-time check, not publication or execution authority;
    /// private mode-0600 data and retained handles are unchanged.
    #[cfg(target_os = "macos")]
    pub fn verify_native_signature(&self) -> Result<(), InstallerStageError> {
        use kitrove_release_policy::apple_code_directory::candidate_signature;
        use kitrove_version_probe::apple_process_identity::prepare_verified_suspended_self;
        use std::os::unix::ffi::OsStrExt as _;

        self.revalidate()?;
        let candidate = candidate_signature(
            self.authenticated.bytes(),
            self.authenticated.spec().target(),
        )
        .map_err(|_| InstallerStageError::VerificationFailed)?;
        let path = Path::new(OsStr::from_bytes(self.retained.parent.path_bytes()))
            .join(DIRECTORY)
            .join(PAYLOAD);
        let prepared = prepare_verified_suspended_self()
            .and_then(|owner| owner.bind_inspection(&path, &candidate))
            .map_err(|_| InstallerStageError::VerificationFailed)?;
        self.revalidate()?;
        let inspected = prepared
            .inspect_native()
            .map_err(|_| InstallerStageError::VerificationFailed);
        // Revalidate even when native inspection refuses. Never cache path success.
        let retained = self.revalidate();
        retained.and(inspected)
    }
}

/// Stage authenticated installer bytes as private data, without executable publication.
/// Unix payloads have mode 0600; Windows payloads use the private ACL boundary.
/// The existing parent must satisfy the ordinary-user destination policy. The fixed
/// `.kitrove-installer-bootstrap` child must be absent. Partial output is preserved
/// on error; callers must not use it or infer authority from its name.
/// No native executable signature check or execution is performed by this API.
///
/// ```compile_fail
/// use kitrove_installer::stage_authenticated_installer_payload;
/// use kitrove_release_provenance::AuthenticatedApplicationExecutable;
/// fn wrong_product(parent: &std::path::Path, app: AuthenticatedApplicationExecutable) {
///     let _ = stage_authenticated_installer_payload(parent, app);
/// }
/// ```
pub fn stage_authenticated_installer_payload(
    parent: &Path,
    authenticated: AuthenticatedInstallerExecutable,
) -> Result<StagedInstallerPayload, InstallerStageError> {
    if crate::compiled_release_target()? != authenticated.spec().target() {
        return Err(InstallerStageError::TargetMismatch);
    }
    native::require_unprivileged_process()?;
    let retained = stage(parent, authenticated.bytes(), |_| Ok(()))?;
    Ok(StagedInstallerPayload {
        retained,
        authenticated,
    })
}

struct RetainedPayload {
    parent: native::OpenedDestination,
    directory: Dir,
    directory_identity: NativeFileIdentity,
    file: File,
    file_identity: NativeFileIdentity,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq)]
enum PublicationBoundary {
    BeforeRename,
    Renamed,
    Executable,
    Synced,
}

impl RetainedPayload {
    fn revalidate(&self, bytes: &[u8]) -> Result<(), InstallerStageError> {
        self.revalidate_named(bytes, PAYLOAD, 0o600)
    }

    fn revalidate_named(
        &self,
        bytes: &[u8],
        name: &str,
        mode: u32,
    ) -> Result<(), InstallerStageError> {
        self.require_namespace(bytes.len(), name, mode)?;
        native::verify_sha256_contents(
            &self.file,
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
        )?;
        self.require_namespace(bytes.len(), name, mode)
    }

    #[cfg(target_os = "macos")]
    fn publish(&self, bytes: &[u8]) -> Result<(), InstallerStageError> {
        self.publish_with(bytes, |_| Ok(()))
    }

    #[cfg(target_os = "macos")]
    fn publish_with(
        &self,
        bytes: &[u8],
        mut boundary: impl FnMut(PublicationBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<(), InstallerStageError> {
        self.revalidate(bytes)?;
        boundary(PublicationBoundary::BeforeRename)?;
        crate::unix_install::rename_noreplace(
            &self.directory,
            OsStr::new(PAYLOAD),
            &self.directory,
            OsStr::new(EXECUTABLE),
        )?;
        // All errors after namespace mutation preserve evidence for inspection.
        let complete = (|| {
            boundary(PublicationBoundary::Renamed)?;
            self.revalidate_named(bytes, EXECUTABLE, 0o600)?;
            native::make_retained_file_executable(
                &self.directory,
                EXECUTABLE,
                &self.file,
                self.file_identity,
                bytes.len() as u64,
            )?;
            boundary(PublicationBoundary::Executable)?;
            self.revalidate_named(bytes, EXECUTABLE, 0o700)?;
            native::sync_directory(&self.directory)?;
            native::sync_directory(self.parent.directory())?;
            boundary(PublicationBoundary::Synced)?;
            self.revalidate_named(bytes, EXECUTABLE, 0o700)
        })();
        complete.map_err(|_: InstallerStageError| InstallerStageError::RecoveryRequired)
    }

    fn require_namespace(
        &self,
        size: usize,
        name: &str,
        mode: u32,
    ) -> Result<(), InstallerStageError> {
        native::revalidate_destination(&self.parent)?;
        native::require_named_directory_identity(
            self.parent.directory(),
            DIRECTORY,
            &self.directory,
            self.directory_identity,
        )?;
        native::require_exact_inventory(&self.directory, &[OsStr::new(name)])?;
        native::require_named_file_identity(
            &self.directory,
            name,
            &self.file,
            self.file_identity,
            mode,
            size as u64,
        )
    }
}

#[derive(Clone, Copy)]
enum Boundary {
    DirectoryCreated,
    FileWritten,
    Synced,
}

fn stage(
    parent: &Path,
    bytes: &[u8],
    mut boundary: impl FnMut(Boundary) -> Result<(), InstallerStageError>,
) -> Result<RetainedPayload, InstallerStageError> {
    let parent = native::open_destination(parent)?;
    native::revalidate_destination(&parent)?;
    let directory = native::create_private_child(parent.directory(), OsStr::new(DIRECTORY))?;
    // From the first created namespace onward, preserve partial evidence on failure.
    let complete = (|| {
        boundary(Boundary::DirectoryCreated)?;
        let directory_identity = native::directory_identity(&directory)?;
        native::revalidate_destination(&parent)?;
        native::require_named_directory_identity(
            parent.directory(),
            DIRECTORY,
            &directory,
            directory_identity,
        )?;
        native::require_exact_inventory(&directory, &[])?;
        let file = native::create_synced_private_file(&directory, OsStr::new(PAYLOAD), bytes)?;
        #[cfg(unix)]
        let file_identity = native::metadata_identity(
            &file
                .metadata()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
        );
        #[cfg(windows)]
        let file_identity = native::file_identity(&file)?;
        boundary(Boundary::FileWritten)?;
        let retained = RetainedPayload {
            parent,
            directory,
            directory_identity,
            file,
            file_identity,
        };
        retained.revalidate(bytes)?;
        #[cfg(unix)]
        {
            native::sync_directory(&retained.directory)?;
            native::sync_directory(retained.parent.directory())?;
        }
        #[cfg(windows)]
        native::sync_stage(&retained.parent, &retained.directory)?;
        boundary(Boundary::Synced)?;
        retained.revalidate(bytes)?;
        Ok(retained)
    })();
    complete.map_err(|_: InstallerStageError| InstallerStageError::RecoveryRequired)
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use cap_std::fs::PermissionsExt as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[cfg(target_os = "macos")]
    #[test]
    fn publication_failures_preserve_exact_phase_without_success() {
        for failure in [
            PublicationBoundary::BeforeRename,
            PublicationBoundary::Renamed,
            PublicationBoundary::Executable,
            PublicationBoundary::Synced,
        ] {
            let root = crate::test_support::private_tempdir();
            let bytes = b"synthetic publication failure evidence";
            let retained = stage(root.path(), bytes, |_| Ok(())).unwrap();
            assert!(
                retained
                    .publish_with(bytes, |at| {
                        if at == failure {
                            Err(InstallerStageError::WriteFailed)
                        } else {
                            Ok(())
                        }
                    })
                    .is_err()
            );
            let (name, mode) = match failure {
                PublicationBoundary::BeforeRename => (PAYLOAD, 0o600),
                PublicationBoundary::Renamed => (EXECUTABLE, 0o600),
                _ => (EXECUTABLE, 0o700),
            };
            retained.revalidate_named(bytes, name, mode).unwrap();
            drop(retained);
            assert_eq!(
                std::fs::read(root.path().join(DIRECTORY).join(name)).unwrap(),
                bytes
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn publication_refuses_late_occupied_name_and_postrename_symlink() {
        for replace_after_rename in [false, true] {
            let root = crate::test_support::private_tempdir();
            let bytes = b"synthetic private payload";
            let retained = stage(root.path(), bytes, |_| Ok(())).unwrap();
            let directory = root.path().join(DIRECTORY);
            let unrelated = root.path().join("unrelated");
            std::fs::write(&unrelated, b"unmanaged").unwrap();
            std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                retained
                    .publish_with(bytes, |at| {
                        if !replace_after_rename && at == PublicationBoundary::BeforeRename {
                            std::fs::write(directory.join(EXECUTABLE), b"occupied").unwrap();
                        }
                        if replace_after_rename && at == PublicationBoundary::Renamed {
                            std::fs::rename(
                                directory.join(EXECUTABLE),
                                directory.join("retained-evidence"),
                            )
                            .unwrap();
                            symlink(&unrelated, directory.join(EXECUTABLE)).unwrap();
                        }
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(std::fs::read(&unrelated).unwrap(), b"unmanaged");
            assert_eq!(
                std::fs::metadata(&unrelated).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                retained.file.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
            if !replace_after_rename {
                assert_eq!(
                    std::fs::read(directory.join(EXECUTABLE)).unwrap(),
                    b"occupied"
                );
                assert_eq!(std::fs::read(directory.join(PAYLOAD)).unwrap(), bytes);
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn publication_retains_inode_and_refuses_occupied_or_changed_data() {
        for case in ["valid", "occupied", "changed"] {
            let root = crate::test_support::private_tempdir();
            let bytes = b"synthetic data, never executed";
            let retained = stage(root.path(), bytes, |_| Ok(())).unwrap();
            let directory = root.path().join(DIRECTORY);
            if case == "occupied" {
                std::fs::write(directory.join(EXECUTABLE), b"unmanaged").unwrap();
            } else if case == "changed" {
                std::fs::write(directory.join(PAYLOAD), b"changed").unwrap();
            }
            // Filesystem-only seam, not native signature acceptance.
            let result = retained.publish(bytes);
            if case == "valid" {
                result.unwrap();
                retained.revalidate_named(bytes, EXECUTABLE, 0o700).unwrap();
                assert!(!directory.join(PAYLOAD).exists());
                assert_eq!(std::fs::read(directory.join(EXECUTABLE)).unwrap(), bytes);
            } else {
                assert!(result.is_err());
                assert!(directory.join(PAYLOAD).is_file());
                if case == "occupied" {
                    assert_eq!(
                        std::fs::read(directory.join(EXECUTABLE)).unwrap(),
                        b"unmanaged"
                    );
                }
            }
        }
    }

    #[test]
    fn stages_exact_nonexecutable_data_and_preserves_it_on_drop() {
        let root = crate::test_support::private_tempdir();
        let bytes = b"#!/bin/sh\nexit 99\n";
        let retained = stage(root.path(), bytes, |_| Ok(())).unwrap();
        retained.revalidate(bytes).unwrap();
        let file = root.path().join(DIRECTORY).join(PAYLOAD);
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(retained);
        assert_eq!(std::fs::read(file).unwrap(), bytes);
        assert!(stage(root.path(), bytes, |_| Ok(())).is_err());
    }

    #[test]
    fn refuses_redirected_parent_and_occupied_child_without_writes() {
        let root = crate::test_support::private_tempdir();
        let target = crate::test_support::private_tempdir();
        symlink(target.path(), root.path().join("redirect")).unwrap();
        assert!(stage(&root.path().join("redirect"), b"data", |_| Ok(())).is_err());
        symlink(target.path(), root.path().join(DIRECTORY)).unwrap();
        assert!(stage(root.path(), b"data", |_| Ok(())).is_err());
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }

    #[test]
    fn preserves_every_created_boundary_on_failure() {
        for failed in 0..3 {
            let root = crate::test_support::private_tempdir();
            let result = stage(root.path(), b"data", |boundary| {
                if boundary as usize == failed {
                    Err(InstallerStageError::WriteFailed)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
            assert!(root.path().join(DIRECTORY).is_dir());
            if failed > 0 {
                assert_eq!(
                    std::fs::read(root.path().join(DIRECTORY).join(PAYLOAD)).unwrap(),
                    b"data"
                );
            }
        }
    }

    #[test]
    fn rejects_changed_bytes_identity_permissions_inventory_and_links() {
        for change in 0..5 {
            let root = crate::test_support::private_tempdir();
            let retained = stage(root.path(), b"data", |_| Ok(())).unwrap();
            let directory = root.path().join(DIRECTORY);
            let file = directory.join(PAYLOAD);
            match change {
                0 => std::fs::write(&file, b"edit").unwrap(),
                1 => {
                    std::fs::rename(&file, directory.join("old")).unwrap();
                    std::fs::write(&file, b"data").unwrap();
                }
                2 => {
                    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap()
                }
                3 => std::fs::write(directory.join("extra"), b"extra").unwrap(),
                _ => std::fs::hard_link(&file, root.path().join("alias")).unwrap(),
            }
            assert!(retained.revalidate(b"data").is_err());
        }
    }

    #[test]
    fn refuses_unsafe_parent_without_permission_repair() {
        let root = crate::test_support::private_tempdir();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(stage(root.path(), b"data", |_| Ok(())).is_err());
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert!(!root.path().join(DIRECTORY).exists());
    }

    #[test]
    fn preserves_competing_payload_before_write() {
        let root = crate::test_support::private_tempdir();
        let file = root.path().join(DIRECTORY).join(PAYLOAD);
        let result = stage(root.path(), b"candidate", |boundary| {
            if matches!(boundary, Boundary::DirectoryCreated) {
                std::fs::write(&file, b"unmanaged").unwrap();
            }
            Ok(())
        });
        assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
        assert_eq!(std::fs::read(file).unwrap(), b"unmanaged");
    }

    #[test]
    fn rejects_directory_swap_during_staging_and_preserves_both_names() {
        let root = crate::test_support::private_tempdir();
        let result = stage(root.path(), b"data", |boundary| {
            if matches!(boundary, Boundary::FileWritten) {
                std::fs::rename(root.path().join(DIRECTORY), root.path().join("retained")).unwrap();
                std::fs::create_dir(root.path().join(DIRECTORY)).unwrap();
            }
            Ok(())
        });
        assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
        assert_eq!(
            std::fs::read(root.path().join("retained").join(PAYLOAD)).unwrap(),
            b"data"
        );
        assert_eq!(
            std::fs::read_dir(root.path().join(DIRECTORY))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn rejects_changed_parent_ancestry_before_returning_success() {
        let root = crate::test_support::private_tempdir();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let displaced = root.path().join("displaced");
        let result = stage(&parent, b"data", |boundary| {
            if matches!(boundary, Boundary::Synced) {
                std::fs::rename(&parent, &displaced).unwrap();
                std::fs::create_dir(&parent).unwrap();
            }
            Ok(())
        });
        assert!(matches!(result, Err(InstallerStageError::RecoveryRequired)));
        assert_eq!(
            std::fs::read(displaced.join(DIRECTORY).join(PAYLOAD)).unwrap(),
            b"data"
        );
        assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
    }
}

#[cfg(windows)]
#[cfg(test)]
#[path = "installer_payload_windows_tests.rs"]
mod windows_tests;
