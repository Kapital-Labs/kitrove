//! Non-executable installer preparation; never application replacement authority.
use std::ffi::OsStr;
use std::path::Path;

use cap_std::fs::{Dir, File};
use kitrove_release_provenance::AuthenticatedInstallerExecutable;
use sha2::{Digest as _, Sha256};

use crate::unix_staging as native;
use crate::{InstallerStageError, NativeFileIdentity};

const DIRECTORY: &str = ".kitrove-installer-bootstrap";
const PAYLOAD: &str = "installer.payload";

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
    /// Rechecks retained ancestry, names, private permissions, identities and bytes.
    /// Success grants no permission to execute, publish or replace a binary.
    pub fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.retained.revalidate(self.authenticated.bytes())
    }
}

/// Stage authenticated installer bytes as private, non-executable data on Unix.
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

impl RetainedPayload {
    fn revalidate(&self, bytes: &[u8]) -> Result<(), InstallerStageError> {
        self.require_namespace(bytes.len())?;
        native::verify_sha256_contents(
            &self.file,
            bytes.len() as u64,
            Sha256::digest(bytes).into(),
        )?;
        self.require_namespace(bytes.len())
    }

    fn require_namespace(&self, size: usize) -> Result<(), InstallerStageError> {
        native::revalidate_destination(&self.parent)?;
        native::require_named_directory_identity(
            self.parent.directory(),
            DIRECTORY,
            &self.directory,
            self.directory_identity,
        )?;
        native::require_exact_inventory(&self.directory, &[OsStr::new(PAYLOAD)])?;
        native::require_named_file_identity(
            &self.directory,
            PAYLOAD,
            &self.file,
            self.file_identity,
            0o600,
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
        let file_identity = native::metadata_identity(
            &file
                .metadata()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
        );
        boundary(Boundary::FileWritten)?;
        let retained = RetainedPayload {
            parent,
            directory,
            directory_identity,
            file,
            file_identity,
        };
        retained.revalidate(bytes)?;
        native::sync_directory(&retained.directory)?;
        native::sync_directory(retained.parent.directory())?;
        boundary(Boundary::Synced)?;
        retained.revalidate(bytes)?;
        Ok(retained)
    })();
    complete.map_err(|_: InstallerStageError| InstallerStageError::RecoveryRequired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

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
