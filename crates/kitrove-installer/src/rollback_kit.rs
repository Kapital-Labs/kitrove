use std::ffi::OsStr;

use kitrove_release_provenance::{AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity};

use crate::{InstallerStageError, NativeFileIdentity, StagedApplication};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RollbackKitIdentities {
    directory: NativeFileIdentity,
    archive: NativeFileIdentity,
    bundle: NativeFileIdentity,
}

impl RollbackKitIdentities {
    pub(crate) fn require_target(self, target: &str) -> Result<(), InstallerStageError> {
        if [self.directory, self.archive, self.bundle]
            .iter()
            .all(|identity| identity.is_valid() && identity.matches_target(target))
        {
            Ok(())
        } else {
            Err(InstallerStageError::RecoveryRequired)
        }
    }
}

pub(crate) const ROLLBACK_DIRECTORY: &str = "rollback-kit";
const ARCHIVE: &str = "archive";
const BUNDLE: &str = "attestation.json";

use crate::staging_policy::{
    InstallerDirectory as Directory, InstallerFile as File, read_private_data_leaf,
};

/// Private durable bytes retained under one locked staging operation.
///
/// This is not an upgrade journal. Reopening a kit requires fresh attestation
/// verification; a retained digest alone never authorizes executable restoration.
pub(crate) struct RetainedRollbackKit {
    directory: Directory,
    identity: NativeFileIdentity,
    archive: KitLeaf,
    bundle: KitLeaf,
}

struct KitLeaf {
    file: File,
    identity: NativeFileIdentity,
}

struct KitInput<'a> {
    archive: &'a [u8],
    archive_sha256: [u8; 32],
    bundle: &'a [u8],
    bundle_sha256: [u8; 32],
}

impl<'a> From<&'a AuthenticatedRecoveryMaterial> for KitInput<'a> {
    fn from(material: &'a AuthenticatedRecoveryMaterial) -> Self {
        Self {
            archive: material.archive_bytes(),
            archive_sha256: material.executable().subject().archive_sha256(),
            bundle: material.bundle_bytes(),
            bundle_sha256: material.executable().subject().attestation_bundle_sha256(),
        }
    }
}

impl RetainedRollbackKit {
    #[cfg(windows)]
    pub(crate) fn sync_material_owned(
        mut self,
        parent: &Directory,
        material: &AuthenticatedRecoveryMaterial,
    ) -> Result<Self, InstallerStageError> {
        self.revalidate_at(parent, material)?;
        let input = KitInput::from(material);
        self.archive.file = crate::windows_staging::flush_retained_private_file(
            &self.directory,
            OsStr::new(ARCHIVE),
            self.archive.file,
            input.archive.len() as u64,
            input.archive_sha256,
        )?;
        self.bundle.file = crate::windows_staging::flush_retained_private_file(
            &self.directory,
            OsStr::new(BUNDLE),
            self.bundle.file,
            input.bundle.len() as u64,
            input.bundle_sha256,
        )?;
        crate::windows_staging::sync_directory(
            parent,
            OsStr::new(ROLLBACK_DIRECTORY),
            &self.directory,
        )?;
        self.revalidate_at(parent, material)?;
        Ok(self)
    }

    #[cfg(unix)]
    pub(crate) fn sync_material(&self) -> Result<(), InstallerStageError> {
        self.archive
            .file
            .sync_all()
            .and_then(|()| self.bundle.file.sync_all())
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        crate::unix_staging::sync_directory(&self.directory)
    }
    // Filesystem/integration fixture only. The normal reopen entry point always
    // verifies Sigstore; this helper is absent from non-test builds.
    #[cfg(all(test, debug_assertions))]
    pub(crate) fn reopen_with_test_subject(
        staged: &StagedApplication,
        expected: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        require_stage_with_record(staged, true, true)?;
        let reopened =
            Self::reopen_material_with_test_subject(staged, expected, expected_archive_sha256)?;
        require_stage_with_record(staged, true, true)?;
        Ok(reopened)
    }

    #[cfg(all(test, debug_assertions))]
    pub(crate) fn reopen_material_with_test_subject(
        staged: &StagedApplication,
        expected: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        Self::reopen_at_with_test_subject(
            &staged._retained.operation,
            expected,
            expected_archive_sha256,
        )
    }

    #[cfg(all(test, debug_assertions))]
    pub(crate) fn reopen_at_with_test_subject(
        operation: &Directory,
        expected: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        Self::reopen_at_with_verifier(operation, expected_archive_sha256, |archive, bundle| {
            let spec = kitrove_release_policy::application_archive_for_target(
                crate::compiled_release_target()?,
            )
            .map_err(|_| InstallerStageError::UnsupportedPlatform)?;
            AuthenticatedRecoveryMaterial::from_test_archive(spec, archive, bundle, expected)
                .map_err(|_| InstallerStageError::VerificationFailed)
        })
    }

    pub(crate) fn reopen(
        staged: &StagedApplication,
        expected: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        require_stage_with_record(staged, true, true)?;
        let reopened = Self::reopen_material(staged, expected, expected_archive_sha256)?;
        require_stage_with_record(staged, true, true)?;
        Ok(reopened)
    }

    /// Fresh material authentication only; the caller validates the executable layout.
    pub(crate) fn reopen_material(
        staged: &StagedApplication,
        expected: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        Self::reopen_at(
            &staged._retained.operation,
            expected,
            expected_archive_sha256,
        )
    }

    /// Authenticates private kit bytes only; callers retain and validate the operation namespace.
    pub(crate) fn reopen_at(
        operation: &Directory,
        expected: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        Self::reopen_at_with_verifier(operation, expected_archive_sha256, |archive, bundle| {
            let spec = kitrove_release_policy::application_archive_for_target(
                crate::compiled_release_target()?,
            )
            .map_err(|_| InstallerStageError::UnsupportedPlatform)?;
            crate::release_intake::verify_material(spec, archive, bundle, expected)
        })
    }

    fn reopen_at_with_verifier(
        operation: &Directory,
        expected_archive_sha256: [u8; 32],
        verify: impl FnOnce(&[u8], &[u8]) -> Result<AuthenticatedRecoveryMaterial, InstallerStageError>,
    ) -> Result<(Self, AuthenticatedRecoveryMaterial), InstallerStageError> {
        #[cfg(unix)]
        let directory =
            crate::unix_staging::open_private_child(operation, OsStr::new(ROLLBACK_DIRECTORY))?;
        #[cfg(windows)]
        let directory = kitrove_windows_security::open_private_directory(
            operation,
            OsStr::new(ROLLBACK_DIRECTORY),
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let identity = directory_identity(&directory)?;
        require_inventory(&directory)?;
        let archive = read_private_data_leaf(
            &directory,
            ARCHIVE,
            kitrove_release_policy::APPLICATION_ARCHIVE_LIMITS.max_archive_bytes as usize,
        )?;
        let bundle = read_private_data_leaf(
            &directory,
            BUNDLE,
            kitrove_release_provenance::APPLICATION_ATTESTATION_BUNDLE_MAX_BYTES,
        )?;
        use sha2::{Digest as _, Sha256};
        if <[u8; 32]>::from(Sha256::digest(&archive.bytes)) != expected_archive_sha256 {
            return Err(InstallerStageError::VerificationFailed);
        }
        let material = verify(&archive.bytes, &bundle.bytes)?;
        let kit = Self {
            directory,
            identity,
            archive: KitLeaf {
                file: archive.file,
                identity: archive.identity,
            },
            bundle: KitLeaf {
                file: bundle.file,
                identity: bundle.identity,
            },
        };
        kit.revalidate_at(operation, &material)?;
        Ok((kit, material))
    }

    #[cfg(test)]
    pub(crate) fn create_for_tests(staged: &StagedApplication) -> Self {
        Self::create_with_hook(staged, &tests::input(), |_| Ok(())).unwrap()
    }
    pub(crate) const fn identities(&self) -> RollbackKitIdentities {
        RollbackKitIdentities {
            directory: self.identity,
            archive: self.archive.identity,
            bundle: self.bundle.identity,
        }
    }

    pub(crate) fn create(
        staged: &StagedApplication,
        material: &AuthenticatedRecoveryMaterial,
    ) -> Result<Self, InstallerStageError> {
        Self::create_direction(
            staged,
            material,
            crate::replacement_direction::ReplacementDirection::Upgrade,
        )
    }

    pub(crate) fn create_direction(
        staged: &StagedApplication,
        material: &AuthenticatedRecoveryMaterial,
        direction: crate::replacement_direction::ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        if !direction.permits(&staged.manifest, material.executable().manifest()) {
            return Err(InstallerStageError::IncompatibleUpgrade);
        }
        Self::create_with_hook(staged, &KitInput::from(material), |_| Ok(()))
    }

    fn create_with_hook(
        staged: &StagedApplication,
        input: &KitInput<'_>,
        mut boundary: impl FnMut(KitBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        require_stage(staged, false)?;
        // After the first possible mutation, preserve all partial evidence and report recovery.
        (|| -> Result<Self, InstallerStageError> {
            let directory = create_directory(&staged._retained.operation)?;
            let identity = directory_identity(&directory)?;
            boundary(KitBoundary::DirectoryCreated)?;
            require_stage(staged, true)?;
            require_directory(&staged._retained.operation, &directory, identity)?;
            let archive = create_leaf(&directory, ARCHIVE, input.archive)?;
            boundary(KitBoundary::ArchiveWritten)?;
            require_stage(staged, true)?;
            require_directory(&staged._retained.operation, &directory, identity)?;
            let bundle = create_leaf(&directory, BUNDLE, input.bundle)?;
            boundary(KitBoundary::BundleWritten)?;
            let kit = Self {
                directory,
                identity,
                archive,
                bundle,
            };
            kit.revalidate_input(staged, input)?;
            #[cfg(unix)]
            {
                crate::unix_staging::sync_directory(&kit.directory)?;
                crate::unix_staging::sync_directory(&staged._retained.operation)?;
            }
            boundary(KitBoundary::Durable)?;
            kit.revalidate_input(staged, input)?;
            Ok(kit)
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    pub(crate) fn revalidate(
        &self,
        staged: &StagedApplication,
        material: &AuthenticatedRecoveryMaterial,
    ) -> Result<(), InstallerStageError> {
        self.revalidate_input(staged, &KitInput::from(material))
    }

    pub(crate) fn revalidate_with_record(
        &self,
        staged: &StagedApplication,
        material: &AuthenticatedRecoveryMaterial,
    ) -> Result<(), InstallerStageError> {
        self.revalidate_input_with_record(staged, &KitInput::from(material), true)
    }

    fn revalidate_input(
        &self,
        staged: &StagedApplication,
        input: &KitInput<'_>,
    ) -> Result<(), InstallerStageError> {
        self.revalidate_input_with_record(staged, input, false)
    }

    fn revalidate_input_with_record(
        &self,
        staged: &StagedApplication,
        input: &KitInput<'_>,
        with_record: bool,
    ) -> Result<(), InstallerStageError> {
        require_stage_with_record(staged, true, with_record)?;
        self.revalidate_material_input(staged, input)?;
        require_stage_with_record(staged, true, with_record)
    }

    /// Material authority only; the transaction must validate the surrounding layout.
    pub(crate) fn revalidate_material(
        &self,
        staged: &StagedApplication,
        material: &AuthenticatedRecoveryMaterial,
    ) -> Result<(), InstallerStageError> {
        self.revalidate_material_input(staged, &KitInput::from(material))
    }

    fn revalidate_material_input(
        &self,
        staged: &StagedApplication,
        input: &KitInput<'_>,
    ) -> Result<(), InstallerStageError> {
        self.revalidate_input_at(&staged._retained.operation, input)
    }

    pub(crate) fn revalidate_at(
        &self,
        operation: &Directory,
        material: &AuthenticatedRecoveryMaterial,
    ) -> Result<(), InstallerStageError> {
        self.revalidate_input_at(operation, &KitInput::from(material))
    }

    fn revalidate_input_at(
        &self,
        operation: &Directory,
        input: &KitInput<'_>,
    ) -> Result<(), InstallerStageError> {
        require_directory(operation, &self.directory, self.identity)?;
        require_inventory(&self.directory)?;
        self.archive.verify(
            &self.directory,
            ARCHIVE,
            input.archive.len() as u64,
            input.archive_sha256,
        )?;
        self.bundle.verify(
            &self.directory,
            BUNDLE,
            input.bundle.len() as u64,
            input.bundle_sha256,
        )?;
        require_inventory(&self.directory)?;
        require_directory(operation, &self.directory, self.identity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KitBoundary {
    DirectoryCreated,
    ArchiveWritten,
    BundleWritten,
    Durable,
}

fn require_stage(staged: &StagedApplication, with_kit: bool) -> Result<(), InstallerStageError> {
    require_stage_with_record(staged, with_kit, false)
}

fn require_stage_with_record(
    staged: &StagedApplication,
    with_kit: bool,
    with_record: bool,
) -> Result<(), InstallerStageError> {
    let mut extra = Vec::new();
    if with_kit {
        extra.push(OsStr::new(ROLLBACK_DIRECTORY));
    }
    if with_record {
        extra.push(OsStr::new(crate::upgrade_record::UPGRADE_RECORD));
    }
    #[cfg(unix)]
    {
        crate::unix_install::revalidate_prepared_stage_with_extra_entries(staged, &extra)
    }
    #[cfg(windows)]
    {
        crate::windows_install::revalidate_stage_with_extra_entries(
            staged,
            crate::install_phase::InstallRecoveryPhase::Prepared,
            None,
            &extra,
        )
    }
}

fn create_directory(parent: &Directory) -> Result<Directory, InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::create_private_child(parent, OsStr::new(ROLLBACK_DIRECTORY))
    }
    #[cfg(windows)]
    {
        kitrove_windows_security::create_private_directory(parent, OsStr::new(ROLLBACK_DIRECTORY))
            .map_err(|_| InstallerStageError::WriteFailed)
    }
}

fn directory_identity(directory: &Directory) -> Result<NativeFileIdentity, InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::directory_identity(directory)
    }
    #[cfg(windows)]
    {
        crate::windows_staging::file_identity(directory)
    }
}

fn require_directory(
    parent: &Directory,
    directory: &Directory,
    identity: NativeFileIdentity,
) -> Result<(), InstallerStageError> {
    #[cfg(unix)]
    {
        crate::unix_staging::require_named_directory_identity(
            parent,
            ROLLBACK_DIRECTORY,
            directory,
            identity,
        )
    }
    #[cfg(windows)]
    {
        kitrove_windows_security::inspect_private_directory(directory)
            .map_err(|_| InstallerStageError::UnsafeState)?;
        crate::windows_staging::require_identity(directory, identity)?;
        crate::windows_staging::require_named_directory_identity(
            parent,
            OsStr::new(ROLLBACK_DIRECTORY),
            identity,
        )
    }
}

fn require_inventory(directory: &Directory) -> Result<(), InstallerStageError> {
    let expected = &[OsStr::new(ARCHIVE), OsStr::new(BUNDLE)];
    #[cfg(unix)]
    {
        crate::unix_staging::require_exact_inventory(directory, expected)
    }
    #[cfg(windows)]
    {
        crate::windows_staging::require_exact_inventory(directory, expected)
    }
}

fn create_leaf(
    directory: &Directory,
    name: &str,
    bytes: &[u8],
) -> Result<KitLeaf, InstallerStageError> {
    #[cfg(unix)]
    let file = crate::unix_staging::create_synced_private_file(directory, OsStr::new(name), bytes)?;
    #[cfg(windows)]
    let file =
        crate::windows_staging::create_written_private_file(directory, OsStr::new(name), bytes)?;
    #[cfg(unix)]
    let identity = crate::unix_staging::metadata_identity(
        &file
            .metadata()
            .map_err(|_| InstallerStageError::WriteFailed)?,
    );
    #[cfg(windows)]
    let identity = crate::windows_staging::file_identity(&file)?;
    Ok(KitLeaf { file, identity })
}

impl KitLeaf {
    fn verify(
        &self,
        parent: &Directory,
        name: &str,
        size: u64,
        digest: [u8; 32],
    ) -> Result<(), InstallerStageError> {
        self.require_identity(parent, name, size)?;
        #[cfg(unix)]
        crate::unix_staging::verify_sha256_contents(&self.file, size, digest)?;
        #[cfg(windows)]
        crate::windows_staging::require_file_contents(&self.file, size, digest)?;
        self.require_identity(parent, name, size)
    }

    fn require_identity(
        &self,
        parent: &Directory,
        name: &str,
        size: u64,
    ) -> Result<(), InstallerStageError> {
        #[cfg(unix)]
        {
            crate::unix_staging::require_named_file_identity(
                parent,
                name,
                &self.file,
                self.identity,
                0o600,
                size,
            )
        }
        #[cfg(windows)]
        {
            kitrove_windows_security::inspect_private_single_link_file(&self.file)
                .map_err(|_| InstallerStageError::UnsafeState)?;
            if self
                .file
                .metadata()
                .map_err(|_| InstallerStageError::UnsafeState)?
                .len()
                != size
            {
                return Err(InstallerStageError::UnsafeState);
            }
            crate::windows_staging::require_identity(&self.file, self.identity)?;
            crate::windows_staging::require_named_file_identity(
                parent,
                OsStr::new(name),
                self.identity,
                false,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestDestination as Destination, prepared_stage};
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::path::PathBuf;

    fn prepared() -> (Destination, StagedApplication, PathBuf) {
        let (destination, staged, path) = prepared_stage(b"candidate");
        (destination, staged, path.join(ROLLBACK_DIRECTORY))
    }

    // Synthetic storage inputs exercise filesystem authority, not archive authentication.
    // The production entry point only accepts AuthenticatedRecoveryMaterial.
    pub(super) fn input() -> KitInput<'static> {
        let archive = b"ARCHIVE-CANARY";
        let bundle = b"BUNDLE-CANARY";
        KitInput {
            archive,
            bundle,
            archive_sha256: Sha256::digest(archive).into(),
            bundle_sha256: Sha256::digest(bundle).into(),
        }
    }

    #[test]
    fn stores_exact_private_material_without_installing_an_executable() {
        let (destination, staged, path) = prepared();
        let kit = RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).unwrap();
        kit.revalidate_input(&staged, &input()).unwrap();
        assert_eq!(fs::read(path.join(ARCHIVE)).unwrap(), input().archive);
        assert_eq!(fs::read(path.join(BUNDLE)).unwrap(), input().bundle);
        assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
        assert!(
            !destination
                .path()
                .join(staged.record.executable_name())
                .exists()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for name in [ARCHIVE, BUNDLE] {
                assert_eq!(
                    fs::metadata(path.join(name)).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert!(RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).is_err());
        assert!(
            require_stage(&staged, false).is_err(),
            "ordinary first-install validation must refuse upgrade-kit inventory"
        );
    }

    #[test]
    fn every_interrupted_storage_boundary_preserves_the_partial_kit() {
        for stop in [
            KitBoundary::DirectoryCreated,
            KitBoundary::ArchiveWritten,
            KitBoundary::BundleWritten,
            KitBoundary::Durable,
        ] {
            let (destination, staged, path) = prepared();
            let result = RetainedRollbackKit::create_with_hook(&staged, &input(), |boundary| {
                if boundary == stop {
                    Err(InstallerStageError::WriteFailed)
                } else {
                    Ok(())
                }
            });
            assert_eq!(result.err(), Some(InstallerStageError::RecoveryRequired));
            assert!(path.is_dir());
            let count = match stop {
                KitBoundary::DirectoryCreated => 0,
                KitBoundary::ArchiveWritten => 1,
                _ => 2,
            };
            assert_eq!(fs::read_dir(&path).unwrap().count(), count);
            assert!(
                !destination
                    .path()
                    .join(staged.record.executable_name())
                    .exists()
            );
        }
    }

    #[test]
    fn raced_leaf_creation_never_overwrites_existing_bytes() {
        for (at, name) in [
            (KitBoundary::DirectoryCreated, ARCHIVE),
            (KitBoundary::ArchiveWritten, BUNDLE),
        ] {
            let (_destination, staged, path) = prepared();
            let result = RetainedRollbackKit::create_with_hook(&staged, &input(), |boundary| {
                if boundary == at {
                    fs::write(path.join(name), b"foreign").unwrap();
                }
                Ok(())
            });
            assert_eq!(result.err(), Some(InstallerStageError::RecoveryRequired));
            assert_eq!(fs::read(path.join(name)).unwrap(), b"foreign");
        }
    }

    #[test]
    fn stale_operation_inventory_blocks_before_kit_creation() {
        let (_destination, staged, path) = prepared();
        let foreign = path.parent().unwrap().join("foreign");
        fs::write(&foreign, b"retained").unwrap();
        assert!(RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).is_err());
        assert!(!path.exists());
        assert_eq!(fs::read(foreign).unwrap(), b"retained");
    }

    #[test]
    fn unexpected_inventory_and_wrong_digest_cannot_revalidate() {
        let (_destination, staged, path) = prepared();
        let kit = RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).unwrap();
        for archive in [false, true] {
            let mut wrong = input();
            if archive {
                wrong.archive_sha256[0] ^= 1;
            } else {
                wrong.bundle_sha256[0] ^= 1;
            }
            assert!(kit.revalidate_input(&staged, &wrong).is_err());
        }
        fs::write(path.join("foreign"), b"preserve").unwrap();
        assert!(kit.revalidate_input(&staged, &input()).is_err());
        assert_eq!(fs::read(path.join("foreign")).unwrap(), b"preserve");
    }

    #[test]
    fn a_kit_cannot_be_rebound_to_another_locked_operation() {
        let (_first, staged, _) = prepared();
        let (_second, other, _) = prepared();
        let kit = RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).unwrap();
        let _other_kit =
            RetainedRollbackKit::create_with_hook(&other, &input(), |_| Ok(())).unwrap();
        assert!(kit.revalidate_input(&other, &input()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn late_byte_and_equal_byte_identity_changes_are_preserved_not_accepted() {
        use std::os::unix::fs::PermissionsExt as _;
        for replace in [false, true] {
            let (destination, staged, path) = prepared();
            let kit = RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).unwrap();
            let archive = path.join(ARCHIVE);
            if replace {
                fs::rename(&archive, destination.path().join("retained-archive")).unwrap();
                fs::write(&archive, input().archive).unwrap();
                fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                assert_eq!(b"ARCHIVE-TAMPER".len(), input().archive.len());
                fs::write(&archive, b"ARCHIVE-TAMPER").unwrap();
            }
            assert!(kit.revalidate_input(&staged, &input()).is_err());
            assert!(archive.exists());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn added_file_acl_is_refused_without_repair() {
        let (_destination, staged, path) = prepared();
        let kit = RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).unwrap();
        kitrove_testkit::install_macos_extended_acl(&path.join(ARCHIVE));
        assert!(kit.revalidate_input(&staged, &input()).is_err());
        assert_eq!(fs::read(path.join(ARCHIVE)).unwrap(), input().archive);
        assert!(crate::unix_staging::require_empty_acl(&kit.archive.file).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_kit_blocks_external_file_writes_and_moves() {
        let (_destination, staged, path) = prepared();
        let kit = RetainedRollbackKit::create_with_hook(&staged, &input(), |_| Ok(())).unwrap();
        for name in [ARCHIVE, BUNDLE] {
            assert!(fs::write(path.join(name), b"changed").is_err());
            assert!(fs::rename(path.join(name), path.join("moved")).is_err());
        }
        kit.revalidate_input(&staged, &input()).unwrap();
    }
}
