use std::path::Path;

use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial,
};

use crate::replacement_direction::ReplacementDirection;
use crate::{InstallerStageError, NativeFileIdentity, StagingInput, require_compiled_target};

/// Read-only prior-leaf evidence, not permission to replace it or proof of durable rollback storage.
pub(crate) struct ReplacementPrecondition<'a> {
    candidate: &'a AuthenticatedApplicationExecutable,
    rollback: &'a AuthenticatedRecoveryMaterial,
    prior: RetainedPrior,
    direction: ReplacementDirection,
}

impl<'a> ReplacementPrecondition<'a> {
    /// Read-only readiness, never a reusable replacement permit.
    pub(crate) fn preflight(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        roots: &[std::path::PathBuf],
        direction: ReplacementDirection,
    ) -> Result<(), InstallerStageError> {
        require_replacement_inputs(candidate, rollback, direction)?;
        let mut states = crate::state_preflight::InspectedStateRoots::capture(roots)?;
        let prior = Self::inspect_direction(destination, candidate, rollback, direction)?;
        #[cfg(unix)]
        let parent = prior.prior.destination.directory();
        #[cfg(windows)]
        let parent = prior
            .prior
            .destination
            .directory()
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        crate::installation_state::require_idle_installer_state(parent)?;
        prior.revalidate()?;
        states.revalidate()?;
        prior.revalidate()
    }

    pub(crate) fn inspect(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
    ) -> Result<Self, InstallerStageError> {
        Self::inspect_direction(
            destination,
            candidate,
            rollback,
            ReplacementDirection::Upgrade,
        )
    }

    pub(crate) fn inspect_direction(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        require_replacement_inputs(candidate, rollback, direction)?;
        let prior =
            RetainedPrior::inspect(destination, &StagingInput::from(rollback.executable()))?;
        Ok(Self {
            candidate,
            rollback,
            prior,
            direction,
        })
    }

    pub(crate) fn revalidate(&self) -> Result<(), InstallerStageError> {
        self.prior
            .revalidate(&StagingInput::from(self.rollback.executable()))
    }

    #[cfg(unix)]
    pub(crate) fn reopen_at(
        destination: &Path,
        staged: &crate::StagedApplication,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        candidate_installed: bool,
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        require_replacement_inputs(candidate, rollback, direction)?;
        let input = StagingInput::from(rollback.executable());
        let destination = crate::unix_staging::open_destination(destination)?;
        let (parent, name) = if candidate_installed {
            (
                &staged._retained.operation,
                crate::staging_policy::STAGED_EXECUTABLE,
            )
        } else {
            (destination.directory(), input.executable_name)
        };
        let leaf = crate::unix_recovery::open_exact_private_file(
            parent,
            name,
            0o700,
            input.executable_bytes.len() as u64,
        )?;
        crate::unix_staging::verify_executable_contents(&leaf.file, &input)?;
        crate::unix_staging::require_named_file_identity(
            parent,
            name,
            &leaf.file,
            leaf.identity,
            0o700,
            input.executable_bytes.len() as u64,
        )?;
        let result = Self {
            candidate,
            rollback,
            direction,
            prior: RetainedPrior {
                destination,
                file: leaf.file,
                identity: leaf.identity,
            },
        };
        result.bind_stage_identity(staged)?;
        Ok(result)
    }

    pub(crate) const fn prior_identity(&self) -> NativeFileIdentity {
        self.prior.identity
    }

    /// Reopened placement evidence is handed directly to the owning Windows pair.
    /// It is not an initial-destination precondition and retains no duplicate file lease.
    #[cfg(windows)]
    pub(crate) fn reopen_windows_pair(
        destination: &Path,
        staged: &crate::StagedApplication,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        prior_retained: bool,
        direction: ReplacementDirection,
    ) -> Result<(Self, std::fs::File), InstallerStageError> {
        require_replacement_inputs(candidate, rollback, direction)?;
        let input = StagingInput::from(rollback.executable());
        let destination = kitrove_windows_security::validate_install_directory(destination)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let (parent, name) = if prior_retained {
            (
                &staged._retained.operation,
                crate::staging_policy::RETAINED_UPGRADE_PRIOR,
            )
        } else {
            (
                destination
                    .directory()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
                input.executable_name,
            )
        };
        let leaf = crate::windows_recovery::open_bounded_private_file(
            parent,
            std::ffi::OsStr::new(name),
            input.executable_bytes.len() as u64,
        )?;
        crate::windows_staging::require_file_contents(
            &leaf.file,
            input.executable_bytes.len() as u64,
            input.executable_sha256,
        )?;
        crate::windows_staging::require_named_file_identity(
            parent,
            std::ffi::OsStr::new(name),
            leaf.identity,
            false,
        )?;
        let precondition = Self {
            candidate,
            rollback,
            direction,
            prior: RetainedPrior {
                destination,
                identity: leaf.identity,
                file: None,
            },
        };
        precondition.bind_stage_identity(staged)?;
        Ok((precondition, leaf.file))
    }

    #[cfg(windows)]
    pub(crate) fn take_windows_file(&mut self) -> Result<std::fs::File, InstallerStageError> {
        self.revalidate()?;
        self.prior
            .file
            .take()
            .ok_or(InstallerStageError::RecoveryRequired)
    }

    pub(crate) const fn direction(&self) -> ReplacementDirection {
        self.direction
    }

    pub(crate) fn bind_to_stage(
        &self,
        staged: &crate::StagedApplication,
    ) -> Result<(), InstallerStageError> {
        self.revalidate()?;
        self.bind_stage_identity(staged)
    }

    pub(crate) fn bind_stage_identity(
        &self,
        staged: &crate::StagedApplication,
    ) -> Result<(), InstallerStageError> {
        staged
            .record
            .matches_release(&StagingInput::from(self.candidate))
            .map_err(|_| InstallerStageError::VerificationFailed)?;
        #[cfg(unix)]
        let identities = self.prior.destination.identities();
        #[cfg(windows)]
        let identities = self
            .prior
            .destination
            .identities()
            .iter()
            .copied()
            .map(crate::windows_staging::native_identity)
            .collect::<Vec<_>>();
        if identities != staged.record.ancestry_identities() {
            return Err(InstallerStageError::UnsafeDestination);
        }
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn sync_prior(&self) -> Result<(), InstallerStageError> {
        self.prior
            .file
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    #[cfg(unix)]
    pub(crate) fn revalidate_prior_at(
        &self,
        parent: &cap_std::fs::Dir,
        name: &str,
    ) -> Result<(), InstallerStageError> {
        let input = StagingInput::from(self.rollback.executable());
        let require_named = || {
            crate::unix_staging::require_named_file_identity(
                parent,
                name,
                &self.prior.file,
                self.prior.identity,
                0o700,
                input.executable_bytes.len() as u64,
            )
        };
        require_named()?;
        crate::unix_staging::verify_executable_contents(&self.prior.file, &input)?;
        require_named()
    }

    pub(crate) const fn candidate(&self) -> &AuthenticatedApplicationExecutable {
        self.candidate
    }

    pub(crate) const fn rollback(&self) -> &AuthenticatedRecoveryMaterial {
        self.rollback
    }
}

fn require_replacement_inputs(
    candidate: &AuthenticatedApplicationExecutable,
    rollback: &AuthenticatedRecoveryMaterial,
    direction: ReplacementDirection,
) -> Result<(), InstallerStageError> {
    require_compiled_target(candidate)?;
    require_compiled_target(rollback.executable())?;
    require_compatible_replacement(
        &StagingInput::from(candidate),
        &StagingInput::from(rollback.executable()),
        direction,
    )?;
    crate::require_current_user_installation()
}

fn require_compatible_replacement(
    candidate: &StagingInput<'_>,
    prior: &StagingInput<'_>,
    direction: ReplacementDirection,
) -> Result<(), InstallerStageError> {
    if candidate.target != prior.target || !direction.permits(&candidate.manifest, &prior.manifest)
    {
        return Err(InstallerStageError::IncompatibleUpgrade);
    }
    Ok(())
}

struct RetainedPrior {
    identity: NativeFileIdentity,
    #[cfg(unix)]
    destination: crate::unix_staging::OpenedDestination,
    #[cfg(unix)]
    file: cap_std::fs::File,
    #[cfg(windows)]
    destination: kitrove_windows_security::ValidatedInstallDirectory,
    #[cfg(windows)]
    file: Option<std::fs::File>,
}

impl RetainedPrior {
    fn inspect(destination: &Path, prior: &StagingInput<'_>) -> Result<Self, InstallerStageError> {
        #[cfg(unix)]
        let retained = {
            let destination = crate::unix_staging::open_destination(destination)?;
            let leaf = crate::unix_recovery::open_exact_private_file(
                destination.directory(),
                prior.executable_name,
                0o700,
                prior.executable_bytes.len() as u64,
            )?;
            Self {
                identity: leaf.identity,
                destination,
                file: leaf.file,
            }
        };
        #[cfg(windows)]
        let retained = {
            let destination = kitrove_windows_security::validate_install_directory(destination)
                .map_err(|_| InstallerStageError::UnsafeDestination)?;
            let file = kitrove_windows_security::open_private_file(
                destination
                    .directory()
                    .map_err(|_| InstallerStageError::UnsafeDestination)?,
                std::ffi::OsStr::new(prior.executable_name),
            )
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
            Self {
                identity: crate::windows_staging::file_identity(&file)?,
                destination,
                file: Some(file),
            }
        };
        retained.revalidate(prior)?;
        Ok(retained)
    }

    fn revalidate(&self, prior: &StagingInput<'_>) -> Result<(), InstallerStageError> {
        self.require_named_authority(prior)?;
        #[cfg(unix)]
        let contents = crate::unix_staging::verify_executable_contents(&self.file, prior);
        #[cfg(windows)]
        let contents = crate::windows_staging::require_file_contents(
            self.file
                .as_ref()
                .ok_or(InstallerStageError::RecoveryRequired)?,
            prior.executable_bytes.len() as u64,
            prior.executable_sha256,
        );
        contents.map_err(|_| InstallerStageError::VerificationFailed)?;
        self.require_named_authority(prior)
    }

    fn require_named_authority(&self, prior: &StagingInput<'_>) -> Result<(), InstallerStageError> {
        #[cfg(unix)]
        {
            crate::unix_staging::revalidate_destination(&self.destination)?;
            crate::unix_staging::require_named_file_identity(
                self.destination.directory(),
                prior.executable_name,
                &self.file,
                self.identity,
                0o700,
                prior.executable_bytes.len() as u64,
            )
        }
        #[cfg(windows)]
        {
            self.destination
                .revalidate()
                .map_err(|_| InstallerStageError::UnsafeDestination)?;
            let file = self
                .file
                .as_ref()
                .ok_or(InstallerStageError::RecoveryRequired)?;
            kitrove_windows_security::inspect_private_single_link_file(file)
                .map_err(|_| InstallerStageError::UnsafeDestination)?;
            crate::windows_staging::require_identity(file, self.identity)?;
            crate::windows_staging::require_named_file_identity(
                self.destination
                    .directory()
                    .map_err(|_| InstallerStageError::UnsafeDestination)?,
                std::ffi::OsStr::new(prior.executable_name),
                self.identity,
                false,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::staging_input;
    use std::fs;
    use std::io::Write as _;

    #[cfg(unix)]
    type Destination = tempfile::TempDir;
    #[cfg(windows)]
    type Destination = crate::windows_test_support::TestDestination;

    fn destination(bytes: &[u8]) -> Destination {
        #[cfg(unix)]
        let destination = crate::test_support::private_tempdir();
        #[cfg(windows)]
        let destination = crate::windows_test_support::destination();
        let input = staging_input(bytes);
        #[cfg(unix)]
        let mut file = {
            let directory = crate::unix_staging::open_destination(destination.path()).unwrap();
            crate::unix_staging::create_private_file(
                directory.directory(),
                std::ffi::OsStr::new(input.executable_name),
                0o700,
            )
            .unwrap()
        };
        #[cfg(windows)]
        let mut file = {
            let directory =
                kitrove_windows_security::validate_install_directory(destination.path()).unwrap();
            kitrove_windows_security::create_private_file(
                directory.directory().unwrap(),
                std::ffi::OsStr::new(input.executable_name),
            )
            .unwrap()
        };
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        destination
    }

    #[test]
    fn prior_inspection_is_exact_and_does_not_create_installer_state() {
        let destination = destination(b"prior executable");
        let input = staging_input(b"prior executable");
        let prior = RetainedPrior::inspect(destination.path(), &input).unwrap();
        prior.revalidate(&input).unwrap();
        assert_eq!(fs::read_dir(destination.path()).unwrap().count(), 1);
        assert_eq!(
            fs::read(destination.path().join(input.executable_name)).unwrap(),
            input.executable_bytes
        );
    }

    #[test]
    fn another_executable_cannot_satisfy_prior_release_evidence() {
        let destination = destination(b"different bytes!");
        assert!(
            RetainedPrior::inspect(destination.path(), &staging_input(b"prior executable"))
                .is_err()
        );
        assert_eq!(fs::read_dir(destination.path()).unwrap().count(), 1);
    }

    #[test]
    fn compatibility_requires_explicit_prior_release_and_forward_version() {
        let prior = staging_input(b"prior");
        let mut candidate = staging_input(b"new");
        assert!(
            require_compatible_replacement(&candidate, &prior, ReplacementDirection::Upgrade)
                .is_err()
        );
        assert!(
            require_compatible_replacement(&candidate, &prior, ReplacementDirection::Rollback)
                .is_err()
        );
        candidate.release_version = "1.2.4".to_owned();
        candidate.release_tag = "v1.2.4";
        let spec =
            kitrove_release_policy::application_archive_for_target(candidate.target).unwrap();
        for predecessors in [vec![], vec![semver::Version::new(1, 2, 3)]] {
            let bytes = kitrove_release_policy::render_release_manifest(
                spec,
                &semver::Version::new(1, 2, 4),
                candidate.executable_sha256,
                &predecessors,
            )
            .unwrap();
            candidate.manifest =
                kitrove_release_policy::parse_release_manifest(spec, &bytes).unwrap();
            assert_eq!(
                require_compatible_replacement(&candidate, &prior, ReplacementDirection::Upgrade)
                    .is_ok(),
                !predecessors.is_empty()
            );
            assert_eq!(
                require_compatible_replacement(&prior, &candidate, ReplacementDirection::Rollback)
                    .is_ok(),
                !predecessors.is_empty()
            );
        }
        assert!(
            require_compatible_replacement(&prior, &candidate, ReplacementDirection::Upgrade)
                .is_err()
        );
        assert!(
            require_compatible_replacement(&prior, &candidate, ReplacementDirection::Rollback)
                .is_ok()
        );
        assert!(
            require_compatible_replacement(&candidate, &prior, ReplacementDirection::Rollback)
                .is_err()
        );
    }

    #[test]
    fn a_new_hard_link_invalidates_prior_authority_without_cleanup() {
        let destination = destination(b"prior executable");
        let input = staging_input(b"prior executable");
        let prior = RetainedPrior::inspect(destination.path(), &input).unwrap();
        let path = destination.path().join(input.executable_name);
        let alias = destination.path().join("alias");
        let linked = fs::hard_link(&path, &alias);
        #[cfg(windows)]
        if let Err(error) = &linked {
            // The retained Windows handle may prevent linking before it can change authority.
            assert!(matches!(error.raw_os_error(), Some(5 | 32)));
            assert!(!alias.exists());
            prior.revalidate(&input).unwrap();
            return;
        }
        linked.unwrap();
        assert!(prior.revalidate(&input).is_err());
        assert_eq!(fs::read(&path).unwrap(), input.executable_bytes);
        assert_eq!(fs::read(&alias).unwrap(), input.executable_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn absent_symlinked_and_unsafe_mode_priors_are_not_adopted_or_repaired() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        for change in 0..3 {
            let destination = destination(b"prior executable");
            let input = staging_input(b"prior executable");
            let path = destination.path().join(input.executable_name);
            if change < 2 {
                let retained = destination.path().join("retained");
                fs::rename(&path, &retained).unwrap();
                if change == 1 {
                    symlink(&retained, &path).unwrap();
                }
            } else {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
            }
            assert!(RetainedPrior::inspect(destination.path(), &input).is_err());
            assert!(
                !destination
                    .path()
                    .join(crate::INSTALLER_STATE_DIRECTORY)
                    .exists()
            );
            if change == 0 {
                assert!(!path.exists());
            } else if change == 1 {
                assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
            } else {
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o777
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn changed_bytes_and_equal_byte_replacement_are_rejected() {
        use std::os::unix::fs::PermissionsExt as _;
        for replace in [false, true] {
            let destination = destination(b"prior executable");
            let input = staging_input(b"prior executable");
            let prior = RetainedPrior::inspect(destination.path(), &input).unwrap();
            let path = destination.path().join(input.executable_name);
            if replace {
                fs::rename(&path, destination.path().join("retained")).unwrap();
                fs::write(&path, input.executable_bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            } else {
                fs::write(&path, b"different bytes!").unwrap();
            }
            assert!(prior.revalidate(&input).is_err());
            assert!(path.exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_prior_prevents_external_write_and_replacement() {
        let destination = destination(b"prior executable");
        let input = staging_input(b"prior executable");
        let prior = RetainedPrior::inspect(destination.path(), &input).unwrap();
        let path = destination.path().join(input.executable_name);
        assert!(fs::write(&path, b"changed").is_err());
        assert!(fs::rename(&path, destination.path().join("moved")).is_err());
        prior.revalidate(&input).unwrap();
    }
}
