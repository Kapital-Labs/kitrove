//! Shared read-only reopening of installer namespace and candidate authority.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::Path;

use super::{open_bounded_private_file, read_bounded_file, retained_operation_name};
use crate::record::{MAX_OPERATION_RECORD_BYTES, PreparedFilesystemEvidence};
use crate::staging_policy::{INSTALLER_LOCK, OPERATION_RECORD, OpenedLeaf, STAGED_EXECUTABLE};
use crate::windows_staging::{self as filesystem, InstallerLock, RetainedStage};
use crate::{
    INSTALLER_STATE_DIRECTORY, InstallerOperationRecord, InstallerStageError, NativeFileIdentity,
    StagedApplication, StagingInput,
};

pub(crate) struct RecoveryRoot {
    pub(crate) destination: kitrove_windows_security::ValidatedInstallDirectory,
    state: File,
    pub(crate) operation: File,
    operation_name: OsString,
    state_identity: NativeFileIdentity,
    operation_identity: NativeFileIdentity,
    lock: InstallerLock,
}

#[derive(Clone, Copy)]
pub(crate) enum CandidateLocation {
    Staged,
    Installed,
    Failed,
}

pub(crate) struct RecoveryCandidate {
    pub(crate) record: InstallerOperationRecord,
    record_leaf: OpenedLeaf,
    executable: OpenedLeaf,
    location: CandidateLocation,
}

impl RecoveryRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, InstallerStageError> {
        let destination = kitrove_windows_security::validate_install_directory(path)
            .map_err(|_| InstallerStageError::UnsafeDestination)?;
        let state = kitrove_windows_security::open_private_directory(
            destination
                .directory()
                .map_err(|_| InstallerStageError::UnsafeDestination)?,
            OsStr::new(INSTALLER_STATE_DIRECTORY),
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let state_identity = filesystem::file_identity(&state)?;
        let lock = filesystem::acquire_existing_installer_lock(&state)?;
        filesystem::revalidate_control_boundary(&destination, &state, state_identity, &lock)?;
        let operation_name = retained_operation_name(&state)?;
        let operation = kitrove_windows_security::open_private_directory(&state, &operation_name)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        let operation_identity = filesystem::file_identity(&operation)?;
        let root = Self {
            destination,
            state,
            operation,
            operation_name,
            state_identity,
            operation_identity,
            lock,
        };
        root.revalidate()?;
        Ok(root)
    }

    pub(crate) fn revalidate(&self) -> Result<(), InstallerStageError> {
        filesystem::revalidate_control_boundary(
            &self.destination,
            &self.state,
            self.state_identity,
            &self.lock,
        )?;
        filesystem::require_identity(&self.operation, self.operation_identity)?;
        filesystem::require_named_directory_identity(
            &self.state,
            &self.operation_name,
            self.operation_identity,
        )?;
        filesystem::require_exact_inventory(
            &self.state,
            &[OsStr::new(INSTALLER_LOCK), &self.operation_name],
        )
    }

    fn candidate_location<'a>(
        &'a self,
        input: &'a StagingInput<'_>,
        location: CandidateLocation,
    ) -> Result<(&'a File, &'a str), InstallerStageError> {
        Ok(match location {
            CandidateLocation::Staged => (&self.operation, STAGED_EXECUTABLE),
            CandidateLocation::Installed => (
                self.destination
                    .directory()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?,
                input.executable_name,
            ),
            CandidateLocation::Failed => (&self.operation, crate::install_phase::FAILED_EXECUTABLE),
        })
    }

    pub(crate) fn candidate(
        &self,
        input: &StagingInput<'_>,
        location: CandidateLocation,
    ) -> Result<RecoveryCandidate, InstallerStageError> {
        self.revalidate()?;
        let record_leaf = open_bounded_private_file(
            &self.operation,
            OsStr::new(OPERATION_RECORD),
            MAX_OPERATION_RECORD_BYTES as u64,
        )?;
        let bytes = read_bounded_file(&record_leaf.file, MAX_OPERATION_RECORD_BYTES)?;
        let unverified = InstallerOperationRecord::parse_untrusted(&bytes).map_err(|error| {
            if error.is_legacy_schema() {
                InstallerStageError::RecoveryRequired
            } else {
                InstallerStageError::UnsafeState
            }
        })?;
        if Some(unverified.operation_id()) != self.operation_name.to_str() {
            return Err(InstallerStageError::UnsafeState);
        }
        let (parent, name) = self.candidate_location(input, location)?;
        let executable =
            open_bounded_private_file(parent, OsStr::new(name), unverified.executable_size())?;
        if executable.size != unverified.executable_size() {
            return Err(InstallerStageError::UnsafeState);
        }
        let destination_path = filesystem::encode_destination_path(self.destination.path())?;
        let ancestry = self
            .destination
            .identities()
            .iter()
            .copied()
            .map(filesystem::native_identity)
            .collect::<Vec<_>>();
        let record = unverified
            .authenticate_prepared(
                input,
                PreparedFilesystemEvidence {
                    destination_path: &destination_path,
                    ancestry_identities: &ancestry,
                    state_identity: self.state_identity,
                    lock_identity: self.lock.identity(),
                    operation_identity: self.operation_identity,
                    staged_identity: executable.identity,
                },
            )
            .map_err(|_| InstallerStageError::UnsafeState)?;
        if bytes
            != record
                .to_json()
                .map_err(|_| InstallerStageError::UnsafeState)?
        {
            return Err(InstallerStageError::UnsafeState);
        }
        let candidate = RecoveryCandidate {
            record,
            record_leaf,
            executable,
            location,
        };
        candidate.revalidate(self, input)?;
        Ok(candidate)
    }
}

impl RecoveryCandidate {
    pub(crate) fn revalidate(
        &self,
        root: &RecoveryRoot,
        input: &StagingInput<'_>,
    ) -> Result<(), InstallerStageError> {
        root.revalidate()?;
        let (parent, name) = root.candidate_location(input, self.location)?;
        filesystem::require_named_file_identity(
            parent,
            OsStr::new(name),
            self.executable.identity,
            false,
        )?;
        filesystem::require_named_file_identity(
            &root.operation,
            OsStr::new(OPERATION_RECORD),
            self.record_leaf.identity,
            false,
        )?;
        filesystem::require_file_contents(
            &self.executable.file,
            input.executable_bytes.len() as u64,
            input.executable_sha256,
        )?;
        if read_bounded_file(&self.record_leaf.file, MAX_OPERATION_RECORD_BYTES)?
            != self
                .record
                .to_json()
                .map_err(|_| InstallerStageError::UnsafeState)?
        {
            return Err(InstallerStageError::UnsafeState);
        }
        root.revalidate()
    }

    pub(crate) fn into_stage(
        self,
        root: RecoveryRoot,
        input: &StagingInput<'_>,
    ) -> Result<StagedApplication, InstallerStageError> {
        self.revalidate(&root, input)?;
        Ok(StagedApplication {
            record: self.record,
            manifest: input.manifest.clone(),
            executable_content_hash: kitrove_model::ContentHash::digest(input.executable_bytes),
            _retained: RetainedStage::new(
                root.destination,
                root.state,
                root.operation,
                self.executable.file,
                self.record_leaf.file,
                root.lock,
            ),
        })
    }
}
