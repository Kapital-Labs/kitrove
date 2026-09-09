use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity,
};

use super::{
    Exchange, Layout, MAX_UPGRADE_PHASE_BYTES, Marker, PendingMarker, marker_name, pending_name,
};
use crate::install_phase::InstallPhase;
use crate::record::{MAX_OPERATION_RECORD_BYTES, PreparedFilesystemEvidence};
use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::RetainedRollbackKit;
use crate::staging_policy::{OPERATION_RECORD, STAGED_EXECUTABLE, read_private_data_leaf};
use crate::state_preflight::InspectedStateRoots;
use crate::unix_recovery::{RecoveryRoot, open_exact_private_file, open_recovery_root};
use crate::unix_staging::{RetainedStage, require_exact_inventory, verify_executable_contents};
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::upgrade_record::RetainedUpgradeRecord;
use crate::upgrade_transaction::PreparedReplacement;
use crate::{
    InstalledApplication, InstallerOperationRecord, InstallerStageError, StagedApplication,
    StagingInput,
};

pub(super) struct DetectedMarkers {
    pub(super) complete: Vec<InstallPhase>,
    pub(super) pending: Vec<InstallPhase>,
}

impl PreparedReplacement<'_> {
    pub(crate) fn recover_rollback(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
    ) -> Result<InstalledApplication, InstallerStageError> {
        Self::recover_direction_with(
            destination,
            candidate,
            state_roots,
            ReplacementDirection::Rollback,
            |staged| {
                RetainedRollbackKit::reopen_material(
                    staged,
                    expected_prior,
                    expected_archive_sha256,
                )
            },
            crate::verify_installed_application,
        )
    }
    /// Reauthenticates retained local material before any resumed replacement or execution.
    pub(crate) fn recover_upgrade(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
    ) -> Result<InstalledApplication, InstallerStageError> {
        Self::recover_upgrade_with(
            destination,
            candidate,
            state_roots,
            |staged| {
                RetainedRollbackKit::reopen_material(
                    staged,
                    expected_prior,
                    expected_archive_sha256,
                )
            },
            crate::verify_installed_application,
        )
    }

    pub(in crate::upgrade_transaction) fn recover_upgrade_with(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        state_roots: &[PathBuf],
        reopen_kit: impl FnOnce(
            &StagedApplication,
        ) -> Result<
            (RetainedRollbackKit, AuthenticatedRecoveryMaterial),
            InstallerStageError,
        >,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        Self::recover_direction_with(
            destination,
            candidate,
            state_roots,
            ReplacementDirection::Upgrade,
            reopen_kit,
            verify,
        )
    }

    pub(in crate::upgrade_transaction) fn recover_direction_with(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
        reopen_kit: impl FnOnce(
            &StagedApplication,
        ) -> Result<
            (RetainedRollbackKit, AuthenticatedRecoveryMaterial),
            InstallerStageError,
        >,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let mut states = InspectedStateRoots::capture(state_roots)?;
        let (staged, layout, phases) = reopen_stage(destination, &StagingInput::from(candidate))?;
        let (kit, rollback) = reopen_kit(&staged)?;
        let prior = ReplacementPrecondition::reopen_at(
            destination,
            &staged,
            candidate,
            &rollback,
            layout == Layout::Exchanged,
            direction,
        )?;
        let record = RetainedUpgradeRecord::reopen_evidence(&staged, &prior, &kit, &mut states)?;
        let prepared = PreparedReplacement {
            record,
            kit,
            prior,
            staged,
            states,
        };
        let mut transaction = Exchange {
            prepared,
            markers: Vec::new(),
            pending: Vec::new(),
            layout,
        };
        for phase in phases.complete {
            let leaf = read_private_data_leaf(
                &transaction.prepared.staged._retained.operation,
                marker_name(phase),
                MAX_UPGRADE_PHASE_BYTES,
            )?;
            if leaf.bytes != transaction.phase_bytes(phase)? {
                return Err(InstallerStageError::RecoveryRequired);
            }
            transaction.markers.push(Marker {
                phase,
                file: leaf.file,
                identity: leaf.identity,
            });
        }
        for phase in phases.pending {
            transaction.pending.push(PendingMarker::open(
                &transaction.prepared.staged._retained.operation,
                phase,
                &transaction.phase_bytes(phase)?,
            )?);
        }
        transaction
            .revalidate()
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        match layout {
            Layout::Restored if transaction.markers.is_empty() => {
                transaction.prepared.install_with_hooks(verify, |_| Ok(()))
            }
            Layout::Restored => {
                transaction
                    .sync_pair()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?;
                if !transaction.has_marker(InstallPhase::RolledBack) {
                    transaction
                        .write_marker(InstallPhase::RolledBack)
                        .map_err(|_| InstallerStageError::RecoveryRequired)?;
                }
                transaction
                    .revalidate()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?;
                Err(InstallerStageError::VerificationFailed)
            }
            Layout::Exchanged => {
                transaction
                    .sync_pair()
                    .map_err(|_| InstallerStageError::RecoveryRequired)?;
                if !transaction.has_marker(InstallPhase::Replaced) {
                    transaction
                        .write_marker(InstallPhase::Replaced)
                        .map_err(|_| InstallerStageError::RecoveryRequired)?;
                }
                transaction.finish(verify, &mut |_| Ok(()))
            }
        }
    }
}

pub(super) fn reopen_stage(
    destination: &Path,
    input: &StagingInput<'_>,
) -> Result<(StagedApplication, Layout, DetectedMarkers), InstallerStageError> {
    let root = open_recovery_root(destination)?;
    let phases = detect_markers(&root)?;
    let leaf = read_private_data_leaf(
        &root.operation,
        OPERATION_RECORD,
        MAX_OPERATION_RECORD_BYTES,
    )?;
    let unverified = InstallerOperationRecord::parse_untrusted(&leaf.bytes)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    if unverified.operation_id() != root.operation_id {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let ancestry = root.destination.identities();
    let mut candidate = None;
    // Both fixed locations are bounded read-only candidates. A failed location grants
    // no authority; the complete record and the other release are checked afterwards.
    for layout in [Layout::Restored, Layout::Exchanged] {
        let (parent, name) = match layout {
            Layout::Restored => (&root.operation, STAGED_EXECUTABLE),
            Layout::Exchanged => (root.destination.directory(), input.executable_name),
        };
        let authenticated = (|| {
            let executable =
                open_exact_private_file(parent, name, 0o700, input.executable_bytes.len() as u64)?;
            let record = unverified
                .clone()
                .authenticate_prepared(
                    input,
                    PreparedFilesystemEvidence {
                        destination_path: root.destination.path_bytes(),
                        ancestry_identities: &ancestry,
                        state_identity: root.state_identity,
                        lock_identity: root.lock.identity(),
                        operation_identity: root.operation_identity,
                        staged_identity: executable.identity,
                    },
                )
                .map_err(|_| InstallerStageError::RecoveryRequired)?;
            if record
                .to_json()
                .map_err(|_| InstallerStageError::RecoveryRequired)?
                != leaf.bytes
            {
                return Err(InstallerStageError::RecoveryRequired);
            }
            verify_executable_contents(&executable.file, input)?;
            Ok((record, executable, layout))
        })();
        if let Ok(found) = authenticated {
            if candidate.is_some() {
                return Err(InstallerStageError::RecoveryRequired);
            }
            candidate = Some(found);
        }
    }
    let (record, executable, layout) = candidate.ok_or(InstallerStageError::RecoveryRequired)?;
    super::pending::require_phase_order(&phases.complete, &phases.pending, layout)?;
    let staged = StagedApplication {
        record,
        manifest: input.manifest.clone(),
        executable_content_hash: kitrove_model::ContentHash::digest(input.executable_bytes),
        _retained: RetainedStage::new(
            root.destination,
            root.state,
            root.operation,
            executable.file,
            leaf.file,
            root.lock,
        ),
    };
    crate::unix_install::revalidate_common(&staged)?;
    Ok((staged, layout, phases))
}

fn detect_markers(root: &RecoveryRoot) -> Result<DetectedMarkers, InstallerStageError> {
    let names = root
        .operation
        .entries()
        .map_err(|_| InstallerStageError::RecoveryRequired)?
        .take(9)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    if names.len() > 8 {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let phases: Vec<_> = InstallPhase::all()
        .iter()
        .copied()
        .filter(|phase| {
            names
                .iter()
                .any(|name| name == OsStr::new(marker_name(*phase)))
        })
        .collect();
    let pending: Vec<_> = InstallPhase::all()
        .iter()
        .copied()
        .filter(|phase| {
            names
                .iter()
                .any(|name| name == OsStr::new(pending_name(*phase)))
        })
        .collect();
    let mut expected = super::phase_inventory(phases.iter().copied());
    expected.extend(pending.iter().map(|phase| OsStr::new(pending_name(*phase))));
    if !crate::staging_policy::inventory_matches(names, &expected) {
        return Err(InstallerStageError::RecoveryRequired);
    }
    require_exact_inventory(&root.operation, &expected)?;
    Ok(DetectedMarkers {
        complete: phases,
        pending,
    })
}
