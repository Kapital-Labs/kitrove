use std::path::{Path, PathBuf};

use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial,
};

use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::RetainedRollbackKit;
use crate::state_preflight::InspectedStateRoots;
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::upgrade_record::RetainedUpgradeRecord;
use crate::{InstallerStageError, StagedApplication, stage_authenticated_application};

#[cfg(unix)]
#[path = "upgrade_transaction/unix.rs"]
mod unix;

#[cfg(any(windows, test))]
#[path = "upgrade_transaction/windows_recovery_plan.rs"]
pub(crate) mod windows_recovery_plan;

#[cfg(any(windows, test))]
#[path = "upgrade_transaction/windows_journal_policy.rs"]
pub(crate) mod windows_journal_policy;

#[cfg(any(windows, test))]
#[path = "upgrade_transaction/windows_journal.rs"]
pub(crate) mod windows_journal;

#[cfg(windows)]
#[path = "upgrade_transaction/windows_pair.rs"]
mod windows_pair;

#[cfg(windows)]
#[path = "upgrade_transaction/windows_reopen.rs"]
mod windows_reopen;

#[cfg(windows)]
#[path = "upgrade_transaction/windows_retirement.rs"]
mod windows_retirement;

/// Owns preparation and every lock together; not replacement or recovery authority alone.
pub(crate) struct PreparedReplacement<'a> {
    record: RetainedUpgradeRecord,
    kit: RetainedRollbackKit,
    prior: ReplacementPrecondition<'a>,
    staged: StagedApplication,
    // Release artifact capabilities and the installer lock before state guards.
    states: InspectedStateRoots,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreparationBoundary {
    StatesLocked,
    Staged,
    KitRetained,
    RecordRetained,
}

impl<'a> PreparedReplacement<'a> {
    /// Keeps freshly authenticated recovery material alive for the complete action.
    /// The callback cannot return a preparation that borrows that local material.
    /// Direction is explicit caller intent and must match the reconstructed record.
    pub(crate) fn with_reopened_preparation<R>(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &kitrove_release_provenance::ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
        action: impl FnOnce(PreparedReplacement<'_>) -> Result<R, InstallerStageError>,
    ) -> Result<R, InstallerStageError> {
        Self::with_reopened_impl(
            destination,
            candidate,
            state_roots,
            direction,
            |staged| RetainedRollbackKit::reopen(staged, expected_prior, expected_archive_sha256),
            action,
        )
    }

    fn with_reopened_impl<R>(
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
        action: impl FnOnce(PreparedReplacement<'_>) -> Result<R, InstallerStageError>,
    ) -> Result<R, InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let mut states = InspectedStateRoots::capture(state_roots)?;
        #[cfg(unix)]
        let staged = crate::unix_recovery::resume_prepared_upgrade(
            destination,
            &crate::StagingInput::from(candidate),
        )?;
        #[cfg(windows)]
        let staged = crate::windows_recovery::resume_prepared_upgrade(
            destination,
            &crate::StagingInput::from(candidate),
        )?;
        let (kit, rollback) = reopen_kit(&staged)?;
        let prior = ReplacementPrecondition::inspect_direction(
            destination,
            candidate,
            &rollback,
            direction,
        )?;
        let record = RetainedUpgradeRecord::reopen(&staged, &prior, &kit, &mut states)?;
        let mut prepared = PreparedReplacement {
            record,
            kit,
            prior,
            staged,
            states,
        };
        prepared.revalidate()?;
        action(prepared)
    }

    pub(crate) fn prepare(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        state_roots: &[PathBuf],
    ) -> Result<Self, InstallerStageError> {
        Self::prepare_with_hook(destination, candidate, rollback, state_roots, |_| Ok(()))
    }

    pub(crate) fn prepare_rollback(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        recovery: &'a AuthenticatedRecoveryMaterial,
        state_roots: &[PathBuf],
    ) -> Result<Self, InstallerStageError> {
        Self::prepare_direction_with_hook(
            destination,
            candidate,
            recovery,
            state_roots,
            ReplacementDirection::Rollback,
            |_| Ok(()),
        )
    }

    fn prepare_with_hook(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        state_roots: &[PathBuf],
        boundary: impl FnMut(PreparationBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        Self::prepare_direction_with_hook(
            destination,
            candidate,
            rollback,
            state_roots,
            ReplacementDirection::Upgrade,
            boundary,
        )
    }

    fn prepare_direction_with_hook(
        destination: &Path,
        candidate: &'a AuthenticatedApplicationExecutable,
        rollback: &'a AuthenticatedRecoveryMaterial,
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
        mut boundary: impl FnMut(PreparationBoundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        let prior = ReplacementPrecondition::inspect_direction(
            destination,
            candidate,
            rollback,
            direction,
        )?;
        let mut states = InspectedStateRoots::capture(state_roots)?;
        boundary(PreparationBoundary::StatesLocked)?;
        let staged = stage_authenticated_application(destination, candidate)?;
        // Stage creation owns its own partial-write errors. Once it succeeds,
        // every later failure leaves durable preparation requiring recovery.
        (|| -> Result<Self, InstallerStageError> {
            boundary(PreparationBoundary::Staged)?;
            prior.bind_to_stage(&staged)?;
            states.revalidate()?;
            let kit = RetainedRollbackKit::create_direction(&staged, rollback, direction)?;
            boundary(PreparationBoundary::KitRetained)?;
            let record = RetainedUpgradeRecord::persist(&staged, &prior, &kit, &mut states)?;
            boundary(PreparationBoundary::RecordRetained)?;
            let mut prepared = Self {
                record,
                kit,
                prior,
                staged,
                states,
            };
            prepared.revalidate()?;
            Ok(prepared)
        })()
        .map_err(|_| InstallerStageError::RecoveryRequired)
    }

    pub(crate) fn revalidate(&mut self) -> Result<(), InstallerStageError> {
        self.record
            .revalidate(&self.staged, &self.prior, &self.kit, &mut self.states)
    }
}

impl std::fmt::Debug for PreparedReplacement<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedReplacement")
            .finish_non_exhaustive()
    }
}

#[cfg(all(unix, debug_assertions))]
#[cfg(test)]
#[path = "upgrade_transaction_tests.rs"]
mod tests;

#[cfg(all(windows, debug_assertions))]
#[cfg(test)]
#[path = "windows_preparation_tests.rs"]
mod windows_tests;
