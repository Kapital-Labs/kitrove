//! Fresh read-only replacement reopening. Stored paths never select state roots.

use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial, ExpectedReleaseIdentity,
};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::PreparedReplacement;
use super::windows_journal::writer::JournaledPair;
use super::windows_journal_policy;
use super::windows_pair::{Layout, RETAINED_PRIOR, WindowsPair};
use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::RetainedRollbackKit;
use crate::staging_policy::{STAGED_EXECUTABLE, entry_exists};
use crate::state_preflight::InspectedStateRoots;
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::upgrade_record::RetainedUpgradeRecord;
use crate::windows_recovery::root::{CandidateLocation, RecoveryRoot};
use crate::{InstallerStageError, StagedApplication, StagingInput};

impl PreparedReplacement<'_> {
    pub(crate) fn install(self) -> Result<crate::InstalledApplication, InstallerStageError> {
        JournaledPair::from_pair(WindowsPair::new(self)?)?.finish()
    }

    pub(crate) fn recover_upgrade(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
    ) -> Result<crate::InstalledApplication, InstallerStageError> {
        Self::recover_windows_direction(
            destination,
            candidate,
            expected_prior,
            expected_archive_sha256,
            state_roots,
            ReplacementDirection::Upgrade,
        )
    }

    pub(crate) fn recover_rollback(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
    ) -> Result<crate::InstalledApplication, InstallerStageError> {
        Self::recover_windows_direction(
            destination,
            candidate,
            expected_prior,
            expected_archive_sha256,
            state_roots,
            ReplacementDirection::Rollback,
        )
    }

    fn recover_windows_direction(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
    ) -> Result<crate::InstalledApplication, InstallerStageError> {
        Self::with_reopened_windows_pair(
            destination,
            candidate,
            expected_prior,
            expected_archive_sha256,
            state_roots,
            direction,
            |owner| owner.finish(),
        )
    }

    pub(in crate::upgrade_transaction) fn with_reopened_windows_pair<R>(
        destination: &Path,
        candidate: &AuthenticatedApplicationExecutable,
        expected_prior: &ExpectedReleaseIdentity,
        expected_archive_sha256: [u8; 32],
        state_roots: &[PathBuf],
        direction: ReplacementDirection,
        action: impl FnOnce(JournaledPair<'_>) -> Result<R, InstallerStageError>,
    ) -> Result<R, InstallerStageError> {
        Self::with_reopened_windows_pair_impl(
            destination,
            candidate,
            state_roots,
            direction,
            |staged| {
                RetainedRollbackKit::reopen_material(
                    staged,
                    expected_prior,
                    expected_archive_sha256,
                )
            },
            action,
        )
    }

    pub(in crate::upgrade_transaction) fn with_reopened_windows_pair_impl<R>(
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
        action: impl FnOnce(JournaledPair<'_>) -> Result<R, InstallerStageError>,
    ) -> Result<R, InstallerStageError> {
        crate::require_compiled_target(candidate)?;
        crate::require_current_user_installation()?;
        let mut states = InspectedStateRoots::capture(state_roots)?;
        let (staged, layout, markers) = reopen_candidate(destination, candidate)?;
        let marker_names = markers.iter().map(OsStr::new).collect::<Vec<_>>();
        let (kit, rollback) = reopen_kit(&staged)?;
        let (prior, prior_file) = ReplacementPrecondition::reopen_windows_pair(
            destination,
            &staged,
            candidate,
            &rollback,
            layout != Layout::Original,
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
        let pair = WindowsPair::from_reopened(prepared, prior_file, layout, &marker_names)?;
        let journal = JournaledPair::from_pair(pair)?;
        action(journal)
    }
}

pub(super) fn reopen_candidate(
    destination: &Path,
    candidate: &AuthenticatedApplicationExecutable,
) -> Result<(StagedApplication, Layout, Vec<String>), InstallerStageError> {
    let root = RecoveryRoot::open(destination)?;
    let input = StagingInput::from(candidate);
    let layout = detect_layout(&root, &input)?;
    let mut markers = Vec::new();
    for phase in windows_journal_policy::PHASES {
        for pending in [false, true] {
            let name = windows_journal_policy::name(phase, pending)?;
            if entry_exists(&root.operation, &name)? {
                markers.push(name);
            }
        }
    }
    let names = markers.iter().map(OsStr::new).collect::<Vec<_>>();
    require_inventory(&root, layout, &names)?;
    let location = if layout == Layout::Published {
        CandidateLocation::Installed
    } else {
        CandidateLocation::Staged
    };
    let retained = root.candidate(&input, location)?;
    require_inventory(&root, layout, &names)?;
    if detect_layout(&root, &input)? != layout {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok((retained.into_stage(root, &input)?, layout, markers))
}

fn detect_layout(
    root: &RecoveryRoot,
    input: &StagingInput<'_>,
) -> Result<Layout, InstallerStageError> {
    let destination = root
        .destination
        .directory()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    match (
        entry_exists(&root.operation, STAGED_EXECUTABLE)?,
        entry_exists(&root.operation, RETAINED_PRIOR)?,
        entry_exists(destination, input.executable_name)?,
    ) {
        (true, false, true) => Ok(Layout::Original),
        (true, true, false) => Ok(Layout::Gap),
        (false, true, true) => Ok(Layout::Published),
        _ => Err(InstallerStageError::RecoveryRequired),
    }
}

fn require_inventory(
    root: &RecoveryRoot,
    layout: Layout,
    markers: &[&OsStr],
) -> Result<(), InstallerStageError> {
    root.revalidate()?;
    crate::windows_staging::require_exact_inventory(
        &root.operation,
        &super::windows_pair::inventory(layout, markers),
    )
}
