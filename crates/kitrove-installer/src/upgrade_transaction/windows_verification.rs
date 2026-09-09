//! Fresh contained probing is required even when retained history says committed.

use super::recovery::{Boundary as RecoveryBoundary, Disposition};
use super::{JournaledPair, WriteBoundary, policy};
use crate::upgrade_transaction::windows_pair::Layout;
use crate::upgrade_transaction::windows_recovery_plan::JournalStage;
use crate::{InstalledApplication, InstallerStageError};
use std::path::Path;

/// Constructible only here, after a matching probe and full pair revalidation.
pub(super) struct FreshProbe {
    binding: policy::Binding,
}

impl FreshProbe {
    pub(super) fn require_binding(
        &self,
        binding: policy::Binding,
    ) -> Result<(), InstallerStageError> {
        if self.binding.bytes(JournalStage::Verified)? != binding.bytes(JournalStage::Verified)? {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::upgrade_transaction) enum Boundary {
    BeforeMove(Layout),
    AfterMove(Layout),
    BeforeProbe,
    AfterProbe,
    Journal(JournalStage, WriteBoundary),
    Recovery(RecoveryBoundary),
}

impl JournaledPair<'_> {
    pub(in crate::upgrade_transaction) fn finish(
        self,
    ) -> Result<InstalledApplication, InstallerStageError> {
        self.finish_with_hooks(crate::verify_installed_application, |_| Ok(()))
    }

    pub(in crate::upgrade_transaction) fn finish_with_hooks(
        self,
        verify: impl FnOnce(
            &Path,
            &semver::Version,
        ) -> Result<kitrove_model::ContentHash, InstallerStageError>,
        mut boundary: impl FnMut(Boundary) -> Result<(), InstallerStageError>,
    ) -> Result<InstalledApplication, InstallerStageError> {
        let (mut owner, disposition) =
            self.recover_placement_with_hook(|point| boundary(Boundary::Recovery(point)))?;
        match disposition {
            Disposition::Restored => return Err(InstallerStageError::VerificationFailed),
            Disposition::Prepared => owner = owner.publish_prepared(&mut boundary)?,
            Disposition::NeedsProbe => {}
        }
        if !owner
            .journal
            .phases(false)
            .contains(&JournalStage::Published)
        {
            owner = owner.record_with_hook(JournalStage::Published, |point| {
                boundary(Boundary::Journal(JournalStage::Published, point))
            })?;
        }
        owner.sync_markers()?;
        owner.pair.sync_pair(&owner.journal.names())?;
        boundary(Boundary::BeforeProbe)?;
        owner.revalidate()?;
        let installed = owner.pair.candidate_metadata()?;
        let observed = verify(&installed.path, installed.manifest.release_version());
        boundary(Boundary::AfterProbe)?;
        owner.revalidate()?;
        if observed.as_ref() != Ok(owner.pair.candidate_content_hash()) {
            owner = owner.record_with_hook(JournalStage::RestoreRequested, |point| {
                boundary(Boundary::Journal(JournalStage::RestoreRequested, point))
            })?;
            let (_, disposition) =
                owner.recover_placement_with_hook(|point| boundary(Boundary::Recovery(point)))?;
            if disposition != Disposition::Restored {
                return Err(InstallerStageError::RecoveryRequired);
            }
            return Err(InstallerStageError::VerificationFailed);
        }
        let proof = FreshProbe {
            binding: owner.journal.binding,
        };
        for phase in [JournalStage::Verified, JournalStage::Committed] {
            if !owner.journal.phases(false).contains(&phase) {
                owner = owner.record_impl(
                    phase,
                    |point| boundary(Boundary::Journal(phase, point)),
                    Some(&proof),
                )?;
            }
            owner.revalidate()?;
        }
        owner.sync_markers()?;
        owner.pair.sync_pair(&owner.journal.names())?;
        owner.revalidate()?;
        Ok(installed)
    }

    /// Initial replacement and explicit recovery of untouched preparation share one
    /// publication path. move_to independently rejects restoration or pending history.
    fn publish_prepared(
        mut self,
        mut boundary: impl FnMut(Boundary) -> Result<(), InstallerStageError>,
    ) -> Result<Self, InstallerStageError> {
        for next in [Layout::Gap, Layout::Published] {
            boundary(Boundary::BeforeMove(next))?;
            self = self.move_to(next)?;
            boundary(Boundary::AfterMove(next))?;
            self.revalidate()?;
            if next == Layout::Gap {
                self = self.record_with_hook(JournalStage::PriorRetained, |point| {
                    boundary(Boundary::Journal(JournalStage::PriorRetained, point))
                })?;
            }
        }
        Ok(self)
    }
}
