//! Recover placement without probing or granting verified/committed authority.

use super::{JournaledPair, WriteBoundary, policy};
use crate::InstallerStageError;
use crate::upgrade_transaction::windows_pair::Layout;
use crate::upgrade_transaction::windows_recovery_plan::{JournalStage, RecoveryStep};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::upgrade_transaction) enum Disposition {
    Prepared,
    NeedsProbe,
    Restored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::upgrade_transaction) enum Boundary {
    Before(RecoveryStep),
    After(RecoveryStep),
    Journal(JournalStage, WriteBoundary),
}

impl<'a> JournaledPair<'a> {
    pub(in crate::upgrade_transaction) fn recover_placement(
        self,
    ) -> Result<(Self, Disposition), InstallerStageError> {
        self.recover_placement_with_hook(|_| Ok(()))
    }

    pub(in crate::upgrade_transaction) fn recover_placement_with_hook(
        mut self,
        mut boundary: impl FnMut(Boundary) -> Result<(), InstallerStageError>,
    ) -> Result<(Self, Disposition), InstallerStageError> {
        // At most: intent, withdrawal, restoration, terminal record, then inspection.
        for _ in 0..5 {
            self.revalidate()?;
            let step = policy::placement_recovery_step(
                self.pair.layout(),
                &self.journal.phases(false),
                &self.journal.phases(true),
            )?;
            let disposition = match step {
                RecoveryStep::Prepared => Some(Disposition::Prepared),
                RecoveryStep::ProbeCandidate => Some(Disposition::NeedsProbe),
                RecoveryStep::Restored => Some(Disposition::Restored),
                _ => None,
            };
            if let Some(disposition) = disposition {
                if disposition == Disposition::Restored {
                    self.sync_markers()?;
                    self.pair.sync_pair(&self.journal.names())?;
                    self.revalidate()?;
                }
                return Ok((self, disposition));
            }
            boundary(Boundary::Before(step))?;
            self = match step {
                RecoveryStep::RecordRestorationIntent | RecoveryStep::CompleteRestoration => {
                    let phase = if step == RecoveryStep::RecordRestorationIntent {
                        JournalStage::RestoreRequested
                    } else {
                        JournalStage::RolledBack
                    };
                    self.record_with_hook(phase, |point| boundary(Boundary::Journal(phase, point)))?
                }
                RecoveryStep::WithdrawCandidate => self.move_to(Layout::Gap)?,
                RecoveryStep::RestorePrior => self.move_to(Layout::Original)?,
                _ => return Err(InstallerStageError::RecoveryRequired),
            };
            boundary(Boundary::After(step))?;
        }
        Err(InstallerStageError::RecoveryRequired)
    }
}
