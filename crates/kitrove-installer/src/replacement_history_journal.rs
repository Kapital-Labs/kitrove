//! Platform journal formats share historical inspection, never live execution authority.

use super::*;
use crate::staging_policy::{InstallerDirectory, STAGED_EXECUTABLE};

#[cfg(unix)]
pub(super) type Journal = Vec<JournalLeaf>;
#[cfg(windows)]
pub(super) type Journal = crate::upgrade_transaction::windows_journal::RetainedJournal;

pub(super) fn open(
    parent: &InstallerDirectory,
    operation: &HistoricalOperationRecord,
    upgrade: &HistoricalUpgradeRecord,
) -> Result<(Journal, HistoricalInstallOutcome), InstallerStageError> {
    #[cfg(unix)]
    {
        use crate::replacement_phase::{
            MAX_UPGRADE_PHASE_BYTES, ReplacementLayout, encode_phase_evidence, marker_name,
            pending_name, require_phase_order,
        };
        let phases = read_journal(parent, marker_name, pending_name, MAX_UPGRADE_PHASE_BYTES)?;
        let complete = phases
            .iter()
            .filter(|leaf| !leaf.pending)
            .map(|leaf| leaf.phase)
            .collect::<Vec<_>>();
        let pending = phases
            .iter()
            .filter(|leaf| leaf.pending)
            .map(|leaf| leaf.phase)
            .collect::<Vec<_>>();
        let layout = if complete.contains(&InstallPhase::RolledBack) {
            ReplacementLayout::Restored
        } else if complete.contains(&InstallPhase::Committed) {
            ReplacementLayout::Exchanged
        } else {
            return Err(InstallerStageError::RecoveryRequired);
        };
        require_phase_order(&complete, &pending, layout)?;
        for phase in &phases {
            let expected = encode_phase_evidence(
                phase.phase,
                upgrade.binding_digest()?,
                operation.recorded_staged_identity(),
                upgrade.prior_identity(),
            )?;
            if (phase.pending && !expected.starts_with(&phase.leaf.bytes))
                || (!phase.pending && expected != phase.leaf.bytes)
            {
                return Err(InstallerStageError::RecoveryRequired);
            }
        }
        Ok((
            phases,
            match layout {
                ReplacementLayout::Exchanged => HistoricalInstallOutcome::Committed,
                ReplacementLayout::Restored => HistoricalInstallOutcome::RolledBack,
            },
        ))
    }
    #[cfg(windows)]
    {
        use crate::upgrade_transaction::windows_journal_policy::{Binding, terminal_layout};
        use crate::upgrade_transaction::windows_recovery_plan::Layout;
        let phases = Journal::open(
            parent,
            Binding::new(
                upgrade.binding_digest()?,
                operation.recorded_staged_identity(),
                upgrade.prior_identity(),
            )?,
        )?;
        let complete = phases.phases(false);
        let pending = phases.phases(true);
        let layout = match terminal_layout(&complete, &pending)? {
            Layout::Original => HistoricalInstallOutcome::RolledBack,
            Layout::Published => HistoricalInstallOutcome::Committed,
            Layout::Gap => return Err(InstallerStageError::RecoveryRequired),
        };
        Ok((phases, layout))
    }
}

pub(super) fn names(journal: &Journal) -> Vec<&OsStr> {
    #[cfg(unix)]
    {
        journal.iter().map(|leaf| OsStr::new(leaf.name())).collect()
    }
    #[cfg(windows)]
    {
        journal.names()
    }
}

pub(super) fn revalidate(
    journal: &Journal,
    parent: &InstallerDirectory,
) -> Result<(), InstallerStageError> {
    #[cfg(unix)]
    {
        for phase in journal {
            phase
                .leaf
                .require_contents(parent, phase.name(), &phase.leaf.bytes)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        journal.revalidate(parent)
    }
}

pub(super) fn synchronize(
    journal: Journal,
    parent: &InstallerDirectory,
) -> Result<Journal, InstallerStageError> {
    #[cfg(unix)]
    {
        for phase in &journal {
            phase.leaf.sync(parent, phase.name())?;
        }
        Ok(journal)
    }
    #[cfg(windows)]
    {
        journal.synchronize(parent)
    }
}

pub(super) fn displaced_name(layout: HistoricalInstallOutcome) -> &'static str {
    #[cfg(windows)]
    if layout == HistoricalInstallOutcome::Committed {
        return crate::staging_policy::RETAINED_UPGRADE_PRIOR;
    }
    #[cfg(unix)]
    let _ = layout;
    STAGED_EXECUTABLE
}
