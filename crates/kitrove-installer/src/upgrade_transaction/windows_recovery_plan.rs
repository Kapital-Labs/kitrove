//! Pure recovery decisions for the Windows two-move transaction.
//!
//! These observations are not filesystem capabilities or parsed-journal authority.
//! The executor must independently authenticate both releases, validate the exact
//! inventory and canonical journal prefix, and hold/revalidate state and installer
//! guards before using a decision. Unknown evidence never authorizes a move.

use crate::InstallerStageError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Layout {
    Original,
    Gap,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileRole {
    Absent,
    Candidate,
    Prior,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalStage {
    Prepared,
    PriorRetained,
    Published,
    Verified,
    Committed,
    RestoreRequested,
    RolledBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryStep {
    Prepared,
    RecordRestorationIntent,
    RestorePrior,
    WithdrawCandidate,
    ProbeCandidate,
    CompleteRestoration,
    Restored,
}

/// Choose one step, never a whole sequence: every completed step requires fresh
/// observations. Positional roles distinguish absent files from unreadable files.
pub(super) fn next_step_for_layout(
    layout: Layout,
    journal: JournalStage,
) -> Result<RecoveryStep, InstallerStageError> {
    use FileRole::*;
    let (destination, candidate, prior) = match layout {
        Layout::Original => (Prior, Candidate, Absent),
        Layout::Gap => (Absent, Candidate, Prior),
        Layout::Published => (Candidate, Absent, Prior),
    };
    next_step(destination, candidate, prior, journal)
}

/// Raw observation policy also refuses unknown or duplicated executable roles.
pub(super) fn next_step(
    destination: FileRole,
    staged_candidate: FileRole,
    retained_prior: FileRole,
    journal: JournalStage,
) -> Result<RecoveryStep, InstallerStageError> {
    use FileRole::{Absent, Candidate, Prior};
    use JournalStage::*;
    let step = match (destination, staged_candidate, retained_prior, journal) {
        (Prior, Candidate, Absent, Prepared) => RecoveryStep::Prepared,
        // A prior move may have completed before its retention marker was durable.
        (Absent, Candidate, Prior, Prepared | PriorRetained) => {
            RecoveryStep::RecordRestorationIntent
        }
        (Absent, Candidate, Prior, RestoreRequested) => RecoveryStep::RestorePrior,
        // PriorRetained must be durable before candidate publication is attempted.
        (Candidate, Absent, Prior, PriorRetained | Published | Verified | Committed) => {
            RecoveryStep::ProbeCandidate
        }
        // A failed probe's durable intent wins even if the candidate is still installed.
        (Candidate, Absent, Prior, RestoreRequested) => RecoveryStep::WithdrawCandidate,
        (Prior, Candidate, Absent, RestoreRequested) => RecoveryStep::CompleteRestoration,
        (Prior, Candidate, Absent, RolledBack) => RecoveryStep::Restored,
        _ => return Err(InstallerStageError::RecoveryRequired),
    };
    Ok(step)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_layout_and_stage_is_closed_and_both_releases_are_preserved() {
        use FileRole::*;
        use JournalStage::*;
        let mut accepted = 0;
        for destination in [Absent, Candidate, Prior, Unknown] {
            for staged in [Absent, Candidate, Prior, Unknown] {
                for retained in [Absent, Candidate, Prior, Unknown] {
                    for journal in [
                        Prepared,
                        PriorRetained,
                        Published,
                        Verified,
                        Committed,
                        RestoreRequested,
                        RolledBack,
                    ] {
                        let result = next_step(destination, staged, retained, journal);
                        let expected = match (destination, staged, retained) {
                            (Prior, Candidate, Absent) => {
                                matches!(journal, Prepared | RestoreRequested | RolledBack)
                            }
                            (Absent, Candidate, Prior) => {
                                matches!(journal, Prepared | PriorRetained | RestoreRequested)
                            }
                            (Candidate, Absent, Prior) => matches!(
                                journal,
                                PriorRetained | Published | Verified | Committed | RestoreRequested
                            ),
                            _ => false,
                        };
                        assert_eq!(
                            result.is_ok(),
                            expected,
                            "{destination:?} {staged:?} {retained:?} {journal:?}"
                        );
                        if result.is_ok() {
                            accepted += 1;
                            let roles = [destination, staged, retained];
                            assert_eq!(roles.iter().filter(|&&role| role == Candidate).count(), 1);
                            assert_eq!(roles.iter().filter(|&&role| role == Prior).count(), 1);
                        } else {
                            assert_eq!(result, Err(InstallerStageError::RecoveryRequired));
                        }
                    }
                }
            }
        }
        assert_eq!(accepted, 11);
    }

    #[test]
    fn interrupted_gap_restores_prior_and_never_publishes_candidate() {
        use FileRole::*;
        for journal in [JournalStage::Prepared, JournalStage::PriorRetained] {
            assert_eq!(
                next_step(Absent, Candidate, Prior, journal),
                Ok(RecoveryStep::RecordRestorationIntent)
            );
        }
        assert_eq!(
            next_step(Absent, Candidate, Prior, JournalStage::RestoreRequested),
            Ok(RecoveryStep::RestorePrior)
        );
        assert_eq!(
            next_step(Prior, Candidate, Absent, JournalStage::RestoreRequested),
            Ok(RecoveryStep::CompleteRestoration)
        );
        assert_eq!(
            next_step(Prior, Candidate, Absent, JournalStage::RolledBack),
            Ok(RecoveryStep::Restored)
        );
    }

    #[test]
    fn restoration_intent_prevents_reprobing_after_a_second_interruption() {
        use FileRole::*;
        assert_eq!(
            next_step(Candidate, Absent, Prior, JournalStage::Committed),
            Ok(RecoveryStep::ProbeCandidate)
        );
        assert_eq!(
            next_step(Candidate, Absent, Prior, JournalStage::RestoreRequested),
            Ok(RecoveryStep::WithdrawCandidate)
        );
        assert_eq!(
            next_step(Absent, Candidate, Prior, JournalStage::RestoreRequested),
            Ok(RecoveryStep::RestorePrior)
        );
        assert_eq!(
            next_step(Candidate, Absent, Prior, JournalStage::Prepared),
            Err(InstallerStageError::RecoveryRequired)
        );
    }
}
