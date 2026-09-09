use super::HistoricalOperationRecord;
use crate::install_phase::{DetectedInstallPhase, InstallPhase};
use crate::{InstallerStageError, NativeFileIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistoricalInstallOutcome {
    Committed,
    RolledBack,
}

/// Validated journal data, not proof of filesystem ownership, durability or execution.
pub(crate) struct HistoricalInstallJournal {
    outcome: HistoricalInstallOutcome,
    installed_identity: NativeFileIdentity,
}

impl HistoricalInstallJournal {
    pub(crate) const fn outcome(&self) -> HistoricalInstallOutcome {
        self.outcome
    }

    pub(crate) const fn recorded_installed_identity(&self) -> NativeFileIdentity {
        self.installed_identity
    }

    /// The caller supplies the complete bounded leaf inventory, including pending files.
    /// Saved identities remain inert; this function does not open paths or finish writes.
    pub(crate) fn parse(
        operation: &HistoricalOperationRecord,
        complete: &[(InstallPhase, &[u8])],
        pending: &[(InstallPhase, &[u8])],
    ) -> Result<Self, InstallerStageError> {
        let fail = || InstallerStageError::RecoveryRequired;
        if complete.len() > InstallPhase::all().len() || pending.len() > InstallPhase::all().len() {
            return Err(fail());
        }
        let mut phases = Vec::new();
        let mut installed_identity = None;
        for &(phase, bytes) in complete {
            if phases.contains(&phase) {
                return Err(fail());
            }
            phases.push(phase);
            let identity = operation.validate_phase_record(bytes, phase)?;
            if installed_identity.is_some_and(|expected| expected != identity) {
                return Err(fail());
            }
            installed_identity = Some(identity);
        }
        let installed_identity = installed_identity.ok_or_else(fail)?;
        let (outcome, detected) = if phases.contains(&InstallPhase::RolledBack) {
            (
                HistoricalInstallOutcome::RolledBack,
                DetectedInstallPhase::RolledBack,
            )
        } else if phases.contains(&InstallPhase::Committed) {
            (
                HistoricalInstallOutcome::Committed,
                DetectedInstallPhase::Committed,
            )
        } else {
            return Err(fail());
        };
        let required = detected.recovery_phase().marker_phases();
        if required.iter().any(|phase| !phases.contains(phase)) {
            return Err(fail());
        }
        let prior = phases
            .into_iter()
            .filter(|phase| !required.contains(phase))
            .collect::<Vec<_>>();
        let pending_phases = pending.iter().map(|(phase, _)| *phase).collect::<Vec<_>>();
        detected.require_journal_order(&pending_phases, &prior)?;
        for &(phase, bytes) in pending {
            let expected = operation.expected_phase_bytes(phase, installed_identity)?;
            // Empty or fully written unpublished records can both be valid interrupted writes.
            if !expected.starts_with(bytes) {
                return Err(fail());
            }
        }
        Ok(Self {
            outcome,
            installed_identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_journal_requires_a_complete_consistent_chain() {
        let (_destination, staged, _path) = crate::test_support::prepared_stage(b"candidate");
        let input = crate::test_support::staging_input(b"candidate");
        let operation = HistoricalOperationRecord::parse_release_bound(
            &staged.record.to_json().unwrap(),
            staged.record.operation_id(),
            &input,
        )
        .unwrap();
        let identity = *staged.record.staged_identity();
        let bytes = InstallPhase::all()
            .iter()
            .map(|&phase| operation.expected_phase_bytes(phase, identity).unwrap())
            .collect::<Vec<_>>();
        let all = InstallPhase::all()
            .iter()
            .zip(&bytes)
            .map(|(&phase, bytes)| (phase, bytes.as_slice()))
            .collect::<Vec<_>>();
        // Exhaust every complete-leaf subset. Ordering of the supplied inventory is irrelevant.
        for mask in 0..16 {
            let mut selected = all
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, entry)| *entry)
                .collect::<Vec<_>>();
            for _ in 0..2 {
                let parsed = HistoricalInstallJournal::parse(&operation, &selected, &[]);
                let expected = match mask {
                    7 => Some(HistoricalInstallOutcome::Committed),
                    9 | 11 | 15 => Some(HistoricalInstallOutcome::RolledBack),
                    _ => None,
                };
                assert_eq!(
                    parsed.as_ref().ok().map(HistoricalInstallJournal::outcome),
                    expected
                );
                if let Ok(journal) = parsed {
                    assert_eq!(journal.recorded_installed_identity(), identity);
                }
                selected.reverse();
            }
        }
        let duplicate = [all[0], all[0], all[1], all[2]];
        assert!(HistoricalInstallJournal::parse(&operation, &duplicate, &[]).is_err());
        assert!(HistoricalInstallJournal::parse(&operation, &[all[0]; 5], &[]).is_err());
        let other = operation
            .expected_phase_bytes(InstallPhase::Committed, *staged.record.operation_identity())
            .unwrap();
        assert!(
            HistoricalInstallJournal::parse(
                &operation,
                &[all[0], all[1], (InstallPhase::Committed, &other)],
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_journal_preserves_only_legal_pending_prefixes() {
        let (_destination, staged, _path) = crate::test_support::prepared_stage(b"candidate");
        let input = crate::test_support::staging_input(b"candidate");
        let operation = HistoricalOperationRecord::parse_release_bound(
            &staged.record.to_json().unwrap(),
            staged.record.operation_id(),
            &input,
        )
        .unwrap();
        let bytes = InstallPhase::all()
            .iter()
            .map(|&phase| {
                operation
                    .expected_phase_bytes(phase, *staged.record.staged_identity())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let all = InstallPhase::all()
            .iter()
            .zip(&bytes)
            .map(|(&phase, bytes)| (phase, bytes.as_slice()))
            .collect::<Vec<_>>();
        for (complete, phase, canonical) in [
            (vec![all[0], all[3]], InstallPhase::Verified, &bytes[1]),
            (
                vec![all[0], all[1], all[3]],
                InstallPhase::Committed,
                &bytes[2],
            ),
        ] {
            for length in 0..=canonical.len() {
                HistoricalInstallJournal::parse(
                    &operation,
                    &complete,
                    &[(phase, &canonical[..length])],
                )
                .unwrap();
            }
            let mut altered = canonical.clone();
            altered.push(b'\n');
            assert!(
                HistoricalInstallJournal::parse(&operation, &complete, &[(phase, &altered)])
                    .is_err()
            );
            altered[0] = b'!';
            assert!(
                HistoricalInstallJournal::parse(&operation, &complete, &[(phase, &altered[..1])])
                    .is_err()
            );
            assert!(
                HistoricalInstallJournal::parse(
                    &operation,
                    &complete,
                    &[(phase, &[]), (phase, &[])]
                )
                .is_err()
            );
        }
        for &phase in InstallPhase::all() {
            assert!(
                HistoricalInstallJournal::parse(&operation, &all[..3], &[(phase, &[])]).is_err()
            );
        }
        assert!(
            HistoricalInstallJournal::parse(
                &operation,
                &[all[0], all[3]],
                &[(InstallPhase::Committed, &[])]
            )
            .is_err()
        );
        assert!(
            HistoricalInstallJournal::parse(
                &operation,
                &[all[0], all[3]],
                &[(InstallPhase::Verified, &[] as &[u8]); 5]
            )
            .is_err()
        );
    }
}
