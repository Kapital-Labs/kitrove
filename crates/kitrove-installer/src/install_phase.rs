use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::record::{encode_hex, is_lower_hex};
use crate::staging_policy::{OPERATION_RECORD, STAGED_EXECUTABLE};
use crate::{InstallerOperationRecord, InstallerStageError, NativeFileIdentity};

pub(crate) const REPLACED_RECORD: &str = "replaced.json";
pub(crate) const VERIFIED_RECORD: &str = "verified.json";
pub(crate) const COMMITTED_RECORD: &str = "committed.json";
pub(crate) const ROLLED_BACK_RECORD: &str = "rolled-back.json";
pub(crate) const MAX_PHASE_RECORD_BYTES: usize = 1024;
pub(crate) const FAILED_EXECUTABLE: &str = "failed-application";
const INSTALL_PHASE_RECORD_SCHEMA: u32 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InstallPhase {
    Replaced,
    Verified,
    Committed,
    RolledBack,
}

impl InstallPhase {
    pub(crate) fn is_bounded_unique_set(phases: &[Self]) -> bool {
        phases.len() <= Self::all().len()
            && phases
                .iter()
                .enumerate()
                .all(|(index, phase)| !phases[..index].contains(phase))
    }

    pub(crate) const fn file_name(self) -> &'static str {
        match self {
            Self::Replaced => REPLACED_RECORD,
            Self::Verified => VERIFIED_RECORD,
            Self::Committed => COMMITTED_RECORD,
            Self::RolledBack => ROLLED_BACK_RECORD,
        }
    }

    pub(crate) const fn pending_file_name(self) -> &'static str {
        match self {
            Self::Replaced => "replaced.pending",
            Self::Verified => "verified.pending",
            Self::Committed => "committed.pending",
            Self::RolledBack => "rolled-back.pending",
        }
    }

    pub(crate) const fn all() -> &'static [Self] {
        &[
            Self::Replaced,
            Self::Verified,
            Self::Committed,
            Self::RolledBack,
        ]
    }

    pub(crate) const fn chain(self) -> &'static [Self] {
        match self {
            Self::Replaced => &[Self::Replaced],
            Self::Verified => &[Self::Replaced, Self::Verified],
            Self::Committed => &[Self::Replaced, Self::Verified, Self::Committed],
            Self::RolledBack => &[Self::Replaced, Self::RolledBack],
        }
    }

    #[cfg(unix)]
    pub(crate) fn inventory(self) -> Vec<&'static OsStr> {
        match self {
            Self::Replaced => InstallRecoveryPhase::Replaced.inventory(),
            Self::Verified => InstallRecoveryPhase::Verified.inventory(),
            Self::Committed => InstallRecoveryPhase::Committed.inventory(),
            Self::RolledBack => InstallRecoveryPhase::RolledBack.inventory(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstallRecoveryPhase {
    Prepared,
    #[cfg(windows)]
    ReplacedUnrecorded,
    Replaced,
    Verified,
    Committed,
    #[cfg(unix)]
    RollbackHandoff,
    #[cfg(unix)]
    RollingBack,
    #[cfg(windows)]
    RolledBackUnrecorded,
    RolledBack,
}

impl InstallRecoveryPhase {
    pub(crate) const fn marker_phases(self) -> &'static [InstallPhase] {
        match self {
            Self::Prepared => &[],
            #[cfg(windows)]
            Self::ReplacedUnrecorded => &[],
            #[cfg(windows)]
            Self::RolledBackUnrecorded => InstallPhase::Replaced.chain(),
            Self::Replaced => InstallPhase::Replaced.chain(),
            #[cfg(unix)]
            Self::RollbackHandoff | Self::RollingBack => InstallPhase::Replaced.chain(),
            Self::Verified => InstallPhase::Verified.chain(),
            Self::Committed => InstallPhase::Committed.chain(),
            Self::RolledBack => InstallPhase::RolledBack.chain(),
        }
    }

    pub(crate) fn inventory(self) -> Vec<&'static OsStr> {
        let mut names = vec![OsStr::new(OPERATION_RECORD)];
        #[cfg(unix)]
        let retains_staged_executable = true;
        #[cfg(windows)]
        let retains_staged_executable = matches!(self, Self::Prepared);
        if retains_staged_executable {
            names.push(OsStr::new(STAGED_EXECUTABLE));
        }
        names.extend(
            self.marker_phases()
                .iter()
                .map(|phase| OsStr::new(phase.file_name())),
        );
        #[cfg(unix)]
        let failed = matches!(
            self,
            Self::RollbackHandoff | Self::RollingBack | Self::RolledBack
        );
        #[cfg(windows)]
        let failed = matches!(self, Self::RolledBack | Self::RolledBackUnrecorded);
        if failed {
            names.push(OsStr::new(FAILED_EXECUTABLE));
        }
        names
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DetectedInstallPhase {
    Prepared,
    ReplacedUnrecorded,
    Replaced,
    Verified,
    Committed,
    #[cfg(unix)]
    RollbackHandoff,
    RollingBack,
    RolledBack,
}

impl DetectedInstallPhase {
    pub(crate) const fn recovery_phase(self) -> InstallRecoveryPhase {
        match self {
            #[cfg(unix)]
            Self::Prepared | Self::ReplacedUnrecorded => InstallRecoveryPhase::Prepared,
            #[cfg(windows)]
            Self::Prepared => InstallRecoveryPhase::Prepared,
            #[cfg(windows)]
            Self::ReplacedUnrecorded => InstallRecoveryPhase::ReplacedUnrecorded,
            Self::Replaced => InstallRecoveryPhase::Replaced,
            Self::Verified => InstallRecoveryPhase::Verified,
            Self::Committed => InstallRecoveryPhase::Committed,
            #[cfg(unix)]
            Self::RollbackHandoff => InstallRecoveryPhase::RollbackHandoff,
            #[cfg(unix)]
            Self::RollingBack => InstallRecoveryPhase::RollingBack,
            #[cfg(windows)]
            Self::RollingBack => InstallRecoveryPhase::RolledBackUnrecorded,
            Self::RolledBack => InstallRecoveryPhase::RolledBack,
        }
    }

    /// Validates extra leaves relative to the complete chain implied by this phase.
    /// Callers must independently bind the bytes and prove the implied chain exists.
    pub(crate) fn require_journal_order(
        self,
        pending: &[InstallPhase],
        prior: &[InstallPhase],
    ) -> Result<(), InstallerStageError> {
        let base = self.recovery_phase().marker_phases();
        let complete = |phase| base.contains(&phase) || prior.contains(&phase);
        let restored = self.is_restored();
        if !InstallPhase::is_bounded_unique_set(pending)
            || !InstallPhase::is_bounded_unique_set(prior)
            || prior.iter().any(|phase| {
                base.contains(phase)
                    || !restored
                    || !matches!(phase, InstallPhase::Verified | InstallPhase::Committed)
            })
            || (complete(InstallPhase::Committed) && !complete(InstallPhase::Verified))
            || pending.iter().any(|phase| {
                complete(*phase)
                    || match phase {
                        InstallPhase::Replaced => self != Self::ReplacedUnrecorded,
                        InstallPhase::Verified => {
                            !complete(InstallPhase::Replaced)
                                || !(restored || self == Self::Replaced)
                        }
                        InstallPhase::Committed => {
                            !complete(InstallPhase::Verified)
                                || !(restored || self == Self::Verified)
                        }
                        InstallPhase::RolledBack => self != Self::RollingBack,
                    }
            })
        {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(())
    }

    pub(crate) const fn is_restored(self) -> bool {
        match self {
            Self::RollingBack | Self::RolledBack => true,
            #[cfg(unix)]
            Self::RollbackHandoff => true,
            _ => false,
        }
    }
}

#[cfg(unix)]
pub(crate) fn classify_operation(
    observed: &[OsString],
    installed: bool,
    failed: bool,
) -> Result<DetectedInstallPhase, InstallerStageError> {
    let matches = |phase: InstallRecoveryPhase| {
        let mut expected = phase
            .inventory()
            .into_iter()
            .map(OsStr::to_owned)
            .collect::<Vec<_>>();
        expected.sort();
        observed == expected
    };
    match (installed, failed) {
        (false, false) if matches(InstallRecoveryPhase::Prepared) => {
            Ok(DetectedInstallPhase::Prepared)
        }
        (true, false) if matches(InstallRecoveryPhase::Prepared) => {
            Ok(DetectedInstallPhase::ReplacedUnrecorded)
        }
        (true, false) if matches(InstallRecoveryPhase::Replaced) => {
            Ok(DetectedInstallPhase::Replaced)
        }
        (true, false) if matches(InstallRecoveryPhase::Verified) => {
            Ok(DetectedInstallPhase::Verified)
        }
        (true, false) if matches(InstallRecoveryPhase::Committed) => {
            Ok(DetectedInstallPhase::Committed)
        }
        (false, true) if matches(InstallRecoveryPhase::RollingBack) => {
            Ok(DetectedInstallPhase::RollingBack)
        }
        (true, true) if matches(InstallRecoveryPhase::RollbackHandoff) => {
            Ok(DetectedInstallPhase::RollbackHandoff)
        }
        (false, true) if matches(InstallRecoveryPhase::RolledBack) => {
            Ok(DetectedInstallPhase::RolledBack)
        }
        _ => Err(InstallerStageError::RecoveryRequired),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallPhaseRecord {
    schema: u32,
    phase: InstallPhase,
    operation_id: String,
    prepared_record_sha256: String,
    installed_identity: NativeFileIdentity,
    executable_sha256: String,
}

impl InstallPhaseRecord {
    /// Recorded identity only; parsing does not establish current filesystem authority.
    pub(crate) const fn recorded_installed_identity(&self) -> NativeFileIdentity {
        self.installed_identity
    }

    pub(crate) fn new(
        phase: InstallPhase,
        prepared: &InstallerOperationRecord,
        installed_identity: NativeFileIdentity,
        executable_sha256: [u8; 32],
    ) -> Result<Self, InstallerStageError> {
        let prepared_bytes = prepared
            .to_json()
            .map_err(|_| InstallerStageError::UnsafeState)?;
        Ok(Self {
            schema: INSTALL_PHASE_RECORD_SCHEMA,
            phase,
            operation_id: prepared.operation_id().to_owned(),
            prepared_record_sha256: encode_hex(&Sha256::digest(&prepared_bytes)),
            installed_identity,
            executable_sha256: encode_hex(&executable_sha256),
        })
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>, InstallerStageError> {
        serde_json::to_vec(self).map_err(|_| InstallerStageError::WriteFailed)
    }

    pub(crate) fn parse_canonical(bytes: &[u8]) -> Result<Self, InstallerStageError> {
        if bytes.is_empty() || bytes.len() > MAX_PHASE_RECORD_BYTES {
            return Err(InstallerStageError::UnsafeState);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| InstallerStageError::UnsafeState)?;
        if record.schema != INSTALL_PHASE_RECORD_SCHEMA
            || record.operation_id.is_empty()
            || !is_lower_hex(&record.prepared_record_sha256, 64)
            || !record.installed_identity.is_valid()
            || !is_lower_hex(&record.executable_sha256, 64)
            || record
                .to_json()
                .map_err(|_| InstallerStageError::UnsafeState)?
                != bytes
        {
            return Err(InstallerStageError::UnsafeState);
        }
        Ok(record)
    }

    pub(crate) fn require_matches(&self, expected: &Self) -> Result<(), InstallerStageError> {
        if self == expected {
            Ok(())
        } else {
            Err(InstallerStageError::UnsafeState)
        }
    }
}

#[cfg(test)]
mod journal_order_tests {
    use super::*;

    #[test]
    fn journal_order_exhausts_phase_and_extra_leaf_combinations() {
        use DetectedInstallPhase as D;
        let phases = [
            D::Prepared,
            D::ReplacedUnrecorded,
            D::Replaced,
            D::Verified,
            D::Committed,
            D::RollingBack,
            D::RolledBack,
            #[cfg(unix)]
            D::RollbackHandoff,
        ];
        let leaves = |mask| {
            InstallPhase::all()
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, phase)| *phase)
                .collect::<Vec<_>>()
        };
        for phase in phases {
            for prior in 0..16 {
                for pending in 0..16 {
                    let expected = match phase {
                        D::Prepared | D::Committed => prior == 0 && pending == 0,
                        D::ReplacedUnrecorded => prior == 0 && matches!(pending, 0 | 1),
                        D::Replaced => prior == 0 && matches!(pending, 0 | 2),
                        D::Verified => prior == 0 && matches!(pending, 0 | 4),
                        _ => {
                            let rollback_pending = pending & 8 != 0;
                            (!rollback_pending || phase == D::RollingBack)
                                && match prior {
                                    0 => matches!(pending & !8, 0 | 2),
                                    2 => matches!(pending & !8, 0 | 4),
                                    6 => pending & !8 == 0,
                                    _ => false,
                                }
                        }
                    };
                    assert_eq!(
                        phase
                            .require_journal_order(&leaves(pending), &leaves(prior))
                            .is_ok(),
                        expected,
                        "{phase:?}: prior={prior}, pending={pending}"
                    );
                }
            }
        }
        assert!(
            D::RolledBack
                .require_journal_order(&[], &[InstallPhase::Verified; 2])
                .is_err()
        );
        assert!(
            D::Replaced
                .require_journal_order(&[InstallPhase::Verified; 2], &[])
                .is_err()
        );
        assert!(
            D::Replaced
                .require_journal_order(&[InstallPhase::Verified; 5], &[])
                .is_err()
        );
        assert!(
            D::RolledBack
                .require_journal_order(&[], &[InstallPhase::Verified; 5])
                .is_err()
        );
    }
}
