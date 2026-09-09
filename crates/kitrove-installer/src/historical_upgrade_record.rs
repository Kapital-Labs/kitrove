use super::*;
use crate::record::history::HistoricalOperationRecord;
use kitrove_release_provenance::{
    AuthenticatedApplicationExecutable, AuthenticatedRecoveryMaterial,
};

/// Release-bound historical data; never a live replacement precondition or preparation.
pub(crate) struct HistoricalUpgradeRecord {
    record: UpgradeRecord,
}

impl HistoricalUpgradeRecord {
    pub(crate) fn parse(
        bytes: &[u8],
        operation: &HistoricalOperationRecord,
        candidate: &AuthenticatedApplicationExecutable,
        prior: &AuthenticatedRecoveryMaterial,
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        if bytes.is_empty() || bytes.len() > MAX_UPGRADE_RECORD_BYTES {
            return Err(InstallerStageError::RecoveryRequired);
        }
        operation.require_release(&StagingInput::from(candidate))?;
        if !direction.permits(candidate.manifest(), prior.executable().manifest()) {
            return Err(InstallerStageError::IncompatibleUpgrade);
        }
        let saved: UpgradeRecordData =
            serde_json::from_slice(bytes).map_err(|_| InstallerStageError::RecoveryRequired)?;
        let record = UpgradeRecord::from_record_digest(
            operation.record_sha256()?,
            &StagingInput::from(prior.executable()),
            saved.prior_identity,
            saved.rollback_kit,
            saved.state_roots,
            direction,
        )?;
        if record.to_json()? != bytes {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(Self { record })
    }

    pub(crate) fn prior_identity(&self) -> NativeFileIdentity {
        self.record.0.prior_identity
    }
    pub(crate) fn kit_identities(&self) -> RollbackKitIdentities {
        self.record.0.rollback_kit
    }
    pub(crate) fn binding_digest(&self) -> Result<[u8; 32], InstallerStageError> {
        Ok(Sha256::digest(self.record.to_json()?).into())
    }
}
