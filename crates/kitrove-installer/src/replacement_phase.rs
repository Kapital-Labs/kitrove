use crate::install_phase::InstallPhase;
use crate::record::encode_hex;
use crate::{InstallerStageError, NativeFileIdentity};
use serde::Serialize;

pub(crate) const MAX_UPGRADE_PHASE_BYTES: usize = 2048;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ReplacementLayout {
    Exchanged,
    Restored,
}

#[derive(Serialize)]
struct PhaseEvidence {
    schema: u32,
    phase: InstallPhase,
    preparation_sha256: String,
    candidate_identity: NativeFileIdentity,
    prior_identity: NativeFileIdentity,
}

pub(crate) fn marker_name(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::Replaced => "upgrade-replaced.json",
        InstallPhase::Verified => "upgrade-verified.json",
        InstallPhase::Committed => "upgrade-committed.json",
        InstallPhase::RolledBack => "upgrade-rolled-back.json",
    }
}

pub(crate) fn pending_name(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::Replaced => "upgrade-replaced.pending",
        InstallPhase::Verified => "upgrade-verified.pending",
        InstallPhase::Committed => "upgrade-committed.pending",
        InstallPhase::RolledBack => "upgrade-rolled-back.pending",
    }
}

pub(crate) fn encode_phase_evidence(
    phase: InstallPhase,
    digest: [u8; 32],
    candidate: NativeFileIdentity,
    prior: NativeFileIdentity,
) -> Result<Vec<u8>, InstallerStageError> {
    let bytes = serde_json::to_vec(&PhaseEvidence {
        schema: 1,
        phase,
        preparation_sha256: encode_hex(&digest),
        candidate_identity: candidate,
        prior_identity: prior,
    })
    .map_err(|_| InstallerStageError::RecoveryRequired)?;
    if bytes.len() > MAX_UPGRADE_PHASE_BYTES {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(bytes)
}

pub(crate) fn require_phase_order(
    complete: &[InstallPhase],
    pending: &[InstallPhase],
    layout: ReplacementLayout,
) -> Result<(), InstallerStageError> {
    use InstallPhase::*;
    let has = |phase| complete.contains(&phase);
    if !InstallPhase::is_bounded_unique_set(complete)
        || !InstallPhase::is_bounded_unique_set(pending)
        || complete.iter().any(|phase| pending.contains(phase))
        || (has(Verified) && !has(Replaced))
        || (has(Committed) && !has(Verified))
        || (has(RolledBack) && !has(Replaced))
        || (has(RolledBack) && layout == ReplacementLayout::Exchanged)
        || pending.iter().any(|phase| match phase {
            Replaced => {
                !complete.is_empty() || pending.len() != 1 || layout != ReplacementLayout::Exchanged
            }
            Verified => !has(Replaced),
            Committed => !has(Verified),
            RolledBack => !has(Replaced) || layout != ReplacementLayout::Restored,
        })
    {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(())
}
