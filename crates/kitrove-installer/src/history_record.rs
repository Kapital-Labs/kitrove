use sha2::{Digest as _, Sha256};

use super::*;
use crate::install_phase::{InstallPhase, InstallPhaseRecord};

#[path = "history_journal.rs"]
pub(crate) mod journal;

/// Canonical release-bound history, not evidence of current placement or past execution.
/// The inner record is deliberately private and cannot be converted to live authority.
pub(crate) struct HistoricalOperationRecord {
    record: InstallerOperationRecord,
    executable_sha256: [u8; 32],
}

impl HistoricalOperationRecord {
    pub(crate) fn require_release(
        &self,
        input: &StagingInput<'_>,
    ) -> Result<(), crate::InstallerStageError> {
        self.record
            .matches_release(input)
            .map_err(|_| crate::InstallerStageError::RecoveryRequired)
    }

    pub(crate) fn parse_release_bound(
        bytes: &[u8],
        selected_operation: &str,
        input: &StagingInput<'_>,
    ) -> Result<Self, InvalidInstallerOperationRecord> {
        if !is_operation_id(selected_operation) {
            return Err(InvalidInstallerOperationRecord::INVALID);
        }
        let parsed = InstallerOperationRecord::parse_untrusted(bytes)?;
        if parsed.operation_id() != selected_operation {
            return Err(InvalidInstallerOperationRecord::INVALID);
        }
        // Saved filesystem fields are comparison context only. Keep this temporary
        // representation inside the historical type; never return it as live evidence.
        let record = InstallerOperationRecord(parsed.0);
        record.matches_release(input)?;
        if record
            .to_json()
            .map_err(|_| InvalidInstallerOperationRecord::INVALID)?
            != bytes
        {
            return Err(InvalidInstallerOperationRecord::INVALID);
        }
        Ok(Self {
            record,
            executable_sha256: input.executable_sha256,
        })
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.record.operation_id()
    }

    pub(crate) fn recorded_operation_identity(&self) -> NativeFileIdentity {
        *self.record.operation_identity()
    }

    pub(crate) fn recorded_staged_identity(&self) -> NativeFileIdentity {
        *self.record.staged_identity()
    }

    pub(crate) fn record_sha256(&self) -> Result<[u8; 32], crate::InstallerStageError> {
        let bytes = self
            .record
            .to_json()
            .map_err(|_| crate::InstallerStageError::RecoveryRequired)?;
        Ok(Sha256::digest(bytes).into())
    }

    pub(crate) fn validate_state_record(
        &self,
        bytes: &[u8],
    ) -> Result<(), crate::InstallerStageError> {
        crate::installation_state::parse_historical_state_evidence(bytes, self.record_sha256()?)
            .map(|_| ())
    }

    /// Binds one complete historical phase. The inventory validator must additionally
    /// require a consistent recorded identity and legal order across all phase leaves.
    pub(crate) fn validate_phase_record(
        &self,
        bytes: &[u8],
        phase: InstallPhase,
    ) -> Result<NativeFileIdentity, crate::InstallerStageError> {
        let parsed = InstallPhaseRecord::parse_canonical(bytes)?;
        let identity = parsed.recorded_installed_identity();
        if self.expected_phase_bytes(phase, identity)? != bytes {
            return Err(crate::InstallerStageError::RecoveryRequired);
        }
        Ok(identity)
    }

    /// Reconstructs historical journal bytes without observing or executing a binary.
    pub(crate) fn expected_phase_bytes(
        &self,
        phase: InstallPhase,
        recorded_installed_identity: NativeFileIdentity,
    ) -> Result<Vec<u8>, crate::InstallerStageError> {
        if !recorded_installed_identity.is_valid()
            || !recorded_installed_identity.matches_target(&self.record.0.target)
        {
            return Err(crate::InstallerStageError::RecoveryRequired);
        }
        InstallPhaseRecord::new(
            phase,
            &self.record,
            recorded_installed_identity,
            self.executable_sha256,
        )?
        .to_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_phase_validation_binds_every_field() {
        let (_destination, staged, _path) = crate::test_support::prepared_stage(b"candidate");
        let input = crate::test_support::staging_input(b"candidate");
        let history = HistoricalOperationRecord::parse_release_bound(
            &staged.record.to_json().unwrap(),
            staged.record.operation_id(),
            &input,
        )
        .unwrap();
        let identity = *staged.record.staged_identity();
        for &phase in InstallPhase::all() {
            let bytes = history.expected_phase_bytes(phase, identity).unwrap();
            assert_eq!(
                history.validate_phase_record(&bytes, phase).unwrap(),
                identity
            );
            for &other in InstallPhase::all() {
                if other != phase {
                    assert!(history.validate_phase_record(&bytes, other).is_err());
                }
            }
            let mut noncanonical = bytes.clone();
            noncanonical.push(b'\n');
            assert!(history.validate_phase_record(&noncanonical, phase).is_err());
            for length in 0..bytes.len() {
                assert!(
                    history
                        .validate_phase_record(&bytes[..length], phase)
                        .is_err()
                );
            }
            let mut foreign = staged.record.clone();
            foreign.0.staged_identity = foreign.0.operation_identity;
            let substituted =
                InstallPhaseRecord::new(phase, &foreign, identity, input.executable_sha256)
                    .unwrap()
                    .to_json()
                    .unwrap();
            assert!(history.validate_phase_record(&substituted, phase).is_err());
            let wrong_digest = InstallPhaseRecord::new(phase, &staged.record, identity, [0; 32])
                .unwrap()
                .to_json()
                .unwrap();
            assert!(history.validate_phase_record(&wrong_digest, phase).is_err());
        }
    }

    #[test]
    fn historical_state_validation_requires_canonical_operation_binding() {
        let (_destination, staged, _path) = crate::test_support::prepared_stage(b"candidate");
        let input = crate::test_support::staging_input(b"candidate");
        let history = HistoricalOperationRecord::parse_release_bound(
            &staged.record.to_json().unwrap(),
            staged.record.operation_id(),
            &input,
        )
        .unwrap();
        let digest = encode_hex(&history.record_sha256().unwrap());
        let bytes =
            format!("{{\"schema\":1,\"candidate_record_sha256\":\"{digest}\",\"state_roots\":[]}}")
                .into_bytes();
        history.validate_state_record(&bytes).unwrap();
        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert!(history.validate_state_record(&noncanonical).is_err());
        for length in 0..bytes.len() {
            assert!(history.validate_state_record(&bytes[..length]).is_err());
        }
        let wrong_digest = String::from_utf8(bytes.clone())
            .unwrap()
            .replace(&digest, &"0".repeat(64));
        assert!(
            history
                .validate_state_record(wrong_digest.as_bytes())
                .is_err()
        );
        let wrong_schema = String::from_utf8(bytes)
            .unwrap()
            .replace("\"schema\":1", "\"schema\":2");
        assert!(
            history
                .validate_state_record(wrong_schema.as_bytes())
                .is_err()
        );
        assert!(
            history
                .validate_state_record(&vec![b' '; 128 * 1024 + 1])
                .is_err()
        );
    }

    #[test]
    fn history_is_canonical_release_bound_and_explicitly_selected() {
        let (_destination, staged, _path) = crate::test_support::prepared_stage(b"candidate");
        let input = crate::test_support::staging_input(b"candidate");
        let bytes = staged.record.to_json().unwrap();
        let selected = staged.record.operation_id();
        let history =
            HistoricalOperationRecord::parse_release_bound(&bytes, selected, &input).unwrap();
        assert_eq!(history.operation_id(), selected);
        assert_eq!(
            history.recorded_operation_identity(),
            *staged.record.operation_identity()
        );
        assert_eq!(
            history.record_sha256().unwrap(),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        for &phase in InstallPhase::all() {
            assert_eq!(
                history
                    .expected_phase_bytes(phase, *staged.record.staged_identity())
                    .unwrap(),
                InstallPhaseRecord::new(
                    phase,
                    &staged.record,
                    *staged.record.staged_identity(),
                    input.executable_sha256,
                )
                .unwrap()
                .to_json()
                .unwrap()
            );
        }
        let mut invalid_identity = *staged.record.staged_identity();
        invalid_identity.file_id = [0; 16];
        assert!(
            history
                .expected_phase_bytes(InstallPhase::Committed, invalid_identity)
                .is_err()
        );
        let mut wrong_platform = *staged.record.staged_identity();
        wrong_platform.platform = match wrong_platform.platform {
            NativeFileIdentityPlatform::Unix => NativeFileIdentityPlatform::Windows,
            NativeFileIdentityPlatform::Windows => NativeFileIdentityPlatform::Unix,
        };
        assert!(
            history
                .expected_phase_bytes(InstallPhase::Committed, wrong_platform)
                .is_err()
        );
        for invalid in [
            "",
            "../operation",
            "A0000000000000000000000000000000",
            "not-an-id",
        ] {
            assert!(
                HistoricalOperationRecord::parse_release_bound(&bytes, invalid, &input).is_err()
            );
        }
        let different = if selected == "00000000000000000000000000000000" {
            "11111111111111111111111111111111"
        } else {
            "00000000000000000000000000000000"
        };
        assert!(HistoricalOperationRecord::parse_release_bound(&bytes, different, &input).is_err());
        assert!(
            HistoricalOperationRecord::parse_release_bound(
                &bytes,
                selected,
                &crate::test_support::staging_input(b"other")
            )
            .is_err()
        );
        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert!(
            HistoricalOperationRecord::parse_release_bound(&noncanonical, selected, &input)
                .is_err()
        );
    }

    #[test]
    fn historical_native_identity_is_not_current_filesystem_authority() {
        let (_destination, staged, _path) = crate::test_support::prepared_stage(b"candidate");
        let input = crate::test_support::staging_input(b"candidate");
        let mut historical = staged.record.clone();
        // Deliberately use another valid recorded identity: parsing may retain it,
        // but no filesystem operation or live authority is produced by this type.
        historical.0.staged_identity = historical.0.operation_identity;
        let bytes = historical.to_json().unwrap();
        let history = HistoricalOperationRecord::parse_release_bound(
            &bytes,
            historical.operation_id(),
            &input,
        )
        .unwrap();
        assert_ne!(
            history
                .expected_phase_bytes(InstallPhase::Committed, *historical.staged_identity())
                .unwrap(),
            InstallPhaseRecord::new(
                InstallPhase::Committed,
                &staged.record,
                *staged.record.staged_identity(),
                input.executable_sha256
            )
            .unwrap()
            .to_json()
            .unwrap()
        );
    }
}
