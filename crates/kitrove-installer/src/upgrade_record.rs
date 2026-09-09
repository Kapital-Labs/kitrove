use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::record::encode_hex;
use crate::replacement_direction::ReplacementDirection;
use crate::rollback_kit::{RetainedRollbackKit, RollbackKitIdentities};
use crate::staging_policy::PrivateDataLeaf;
use crate::state_preflight::{InspectedStateRoots, StateRootRecord};
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::{
    InstallerOperationRecord, InstallerStageError, NativeFileIdentity, StagedApplication,
    StagingInput,
};

pub(crate) const UPGRADE_RECORD: &str = "upgrade.json";
pub(crate) const MAX_UPGRADE_RECORD_BYTES: usize = 128 * 1024;

#[path = "historical_upgrade_record.rs"]
pub(crate) mod history;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PreparationPhase {
    StatePreflightRetained,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PriorRelease {
    target: String,
    tag: String,
    version: String,
    source_commit: String,
    signer_identity: String,
    trust_root_sha256: String,
    archive_name: String,
    archive_sha256: String,
    bundle_sha256: String,
    manifest_sha256: String,
    executable_sha256: String,
    executable_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UpgradeRecordData {
    schema: u32,
    direction: ReplacementDirection,
    phase: PreparationPhase,
    candidate_record_sha256: String,
    prior: PriorRelease,
    prior_identity: NativeFileIdentity,
    rollback_kit: RollbackKitIdentities,
    state_roots: Vec<StateRootRecord>,
}

/// Reconstructed preparation evidence, never upgrade or replacement authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpgradeRecord(UpgradeRecordData);

pub(crate) struct RetainedUpgradeRecord {
    record: UpgradeRecord,
    leaf: PrivateDataLeaf,
}

/// Retention-only evidence. There is deliberately no conversion to live preparation.
pub(crate) struct TerminalUpgradeRecord {
    retained: RetainedUpgradeRecord,
}

impl TerminalUpgradeRecord {
    #[cfg(windows)]
    pub(crate) fn leaf_identity(&self) -> NativeFileIdentity {
        self.retained.leaf.identity
    }

    #[cfg(windows)]
    pub(crate) fn sync_owned(
        mut self,
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
    ) -> Result<Self, InstallerStageError> {
        self.revalidate(staged, precondition, kit)?;
        self.retained.leaf = self
            .retained
            .leaf
            .sync_owned(&staged._retained.operation, UPGRADE_RECORD)?;
        self.revalidate(staged, precondition, kit)?;
        Ok(self)
    }

    pub(crate) fn reopen(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
    ) -> Result<Self, InstallerStageError> {
        let leaf = crate::staging_policy::read_private_data_leaf(
            &staged._retained.operation,
            UPGRADE_RECORD,
            MAX_UPGRADE_RECORD_BYTES,
        )?;
        let historical: UpgradeRecordData = serde_json::from_slice(&leaf.bytes)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        StateRootRecord::validate_history(&historical.state_roots)?;
        let expected =
            UpgradeRecord::from_history(staged, precondition, kit, historical.state_roots)?;
        expected.authenticate_bytes(&leaf.bytes)?;
        let record = Self {
            retained: RetainedUpgradeRecord {
                record: expected,
                leaf,
            },
        };
        record.revalidate(staged, precondition, kit)?;
        Ok(record)
    }

    pub(crate) fn revalidate(
        &self,
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
    ) -> Result<(), InstallerStageError> {
        let expected = UpgradeRecord::from_history(
            staged,
            precondition,
            kit,
            self.retained.record.0.state_roots.clone(),
        )?;
        if self.retained.record != expected {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.retained.require_file(staged)
    }

    pub(crate) fn binding_digest(&self) -> Result<[u8; 32], InstallerStageError> {
        self.retained.binding_digest()
    }

    #[cfg(unix)]
    pub(crate) fn sync(&self) -> Result<(), InstallerStageError> {
        self.retained
            .leaf
            .file
            .sync_all()
            .map_err(|_| InstallerStageError::RecoveryRequired)
    }
}

impl RetainedUpgradeRecord {
    pub(crate) fn reopen(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        precondition.bind_to_stage(staged)?;
        kit.revalidate_with_record(staged, precondition.rollback())?;
        let retained = Self::reopen_evidence(staged, precondition, kit, states)?;
        retained.revalidate(staged, precondition, kit, states)?;
        Ok(retained)
    }

    /// Record authentication only; the caller must validate kit and current layout.
    pub(crate) fn reopen_evidence(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        let record = UpgradeRecord::from_retained(staged, precondition, kit, states)?;
        let leaf = crate::staging_policy::read_private_data_leaf(
            &staged._retained.operation,
            UPGRADE_RECORD,
            MAX_UPGRADE_RECORD_BYTES,
        )?;
        record.authenticate_bytes(&leaf.bytes)?;
        let retained = Self { record, leaf };
        retained.revalidate_evidence(staged, precondition, kit, states)?;
        Ok(retained)
    }

    pub(crate) fn persist(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        let record = UpgradeRecord::prepare(staged, precondition, kit, states)?;
        let retained = Self::persist_record(staged, record)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        retained
            .revalidate(staged, precondition, kit, states)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        Ok(retained)
    }

    fn persist_record(
        staged: &StagedApplication,
        record: UpgradeRecord,
    ) -> Result<Self, InstallerStageError> {
        let leaf = crate::staging_policy::create_private_data_leaf(
            &staged._retained.operation,
            UPGRADE_RECORD,
            record.to_json()?,
        )?;
        let retained = Self { record, leaf };
        retained.require_file(staged)?;
        Ok(retained)
    }

    pub(crate) fn revalidate(
        &self,
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<(), InstallerStageError> {
        precondition.bind_to_stage(staged)?;
        kit.revalidate_with_record(staged, precondition.rollback())?;
        self.revalidate_evidence(staged, precondition, kit, states)?;
        precondition.bind_to_stage(staged)?;
        states.revalidate()
    }

    /// Record evidence only; placement and kit authority are checked by the transaction.
    pub(crate) fn revalidate_evidence(
        &self,
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<(), InstallerStageError> {
        let expected = UpgradeRecord::from_retained(staged, precondition, kit, states)?;
        if self.record != expected {
            return Err(InstallerStageError::RecoveryRequired);
        }
        self.require_file(staged)
    }

    pub(crate) fn binding_digest(&self) -> Result<[u8; 32], InstallerStageError> {
        Ok(Sha256::digest(self.record.to_json()?).into())
    }

    fn require_file(&self, staged: &StagedApplication) -> Result<(), InstallerStageError> {
        self.leaf.require_contents(
            &staged._retained.operation,
            UPGRADE_RECORD,
            &self.record.to_json()?,
        )
    }
}

impl UpgradeRecord {
    pub(crate) fn prepare(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        precondition.bind_to_stage(staged)?;
        kit.revalidate(staged, precondition.rollback())?;
        precondition.bind_to_stage(staged)?;
        Self::from_retained(staged, precondition, kit, states)
    }

    fn from_retained(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        states: &mut InspectedStateRoots,
    ) -> Result<Self, InstallerStageError> {
        Self::from_history(staged, precondition, kit, states.records()?)
    }

    fn from_history(
        staged: &StagedApplication,
        precondition: &ReplacementPrecondition<'_>,
        kit: &RetainedRollbackKit,
        state_roots: Vec<StateRootRecord>,
    ) -> Result<Self, InstallerStageError> {
        Self::from_evidence(
            &staged.record,
            &StagingInput::from(precondition.rollback().executable()),
            precondition.prior_identity(),
            kit.identities(),
            state_roots,
            precondition.direction(),
        )
    }

    fn from_evidence(
        candidate: &InstallerOperationRecord,
        prior: &StagingInput<'_>,
        prior_identity: NativeFileIdentity,
        rollback_kit: RollbackKitIdentities,
        state_roots: Vec<StateRootRecord>,
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        let candidate_bytes = candidate
            .to_json()
            .map_err(|_| InstallerStageError::UnsafeState)?;
        Self::from_record_digest(
            Sha256::digest(candidate_bytes).into(),
            prior,
            prior_identity,
            rollback_kit,
            state_roots,
            direction,
        )
    }

    fn from_record_digest(
        candidate_record_sha256: [u8; 32],
        prior: &StagingInput<'_>,
        prior_identity: NativeFileIdentity,
        rollback_kit: RollbackKitIdentities,
        state_roots: Vec<StateRootRecord>,
        direction: ReplacementDirection,
    ) -> Result<Self, InstallerStageError> {
        StateRootRecord::validate_history(&state_roots)?;
        rollback_kit.require_target(prior.target)?;
        if !prior_identity.is_valid() || !prior_identity.matches_target(prior.target) {
            return Err(InstallerStageError::RecoveryRequired);
        }
        Ok(Self(UpgradeRecordData {
            schema: 3,
            direction,
            phase: PreparationPhase::StatePreflightRetained,
            candidate_record_sha256: encode_hex(&candidate_record_sha256),
            prior: PriorRelease {
                target: prior.target.to_owned(),
                tag: prior.release_tag.to_owned(),
                version: prior.release_version.clone(),
                source_commit: prior.source_commit.to_owned(),
                signer_identity: prior.signer_identity.to_owned(),
                trust_root_sha256: encode_hex(&prior.trust_root_sha256),
                archive_name: prior.archive_name.to_owned(),
                archive_sha256: encode_hex(&prior.archive_sha256),
                bundle_sha256: encode_hex(&prior.attestation_bundle_sha256),
                manifest_sha256: encode_hex(&prior.manifest_sha256),
                executable_sha256: encode_hex(&prior.executable_sha256),
                executable_size: prior.executable_bytes.len() as u64,
            },
            prior_identity,
            rollback_kit,
            state_roots,
        }))
    }

    pub(crate) fn to_json(&self) -> Result<Vec<u8>, InstallerStageError> {
        let bytes = serde_json::to_vec(&self.0).map_err(|_| InstallerStageError::UnsafeState)?;
        if bytes.len() > MAX_UPGRADE_RECORD_BYTES {
            return Err(InstallerStageError::UnsafeState);
        }
        Ok(bytes)
    }

    /// Compares hostile bytes to independently reconstructed evidence. No fields
    /// from this parser become input to filesystem mutation or release verification.
    pub(crate) fn authenticate_bytes(&self, bytes: &[u8]) -> Result<(), InstallerStageError> {
        if bytes.len() > MAX_UPGRADE_RECORD_BYTES {
            return Err(InstallerStageError::RecoveryRequired);
        }
        let parsed: UpgradeRecordData =
            serde_json::from_slice(bytes).map_err(|_| InstallerStageError::RecoveryRequired)?;
        if parsed == self.0 {
            Ok(())
        } else {
            Err(InstallerStageError::RecoveryRequired)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{prepared_stage, staging_input};

    // Synthetic evidence isolates record binding; the Unix integration test below
    // exercises the opaque authenticated-material and prior-executable boundary.
    fn record(staged: &StagedApplication, kit: &RetainedRollbackKit) -> UpgradeRecord {
        let (_parent, path) =
            crate::test_support::initialized_state(crate::test_support::EMPTY_STATE);
        let mut states = InspectedStateRoots::capture(&[path]).unwrap();
        UpgradeRecord::from_evidence(
            &staged.record,
            &staging_input(b"prior"),
            *staged.record.staged_identity(),
            kit.identities(),
            states.records().unwrap(),
            ReplacementDirection::Upgrade,
        )
        .unwrap()
    }

    #[test]
    fn every_record_leaf_is_bound_to_reconstructed_evidence() {
        let (_destination, staged, _) = prepared_stage(b"candidate");
        let kit = RetainedRollbackKit::create_for_tests(&staged);
        let record = record(&staged, &kit);
        let bytes = record.to_json().unwrap();
        record.authenticate_bytes(&bytes).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(original["phase"], "state_preflight_retained");

        fn check_leaves(record: &UpgradeRecord, original: &serde_json::Value, path: &str) {
            let value = original.pointer(path).unwrap();
            match value {
                serde_json::Value::Object(fields) => {
                    for key in fields.keys() {
                        check_leaves(record, original, &format!("{path}/{key}"));
                    }
                }
                serde_json::Value::Array(items) => {
                    for index in 0..items.len() {
                        check_leaves(record, original, &format!("{path}/{index}"));
                    }
                }
                _ => {
                    let mut changed = original.clone();
                    *changed.pointer_mut(path).unwrap() = match value {
                        serde_json::Value::String(_) => serde_json::json!("altered"),
                        serde_json::Value::Number(number) => {
                            serde_json::json!(number.as_u64().unwrap() ^ 1)
                        }
                        _ => panic!("unexpected record field shape"),
                    };
                    assert!(
                        record
                            .authenticate_bytes(&serde_json::to_vec(&changed).unwrap())
                            .is_err(),
                        "unbound {path}"
                    );
                }
            }
        }
        check_leaves(&record, &original, "");
    }

    #[test]
    fn hostile_record_shapes_and_phase_escalation_are_refused() {
        let (_destination, staged, _) = prepared_stage(b"candidate");
        let kit = RetainedRollbackKit::create_for_tests(&staged);
        let record = record(&staged, &kit);
        let bytes = record.to_json().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for pointer in [
            "",
            "/prior",
            "/prior_identity",
            "/rollback_kit",
            "/state_roots/0",
        ] {
            let mut changed = original.clone();
            changed
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("foreign".into(), serde_json::json!(true));
            assert!(
                record
                    .authenticate_bytes(&serde_json::to_vec(&changed).unwrap())
                    .is_err()
            );
        }
        for phase in [
            "rollback_material_retained",
            "prepared",
            "upgrade_ready",
            "committed",
            "rolled_back",
        ] {
            let mut changed = original.clone();
            changed["phase"] = serde_json::json!(phase);
            assert!(
                record
                    .authenticate_bytes(&serde_json::to_vec(&changed).unwrap())
                    .is_err()
            );
        }
        for schema in [1, 2, 4] {
            let mut changed = original.clone();
            changed["schema"] = serde_json::json!(schema);
            assert!(
                record
                    .authenticate_bytes(&serde_json::to_vec(&changed).unwrap())
                    .is_err()
            );
        }
        let mut changed = original.clone();
        changed["state_roots"] = serde_json::json!([]);
        assert!(
            record
                .authenticate_bytes(&serde_json::to_vec(&changed).unwrap())
                .is_err()
        );
        changed.as_object_mut().unwrap().remove("state_roots");
        changed["schema"] = serde_json::json!(1);
        changed["phase"] = serde_json::json!("rollback_material_retained");
        assert!(
            record
                .authenticate_bytes(&serde_json::to_vec(&changed).unwrap())
                .is_err()
        );
        let duplicate = format!(
            "{{\"schema\":1,{}",
            std::str::from_utf8(&bytes[1..]).unwrap()
        );
        for hostile in [
            duplicate.as_bytes(),
            b"{}",
            &vec![b' '; MAX_UPGRADE_RECORD_BYTES + 1],
        ] {
            assert!(record.authenticate_bytes(hostile).is_err());
        }
    }

    #[test]
    fn persistence_is_exact_and_never_overwrites() {
        let (_destination, staged, operation) = prepared_stage(b"candidate");
        let kit = RetainedRollbackKit::create_for_tests(&staged);
        let record = record(&staged, &kit);
        let expected = record.to_json().unwrap();
        let retained = RetainedUpgradeRecord::persist_record(&staged, record.clone()).unwrap();
        retained.require_file(&staged).unwrap();
        assert!(RetainedUpgradeRecord::persist_record(&staged, record).is_err());
        assert_eq!(
            std::fs::read(operation.join(UPGRADE_RECORD)).unwrap(),
            expected
        );
        retained.require_file(&staged).unwrap();
    }

    #[test]
    fn record_write_and_identity_replacement_are_refused_or_detected() {
        let (_destination, staged, operation) = prepared_stage(b"candidate");
        let kit = RetainedRollbackKit::create_for_tests(&staged);
        let record = record(&staged, &kit);
        let bytes = record.to_json().unwrap();
        let retained = RetainedUpgradeRecord::persist_record(&staged, record).unwrap();
        let path = operation.join(UPGRADE_RECORD);
        #[cfg(unix)]
        {
            std::fs::write(&path, vec![b' '; bytes.len()]).unwrap();
            assert!(retained.require_file(&staged).is_err());
            std::fs::write(&path, &bytes).unwrap();
            retained.require_file(&staged).unwrap();
            std::fs::rename(&path, operation.join("displaced-record")).unwrap();
            std::fs::copy(operation.join("displaced-record"), &path).unwrap();
            assert!(retained.require_file(&staged).is_err());
        }
        #[cfg(windows)]
        {
            assert!(std::fs::write(&path, vec![b' '; bytes.len()]).is_err());
            assert!(std::fs::rename(&path, operation.join("displaced-record")).is_err());
            retained.require_file(&staged).unwrap();
        }
    }

    #[test]
    fn candidate_record_requires_the_exact_release_evidence() {
        let (_destination, staged, _) = prepared_stage(b"candidate");
        let mut input = staging_input(b"candidate");
        staged.record.matches_release(&input).unwrap();
        input.attestation_bundle_sha256[0] ^= 1;
        assert!(staged.record.matches_release(&input).is_err());
    }

    #[test]
    #[cfg(all(unix, debug_assertions))]
    fn authenticated_preparation_retains_prior_without_claiming_upgrade_readiness() {
        use std::io::Write as _;
        let spec = kitrove_release_policy::application_archive_for_target(
            crate::compiled_release_target().unwrap(),
        )
        .unwrap();
        let (candidate, rollback) = crate::test_support::upgrade_releases();
        let destination = crate::test_support::private_tempdir();
        let directory = crate::unix_staging::open_destination(destination.path()).unwrap();
        let mut prior = crate::unix_staging::create_private_file(
            directory.directory(),
            std::ffi::OsStr::new(spec.executable_name()),
            0o700,
        )
        .unwrap();
        prior.write_all(rollback.executable().bytes()).unwrap();
        prior.sync_all().unwrap();
        drop(prior);
        let precondition =
            ReplacementPrecondition::inspect(destination.path(), &candidate, &rollback).unwrap();
        let (_state_parent, state_path) =
            crate::test_support::initialized_state(crate::test_support::EMPTY_STATE);
        let mut states = InspectedStateRoots::capture(std::slice::from_ref(&state_path)).unwrap();
        let staged =
            crate::stage_authenticated_application(destination.path(), &candidate).unwrap();
        let other_destination = crate::test_support::private_tempdir();
        let other_stage =
            crate::stage_authenticated_application(other_destination.path(), &candidate).unwrap();
        assert_eq!(
            precondition.bind_to_stage(&other_stage),
            Err(InstallerStageError::UnsafeDestination)
        );
        let kit = RetainedRollbackKit::create(&staged, &rollback).unwrap();
        let retained =
            RetainedUpgradeRecord::persist(&staged, &precondition, &kit, &mut states).unwrap();
        retained
            .revalidate(&staged, &precondition, &kit, &mut states)
            .unwrap();
        assert_eq!(
            retained.record.0.phase,
            PreparationPhase::StatePreflightRetained
        );
        assert_eq!(
            std::fs::read(destination.path().join(spec.executable_name())).unwrap(),
            rollback.executable().bytes()
        );
        assert!(RetainedUpgradeRecord::persist(&staged, &precondition, &kit, &mut states).is_err());
        retained
            .revalidate(&staged, &precondition, &kit, &mut states)
            .unwrap();
        let mut no_states = InspectedStateRoots::capture(&[]).unwrap();
        assert!(
            retained
                .revalidate(&staged, &precondition, &kit, &mut no_states)
                .is_err()
        );
        std::fs::write(state_path.join("state.json"), b"changed").unwrap();
        assert!(
            retained
                .revalidate(&staged, &precondition, &kit, &mut states)
                .is_err()
        );
        assert_eq!(
            std::fs::read(destination.path().join(spec.executable_name())).unwrap(),
            rollback.executable().bytes()
        );
    }
}
