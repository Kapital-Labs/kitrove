use super::{
    CaptureLimits, ManifestCommitKind, PackCreationPlan, PackMutationKind, PackUpdatePlan, Path,
    PortableManifestCommitOutcome, PortableTransactionError, RecoveryPolicy,
    commit_manifest_plan_with_recovery, commit_pack_mutation_inner,
};
use super::{
    PackDistributionPlan, PackRollbackPlan, VerifiedObjectEnvelope,
    commit_pack_adoption_with_recovery, commit_pack_rollback_with_recovery,
};

/// Imports an explicitly approved exact pack closure without implicit recovery.
///
/// The caller must compare the typed plan digest with approval first.
pub fn commit_approved_pack_distribution_adoption(
    plan: &PackDistributionPlan,
    objects: &[VerifiedObjectEnvelope],
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    commit_pack_adoption_with_recovery(
        plan,
        objects,
        environment_root,
        limits,
        RecoveryPolicy::Refuse,
    )
}

/// Commits an explicitly approved rollback without implicit recovery.
///
/// The caller must compare the typed plan digest with approval first.
pub fn commit_approved_pack_rollback(
    plan: &PackRollbackPlan,
    objects: &[VerifiedObjectEnvelope],
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    commit_pack_rollback_with_recovery(
        plan,
        objects,
        environment_root,
        limits,
        RecoveryPolicy::Refuse,
    )
}

/// Commits a confirmed pack-creation plan without writing or replacing immutable objects.
pub fn commit_pack_creation(
    plan: &PackCreationPlan,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    commit_pack_mutation_inner(
        plan,
        PackMutationKind::Create,
        environment_root,
        limits,
        None,
    )
}

/// Commits a confirmed pack-update plan without writing or replacing immutable objects.
pub fn commit_pack_update(
    plan: &PackUpdatePlan,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    commit_pack_mutation_inner(
        plan,
        PackMutationKind::Update,
        environment_root,
        limits,
        None,
    )
}

/// Commits an exact pack-authoring plan without recovering any earlier transaction.
///
/// The caller must compare the plan digest with explicit approval. Pending journals
/// are refused under the environment lock before any recovery or cleanup.
pub fn commit_approved_pack_mutation(
    plan: &PackCreationPlan,
    environment_root: &Path,
    limits: CaptureLimits,
) -> Result<PortableManifestCommitOutcome, PortableTransactionError> {
    let kind = match plan.operation() {
        PackMutationKind::Create => ManifestCommitKind::Create,
        PackMutationKind::Update => ManifestCommitKind::Update,
    };
    commit_manifest_plan_with_recovery(
        plan,
        kind,
        None,
        environment_root,
        limits,
        None,
        RecoveryPolicy::Refuse,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable_transaction::{
        JOURNAL_PATH, JournalPhase, LOCK_PATH, MANIFEST_PATH, tests as fixtures,
    };

    #[test]
    fn approved_import_and_rollback_preserve_valid_pending_phases() {
        use crate::portable_transaction::commit_manifest_plan_inner;
        use kitrove_model::{AssetId, EnvironmentManifest, RemoteRevision, SyncLimits};
        use std::{collections::BTreeSet, sync::Arc};

        for rollback in [false, true] {
            for phase in [
                JournalPhase::Prepared,
                JournalPhase::ManifestCommitted,
                JournalPhase::LockCommitted,
                JournalPhase::Verified,
                JournalPhase::Complete,
            ] {
                let (_temporary, root, rollback_plan) = fixtures::pack_rollback_environment();
                let distributed = EnvironmentManifest::from_toml(
                    &std::fs::read_to_string(root.join(MANIFEST_PATH)).unwrap(),
                )
                .unwrap();
                let history = crate::VerifiedRemoteHistory::new(
                    vec![(
                        RemoteRevision::parse("test:approved-import").unwrap(),
                        Arc::new(
                            crate::PortableSnapshotV1::new(
                                distributed.clone(),
                                BTreeSet::new(),
                                SyncLimits::default(),
                            )
                            .unwrap(),
                        ),
                    )],
                    SyncLimits::default(),
                )
                .unwrap();
                let mut empty = distributed;
                empty.assets.clear();
                empty.packs.clear();
                empty.profiles.clear();
                empty.required_bindings.clear();
                let selection =
                    crate::select_pack_distribution(&history, &AssetId::parse("left").unwrap())
                        .unwrap();
                let adoption = crate::plan_pack_distribution_adoption(&empty, &selection).unwrap();
                if !rollback {
                    std::fs::write(root.join(MANIFEST_PATH), empty.to_toml().unwrap()).unwrap();
                    std::fs::write(
                        root.join(LOCK_PATH),
                        crate::derive_lockfile(&empty).unwrap().to_json().unwrap(),
                    )
                    .unwrap();
                }
                let interrupted = if rollback {
                    commit_manifest_plan_inner(
                        &rollback_plan,
                        ManifestCommitKind::Rollback,
                        Some(&[]),
                        &root,
                        CaptureLimits::default(),
                        Some(phase),
                    )
                } else {
                    commit_manifest_plan_inner(
                        &adoption,
                        ManifestCommitKind::Adopt,
                        Some(&[]),
                        &root,
                        CaptureLimits::default(),
                        Some(phase),
                    )
                }
                .unwrap_err();
                assert_eq!(interrupted.code(), "transaction.interrupted");
                let snapshot = || {
                    [MANIFEST_PATH, LOCK_PATH, JOURNAL_PATH]
                        .map(|path| std::fs::read(root.join(path)).unwrap())
                };
                let before = snapshot();
                let refused = if rollback {
                    commit_approved_pack_rollback(
                        &rollback_plan,
                        &[],
                        &root,
                        CaptureLimits::default(),
                    )
                } else {
                    commit_approved_pack_distribution_adoption(
                        &adoption,
                        &[],
                        &root,
                        CaptureLimits::default(),
                    )
                }
                .unwrap_err();
                assert_eq!(refused.code(), "transaction.recovery_required");
                assert_eq!(snapshot(), before);
                let recovered = if rollback {
                    crate::commit_pack_rollback(
                        &rollback_plan,
                        &[],
                        &root,
                        CaptureLimits::default(),
                    )
                } else {
                    crate::commit_pack_distribution_adoption(
                        &adoption,
                        &[],
                        &root,
                        CaptureLimits::default(),
                    )
                };
                assert!(recovered.is_ok(), "{recovered:?}");
            }
        }
    }

    #[test]
    fn approved_authoring_preserves_every_valid_pending_metadata_phase() {
        for create in [true, false] {
            for phase in [
                JournalPhase::Prepared,
                JournalPhase::ManifestCommitted,
                JournalPhase::LockCommitted,
                JournalPhase::Verified,
                JournalPhase::Complete,
            ] {
                let (_root, environment, plan) = if create {
                    fixtures::pack_creation_environment()
                } else {
                    fixtures::pack_update_environment()
                };
                let interrupted = commit_pack_mutation_inner(
                    &plan,
                    plan.operation(),
                    &environment,
                    CaptureLimits::default(),
                    Some(phase),
                );
                assert!(interrupted.is_err());
                let snapshot = || {
                    [MANIFEST_PATH, LOCK_PATH, JOURNAL_PATH]
                        .map(|path| std::fs::read(environment.join(path)).unwrap())
                };
                let before = snapshot();
                let result =
                    commit_approved_pack_mutation(&plan, &environment, CaptureLimits::default())
                        .unwrap_err();
                assert_eq!(result.code(), "transaction.recovery_required");
                assert_eq!(snapshot(), before);
            }
        }
    }
}
