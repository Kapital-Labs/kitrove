use super::{
    CaptureLimits, ManifestCommitKind, PackCreationPlan, PackMutationKind, PackUpdatePlan, Path,
    PortableManifestCommitOutcome, PortableTransactionError, RecoveryPolicy,
    commit_manifest_plan_with_recovery, commit_pack_mutation_inner,
};

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
