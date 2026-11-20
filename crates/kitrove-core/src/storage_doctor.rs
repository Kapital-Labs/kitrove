//! Bounded, unlocked storage observations without mutation authority.

use crate::local_state_authority;
use crate::object_mutation::{ObjectStore, PrivateDirectoryAclObservation, guarded_backup_path};
use crate::quarantine_cleanup::budget::QuarantineCleanupBudget;
use crate::quarantine_cleanup::coordinator::readonly_inspection_budget;
use crate::quarantine_cleanup::inspection::{
    QuarantineInspectionError, inspect_store_quarantine_detailed,
};
use crate::read_only_fs::{self, ReadOnlyRootOpen};
use kitrove_model::PortablePath;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

macro_rules! vocabulary {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
        pub enum $name {
            $(#[serde(rename = $label)] $variant),+
        }
        impl $name {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

vocabulary!(StorageDoctorInspection { Unlocked => "unlocked" });
vocabulary!(StorageDoctorMutationAccess { NotTested => "not_tested" });
vocabulary!(StorageDoctorRole {
    Collection => "collection", PrivateState => "private_state",
    UserHome => "user_home", Project => "project",
});
vocabulary!(StorageDoctorStage {
    Root => "root", PrivateBoundary => "private_boundary", PrivateAcl => "private_acl",
    StateFile => "state_file",
    ControlDirectory => "control_directory", ExistingLock => "existing_lock",
    RecoveryMarkers => "recovery_markers", RetainedCleanup => "retained_cleanup",
});
vocabulary!(StorageDoctorStatus {
    Ok => "ok", Absent => "absent", Blocked => "blocked", NotChecked => "not_checked",
});
vocabulary!(StorageDoctorCode {
    Checked => "checked", Absent => "absent", UnsafeRoot => "unsafe_root",
    InspectRejected => "inspect_rejected", AclEmpty => "acl_empty",
    AclNotEmpty => "acl_not_empty", AclReadFailed => "acl_read_failed",
    AclNotApplicable => "acl_not_applicable", NativeAclChecked => "native_acl_checked",
    NativeAclRejected => "native_acl_rejected", LockUnsafe => "lock_unsafe",
    RecoveryPresent => "recovery_present", RecoveryUnsafe => "recovery_unsafe",
    RetainedUnsafe => "retained_unsafe", RetainedUnrecognized => "retained_unrecognized",
    InspectionLimit => "inspection_limit", PriorCheckBlocked => "prior_check_blocked",
    MetadataUnreadable => "metadata_unreadable",
    StateFileMissing => "state_file_missing", StateFileUnverified => "state_file_unverified",
});

vocabulary!(StorageDoctorCleanupReason {
    MetadataUnreadable => "metadata_unreadable",
    DirectoryUnreadable => "directory_unreadable",
    OpenRejected => "open_rejected",
    LinkOrReparsePoint => "link_or_reparse_point",
    WrongEntryKind => "wrong_entry_kind",
    IdentityMismatch => "identity_mismatch",
    ChangedDuringInspection => "changed_during_inspection",
    FileLinkCountRejected => "file_link_count_rejected",
    PendingBatchNotVerifiedEmpty => "pending_batch_not_verified_empty",
    MultipleCleanupBatches => "multiple_cleanup_batches",
    UnrecognizedName => "unrecognized_name",
    DirectoryOwnerMismatch => "directory_owner_mismatch",
    DirectoryModeRejected => "directory_mode_rejected",
    AclNotEmpty => "acl_not_empty",
    AclUnreadable => "acl_unreadable",
    NativeProtectionRejected => "native_protection_rejected",
    BoundaryUnverified => "boundary_unverified",
    InspectionLimit => "inspection_limit",
});

vocabulary!(StorageDoctorCleanupLocation {
    Boundary => "boundary", Entry => "entry", Descendant => "descendant",
});

/// First failed invariant, without names, paths or filesystem identity values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct StorageDoctorCleanupDetail {
    pub location: StorageDoctorCleanupLocation,
    pub reason: StorageDoctorCleanupReason,
    /// One-based position in this inspection's bounded, sorted top-level listing.
    /// This is not a stable identifier and never authorizes a recovery operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<usize>,
}

/// Caller-resolved roots. Paths are never copied into the report.
#[derive(Clone, Copy)]
pub struct StorageDoctorRoots<'a> {
    pub collection: &'a Path,
    pub private_state: &'a Path,
    pub user_home: &'a Path,
    pub project: Option<&'a Path>,
}

/// An observation of existing storage, not a prediction of mutation success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageDoctorCheck {
    pub role: StorageDoctorRole,
    pub stage: StorageDoctorStage,
    pub status: StorageDoctorStatus,
    pub code: StorageDoctorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<StorageDoctorCleanupDetail>,
}

/// Content- and path-redacted observations made without acquiring mutation locks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageDoctorReport {
    pub inspection: StorageDoctorInspection,
    pub mutation_access: StorageDoctorMutationAccess,
    pub checks: Vec<StorageDoctorCheck>,
}

/// Inspects existing boundaries and metadata without creating, repairing or reclaiming storage.
#[must_use]
pub fn inspect_storage_doctor(roots: StorageDoctorRoots<'_>) -> StorageDoctorReport {
    let mut requested = vec![
        (StorageDoctorRole::Collection, roots.collection),
        (StorageDoctorRole::PrivateState, roots.private_state),
        (StorageDoctorRole::UserHome, roots.user_home),
    ];
    if let Some(project) = roots.project {
        requested.push((StorageDoctorRole::Project, project));
    }
    let mut budget = readonly_inspection_budget(requested.len()).ok();
    let mut checks = Vec::new();
    for (role, path) in requested {
        inspect_root(role, path, &mut budget, &mut checks);
    }
    StorageDoctorReport {
        inspection: StorageDoctorInspection::Unlocked,
        mutation_access: StorageDoctorMutationAccess::NotTested,
        checks,
    }
}

fn record(
    checks: &mut Vec<StorageDoctorCheck>,
    role: StorageDoctorRole,
    stage: StorageDoctorStage,
    status: StorageDoctorStatus,
    code: StorageDoctorCode,
    count: Option<usize>,
) {
    checks.push(StorageDoctorCheck {
        role,
        stage,
        status,
        code,
        count,
        detail: None,
    });
}

fn unavailable(
    checks: &mut Vec<StorageDoctorCheck>,
    role: StorageDoctorRole,
    include_private: bool,
) {
    let mut stages = vec![
        StorageDoctorStage::ControlDirectory,
        StorageDoctorStage::ExistingLock,
        StorageDoctorStage::RecoveryMarkers,
        StorageDoctorStage::RetainedCleanup,
    ];
    if role == StorageDoctorRole::PrivateState {
        stages.insert(0, StorageDoctorStage::StateFile);
        if include_private {
            stages.splice(
                0..0,
                [
                    StorageDoctorStage::PrivateBoundary,
                    StorageDoctorStage::PrivateAcl,
                ],
            );
        }
    }
    for stage in stages {
        record(
            checks,
            role,
            stage,
            StorageDoctorStatus::NotChecked,
            StorageDoctorCode::PriorCheckBlocked,
            None,
        );
    }
}

fn inspect_root(
    role: StorageDoctorRole,
    path: &Path,
    budget: &mut Option<QuarantineCleanupBudget>,
    checks: &mut Vec<StorageDoctorCheck>,
) {
    let root_status = match read_only_fs::open_root_nofollow(path) {
        ReadOnlyRootOpen::Missing => Some((StorageDoctorStatus::Absent, StorageDoctorCode::Absent)),
        ReadOnlyRootOpen::Unsafe => {
            Some((StorageDoctorStatus::Blocked, StorageDoctorCode::UnsafeRoot))
        }
        ReadOnlyRootOpen::Open(_) => None,
    };
    if let Some((status, code)) = root_status {
        record(checks, role, StorageDoctorStage::Root, status, code, None);
        unavailable(checks, role, true);
        return;
    }
    let Ok(store) = ObjectStore::open(path) else {
        record(
            checks,
            role,
            StorageDoctorStage::Root,
            StorageDoctorStatus::Blocked,
            StorageDoctorCode::UnsafeRoot,
            None,
        );
        unavailable(checks, role, true);
        return;
    };
    record(
        checks,
        role,
        StorageDoctorStage::Root,
        StorageDoctorStatus::Ok,
        StorageDoctorCode::Checked,
        None,
    );
    if role == StorageDoctorRole::PrivateState {
        let protected = store.inspect_private_root_boundary().is_ok();
        record(
            checks,
            role,
            StorageDoctorStage::PrivateBoundary,
            if protected {
                StorageDoctorStatus::Ok
            } else {
                StorageDoctorStatus::Blocked
            },
            if protected {
                StorageDoctorCode::Checked
            } else {
                StorageDoctorCode::InspectRejected
            },
            None,
        );
        inspect_private_acl(&store, role, checks);
        if !protected {
            unavailable(checks, role, false);
            return;
        }
        inspect_state_file(&store, checks);
    }
    match store.inspect_existing_control_boundary() {
        Ok(false) => {
            for stage in [
                StorageDoctorStage::ControlDirectory,
                StorageDoctorStage::ExistingLock,
                StorageDoctorStage::RecoveryMarkers,
                StorageDoctorStage::RetainedCleanup,
            ] {
                record(
                    checks,
                    role,
                    stage,
                    StorageDoctorStatus::Absent,
                    StorageDoctorCode::Absent,
                    Some(0),
                );
            }
            return;
        }
        Err(_) => {
            record(
                checks,
                role,
                StorageDoctorStage::ControlDirectory,
                StorageDoctorStatus::Blocked,
                StorageDoctorCode::InspectRejected,
                None,
            );
            for stage in [
                StorageDoctorStage::ExistingLock,
                StorageDoctorStage::RecoveryMarkers,
                StorageDoctorStage::RetainedCleanup,
            ] {
                record(
                    checks,
                    role,
                    stage,
                    StorageDoctorStatus::NotChecked,
                    StorageDoctorCode::PriorCheckBlocked,
                    None,
                );
            }
            return;
        }
        Ok(true) => record(
            checks,
            role,
            StorageDoctorStage::ControlDirectory,
            StorageDoctorStatus::Ok,
            StorageDoctorCode::Checked,
            None,
        ),
    }
    inspect_locks(&store, role, checks);
    inspect_markers(&store, role, checks);
    inspect_retained(&store, role, budget.as_mut(), checks);
}

fn inspect_private_acl(
    store: &ObjectStore,
    role: StorageDoctorRole,
    checks: &mut Vec<StorageDoctorCheck>,
) {
    let (status, code) = match store.inspect_private_root_acl() {
        Err(_) => (
            StorageDoctorStatus::NotChecked,
            StorageDoctorCode::PriorCheckBlocked,
        ),
        #[cfg(target_os = "macos")]
        Ok(PrivateDirectoryAclObservation::Empty) => {
            (StorageDoctorStatus::Ok, StorageDoctorCode::AclEmpty)
        }
        #[cfg(target_os = "macos")]
        Ok(PrivateDirectoryAclObservation::NotEmpty) => {
            (StorageDoctorStatus::Blocked, StorageDoctorCode::AclNotEmpty)
        }
        #[cfg(target_os = "macos")]
        Ok(PrivateDirectoryAclObservation::ReadFailed) => (
            StorageDoctorStatus::Blocked,
            StorageDoctorCode::AclReadFailed,
        ),
        #[cfg(windows)]
        Ok(PrivateDirectoryAclObservation::NativeChecked) => {
            (StorageDoctorStatus::Ok, StorageDoctorCode::NativeAclChecked)
        }
        #[cfg(windows)]
        Ok(PrivateDirectoryAclObservation::NativeRejected) => (
            StorageDoctorStatus::Blocked,
            StorageDoctorCode::NativeAclRejected,
        ),
        #[cfg(not(any(target_os = "macos", windows)))]
        Ok(PrivateDirectoryAclObservation::NotApplicable) => (
            StorageDoctorStatus::NotChecked,
            StorageDoctorCode::AclNotApplicable,
        ),
    };
    record(
        checks,
        role,
        StorageDoctorStage::PrivateAcl,
        status,
        code,
        None,
    );
}

fn inspect_state_file(store: &ObjectStore, checks: &mut Vec<StorageDoctorCheck>) {
    let (status, code, count) =
        match store.inspect_existing_fixed_file(&fixed_path("state.json"), true) {
            Ok(true) => (StorageDoctorStatus::Ok, StorageDoctorCode::Checked, Some(1)),
            Ok(false) => (
                StorageDoctorStatus::Absent,
                StorageDoctorCode::StateFileMissing,
                Some(0),
            ),
            Err(_) => (
                StorageDoctorStatus::Blocked,
                StorageDoctorCode::StateFileUnverified,
                None,
            ),
        };
    record(
        checks,
        StorageDoctorRole::PrivateState,
        StorageDoctorStage::StateFile,
        status,
        code,
        count,
    );
}

fn inspect_locks(
    store: &ObjectStore,
    role: StorageDoctorRole,
    checks: &mut Vec<StorageDoctorCheck>,
) {
    let mut names = vec![".kitrove/environment.lock"];
    if role == StorageDoctorRole::PrivateState {
        names.push(".kitrove/lifecycle.lock");
    }
    let mut count = 0;
    for name in names {
        match store.inspect_existing_fixed_file(&fixed_path(name), true) {
            Ok(present) => count += usize::from(present),
            Err(_) => {
                record(
                    checks,
                    role,
                    StorageDoctorStage::ExistingLock,
                    StorageDoctorStatus::Blocked,
                    StorageDoctorCode::LockUnsafe,
                    None,
                );
                return;
            }
        }
    }
    record(
        checks,
        role,
        StorageDoctorStage::ExistingLock,
        if count == 0 {
            StorageDoctorStatus::Absent
        } else {
            StorageDoctorStatus::Ok
        },
        if count == 0 {
            StorageDoctorCode::Absent
        } else {
            StorageDoctorCode::Checked
        },
        Some(count),
    );
}

fn inspect_markers(
    store: &ObjectStore,
    role: StorageDoctorRole,
    checks: &mut Vec<StorageDoctorCheck>,
) {
    let originals = match role {
        StorageDoctorRole::Collection => local_state_authority::ALL_PORTABLE_RECOVERY.to_vec(),
        StorageDoctorRole::PrivateState => local_state_authority::ALL_LOCAL_STATE_RECOVERY.to_vec(),
        StorageDoctorRole::UserHome | StorageDoctorRole::Project => {
            local_state_authority::ALL_LOCAL_STATE_RECOVERY
                .iter()
                .chain(local_state_authority::ALL_PORTABLE_RECOVERY)
                .copied()
                .collect()
        }
    };
    let mut paths = BTreeSet::new();
    for original in originals {
        let path = fixed_path(original);
        if original.ends_with(".pending") {
            paths.insert(guarded_backup_path(&path).expect("fixed guarded recovery marker"));
        }
        paths.insert(path);
    }
    let mut count = 0;
    for path in paths {
        match store.inspect_existing_fixed_file(&path, role == StorageDoctorRole::PrivateState) {
            Ok(present) => count += usize::from(present),
            Err(_) => {
                record(
                    checks,
                    role,
                    StorageDoctorStage::RecoveryMarkers,
                    StorageDoctorStatus::Blocked,
                    StorageDoctorCode::RecoveryUnsafe,
                    None,
                );
                return;
            }
        }
    }
    record(
        checks,
        role,
        StorageDoctorStage::RecoveryMarkers,
        if count == 0 {
            StorageDoctorStatus::Absent
        } else {
            StorageDoctorStatus::Blocked
        },
        if count == 0 {
            StorageDoctorCode::Absent
        } else {
            StorageDoctorCode::RecoveryPresent
        },
        Some(count),
    );
}

fn inspect_retained(
    store: &ObjectStore,
    role: StorageDoctorRole,
    budget: Option<&mut QuarantineCleanupBudget>,
    checks: &mut Vec<StorageDoctorCheck>,
) {
    match store.open_existing_removal_quarantine() {
        Ok(None) => {
            record(
                checks,
                role,
                StorageDoctorStage::RetainedCleanup,
                StorageDoctorStatus::Absent,
                StorageDoctorCode::Absent,
                Some(0),
            );
            return;
        }
        Err(error) => {
            record(
                checks,
                role,
                StorageDoctorStage::RetainedCleanup,
                StorageDoctorStatus::Blocked,
                StorageDoctorCode::RetainedUnsafe,
                None,
            );
            checks.last_mut().expect("recorded retained failure").detail =
                Some(StorageDoctorCleanupDetail {
                    location: StorageDoctorCleanupLocation::Boundary,
                    reason: error
                        .inspection_reason()
                        .unwrap_or(StorageDoctorCleanupReason::BoundaryUnverified),
                    entry: None,
                });
            return;
        }
        Ok(Some(_)) => {}
    }
    let outcome = budget.map(|budget| inspect_store_quarantine_detailed(store, budget));
    let detail = outcome
        .as_ref()
        .and_then(|result| result.as_ref().err().map(|error| error.detail));
    let (status, code, count) = match outcome.map(|result| result.map_err(|error| error.coarse)) {
        Some(Ok(inspection)) => (
            StorageDoctorStatus::Ok,
            StorageDoctorCode::Checked,
            Some(inspection.work().top_level_entries()),
        ),
        Some(Err(QuarantineInspectionError::UnrecognizedState)) => (
            StorageDoctorStatus::Blocked,
            StorageDoctorCode::RetainedUnrecognized,
            None,
        ),
        Some(Err(QuarantineInspectionError::UnsafeState)) => (
            StorageDoctorStatus::Blocked,
            StorageDoctorCode::RetainedUnsafe,
            None,
        ),
        Some(Err(QuarantineInspectionError::Budget(_))) | None => (
            StorageDoctorStatus::Blocked,
            StorageDoctorCode::InspectionLimit,
            None,
        ),
    };
    record(
        checks,
        role,
        StorageDoctorStage::RetainedCleanup,
        status,
        code,
        count,
    );
    checks
        .last_mut()
        .expect("recorded retained inspection")
        .detail = detail;
}

fn fixed_path(value: &str) -> PortablePath {
    PortablePath::parse(value).expect("fixed storage doctor control path")
}

#[cfg(test)]
#[path = "storage_doctor_tests.rs"]
mod tests;
