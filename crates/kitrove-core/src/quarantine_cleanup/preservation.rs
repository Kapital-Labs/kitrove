//! A preservation-only rename. Ordinary cleanup still requires the full recorded identity.

use std::ffi::OsStr;
use std::path::Path;

use cap_std::fs::Dir;
use kitrove_agent_skills::CaptureLimits;
use kitrove_model::{ContentHash, EnvironmentManifest, LocalState, PortablePath};
use kitrove_state_lifecycle::StateAuthority;

use crate::filesystem_identity::MetadataIdentity;
use crate::local_state_authority::{ALL_LOCAL_STATE_RECOVERY, ALL_PORTABLE_RECOVERY};
use crate::object_mutation::{ObjectStore, guarded_backup_path, rename_noreplace, sync_directory};
use crate::{LockStatus, compare_lockfile, verify_referenced_objects};

use super::coordinator::readonly_inspection_budget;
use super::inspection::inspect_for_preservation;

pub(crate) const HOLD_NAME: &str = "removal-quarantine-preserved-v1";
pub const RETAINED_HOLD_PATH: &str = ".kitrove/removal-quarantine-preserved-v1";
const ACTIVE_NAME: &str = "removal-quarantine";
const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

/// The only roots this operation can preserve. Tool destinations are outside its scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreservationRoot {
    Collection,
    PrivateState,
}

impl PreservationRoot {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collection => "collection",
            Self::PrivateState => "private-state",
        }
    }
}

/// Redacted authorization preview. Counts are for the whole selected quarantine.
#[derive(Debug, Eq, PartialEq)]
pub struct QuarantinePreservationPlan {
    pub root: PreservationRoot,
    pub entries: usize,
    pub device_mismatches: usize,
    pub digest: ContentHash,
}

/// Closed recovery outcomes suitable for sharing without paths or file identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreservationError {
    UnsafeStorage,
    AuthorityUnverified,
    RecoveryPending,
    UnsupportedEntry,
    IncompleteCleanup,
    FileIdentityChanged,
    InspectionLimit,
    NoDeviceMismatch,
    HoldExists,
    LockUnavailable,
    PlanChanged,
    MoveRefused,
    PreservedNeedsReview,
}

impl PreservationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsafeStorage => "recover.unsafe_storage",
            Self::AuthorityUnverified => "recover.authority_unverified",
            Self::RecoveryPending => "recover.pending_transaction",
            Self::UnsupportedEntry => "recover.unsupported_entry",
            Self::IncompleteCleanup => "recover.incomplete_cleanup",
            Self::FileIdentityChanged => "recover.file_identity_changed",
            Self::InspectionLimit => "recover.inspection_limit",
            Self::NoDeviceMismatch => "recover.no_device_mismatch",
            Self::HoldExists => "recover.hold_exists",
            Self::LockUnavailable => "recover.lock_unavailable",
            Self::PlanChanged => "recover.plan_changed",
            Self::MoveRefused => "recover.move_refused",
            Self::PreservedNeedsReview => "recover.preserved_needs_review",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::UnsafeStorage => {
                "the collection or private storage boundary could not be verified"
            }
            Self::AuthorityUnverified => {
                "verify the collection, its lock and objects, and private state before recovery"
            }
            Self::RecoveryPending => {
                "a pending transaction or recovery marker needs separate review"
            }
            Self::UnsupportedEntry => "a retained entry needs separate inspection",
            Self::IncompleteCleanup => "an unfinished cleanup batch needs separate review",
            Self::FileIdentityChanged => {
                "a retained entry has a different file ID and needs separate review"
            }
            Self::InspectionLimit => "the retained entries exceed the inspection limit",
            Self::NoDeviceMismatch => "no recognized retained entries have a device-only mismatch",
            Self::HoldExists => "a previous preservation hold already exists",
            Self::LockUnavailable => {
                "the collection or private state is busy or its lock could not be verified"
            }
            Self::PlanChanged => {
                "storage changed since the preview; generate a fresh recovery plan"
            }
            Self::MoveRefused => "the operating system refused to move the retained directory",
            Self::PreservedNeedsReview => {
                "the retained directory moved, but final verification failed; inspect the preservation hold before continuing"
            }
        }
    }
}

struct ReviewedPreservation {
    plan: QuarantinePreservationPlan,
    control: Dir,
    quarantine: Dir,
}

fn fixed(path: &str) -> PortablePath {
    PortablePath::parse(path).expect("fixed recovery authority path")
}

fn verify_no_pending(store: &ObjectStore) -> Result<(), PreservationError> {
    for path in ALL_PORTABLE_RECOVERY.iter().chain(ALL_LOCAL_STATE_RECOVERY) {
        let marker = fixed(path);
        let backup = path
            .ends_with(".pending")
            .then(|| guarded_backup_path(&marker).expect("fixed guarded recovery marker"));
        for candidate in std::iter::once(&marker).chain(backup.iter()) {
            match store.inspect_existing_fixed_file(candidate, true) {
                Ok(false) => {}
                Ok(true) | Err(_) => return Err(PreservationError::RecoveryPending),
            }
        }
    }
    Ok(())
}

fn verify_authority(
    collection: &ObjectStore,
    private_state: &ObjectStore,
    collection_path: &Path,
    fingerprint: &mut blake3::Hasher,
) -> Result<(), PreservationError> {
    let error = PreservationError::AuthorityUnverified;
    let read = |store: &ObjectStore, path: &str| {
        store
            .read_text(&fixed(path), MAX_CONTROL_BYTES)
            .map_err(|_| error)?
            .ok_or(error)
    };
    let manifest_text = read(collection, "kitrove.toml")?;
    let lock = read(collection, "kitrove.lock.json")?;
    let state_text = read(private_state, "state.json")?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| error)?;
    LocalState::from_json(&state_text).map_err(|_| error)?;
    if compare_lockfile(&manifest, Some(&lock))
        .map_err(|_| error)?
        .status()
        != LockStatus::InSync
        || !verify_referenced_objects(&manifest, collection_path, CaptureLimits::default())
            .map_err(|_| error)?
            .is_clean()
    {
        return Err(error);
    }
    for document in [manifest_text, lock, state_text] {
        fingerprint.update(blake3::hash(document.as_bytes()).as_bytes());
    }
    Ok(())
}

fn review(
    collection: &ObjectStore,
    private_state: &ObjectStore,
    collection_path: &Path,
    role: PreservationRoot,
) -> Result<ReviewedPreservation, PreservationError> {
    let boundary = PreservationError::UnsafeStorage;
    collection
        .require_non_overlapping_root(private_state)
        .map_err(|_| boundary)?;
    let mut fingerprint = blake3::Hasher::new_derive_key("kitrove quarantine preservation plan v1");
    fingerprint.update(role.as_str().as_bytes());
    for store in [collection, private_state] {
        verify_no_pending(store)?;
        let identity = store.verified_root_identity().map_err(|_| boundary)?;
        add_identity(&mut fingerprint, identity);
    }
    verify_authority(collection, private_state, collection_path, &mut fingerprint)?;
    let target = selected(role, collection, private_state);
    let (control, quarantine) = target.pin_quarantine_for_preservation().map_err(|error| {
        if error.code() == "recover.hold_exists" {
            PreservationError::HoldExists
        } else {
            boundary
        }
    })?;
    for directory in [&control, &quarantine] {
        let metadata = directory.dir_metadata().map_err(|_| boundary)?;
        add_identity(&mut fingerprint, MetadataIdentity::from_metadata(&metadata));
    }
    let mut budget =
        readonly_inspection_budget(1).map_err(|_| PreservationError::InspectionLimit)?;
    let (entries, device_mismatches) =
        inspect_for_preservation(&quarantine, &mut budget, &mut fingerprint)?;
    target
        .revalidate_preservation_source(&control, &quarantine)
        .map_err(|_| boundary)?;
    Ok(ReviewedPreservation {
        plan: QuarantinePreservationPlan {
            root: role,
            entries,
            device_mismatches,
            digest: ContentHash::digest(fingerprint.finalize().as_bytes()),
        },
        control,
        quarantine,
    })
}

fn add_identity(fingerprint: &mut blake3::Hasher, identity: MetadataIdentity) {
    fingerprint.update(&identity.device.to_le_bytes());
    fingerprint.update(&identity.inode.to_le_bytes());
}

fn selected<'a>(
    role: PreservationRoot,
    collection: &'a ObjectStore,
    private_state: &'a ObjectStore,
) -> &'a ObjectStore {
    match role {
        PreservationRoot::Collection => collection,
        PreservationRoot::PrivateState => private_state,
    }
}

/// Observe the entire selected quarantine and issue a digest without acquiring a lock.
pub fn plan_quarantine_preservation(
    collection_path: &Path,
    private_path: &Path,
    role: PreservationRoot,
) -> Result<QuarantinePreservationPlan, PreservationError> {
    let boundary = PreservationError::UnsafeStorage;
    let collection = ObjectStore::open(collection_path).map_err(|_| boundary)?;
    let state = ObjectStore::open_private_state(private_path).map_err(|_| boundary)?;
    Ok(review(&collection, &state, collection_path, role)?.plan)
}

/// Move one directory intact after revalidating its exact preview with both roots locked.
pub fn preserve_quarantine(
    collection_path: &Path,
    private_path: &Path,
    role: PreservationRoot,
    expected: &ContentHash,
) -> Result<QuarantinePreservationPlan, PreservationError> {
    if &plan_quarantine_preservation(collection_path, private_path, role)?.digest != expected {
        return Err(PreservationError::PlanChanged);
    }
    let boundary = PreservationError::UnsafeStorage;
    let busy = PreservationError::LockUnavailable;
    let authority = StateAuthority::open_existing(private_path).map_err(|_| boundary)?;
    let lifecycle = authority.try_lock_exclusive().map_err(|_| busy)?;
    let access = authority.exclusive_access(&lifecycle).map_err(|_| busy)?;
    let collection = ObjectStore::open(collection_path).map_err(|_| boundary)?;
    let state = ObjectStore::open_private_state_for_mutation(private_path).map_err(|_| boundary)?;
    let _locks = ObjectStore::try_lock_distinct_roots(&[&collection, &state]).map_err(|_| busy)?;
    let reviewed = review(&collection, &state, collection_path, role)?;
    if &reviewed.plan.digest != expected {
        return Err(PreservationError::PlanChanged);
    }
    access.revalidate().map_err(|_| busy)?;
    selected(role, &collection, &state)
        .revalidate_preservation_source(&reviewed.control, &reviewed.quarantine)
        .map_err(|_| PreservationError::PlanChanged)?;
    rename_noreplace(
        &reviewed.control,
        OsStr::new(ACTIVE_NAME),
        &reviewed.control,
        OsStr::new(HOLD_NAME),
    )
    .map_err(|_| PreservationError::MoveRefused)?;

    let incomplete = PreservationError::PreservedNeedsReview;
    sync_directory(&reviewed.control).map_err(|_| incomplete)?;
    access.revalidate().map_err(|_| incomplete)?;
    selected(role, &collection, &state)
        .verify_preservation_destination(&reviewed.control, &reviewed.quarantine)
        .map_err(|_| incomplete)?;
    Ok(reviewed.plan)
}
