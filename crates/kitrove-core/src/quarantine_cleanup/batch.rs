use std::ffi::{OsStr, OsString};

use cap_fs_ext::{
    DirEntryExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
};
use cap_std::fs::{Dir, OpenOptions};
use kitrove_agent_skills::{BoundedDirectoryEntries, collect_bounded_sorted_directory_entries};

#[cfg(unix)]
use crate::filesystem_identity::MetadataIdentity;
use crate::object_mutation::{
    ObjectStore, random_nonce, rename_noreplace, secure_private_directory_for_mutation,
    sync_directory,
};
#[cfg(windows)]
use crate::quarantine_name::RetainedTombstoneName;
use crate::quarantine_name::{
    CleanupBatchName, CleanupLeafName, CleanupPendingName, RemovalTombstoneName, RemovedObjectKind,
};
use crate::read_only_fs::{has_single_file_link, safe_metadata, same_file};

use super::budget::{
    QuarantineBudgetError, QuarantineCleanupBudget, QuarantineWorkPortion, TombstoneWork,
};
use super::inspection::{
    CleanupDisposition, QuarantineCandidate, QuarantineInspection, QuarantineInspectionError,
    is_empty_directory, open_verified_directory, open_verified_file_capability,
};

#[cfg(unix)]
type PlatformIdentity = MetadataIdentity;
#[cfg(windows)]
type PlatformIdentity = kitrove_windows_security::WindowsFileIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuarantineCleanupError {
    Budget(QuarantineBudgetError),
    UnsafeState,
    MutationFailed,
}

impl From<QuarantineBudgetError> for QuarantineCleanupError {
    fn from(error: QuarantineBudgetError) -> Self {
        Self::Budget(error)
    }
}

impl From<QuarantineInspectionError> for QuarantineCleanupError {
    fn from(error: QuarantineInspectionError) -> Self {
        match error {
            QuarantineInspectionError::Budget(error) => Self::Budget(error),
            QuarantineInspectionError::UnsafeState
            | QuarantineInspectionError::UnrecognizedState => Self::UnsafeState,
        }
    }
}

struct StagedBatch {
    quarantine: Dir,
    directory: Dir,
    name: OsString,
    #[cfg(windows)]
    identity: PlatformIdentity,
}

struct ValidatedBatch {
    work: TombstoneWork,
    boundary: DirectoryBoundary,
    entries: Vec<ValidatedEntry>,
}

struct ValidatedEntry {
    name: OsString,
    identity: PlatformIdentity,
    kind: ValidatedKind,
}

enum ValidatedKind {
    File { require_single_link: bool },
    Directory(Vec<ValidatedEntry>),
}

#[derive(Clone, Copy)]
enum BatchChildAuthority {
    Tombstone(RemovalTombstoneName),
    Leaf(CleanupLeafName),
}

impl BatchChildAuthority {
    fn parse(name: &OsStr) -> Option<Self> {
        RemovalTombstoneName::parse(name)
            .map(Self::Tombstone)
            .or_else(|| CleanupLeafName::parse(name).map(Self::Leaf))
    }

    const fn identity(self) -> PlatformIdentity {
        match self {
            Self::Tombstone(authority) => authority.identity,
            Self::Leaf(authority) => authority.identity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryBoundary {
    #[cfg(unix)]
    device: u64,
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(target_os = "linux")]
    mount_id: u64,
}

type RenameOperation<'a> = dyn FnMut(&Dir, &OsStr, &Dir, &OsStr) -> Result<(), ()> + 'a;

struct CleanupOperations<'a> {
    rename: &'a mut RenameOperation<'a>,
    sync_file: &'a mut dyn FnMut(&cap_std::fs::File) -> Result<(), ()>,
    #[cfg(unix)]
    before_source_move: &'a mut dyn FnMut(&Dir, &OsStr),
    before_isolated_unlink: &'a mut dyn FnMut(&Dir, &OsStr),
    after_synced_deletion: &'a mut dyn FnMut() -> Result<(), ()>,
    after_staging: &'a mut dyn FnMut(),
    after_validation: &'a mut dyn FnMut(),
}

#[derive(Clone, Copy)]
struct DeletionContext<'a> {
    boundary: DirectoryBoundary,
    #[cfg(unix)]
    root: &'a Dir,
    #[cfg(windows)]
    _lifetime: std::marker::PhantomData<&'a Dir>,
}

/// Reclaims a completely inspected set of supported-platform quarantines as one bounded operation.
///
/// The caller must hold the sorted lock set for every store. All staging work is precharged before
/// the first mutation, and every staged root is validated before any batch is deleted.
pub(crate) fn cleanup_inspected_quarantines(
    targets: &[(&ObjectStore, &QuarantineInspection)],
    budget: &mut QuarantineCleanupBudget,
) -> Result<(), QuarantineCleanupError> {
    let mut rename =
        |source: &Dir, source_name: &OsStr, destination: &Dir, destination_name: &OsStr| {
            rename_noreplace(source, source_name, destination, destination_name)
        };
    let mut sync_file = |file: &cap_std::fs::File| file.sync_all().map_err(|_| ());
    #[cfg(unix)]
    let mut before_source_move = |_: &Dir, _: &OsStr| {};
    let mut before_isolated_unlink = |_: &Dir, _: &OsStr| {};
    let mut after_synced_deletion = || Ok(());
    let mut after_staging = || {};
    let mut after_validation = || {};
    cleanup_inspected_quarantines_with_hooks(
        targets,
        budget,
        &mut CleanupOperations {
            rename: &mut rename,
            sync_file: &mut sync_file,
            #[cfg(unix)]
            before_source_move: &mut before_source_move,
            before_isolated_unlink: &mut before_isolated_unlink,
            after_synced_deletion: &mut after_synced_deletion,
            after_staging: &mut after_staging,
            after_validation: &mut after_validation,
        },
    )
}

fn cleanup_inspected_quarantines_with_hooks(
    targets: &[(&ObjectStore, &QuarantineInspection)],
    budget: &mut QuarantineCleanupBudget,
    operations: &mut CleanupOperations<'_>,
) -> Result<(), QuarantineCleanupError> {
    precharge_staging(targets, budget)?;

    let mut staged = Vec::with_capacity(targets.len());
    for (store, inspection) in targets {
        if let Some(batch) = stage_root(store, inspection, operations.rename, operations.sync_file)?
        {
            staged.push(batch);
        }
    }
    (operations.after_staging)();

    let mut validated = Vec::with_capacity(staged.len());
    let mut deletion_work = TombstoneWork::default();
    for batch in &staged {
        let snapshot = validate_batch(batch, budget)?;
        deletion_work =
            deletion_work
                .checked_add(snapshot.work)
                .ok_or(QuarantineCleanupError::Budget(
                    QuarantineBudgetError::ArithmeticOverflow,
                ))?;
        validated.push(snapshot);
    }
    let secure_and_delete_work =
        deletion_work
            .checked_add(deletion_work)
            .ok_or(QuarantineCleanupError::Budget(
                QuarantineBudgetError::ArithmeticOverflow,
            ))?;
    budget.try_consume(
        QuarantineWorkPortion::CleanupDeletion,
        secure_and_delete_work,
    )?;
    for (batch, snapshot) in staged.iter().zip(&validated) {
        secure_validated_directories(&batch.directory, &snapshot.entries, snapshot.boundary)?;
    }
    (operations.after_validation)();

    for (batch, snapshot) in staged.into_iter().zip(validated) {
        snapshot.boundary.require_match(&batch.directory)?;
        delete_validated_entries(
            &batch.directory,
            &snapshot.entries,
            true,
            DeletionContext {
                boundary: snapshot.boundary,
                #[cfg(unix)]
                root: &batch.directory,
                #[cfg(windows)]
                _lifetime: std::marker::PhantomData,
            },
            operations,
        )?;
        verify_batch_name(&batch.quarantine, &batch.name, &batch.directory)?;
        delete_batch_root(batch)?;
        (operations.after_synced_deletion)().map_err(|_| QuarantineCleanupError::MutationFailed)?;
    }
    Ok(())
}

#[cfg(unix)]
fn delete_batch_root(batch: StagedBatch) -> Result<(), QuarantineCleanupError> {
    batch
        .directory
        .remove_open_dir()
        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    sync_directory(&batch.quarantine).map_err(|_| QuarantineCleanupError::MutationFailed)
}

#[cfg(windows)]
fn delete_batch_root(batch: StagedBatch) -> Result<(), QuarantineCleanupError> {
    let StagedBatch {
        quarantine,
        directory,
        name,
        identity,
    } = batch;
    drop(directory);
    kitrove_windows_security::delete_owned_directory(&quarantine, &name, identity)
        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    sync_directory(&quarantine).map_err(|_| QuarantineCleanupError::MutationFailed)
}

fn precharge_staging(
    targets: &[(&ObjectStore, &QuarantineInspection)],
    budget: &mut QuarantineCleanupBudget,
) -> Result<(), QuarantineCleanupError> {
    let mut work = TombstoneWork::default();
    for (_, inspection) in targets {
        let mut control_entries = 0usize;
        let mut has_pending = false;
        let mut has_interrupted = false;
        let mut tombstones = 0usize;
        for candidate in inspection.candidates() {
            match candidate {
                QuarantineCandidate::File {
                    disposition: CleanupDisposition::Eligible,
                    ..
                }
                | QuarantineCandidate::Directory {
                    disposition: CleanupDisposition::Eligible,
                    ..
                } => {
                    tombstones =
                        tombstones
                            .checked_add(1)
                            .ok_or(QuarantineCleanupError::Budget(
                                QuarantineBudgetError::ArithmeticOverflow,
                            ))?;
                }
                #[cfg(windows)]
                QuarantineCandidate::File {
                    disposition: CleanupDisposition::Retain,
                    ..
                }
                | QuarantineCandidate::Directory {
                    disposition: CleanupDisposition::Retain,
                    ..
                } => return Err(QuarantineCleanupError::UnsafeState),
                QuarantineCandidate::EmptyPendingBatch { .. } => {
                    control_entries =
                        control_entries
                            .checked_add(1)
                            .ok_or(QuarantineCleanupError::Budget(
                                QuarantineBudgetError::ArithmeticOverflow,
                            ))?;
                    has_pending = true;
                }
                QuarantineCandidate::InterruptedBatch { .. } => {
                    control_entries =
                        control_entries
                            .checked_add(1)
                            .ok_or(QuarantineCleanupError::Budget(
                                QuarantineBudgetError::ArithmeticOverflow,
                            ))?;
                    has_interrupted = true;
                }
            }
        }
        if control_entries > 1 {
            return Err(QuarantineCleanupError::UnsafeState);
        }
        let batch_transition = usize::from(has_pending || (!has_interrupted && tombstones > 0));
        work = work
            .checked_add(TombstoneWork::new(
                tombstones
                    .checked_add(batch_transition)
                    .ok_or(QuarantineCleanupError::Budget(
                        QuarantineBudgetError::ArithmeticOverflow,
                    ))?,
                0,
                0,
            ))
            .ok_or(QuarantineCleanupError::Budget(
                QuarantineBudgetError::ArithmeticOverflow,
            ))?;
    }
    budget.try_consume(QuarantineWorkPortion::CleanupDeletion, work)?;
    Ok(())
}

fn stage_root(
    store: &ObjectStore,
    inspection: &QuarantineInspection,
    rename: &mut RenameOperation<'_>,
    sync_file: &mut dyn FnMut(&cap_std::fs::File) -> Result<(), ()>,
) -> Result<Option<StagedBatch>, QuarantineCleanupError> {
    if inspection.candidates().is_empty() {
        return Ok(None);
    }
    let quarantine = store
        .open_existing_removal_quarantine()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?
        .ok_or(QuarantineCleanupError::UnsafeState)?;

    let control = inspection.candidates().iter().find(|candidate| {
        matches!(
            candidate,
            QuarantineCandidate::EmptyPendingBatch { .. }
                | QuarantineCandidate::InterruptedBatch { .. }
        )
    });
    let batch = match control {
        Some(QuarantineCandidate::EmptyPendingBatch { name }) => {
            promote_pending_batch(&quarantine, name, rename)?
        }
        Some(QuarantineCandidate::InterruptedBatch { name, .. }) => {
            open_interrupted_batch(&quarantine, name)?
        }
        Some(_) => unreachable!("control selection admits only cleanup batches"),
        None => create_batch(&quarantine, rename)?,
    };

    for candidate in inspection.candidates() {
        match candidate {
            QuarantineCandidate::File { name, .. } => {
                stage_file(&quarantine, &batch.directory, name, rename, sync_file)?;
            }
            QuarantineCandidate::Directory { name, .. } => {
                stage_directory(&quarantine, &batch.directory, name, rename)?;
            }
            QuarantineCandidate::EmptyPendingBatch { .. }
            | QuarantineCandidate::InterruptedBatch { .. } => {}
        }
    }
    Ok(Some(batch))
}

fn create_batch(
    quarantine: &Dir,
    rename: &mut RenameOperation<'_>,
) -> Result<StagedBatch, QuarantineCleanupError> {
    let pending_name = CleanupPendingName::encode(
        &random_nonce().map_err(|_| QuarantineCleanupError::MutationFailed)?,
    )
    .ok_or(QuarantineCleanupError::MutationFailed)?;
    create_private_batch_directory(quarantine, &pending_name)?;
    sync_directory(quarantine).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    promote_pending_batch(quarantine, &pending_name, rename)
}

#[cfg(unix)]
fn create_private_batch_directory(
    quarantine: &Dir,
    pending_name: &OsStr,
) -> Result<(), QuarantineCleanupError> {
    quarantine
        .create_dir(pending_name)
        .map_err(|_| QuarantineCleanupError::MutationFailed)
}

#[cfg(windows)]
fn create_private_batch_directory(
    quarantine: &Dir,
    pending_name: &OsStr,
) -> Result<(), QuarantineCleanupError> {
    kitrove_windows_security::create_private_directory(quarantine, pending_name)
        .map(|_| ())
        .map_err(|_| QuarantineCleanupError::MutationFailed)
}

fn promote_pending_batch(
    quarantine: &Dir,
    pending_name: &OsStr,
    _rename: &mut RenameOperation<'_>,
) -> Result<StagedBatch, QuarantineCleanupError> {
    if CleanupPendingName::parse(pending_name).is_none() {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    let selected = quarantine
        .symlink_metadata(pending_name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let directory = open_verified_directory(quarantine, pending_name, &selected)?;
    if !is_empty_directory(&directory)? {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    let identity = directory_identity(&directory)?;
    let final_name = CleanupBatchName { identity }
        .encode(&random_nonce().map_err(|_| QuarantineCleanupError::MutationFailed)?)
        .ok_or(QuarantineCleanupError::MutationFailed)?;
    #[cfg(unix)]
    _rename(quarantine, pending_name, quarantine, &final_name)
        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    #[cfg(windows)]
    {
        let rollback_name = CleanupPendingName::encode(
            &random_nonce().map_err(|_| QuarantineCleanupError::MutationFailed)?,
        )
        .ok_or(QuarantineCleanupError::MutationFailed)?;
        drop(directory);
        kitrove_windows_security::promote_owned_directory(
            quarantine,
            pending_name,
            &final_name,
            &rollback_name,
            identity,
        )
        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    }
    sync_directory(quarantine).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    #[cfg(windows)]
    let directory = {
        let selected = quarantine
            .symlink_metadata(&final_name)
            .map_err(|_| QuarantineCleanupError::UnsafeState)?;
        open_verified_directory(quarantine, &final_name, &selected)?
    };
    verify_batch_name(quarantine, &final_name, &directory)?;
    Ok(StagedBatch {
        quarantine: quarantine
            .try_clone()
            .map_err(|_| QuarantineCleanupError::MutationFailed)?,
        directory,
        name: final_name,
        #[cfg(windows)]
        identity,
    })
}

fn open_interrupted_batch(
    quarantine: &Dir,
    name: &OsStr,
) -> Result<StagedBatch, QuarantineCleanupError> {
    let selected = quarantine
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let directory = open_verified_directory(quarantine, name, &selected)?;
    verify_batch_name(quarantine, name, &directory)?;
    #[cfg(windows)]
    let identity = directory_identity(&directory)?;
    Ok(StagedBatch {
        quarantine: quarantine
            .try_clone()
            .map_err(|_| QuarantineCleanupError::MutationFailed)?,
        directory,
        name: name.to_owned(),
        #[cfg(windows)]
        identity,
    })
}

fn verify_batch_name(
    quarantine: &Dir,
    name: &OsStr,
    directory: &Dir,
) -> Result<(), QuarantineCleanupError> {
    let authority = CleanupBatchName::parse(name).ok_or(QuarantineCleanupError::UnsafeState)?;
    let named = quarantine
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let opened = directory
        .dir_metadata()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    verify_private_batch_directory(directory)?;
    if !safe_metadata(&named)
        || !named.is_dir()
        || !same_file(&named, &opened)
        || directory_identity(directory)? != authority.identity
    {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_private_batch_directory(_directory: &Dir) -> Result<(), QuarantineCleanupError> {
    Ok(())
}

#[cfg(windows)]
fn verify_private_batch_directory(directory: &Dir) -> Result<(), QuarantineCleanupError> {
    kitrove_windows_security::inspect_private_directory(directory)
        .map_err(|_| QuarantineCleanupError::UnsafeState)
}

#[cfg(unix)]
fn directory_identity(directory: &Dir) -> Result<PlatformIdentity, QuarantineCleanupError> {
    directory
        .dir_metadata()
        .map(|metadata| MetadataIdentity::from_metadata(&metadata))
        .map_err(|_| QuarantineCleanupError::UnsafeState)
}

#[cfg(windows)]
fn directory_identity(directory: &Dir) -> Result<PlatformIdentity, QuarantineCleanupError> {
    kitrove_windows_security::file_identity(directory)
        .map_err(|_| QuarantineCleanupError::UnsafeState)
}

#[cfg(unix)]
fn file_identity(
    file: &cap_std::fs::File,
    metadata: &cap_std::fs::Metadata,
) -> Result<PlatformIdentity, QuarantineCleanupError> {
    let _ = file;
    Ok(MetadataIdentity::from_metadata(metadata))
}

#[cfg(windows)]
fn file_identity(
    file: &cap_std::fs::File,
    _metadata: &cap_std::fs::Metadata,
) -> Result<PlatformIdentity, QuarantineCleanupError> {
    kitrove_windows_security::file_identity(file).map_err(|_| QuarantineCleanupError::UnsafeState)
}

fn stage_file(
    quarantine: &Dir,
    batch: &Dir,
    name: &OsStr,
    _rename: &mut RenameOperation<'_>,
    sync_file: &mut dyn FnMut(&cap_std::fs::File) -> Result<(), ()>,
) -> Result<(), QuarantineCleanupError> {
    let authority = RemovalTombstoneName::parse(name).ok_or(QuarantineCleanupError::UnsafeState)?;
    if authority.kind != RemovedObjectKind::File {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    let selected = quarantine
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    let file = quarantine
        .open_with(name, &options)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let opened = file
        .metadata()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    verify_owned_file(&file)?;
    let identity = file_identity(&file, &opened)?;
    if !safe_metadata(&opened)
        || !opened.is_file()
        || !same_file(&selected, &opened)
        || identity != authority.identity
        || !has_single_file_link(&opened)
    {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    #[cfg(unix)]
    if opened.len() != 0 {
        file.set_len(0)
            .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    }
    sync_file(&file).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    let before_move = file
        .metadata()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    if file_identity(&file, &before_move)? != authority.identity
        || !has_single_file_link(&before_move)
    {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    #[cfg(unix)]
    _rename(quarantine, name, batch, name).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    #[cfg(windows)]
    {
        let rollback = windows_retained_name(RemovedObjectKind::File)?;
        drop(file);
        kitrove_windows_security::move_owned_file(
            quarantine,
            name,
            batch,
            name,
            &rollback,
            authority.identity,
        )
        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    }
    #[cfg(windows)]
    let file = {
        let selected = batch
            .symlink_metadata(name)
            .map_err(|_| QuarantineCleanupError::UnsafeState)?;
        open_verified_file_capability(batch, name, &selected)?.0
    };
    verify_staged_file(batch, name, &file, authority.identity)?;
    sync_directory(quarantine).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    sync_directory(batch).map_err(|_| QuarantineCleanupError::MutationFailed)
}

#[cfg(windows)]
fn windows_retained_name(kind: RemovedObjectKind) -> Result<OsString, QuarantineCleanupError> {
    RetainedTombstoneName { kind }
        .encode(&random_nonce().map_err(|_| QuarantineCleanupError::MutationFailed)?)
        .ok_or(QuarantineCleanupError::MutationFailed)
}

fn verify_staged_file(
    batch: &Dir,
    name: &OsStr,
    file: &cap_std::fs::File,
    identity: PlatformIdentity,
) -> Result<(), QuarantineCleanupError> {
    let named = batch
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let opened = file
        .metadata()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    if !safe_metadata(&named)
        || !named.is_file()
        || !same_file(&named, &opened)
        || file_identity(file, &opened)? != identity
        || !has_single_file_link(&opened)
    {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_owned_file(_file: &cap_std::fs::File) -> Result<(), QuarantineCleanupError> {
    Ok(())
}

#[cfg(windows)]
fn verify_owned_file(file: &cap_std::fs::File) -> Result<(), QuarantineCleanupError> {
    kitrove_windows_security::inspect_owned_file(file)
        .map_err(|_| QuarantineCleanupError::UnsafeState)
}

fn stage_directory(
    quarantine: &Dir,
    batch: &Dir,
    name: &OsStr,
    _rename: &mut RenameOperation<'_>,
) -> Result<(), QuarantineCleanupError> {
    let authority = RemovalTombstoneName::parse(name).ok_or(QuarantineCleanupError::UnsafeState)?;
    if authority.kind != RemovedObjectKind::Directory {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    let selected = quarantine
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let directory = open_verified_directory(quarantine, name, &selected)?;
    verify_owned_directory(&directory)?;
    if directory_identity(&directory)? != authority.identity {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    #[cfg(windows)]
    drop(directory);
    #[cfg(unix)]
    _rename(quarantine, name, batch, name).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    #[cfg(windows)]
    {
        let rollback = windows_retained_name(RemovedObjectKind::Directory)?;
        kitrove_windows_security::move_owned_directory(
            quarantine,
            name,
            batch,
            name,
            &rollback,
            authority.identity,
        )
        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
    }
    let named = batch
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    #[cfg(windows)]
    let directory = open_verified_directory(batch, name, &named)?;
    #[cfg(windows)]
    verify_owned_directory(&directory)?;
    let after = directory
        .dir_metadata()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    if !safe_metadata(&named)
        || !named.is_dir()
        || !same_file(&named, &after)
        || directory_identity(&directory)? != authority.identity
    {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    sync_directory(quarantine).map_err(|_| QuarantineCleanupError::MutationFailed)?;
    sync_directory(batch).map_err(|_| QuarantineCleanupError::MutationFailed)
}

#[cfg(unix)]
fn verify_owned_directory(_directory: &Dir) -> Result<(), QuarantineCleanupError> {
    Ok(())
}

#[cfg(windows)]
fn verify_owned_directory(directory: &Dir) -> Result<(), QuarantineCleanupError> {
    kitrove_windows_security::inspect_owned_directory(directory)
        .map_err(|_| QuarantineCleanupError::UnsafeState)
}

fn validate_batch(
    batch: &StagedBatch,
    budget: &mut QuarantineCleanupBudget,
) -> Result<ValidatedBatch, QuarantineCleanupError> {
    verify_batch_name(&batch.quarantine, &batch.name, &batch.directory)?;
    budget.try_top_level_entry(QuarantineWorkPortion::CleanupValidation)?;
    let boundary = DirectoryBoundary::from_directory(&batch.directory)?;
    let (entries, descendants) =
        validate_directory_entries(&batch.directory, budget, 0, boundary, true)?;
    Ok(ValidatedBatch {
        work: TombstoneWork::new(1, descendants.descendant_visits(), descendants.max_depth()),
        boundary,
        entries,
    })
}

fn validate_directory_entries(
    directory: &Dir,
    budget: &mut QuarantineCleanupBudget,
    parent_depth: usize,
    boundary: DirectoryBoundary,
    require_authority_names: bool,
) -> Result<(Vec<ValidatedEntry>, TombstoneWork), QuarantineCleanupError> {
    let portion = QuarantineWorkPortion::CleanupValidation;
    let entries = directory
        .entries()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let entries = collect_bounded_sorted_directory_entries(
        entries,
        budget.remaining_descendant_visits(portion),
    )
    .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let BoundedDirectoryEntries::Complete(entries) = entries else {
        return Err(QuarantineCleanupError::Budget(
            QuarantineBudgetError::ReservationExceeded(portion),
        ));
    };
    let mut validated = Vec::with_capacity(entries.len());
    let mut work = TombstoneWork::default();
    for entry in entries {
        let depth = parent_depth
            .checked_add(1)
            .ok_or(QuarantineCleanupError::Budget(
                QuarantineBudgetError::ArithmeticOverflow,
            ))?;
        budget.try_descendant(portion, depth)?;
        work = work.checked_add(TombstoneWork::new(0, 1, depth)).ok_or(
            QuarantineCleanupError::Budget(QuarantineBudgetError::ArithmeticOverflow),
        )?;
        let name = entry.file_name();
        let selected = entry
            .full_metadata()
            .map_err(|_| QuarantineCleanupError::UnsafeState)?;
        let authority = if require_authority_names {
            Some(BatchChildAuthority::parse(&name).ok_or(QuarantineCleanupError::UnsafeState)?)
        } else {
            None
        };
        if selected.is_file() {
            if authority.is_some_and(|authority| {
                matches!(
                    authority,
                    BatchChildAuthority::Tombstone(authority)
                        if authority.kind != RemovedObjectKind::File
                )
            }) {
                return Err(QuarantineCleanupError::UnsafeState);
            }
            let (file, opened) = open_verified_file_capability(directory, &name, &selected)?;
            verify_owned_file(&file)?;
            let identity = file_identity(&file, &opened)?;
            if authority.is_some_and(|authority| authority.identity() != identity) {
                return Err(QuarantineCleanupError::UnsafeState);
            }
            let require_single_link = matches!(authority, Some(BatchChildAuthority::Tombstone(_)));
            if require_single_link && !valid_authoritative_file(&opened) {
                return Err(QuarantineCleanupError::UnsafeState);
            }
            validated.push(ValidatedEntry {
                name,
                identity,
                kind: ValidatedKind::File {
                    require_single_link,
                },
            });
        } else if selected.is_dir() {
            if authority.is_some_and(|authority| {
                !matches!(
                    authority,
                    BatchChildAuthority::Tombstone(authority)
                        if authority.kind == RemovedObjectKind::Directory
                )
            }) {
                return Err(QuarantineCleanupError::UnsafeState);
            }
            let child = open_verified_directory(directory, &name, &selected)?;
            boundary.require_match(&child)?;
            verify_owned_directory(&child)?;
            let identity = directory_identity(&child)?;
            if authority.is_some_and(|authority| authority.identity() != identity) {
                return Err(QuarantineCleanupError::UnsafeState);
            }
            let (children, child_work) =
                validate_directory_entries(&child, budget, depth, boundary, false)?;
            work = work
                .checked_add(child_work)
                .ok_or(QuarantineCleanupError::Budget(
                    QuarantineBudgetError::ArithmeticOverflow,
                ))?;
            validated.push(ValidatedEntry {
                name,
                identity,
                kind: ValidatedKind::Directory(children),
            });
        } else {
            return Err(QuarantineCleanupError::UnsafeState);
        }
    }
    Ok((validated, work))
}

#[cfg(unix)]
fn valid_authoritative_file(metadata: &cap_std::fs::Metadata) -> bool {
    has_single_file_link(metadata) && metadata.len() == 0
}

#[cfg(windows)]
fn valid_authoritative_file(metadata: &cap_std::fs::Metadata) -> bool {
    has_single_file_link(metadata)
}

fn secure_validated_directories(
    directory: &Dir,
    expected: &[ValidatedEntry],
    boundary: DirectoryBoundary,
) -> Result<(), QuarantineCleanupError> {
    boundary.require_match(directory)?;
    secure_private_directory_for_mutation(directory)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let entries = directory
        .entries()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let entries = collect_bounded_sorted_directory_entries(entries, expected.len())
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let BoundedDirectoryEntries::Complete(entries) = entries else {
        return Err(QuarantineCleanupError::UnsafeState);
    };
    if entries.len() != expected.len() {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    for (entry, expected) in entries.into_iter().zip(expected) {
        let name = entry.file_name();
        if name != expected.name {
            return Err(QuarantineCleanupError::UnsafeState);
        }
        let selected = entry
            .full_metadata()
            .map_err(|_| QuarantineCleanupError::UnsafeState)?;
        match &expected.kind {
            ValidatedKind::File { .. } if safe_metadata(&selected) && selected.is_file() => {
                let (file, opened) = open_verified_file_capability(directory, &name, &selected)?;
                verify_owned_file(&file)?;
                if file_identity(&file, &opened)? != expected.identity {
                    return Err(QuarantineCleanupError::UnsafeState);
                }
            }
            ValidatedKind::Directory(children) if safe_metadata(&selected) && selected.is_dir() => {
                let child = open_verified_directory(directory, &name, &selected)?;
                verify_owned_directory(&child)?;
                if directory_identity(&child)? != expected.identity {
                    return Err(QuarantineCleanupError::UnsafeState);
                }
                secure_validated_directories(&child, children, boundary)?;
            }
            _ => return Err(QuarantineCleanupError::UnsafeState),
        }
    }
    sync_directory(directory).map_err(|_| QuarantineCleanupError::MutationFailed)
}

fn delete_validated_entries(
    directory: &Dir,
    expected: &[ValidatedEntry],
    require_authority_names: bool,
    context: DeletionContext<'_>,
    operations: &mut CleanupOperations<'_>,
) -> Result<(), QuarantineCleanupError> {
    let entries = directory
        .entries()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let entries = collect_bounded_sorted_directory_entries(entries, expected.len())
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let BoundedDirectoryEntries::Complete(entries) = entries else {
        return Err(QuarantineCleanupError::UnsafeState);
    };
    if entries.len() != expected.len() {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    for (entry, expected) in entries.into_iter().zip(expected) {
        let name = entry.file_name();
        if name != expected.name {
            return Err(QuarantineCleanupError::UnsafeState);
        }
        let selected = entry
            .full_metadata()
            .map_err(|_| QuarantineCleanupError::UnsafeState)?;
        if require_authority_names {
            let authority =
                BatchChildAuthority::parse(&name).ok_or(QuarantineCleanupError::UnsafeState)?;
            if authority.identity() != expected.identity {
                return Err(QuarantineCleanupError::UnsafeState);
            }
        }
        match &expected.kind {
            ValidatedKind::File {
                require_single_link,
            } => {
                let (file, opened) = open_verified_file_capability(directory, &name, &selected)?;
                verify_owned_file(&file)?;
                if file_identity(&file, &opened)? != expected.identity
                    || (*require_single_link && !valid_authoritative_file(&opened))
                {
                    return Err(QuarantineCleanupError::UnsafeState);
                }
                #[cfg(unix)]
                {
                    let isolated_name = if require_authority_names {
                        name.clone()
                    } else {
                        let leaf_name = CleanupLeafName {
                            identity: expected.identity,
                        }
                        .encode(
                            &random_nonce().map_err(|_| QuarantineCleanupError::MutationFailed)?,
                        )
                        .ok_or(QuarantineCleanupError::MutationFailed)?;
                        (operations.before_source_move)(directory, &name);
                        verify_named_file(directory, &name, &file, expected.identity)?;
                        (operations.rename)(directory, &name, context.root, &leaf_name)
                            .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                        verify_isolated_file(context.root, &leaf_name, &file, expected.identity)?;
                        sync_directory(directory)
                            .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                        sync_directory(context.root)
                            .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                        leaf_name
                    };
                    (operations.before_isolated_unlink)(context.root, &isolated_name);
                    verify_isolated_file(context.root, &isolated_name, &file, expected.identity)?;
                    context
                        .root
                        .remove_file(&isolated_name)
                        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                    sync_directory(context.root)
                        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                    (operations.after_synced_deletion)()
                        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                }
                #[cfg(windows)]
                {
                    let _ = require_authority_names;
                    (operations.before_isolated_unlink)(directory, &name);
                    drop(file);
                    if *require_single_link {
                        kitrove_windows_security::delete_owned_single_link_file(
                            directory,
                            &name,
                            expected.identity,
                        )
                    } else {
                        kitrove_windows_security::delete_owned_file(
                            directory,
                            &name,
                            expected.identity,
                        )
                    }
                    .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                    sync_directory(directory)
                        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                    (operations.after_synced_deletion)()
                        .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                }
            }
            ValidatedKind::Directory(children) => {
                let child = open_verified_directory(directory, &name, &selected)?;
                context.boundary.require_match(&child)?;
                verify_owned_directory(&child)?;
                if directory_identity(&child)? != expected.identity {
                    return Err(QuarantineCleanupError::UnsafeState);
                }
                delete_validated_entries(&child, children, false, context, operations)?;
                #[cfg(unix)]
                child
                    .remove_open_dir()
                    .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                #[cfg(windows)]
                drop(child);
                #[cfg(windows)]
                kitrove_windows_security::delete_owned_directory(
                    directory,
                    &name,
                    expected.identity,
                )
                .map_err(|_| QuarantineCleanupError::MutationFailed)?;
                sync_directory(directory).map_err(|_| QuarantineCleanupError::MutationFailed)?;
                (operations.after_synced_deletion)()
                    .map_err(|_| QuarantineCleanupError::MutationFailed)?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_named_file(
    parent: &Dir,
    name: &OsStr,
    file: &cap_std::fs::File,
    identity: PlatformIdentity,
) -> Result<(), QuarantineCleanupError> {
    let named = parent
        .symlink_metadata(name)
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    let opened = file
        .metadata()
        .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    if !safe_metadata(&named)
        || !named.is_file()
        || !same_file(&named, &opened)
        || MetadataIdentity::from_metadata(&opened) != identity
    {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_isolated_file(
    parent: &Dir,
    name: &OsStr,
    file: &cap_std::fs::File,
    identity: PlatformIdentity,
) -> Result<(), QuarantineCleanupError> {
    let authority = BatchChildAuthority::parse(name).ok_or(QuarantineCleanupError::UnsafeState)?;
    if authority.identity() != identity {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    verify_named_file(parent, name, file, identity)
}

impl DirectoryBoundary {
    fn from_directory(directory: &Dir) -> Result<Self, QuarantineCleanupError> {
        let identity = directory_identity(directory)?;
        Ok(Self {
            #[cfg(unix)]
            device: identity.device,
            #[cfg(windows)]
            volume_serial_number: identity.volume_serial_number,
            #[cfg(target_os = "linux")]
            mount_id: mount_id(directory)?,
        })
    }

    fn require_match(self, directory: &Dir) -> Result<(), QuarantineCleanupError> {
        let identity = directory_identity(directory)?;
        #[cfg(unix)]
        if identity.device != self.device {
            return Err(QuarantineCleanupError::UnsafeState);
        }
        #[cfg(windows)]
        if identity.volume_serial_number != self.volume_serial_number {
            return Err(QuarantineCleanupError::UnsafeState);
        }
        #[cfg(target_os = "linux")]
        if mount_id(directory)? != self.mount_id {
            return Err(QuarantineCleanupError::UnsafeState);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mount_id(directory: &Dir) -> Result<u64, QuarantineCleanupError> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    let stat = statx(
        directory,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT,
        StatxFlags::MNT_ID,
    )
    .map_err(|_| QuarantineCleanupError::UnsafeState)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(QuarantineCleanupError::UnsafeState);
    }
    Ok(stat.stx_mnt_id)
}

#[cfg(test)]
fn cleanup_budget_for_test(
    roots: usize,
    inspection: TombstoneWork,
    validation: TombstoneWork,
    deletion: TombstoneWork,
) -> QuarantineCleanupBudget {
    use super::budget::{CleanupPassWork, QuarantineCleanupLimits, QuarantineCleanupReservation};

    let reservation = QuarantineCleanupReservation::try_new(
        QuarantineCleanupLimits::try_new(roots, 64, 64, 8).unwrap(),
        roots,
        CleanupPassWork::new(inspection, validation, deletion),
        TombstoneWork::default(),
        TombstoneWork::default(),
    )
    .unwrap();
    QuarantineCleanupBudget::new(reservation)
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use cap_fs_ext::DirExt as _;
    use kitrove_model::PortablePath;

    use super::*;
    use crate::quarantine_cleanup::inspection::inspect_store_quarantine;

    macro_rules! cleanup_with_hooks {
        (
            $targets:expr,
            $budget:expr,
            $rename:expr,
            $sync_file:expr,
            $before_isolated_unlink:expr,
            $after_synced_deletion:expr,
            $after_staging:expr,
            $after_validation:expr $(,)?
        ) => {{
            let mut before_source_move = |_: &Dir, _: &OsStr| {};
            let mut after_staging = $after_staging;
            let mut after_validation = $after_validation;
            cleanup_inspected_quarantines_with_hooks(
                $targets,
                $budget,
                &mut CleanupOperations {
                    rename: $rename,
                    sync_file: $sync_file,
                    before_source_move: &mut before_source_move,
                    before_isolated_unlink: $before_isolated_unlink,
                    after_synced_deletion: $after_synced_deletion,
                    after_staging: &mut after_staging,
                    after_validation: &mut after_validation,
                },
            )
        }};
    }

    fn cleanup_budget(
        roots: usize,
        inspection: TombstoneWork,
        validation: TombstoneWork,
        deletion: TombstoneWork,
    ) -> QuarantineCleanupBudget {
        cleanup_budget_for_test(roots, inspection, validation, deletion)
    }

    fn create_private_quarantine(root: &std::path::Path) -> std::path::PathBuf {
        let control = root.join(".kitrove");
        let quarantine = control.join("removal-quarantine");
        fs::create_dir_all(&quarantine).unwrap();
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&quarantine, fs::Permissions::from_mode(0o700)).unwrap();
        quarantine
    }

    fn only_batch_path(root: &std::path::Path) -> std::path::PathBuf {
        let quarantine = root.join(".kitrove/removal-quarantine");
        let entries: Vec<_> = fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(CleanupBatchName::parse(&entries[0].file_name()).is_some());
        entries[0].path()
    }

    fn batch_path(root: &std::path::Path) -> std::path::PathBuf {
        fs::read_dir(root.join(".kitrove/removal-quarantine"))
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| CleanupBatchName::parse(&entry.file_name()).is_some())
            .unwrap()
            .path()
    }

    #[test]
    fn file_and_directory_tombstones_are_staged_validated_and_removed() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("file"), "managed").unwrap();
        fs::create_dir_all(root.join("tree/nested")).unwrap();
        fs::write(root.join("tree/nested/file"), "managed").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let tree = root.join("tree");
        let tree_name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity::from_metadata(&fs::metadata(&tree).unwrap()),
        }
        .encode("00112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(
            &tree,
            root.join(".kitrove/removal-quarantine").join(tree_name),
        )
        .unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(2, 2, 2),
            TombstoneWork::new(1, 4, 3),
            TombstoneWork::new(5, 8, 3),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget).unwrap();

        assert_eq!(
            fs::read_dir(root.join(".kitrove/removal-quarantine"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn insufficient_final_deletion_budget_retains_a_recoverable_batch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("file"), "managed").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let mut insufficient = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(2, 1, 1),
        );
        let inspection = inspect_store_quarantine(&store, &mut insufficient).unwrap();

        assert_eq!(
            cleanup_inspected_quarantines(&[(&store, &inspection)], &mut insufficient),
            Err(QuarantineCleanupError::Budget(
                QuarantineBudgetError::ReservationExceeded(QuarantineWorkPortion::CleanupDeletion)
            ))
        );
        let quarantine = root.join(".kitrove/removal-quarantine");
        let retained: Vec<_> = fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(retained.len(), 1);
        assert!(CleanupBatchName::parse(&retained[0]).is_some());

        let mut recovery = cleanup_budget(
            1,
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(2, 2, 1),
        );
        let interrupted = inspect_store_quarantine(&store, &mut recovery).unwrap();
        assert!(matches!(
            interrupted.candidates(),
            [QuarantineCandidate::InterruptedBatch { .. }]
        ));
        cleanup_inspected_quarantines(&[(&store, &interrupted)], &mut recovery).unwrap();
        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
    }

    #[test]
    fn nonempty_file_remnant_is_truncated_and_empty_pending_is_recovered() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();

        let file_root = parent.join("file-root");
        fs::create_dir(&file_root).unwrap();
        fs::write(file_root.join("file"), "managed").unwrap();
        let file_store = ObjectStore::open(&file_root).unwrap();
        let _file_lock = ObjectStore::try_lock_distinct_roots(&[&file_store]).unwrap();
        file_store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let quarantine = file_root.join(".kitrove/removal-quarantine");
        let tombstone = fs::read_dir(&quarantine)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(&tombstone, "crash-remnant").unwrap();
        let mut file_budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(4, 2, 1),
        );
        let file_inspection = inspect_store_quarantine(&file_store, &mut file_budget).unwrap();
        cleanup_inspected_quarantines(&[(&file_store, &file_inspection)], &mut file_budget)
            .unwrap();
        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);

        let pending_root = parent.join("pending-root");
        fs::create_dir(&pending_root).unwrap();
        let pending_quarantine = create_private_quarantine(&pending_root);
        let pending = CleanupPendingName::encode("90112233445566778899aabbccddeeff").unwrap();
        fs::create_dir(pending_quarantine.join(pending)).unwrap();
        let pending_store = ObjectStore::open(&pending_root).unwrap();
        let _pending_lock = ObjectStore::try_lock_distinct_roots(&[&pending_store]).unwrap();
        let mut pending_budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(3, 0, 0),
        );
        let pending_inspection =
            inspect_store_quarantine(&pending_store, &mut pending_budget).unwrap();
        cleanup_inspected_quarantines(
            &[(&pending_store, &pending_inspection)],
            &mut pending_budget,
        )
        .unwrap();
        assert_eq!(fs::read_dir(pending_quarantine).unwrap().count(), 0);
    }

    #[test]
    fn validation_budget_exhaustion_retains_batch_before_deletion() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("file"), "managed").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(4, 2, 1),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert_eq!(
            cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget),
            Err(QuarantineCleanupError::Budget(
                QuarantineBudgetError::ReservationExceeded(
                    QuarantineWorkPortion::CleanupValidation
                )
            ))
        );
        assert!(only_batch_path(&root).exists());
    }

    #[test]
    fn zero_length_retry_still_syncs_before_staging() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("file"), "managed").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let quarantine = root.join(".kitrove/removal-quarantine");
        let tombstone = fs::read_dir(&quarantine)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(&tombstone, "crash-remnant").unwrap();
        let mut first_budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(4, 2, 1),
        );
        let first_inspection = inspect_store_quarantine(&store, &mut first_budget).unwrap();
        assert_eq!(
            cleanup_with_hooks!(
                &[(&store, &first_inspection)],
                &mut first_budget,
                &mut |source, source_name, destination, destination_name| {
                    rename_noreplace(source, source_name, destination, destination_name)
                },
                &mut |_| Err(()),
                &mut |_, _| {},
                &mut || Ok(()),
                || {},
                || {},
            ),
            Err(QuarantineCleanupError::MutationFailed)
        );
        assert_eq!(fs::metadata(&tombstone).unwrap().len(), 0);

        let mut retry_budget = cleanup_budget(
            1,
            TombstoneWork::new(2, 0, 0),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(4, 2, 1),
        );
        let retry_inspection = inspect_store_quarantine(&store, &mut retry_budget).unwrap();
        let mut sync_calls = 0usize;
        cleanup_with_hooks!(
            &[(&store, &retry_inspection)],
            &mut retry_budget,
            &mut |source, source_name, destination, destination_name| {
                rename_noreplace(source, source_name, destination, destination_name)
            },
            &mut |file| {
                sync_calls += 1;
                file.sync_all().map_err(|_| ())
            },
            &mut |_, _| {},
            &mut || Ok(()),
            || {},
            || {},
        )
        .unwrap();
        assert_eq!(sync_calls, 1);
        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
    }

    #[test]
    fn moved_replacement_is_never_accepted_by_restart_validation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("file"), "original").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(4, 2, 1),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        let mut swapped = false;

        let result = cleanup_with_hooks!(
            &[(&store, &inspection)],
            &mut budget,
            &mut |source, source_name, destination, destination_name| {
                if !swapped && RemovalTombstoneName::parse(source_name).is_some() {
                    rename_noreplace(source, source_name, source, OsStr::new("swapped-original"))?;
                    source.write(source_name, b"replacement").map_err(|_| ())?;
                    swapped = true;
                }
                rename_noreplace(source, source_name, destination, destination_name)
            },
            &mut |file| file.sync_all().map_err(|_| ()),
            &mut |_, _| {},
            &mut || Ok(()),
            || {},
            || {},
        );

        assert_eq!(result, Err(QuarantineCleanupError::UnsafeState));
        let batch = batch_path(&root);
        let replacement = fs::read_dir(&batch)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(fs::read_to_string(&replacement).unwrap(), "replacement");
        let mut restart_budget = cleanup_budget(
            1,
            TombstoneWork::new(2, 1, 1),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(1, 1, 1),
        );
        assert_eq!(
            inspect_store_quarantine(&store, &mut restart_budget),
            Err(QuarantineInspectionError::UnrecognizedState)
        );
        assert_eq!(fs::read_to_string(replacement).unwrap(), "replacement");
    }

    #[test]
    fn changed_tree_after_validation_is_retained_without_unbounded_removal() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        fs::write(root.join("file"), "managed").unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("file").unwrap())
            .unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(4, 2, 1),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        let result = cleanup_with_hooks!(
            &[(&store, &inspection)],
            &mut budget,
            &mut |source, source_name, destination, destination_name| {
                rename_noreplace(source, source_name, destination, destination_name)
            },
            &mut |file| file.sync_all().map_err(|_| ()),
            &mut |_, _| {},
            &mut || Ok(()),
            || {},
            || {
                fs::write(only_batch_path(&root).join("attacker-added"), "retain").unwrap();
            },
        );

        assert_eq!(result, Err(QuarantineCleanupError::UnsafeState));
        let batch = only_batch_path(&root);
        assert_eq!(
            fs::read_to_string(batch.join("attacker-added")).unwrap(),
            "retain"
        );
    }

    #[test]
    fn isolated_file_replacement_is_detected_and_never_unlinked() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("file"), "original").unwrap();
        let quarantine = create_private_quarantine(&root);
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity::from_metadata(&fs::metadata(&tree).unwrap()),
        }
        .encode("b0112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&tree, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(1, 2, 2),
            TombstoneWork::new(4, 4, 2),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        let mut replaced = false;

        let result = cleanup_with_hooks!(
            &[(&store, &inspection)],
            &mut budget,
            &mut |source, source_name, destination, destination_name| {
                rename_noreplace(source, source_name, destination, destination_name)
            },
            &mut |file| file.sync_all().map_err(|_| ()),
            &mut |directory, name| {
                assert!(CleanupLeafName::parse(name).is_some());
                rename_noreplace(directory, name, directory, OsStr::new("saved-original")).unwrap();
                directory.write(name, b"replacement").unwrap();
                replaced = true;
            },
            &mut || Ok(()),
            || {},
            || {},
        );

        assert_eq!(result, Err(QuarantineCleanupError::UnsafeState));
        assert!(replaced);
        let batch = only_batch_path(&root);
        let replacement = fs::read_dir(&batch)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| CleanupLeafName::parse(&entry.file_name()).is_some())
            .unwrap()
            .path();
        assert_eq!(fs::read_to_string(replacement).unwrap(), "replacement");
        assert_eq!(
            fs::read_to_string(batch.join("saved-original")).unwrap(),
            "original"
        );
    }

    #[test]
    fn source_replacement_is_detected_before_evacuation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("file"), "original").unwrap();
        let quarantine = create_private_quarantine(&root);
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity::from_metadata(&fs::metadata(&tree).unwrap()),
        }
        .encode("c0112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&tree, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(1, 2, 2),
            TombstoneWork::new(5, 4, 2),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        let mut replaced = false;
        let mut rename =
            |source: &Dir, source_name: &OsStr, destination: &Dir, destination_name: &OsStr| {
                rename_noreplace(source, source_name, destination, destination_name)
            };
        let mut sync_file = |file: &cap_std::fs::File| file.sync_all().map_err(|_| ());
        let mut before_source_move = |directory: &Dir, name: &OsStr| {
            assert_eq!(
                cap_std::fs::PermissionsExt::mode(&directory.dir_metadata().unwrap().permissions(),)
                    & 0o777,
                0o700
            );
            rename_noreplace(directory, name, directory, OsStr::new("saved-original")).unwrap();
            directory.write(name, b"replacement").unwrap();
            replaced = true;
        };
        let mut before_isolated_unlink = |_: &Dir, _: &OsStr| {};
        let mut after_synced_deletion = || Ok(());
        let mut after_staging = || {};
        let mut after_validation = || {};

        let result = cleanup_inspected_quarantines_with_hooks(
            &[(&store, &inspection)],
            &mut budget,
            &mut CleanupOperations {
                rename: &mut rename,
                sync_file: &mut sync_file,
                #[cfg(unix)]
                before_source_move: &mut before_source_move,
                before_isolated_unlink: &mut before_isolated_unlink,
                after_synced_deletion: &mut after_synced_deletion,
                after_staging: &mut after_staging,
                after_validation: &mut after_validation,
            },
        );

        assert_eq!(result, Err(QuarantineCleanupError::UnsafeState));
        assert!(replaced);
        let batch = only_batch_path(&root);
        let staged_tree = fs::read_dir(&batch)
            .unwrap()
            .map(|entry| entry.unwrap())
            .find(|entry| entry.path().is_dir())
            .unwrap()
            .path();
        assert_eq!(
            fs::read_to_string(staged_tree.join("file")).unwrap(),
            "replacement"
        );
        assert_eq!(
            fs::read_to_string(staged_tree.join("saved-original")).unwrap(),
            "original"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extended_acl_blocks_cleanup_before_directory_permissions_change() {
        use std::os::fd::AsFd as _;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("file"), "original").unwrap();
        kitrove_testkit::install_macos_extended_acl(&tree);
        let original_mode = fs::metadata(&tree).unwrap().permissions().mode() & 0o777;
        let quarantine = create_private_quarantine(&root);
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity::from_metadata(&fs::metadata(&tree).unwrap()),
        }
        .encode("d0112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&tree, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 1, 1),
            TombstoneWork::new(1, 2, 2),
            TombstoneWork::new(4, 4, 2),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert_eq!(
            cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget),
            Err(QuarantineCleanupError::UnsafeState)
        );
        let staged_tree = fs::read_dir(only_batch_path(&root))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::metadata(&staged_tree).unwrap().permissions().mode() & 0o777,
            original_mode
        );
        let opened = fs::File::open(staged_tree).unwrap();
        assert!(
            !calcifer_macos_acl::read_acl(opened.as_fd())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn two_roots_use_only_root_local_renames_and_validate_before_deletion() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let roots = [parent.join("first"), parent.join("second")];
        for root in &roots {
            fs::create_dir(root).unwrap();
            fs::write(root.join("file"), "managed").unwrap();
        }
        let first = ObjectStore::open(&roots[0]).unwrap();
        let second = ObjectStore::open(&roots[1]).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&first, &second]).unwrap();
        let path = PortablePath::parse("file").unwrap();
        first.remove_regular_file_if_present(&path).unwrap();
        second.remove_regular_file_if_present(&path).unwrap();
        let mut budget = cleanup_budget(
            2,
            TombstoneWork::new(2, 0, 0),
            TombstoneWork::new(2, 3, 1),
            TombstoneWork::new(8, 4, 1),
        );
        let first_inspection = inspect_store_quarantine(&first, &mut budget).unwrap();
        let second_inspection = inspect_store_quarantine(&second, &mut budget).unwrap();
        let mut owners: Vec<(MetadataIdentity, MetadataIdentity)> = Vec::new();
        let mut moves = 0usize;

        let result = cleanup_with_hooks!(
            &[(&first, &first_inspection), (&second, &second_inspection)],
            &mut budget,
            &mut |source, source_name, destination, destination_name| {
                let source_identity =
                    MetadataIdentity::from_metadata(&source.dir_metadata().map_err(|_| ())?);
                let destination_identity =
                    MetadataIdentity::from_metadata(&destination.dir_metadata().map_err(|_| ())?);
                if CleanupPendingName::parse(source_name).is_some() {
                    if source_identity != destination_identity {
                        return Err(());
                    }
                    rename_noreplace(source, source_name, destination, destination_name)?;
                    let batch = destination
                        .open_dir_nofollow(destination_name)
                        .map_err(|_| ())?;
                    owners.push((
                        MetadataIdentity::from_metadata(&batch.dir_metadata().map_err(|_| ())?),
                        source_identity,
                    ));
                } else {
                    let owner = owners.iter().find_map(|(batch, root)| {
                        (*batch == destination_identity).then_some(*root)
                    });
                    if owner != Some(source_identity) {
                        return Err(()); // The injected backend treats cross-root moves as EXDEV.
                    }
                    rename_noreplace(source, source_name, destination, destination_name)?;
                    moves += 1;
                }
                Ok(())
            },
            &mut |file| file.sync_all().map_err(|_| ()),
            &mut |_, _| {},
            &mut || Ok(()),
            || {
                std::os::unix::fs::symlink("outside", only_batch_path(&roots[1]).join("late-link"))
                    .unwrap();
            },
            || {},
        );

        assert_eq!(result, Err(QuarantineCleanupError::UnsafeState));
        assert_eq!(moves, 2);
        assert!(only_batch_path(&roots[0]).exists());
        assert!(only_batch_path(&roots[1]).exists());
    }

    #[test]
    fn partial_recursive_deletion_resumes_from_the_synced_remainder() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        fs::write(tree.join("a"), "a").unwrap();
        fs::write(tree.join("b"), "b").unwrap();
        let quarantine = create_private_quarantine(&root);
        let name = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity: MetadataIdentity::from_metadata(&fs::metadata(&tree).unwrap()),
        }
        .encode("a0112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&tree, quarantine.join(name)).unwrap();
        let store = ObjectStore::open(&root).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        let mut budget = cleanup_budget(
            1,
            TombstoneWork::new(1, 2, 1),
            TombstoneWork::new(1, 3, 2),
            TombstoneWork::new(4, 6, 2),
        );
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        let mut deletions = 0usize;

        let result = cleanup_with_hooks!(
            &[(&store, &inspection)],
            &mut budget,
            &mut |source, source_name, destination, destination_name| {
                rename_noreplace(source, source_name, destination, destination_name)
            },
            &mut |file| file.sync_all().map_err(|_| ()),
            &mut |_, _| {},
            &mut || {
                deletions += 1;
                (deletions != 1).then_some(()).ok_or(())
            },
            || {},
            || {},
        );

        assert_eq!(result, Err(QuarantineCleanupError::MutationFailed));
        assert_eq!(deletions, 1);
        let batch = only_batch_path(&root);
        assert!(
            fs::read_dir(batch)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path()
                .is_dir()
        );

        let mut recovery = cleanup_budget(
            1,
            TombstoneWork::new(1, 2, 2),
            TombstoneWork::new(1, 2, 2),
            TombstoneWork::new(2, 4, 2),
        );
        let interrupted = inspect_store_quarantine(&store, &mut recovery).unwrap();
        cleanup_inspected_quarantines(&[(&store, &interrupted)], &mut recovery).unwrap();
        assert_eq!(fs::read_dir(quarantine).unwrap().count(), 0);
    }

    #[test]
    fn second_root_deletion_failure_recovers_with_one_shared_budget() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let roots = [parent.join("first-delete"), parent.join("second-delete")];
        for root in &roots {
            fs::create_dir(root).unwrap();
            fs::write(root.join("file"), "managed").unwrap();
        }
        let first = ObjectStore::open(&roots[0]).unwrap();
        let second = ObjectStore::open(&roots[1]).unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&first, &second]).unwrap();
        let path = PortablePath::parse("file").unwrap();
        first.remove_regular_file_if_present(&path).unwrap();
        second.remove_regular_file_if_present(&path).unwrap();
        let mut budget = cleanup_budget(
            2,
            TombstoneWork::new(2, 0, 0),
            TombstoneWork::new(2, 2, 1),
            TombstoneWork::new(8, 4, 1),
        );
        let first_inspection = inspect_store_quarantine(&first, &mut budget).unwrap();
        let second_inspection = inspect_store_quarantine(&second, &mut budget).unwrap();
        let mut deletions = 0usize;

        let result = cleanup_with_hooks!(
            &[(&first, &first_inspection), (&second, &second_inspection)],
            &mut budget,
            &mut |source, source_name, destination, destination_name| {
                rename_noreplace(source, source_name, destination, destination_name)
            },
            &mut |file| file.sync_all().map_err(|_| ()),
            &mut |_, _| {},
            &mut || {
                deletions += 1;
                (deletions != 3).then_some(()).ok_or(())
            },
            || {},
            || {},
        );

        assert_eq!(result, Err(QuarantineCleanupError::MutationFailed));
        assert_eq!(
            fs::read_dir(roots[0].join(".kitrove/removal-quarantine"))
                .unwrap()
                .count(),
            0
        );
        assert!(only_batch_path(&roots[1]).exists());

        let mut recovery = cleanup_budget(
            2,
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(1, 0, 0),
            TombstoneWork::new(2, 0, 0),
        );
        let first_recovery = inspect_store_quarantine(&first, &mut recovery).unwrap();
        let second_recovery = inspect_store_quarantine(&second, &mut recovery).unwrap();
        cleanup_inspected_quarantines(
            &[(&first, &first_recovery), (&second, &second_recovery)],
            &mut recovery,
        )
        .unwrap();
        assert_eq!(
            fs::read_dir(roots[1].join(".kitrove/removal-quarantine"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::fs;
    use std::io::Write as _;

    use kitrove_model::PortablePath;

    use super::*;
    use crate::quarantine_cleanup::coordinator::{MutationWork, cleanup_locked_stores};
    use crate::quarantine_cleanup::inspection::{FileContentState, inspect_store_quarantine};
    use crate::quarantine_name::{RemovedObjectKind, RetainedTombstoneName};

    fn cleanup_budget() -> QuarantineCleanupBudget {
        let bounded_work = TombstoneWork::new(8, 16, 8);
        cleanup_budget_for_test(1, bounded_work, bounded_work, bounded_work)
    }

    fn quarantine_is_empty(root: &std::path::Path) -> bool {
        fs::read_dir(root.join(".kitrove/removal-quarantine"))
            .unwrap()
            .next()
            .is_none()
    }

    fn create_authoritative_tree_tombstone(quarantine: &Dir) {
        let staged = RetainedTombstoneName {
            kind: RemovedObjectKind::Directory,
        }
        .encode("10112233445566778899aabbccddeeff")
        .unwrap();
        let directory =
            kitrove_windows_security::create_owned_directory(quarantine, &staged).unwrap();
        let nested = kitrove_windows_security::create_owned_directory(
            &directory,
            std::ffi::OsStr::new("nested"),
        )
        .unwrap();
        let mut file =
            kitrove_windows_security::create_owned_file(&nested, std::ffi::OsStr::new("file"))
                .unwrap();
        file.write_all(b"nested contents").unwrap();
        file.sync_all().unwrap();
        let identity = kitrove_windows_security::file_identity(&directory).unwrap();
        drop((file, nested, directory));
        let authoritative = RemovalTombstoneName {
            kind: RemovedObjectKind::Directory,
            identity,
        }
        .encode("20112233445566778899aabbccddeeff")
        .unwrap();
        let rollback = RetainedTombstoneName {
            kind: RemovedObjectKind::Directory,
        }
        .encode("30112233445566778899aabbccddeeff")
        .unwrap();
        kitrove_windows_security::promote_owned_directory(
            quarantine,
            &staged,
            &authoritative,
            &rollback,
            identity,
        )
        .unwrap();
    }

    #[test]
    fn windows_nonempty_file_tombstone_is_deleted_by_the_bounded_batch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        store
            .stage_text(
                &PortablePath::parse("managed").unwrap(),
                "contents remain until exact deletion",
                1024,
            )
            .unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("managed").unwrap())
            .unwrap();
        let mut budget = cleanup_budget();
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        assert!(matches!(
            inspection.candidates(),
            [QuarantineCandidate::File {
                content: FileContentState::NonEmpty,
                disposition: CleanupDisposition::Eligible,
                ..
            }]
        ));

        cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget).unwrap();

        assert!(quarantine_is_empty(&root));
    }

    #[test]
    fn windows_empty_pending_batch_is_promoted_and_recovered() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        store
            .stage_text(
                &PortablePath::parse("managed").unwrap(),
                "pending recovery",
                1024,
            )
            .unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("managed").unwrap())
            .unwrap();
        let quarantine = store.open_existing_removal_quarantine().unwrap().unwrap();
        let pending = CleanupPendingName::encode("40112233445566778899aabbccddeeff").unwrap();
        kitrove_windows_security::create_private_directory(&quarantine, &pending).unwrap();
        let mut budget = cleanup_budget();
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        assert!(
            inspection.candidates().iter().any(|candidate| matches!(
                candidate,
                QuarantineCandidate::EmptyPendingBatch { .. }
            ))
        );

        cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget).unwrap();

        assert!(quarantine_is_empty(&root));
    }

    #[test]
    fn windows_interrupted_nested_batch_is_reinspected_and_resumed() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        store
            .stage_text(
                &PortablePath::parse("seed").unwrap(),
                "create quarantine",
                1024,
            )
            .unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("seed").unwrap())
            .unwrap();
        let quarantine = store.open_existing_removal_quarantine().unwrap().unwrap();
        let seed_name = quarantine
            .entries()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name();
        let seed_authority = RemovalTombstoneName::parse(&seed_name).unwrap();
        kitrove_windows_security::delete_owned_single_link_file(
            &quarantine,
            &seed_name,
            seed_authority.identity,
        )
        .unwrap();
        sync_directory(&quarantine).unwrap();
        create_authoritative_tree_tombstone(&quarantine);
        let mut budget = cleanup_budget();
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();
        let mut rename =
            |source: &Dir, source_name: &OsStr, destination: &Dir, destination_name: &OsStr| {
                rename_noreplace(source, source_name, destination, destination_name)
            };
        let mut sync_file = |file: &cap_std::fs::File| file.sync_all().map_err(|_| ());
        let mut before_isolated_unlink = |_: &Dir, _: &OsStr| {};
        let mut deletion_count = 0usize;
        let mut after_synced_deletion = || {
            deletion_count += 1;
            Err(())
        };
        let mut after_staging = || {};
        let mut after_validation = || {};

        assert_eq!(
            cleanup_inspected_quarantines_with_hooks(
                &[(&store, &inspection)],
                &mut budget,
                &mut CleanupOperations {
                    rename: &mut rename,
                    sync_file: &mut sync_file,
                    before_isolated_unlink: &mut before_isolated_unlink,
                    after_synced_deletion: &mut after_synced_deletion,
                    after_staging: &mut after_staging,
                    after_validation: &mut after_validation,
                },
            ),
            Err(QuarantineCleanupError::MutationFailed)
        );
        assert_eq!(deletion_count, 1);
        let mut recovery_budget = cleanup_budget();
        let recovery = inspect_store_quarantine(&store, &mut recovery_budget).unwrap();
        assert!(
            recovery
                .candidates()
                .iter()
                .any(|candidate| matches!(candidate, QuarantineCandidate::InterruptedBatch { .. }))
        );

        cleanup_inspected_quarantines(&[(&store, &recovery)], &mut recovery_budget).unwrap();

        assert!(quarantine_is_empty(&root));
    }

    #[test]
    fn windows_empty_directory_tombstone_is_deleted_by_the_bounded_batch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        store
            .create_empty_directory_for_test(&PortablePath::parse("staging").unwrap())
            .unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_empty_directory_if_present(&PortablePath::parse("staging").unwrap())
            .unwrap();
        let mut budget = cleanup_budget();
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget).unwrap();

        assert!(quarantine_is_empty(&root));
    }

    #[test]
    fn windows_transaction_coordinator_reclaims_before_forward_work() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        store
            .stage_text(
                &PortablePath::parse("managed").unwrap(),
                "coordinator",
                1024,
            )
            .unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("managed").unwrap())
            .unwrap();

        cleanup_locked_stores(&[&store], MutationWork::none(), MutationWork::none()).unwrap();

        assert!(quarantine_is_empty(&root));
    }

    #[test]
    fn windows_legacy_retained_authority_blocks_the_batch_without_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let store = ObjectStore::open(&root).unwrap();
        store
            .stage_text(&PortablePath::parse("managed").unwrap(), "retained", 1024)
            .unwrap();
        let _locks = ObjectStore::try_lock_distinct_roots(&[&store]).unwrap();
        store
            .remove_regular_file_if_present(&PortablePath::parse("managed").unwrap())
            .unwrap();
        let quarantine = root.join(".kitrove/removal-quarantine");
        let original = fs::read_dir(&quarantine)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let retained = RetainedTombstoneName {
            kind: RemovedObjectKind::File,
        }
        .encode("00112233445566778899aabbccddeeff")
        .unwrap();
        fs::rename(&original, quarantine.join(&retained)).unwrap();
        let retained_bytes = fs::read(quarantine.join(&retained)).unwrap();
        let mut budget = cleanup_budget();
        let inspection = inspect_store_quarantine(&store, &mut budget).unwrap();

        assert_eq!(
            cleanup_inspected_quarantines(&[(&store, &inspection)], &mut budget),
            Err(QuarantineCleanupError::UnsafeState)
        );
        let remaining = fs::read_dir(&quarantine)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(remaining, [retained]);
        assert_eq!(
            fs::read(quarantine.join(&remaining[0])).unwrap(),
            retained_bytes
        );
    }
}
