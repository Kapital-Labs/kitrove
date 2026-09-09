//! Shared executable evidence only; callers retain namespace, journal and state guards.

use super::{Layout, RETAINED_PRIOR};
use crate::staging_policy::{STAGED_EXECUTABLE, require_absent_entry};
use crate::upgrade_precondition::ReplacementPrecondition;
use crate::windows_staging as filesystem;
use crate::{InstallerStageError, NativeFileIdentity, StagedApplication};
use std::ffi::OsStr;
use std::fs::File;

pub(in crate::upgrade_transaction) fn location(
    staged: &StagedApplication,
    candidate: bool,
    layout: Layout,
) -> Result<(&File, &str), InstallerStageError> {
    if (candidate && layout == Layout::Published) || (!candidate && layout == Layout::Original) {
        Ok((
            staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            staged.record.executable_name(),
        ))
    } else {
        Ok((
            &staged._retained.operation,
            if candidate {
                STAGED_EXECUTABLE
            } else {
                RETAINED_PRIOR
            },
        ))
    }
}

pub(in crate::upgrade_transaction) fn evidence(
    staged: &StagedApplication,
    prior: &ReplacementPrecondition<'_>,
    candidate: bool,
) -> (NativeFileIdentity, u64, [u8; 32]) {
    if candidate {
        (
            *staged.record.staged_identity(),
            staged.record.executable_size(),
            staged.manifest.executable_sha256(),
        )
    } else {
        let executable = prior.rollback().executable();
        (
            prior.prior_identity(),
            executable.bytes().len() as u64,
            executable.executable_sha256(),
        )
    }
}

pub(in crate::upgrade_transaction) fn require(
    staged: &StagedApplication,
    prior: &ReplacementPrecondition<'_>,
    prior_file: Option<&File>,
    layout: Layout,
) -> Result<(), InstallerStageError> {
    for candidate in [false, true] {
        let (parent, name) = location(staged, candidate, layout)?;
        let (identity, size, digest) = evidence(staged, prior, candidate);
        let file = if candidate {
            staged._retained.executable()?
        } else {
            prior_file.ok_or(InstallerStageError::RecoveryRequired)?
        };
        require_leaf(parent, name, file, identity, size, digest)?;
    }
    if layout == Layout::Gap {
        require_absent_entry(
            staged
                ._retained
                .destination
                .directory()
                .map_err(|_| InstallerStageError::RecoveryRequired)?,
            staged.record.executable_name(),
        )?;
    }
    Ok(())
}

pub(in crate::upgrade_transaction) fn require_leaf(
    parent: &File,
    name: &str,
    file: &File,
    identity: NativeFileIdentity,
    size: u64,
    digest: [u8; 32],
) -> Result<(), InstallerStageError> {
    filesystem::require_identity(file, identity)?;
    kitrove_windows_security::inspect_private_single_link_file(file)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    filesystem::require_named_file_identity(parent, OsStr::new(name), identity, false)?;
    filesystem::require_file_contents(file, size, digest)?;
    filesystem::require_named_file_identity(parent, OsStr::new(name), identity, false)
}

pub(in crate::upgrade_transaction) fn synchronize(
    staged: &mut StagedApplication,
    prior: &ReplacementPrecondition<'_>,
    prior_file: &mut Option<File>,
    layout: Layout,
) -> Result<(), InstallerStageError> {
    require(staged, prior, prior_file.as_ref(), layout)?;
    for candidate in [false, true] {
        let held = if candidate {
            staged._retained.executable.take()
        } else {
            prior_file.take()
        }
        .ok_or(InstallerStageError::RecoveryRequired)?;
        let (_, size, digest) = evidence(staged, prior, candidate);
        let (parent, name) = location(staged, candidate, layout)?;
        let synced =
            filesystem::flush_retained_private_file(parent, OsStr::new(name), held, size, digest)?;
        if candidate {
            staged._retained.executable = Some(synced);
        } else {
            *prior_file = Some(synced);
        }
    }
    require(staged, prior, prior_file.as_ref(), layout)
}
