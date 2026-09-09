use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::Path;

use cap_std::fs::Dir;

use crate::install_phase::{
    InstallPhase, InstallPhaseRecord, InstallRecoveryPhase, MAX_PHASE_RECORD_BYTES,
};
use crate::staging_policy::{OpenedLeaf, RecoveryKind};
use crate::windows_staging::{file_identity, require_exact_inventory, require_named_file_identity};
use crate::{InstallerStageError, StagedApplication, StagingInput};

struct InterruptedPhaseWrite {
    name: &'static str,
    leaf: OpenedLeaf,
}

#[path = "windows_recovery_root.rs"]
pub(crate) mod root;

pub(crate) fn resume(
    destination_parent: &Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    resume_install_phase(destination_parent, input, InstallRecoveryPhase::Prepared)
}

#[cfg(test)]
fn resume_after_security_preflight(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    before_final_rebind: impl FnOnce() -> Result<(), InstallerStageError>,
) -> Result<StagedApplication, InstallerStageError> {
    resume_phase_after_security_preflight(
        destination_parent,
        input,
        InstallRecoveryPhase::Prepared,
        before_final_rebind,
    )
}

pub(crate) fn resume_install_phase(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    phase: InstallRecoveryPhase,
) -> Result<StagedApplication, InstallerStageError> {
    kitrove_windows_security::require_unelevated_process()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    resume_phase_after_security_preflight(destination_parent, input, phase, || Ok(()))
}

pub(crate) fn resume_phase_after_security_preflight(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    phase: InstallRecoveryPhase,
    before_final_rebind: impl FnOnce() -> Result<(), InstallerStageError>,
) -> Result<StagedApplication, InstallerStageError> {
    resume_detected_phase_after_security_preflight(
        destination_parent,
        input,
        Some(phase),
        before_final_rebind,
    )
    .map(|(staged, _)| staged)
}

pub(crate) fn resume_detected_phase_after_security_preflight(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    expected_phase: Option<InstallRecoveryPhase>,
    before_final_rebind: impl FnOnce() -> Result<(), InstallerStageError>,
) -> Result<(StagedApplication, InstallRecoveryPhase), InstallerStageError> {
    resume_with_kind(
        destination_parent,
        input,
        expected_phase,
        RecoveryKind::Installation,
        before_final_rebind,
    )
}

pub(crate) fn resume_prepared_upgrade(
    destination_parent: &Path,
    input: &StagingInput<'_>,
) -> Result<StagedApplication, InstallerStageError> {
    kitrove_windows_security::require_unelevated_process()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    resume_with_kind(
        destination_parent,
        input,
        Some(InstallRecoveryPhase::Prepared),
        RecoveryKind::UpgradePreparation,
        || Ok(()),
    )
    .map(|(staged, _)| staged)
}

fn resume_with_kind(
    destination_parent: &Path,
    input: &StagingInput<'_>,
    expected_phase: Option<InstallRecoveryPhase>,
    kind: RecoveryKind,
    before_final_rebind: impl FnOnce() -> Result<(), InstallerStageError>,
) -> Result<(StagedApplication, InstallRecoveryPhase), InstallerStageError> {
    let root = root::RecoveryRoot::open(destination_parent)?;
    let operation = &root.operation;
    // Classification is only a hint. The chosen phase, every marker, and the candidate
    // are authenticated below while the same operation lock remains held.
    let state_bound = kind == RecoveryKind::StateBoundInstallation;
    let pending = if state_bound {
        None
    } else {
        open_interrupted_phase_write(operation)?
    };
    let preserved = if state_bound {
        retained_phase_names(operation)?
    } else {
        Vec::new()
    };
    if kind == RecoveryKind::UpgradePreparation
        && (pending.is_some() || expected_phase != Some(InstallRecoveryPhase::Prepared))
    {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let phase_inventory = |phase: InstallRecoveryPhase| {
        let mut names = phase.inventory();
        names.extend(kind.extra_entries());
        names.extend(pending.as_ref().map(|pending| OsStr::new(pending.name)));
        names.extend(preserved.iter().copied().filter(|name| {
            InstallPhase::all()
                .iter()
                .any(|candidate| *name == OsStr::new(candidate.pending_file_name()))
                || (matches!(
                    phase,
                    InstallRecoveryPhase::RolledBack | InstallRecoveryPhase::RolledBackUnrecorded
                ) && [InstallPhase::Verified, InstallPhase::Committed]
                    .iter()
                    .any(|candidate| *name == OsStr::new(candidate.file_name())))
        }));
        names
    };
    let phase = match expected_phase {
        Some(phase) => phase,
        None => [
            InstallRecoveryPhase::Prepared,
            InstallRecoveryPhase::ReplacedUnrecorded,
            InstallRecoveryPhase::Replaced,
            InstallRecoveryPhase::Verified,
            InstallRecoveryPhase::Committed,
            InstallRecoveryPhase::RolledBack,
            InstallRecoveryPhase::RolledBackUnrecorded,
        ]
        .into_iter()
        .find(|phase| require_exact_inventory(operation, &phase_inventory(*phase)).is_ok())
        .ok_or(InstallerStageError::RecoveryRequired)?,
    };
    require_exact_inventory(operation, &phase_inventory(phase))?;

    let location = match phase {
        InstallRecoveryPhase::Prepared => root::CandidateLocation::Staged,
        InstallRecoveryPhase::RolledBack | InstallRecoveryPhase::RolledBackUnrecorded => {
            root::CandidateLocation::Failed
        }
        _ => root::CandidateLocation::Installed,
    };
    let candidate = root.candidate(input, location)?;
    let record = &candidate.record;

    let mut phase_markers = Vec::with_capacity(phase.marker_phases().len());
    for marker_phase in phase.marker_phases() {
        let marker = open_bounded_private_file(
            operation,
            OsStr::new(marker_phase.file_name()),
            MAX_PHASE_RECORD_BYTES as u64,
        )?;
        let bytes = read_bounded_file(&marker.file, MAX_PHASE_RECORD_BYTES)?;
        InstallPhaseRecord::parse_canonical(&bytes)?.require_matches(&InstallPhaseRecord::new(
            *marker_phase,
            record,
            *record.staged_identity(),
            input.executable_sha256,
        )?)?;
        phase_markers.push(marker.file);
    }

    before_final_rebind()?;
    candidate.revalidate(&root, input)?;
    require_exact_inventory(operation, &phase_inventory(phase))?;
    let mut staged = candidate.into_stage(root, input)?;
    staged._retained.phase_markers = phase_markers;
    let installed_name = match phase {
        InstallRecoveryPhase::Prepared
        | InstallRecoveryPhase::RolledBack
        | InstallRecoveryPhase::RolledBackUnrecorded => None,
        _ => Some(input.executable_name),
    };
    let base_inventory = phase.inventory();
    let extra_entries = phase_inventory(phase)
        .into_iter()
        .filter(|name| !base_inventory.contains(name))
        .collect::<Vec<_>>();
    crate::windows_install::revalidate_stage_with_extra_entries(
        &staged,
        phase,
        installed_name,
        &extra_entries,
    )?;
    if let Some(pending) = pending {
        require_named_file_identity(
            &staged._retained.operation,
            OsStr::new(pending.name),
            pending.leaf.identity,
            false,
        )?;
        let identity = kitrove_windows_security::file_identity(&pending.leaf.file)
            .map_err(|_| InstallerStageError::RecoveryRequired)?;
        // The pending bytes are never authority. Delete only this authenticated,
        // bounded private leaf after binding the complete operation and candidate.
        drop(pending.leaf.file);
        kitrove_windows_security::delete_owned_single_link_file(
            &staged._retained.operation,
            OsStr::new(pending.name),
            identity,
        )
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
        crate::windows_install::revalidate_stage(&staged, phase, installed_name)?;
    }
    Ok((staged, phase))
}

fn open_interrupted_phase_write(
    operation: &std::fs::File,
) -> Result<Option<InterruptedPhaseWrite>, InstallerStageError> {
    let directory = Dir::from_std_file(
        operation
            .try_clone()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    let mut pending = None;
    for phase in InstallPhase::all() {
        let name = phase.pending_file_name();
        match directory.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(InstallerStageError::RecoveryRequired),
            Ok(_) => {}
        }
        if pending.is_some() {
            return Err(InstallerStageError::RecoveryRequired);
        }
        pending = Some(InterruptedPhaseWrite {
            name,
            leaf: open_bounded_private_file(
                operation,
                OsStr::new(name),
                MAX_PHASE_RECORD_BYTES as u64,
            )?,
        });
    }
    Ok(pending)
}

fn retained_operation_name(state: &std::fs::File) -> Result<OsString, InstallerStageError> {
    let directory = Dir::from_std_file(
        state
            .try_clone()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    let entries = directory
        .entries()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    crate::staging_policy::retained_operation_name(
        entries.map(|entry| entry.map(|entry| entry.file_name())),
    )
}

pub(crate) fn open_bounded_private_file(
    parent: &std::fs::File,
    name: &OsStr,
    maximum: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    let leaf = open_pending_private_file(parent, name, maximum)?;
    if leaf.size == 0 {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(leaf)
}

pub(crate) fn open_pending_private_file(
    parent: &std::fs::File,
    name: &OsStr,
    maximum: u64,
) -> Result<OpenedLeaf, InstallerStageError> {
    let file = kitrove_windows_security::open_private_file(parent, name)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    let size = file
        .metadata()
        .map_err(|_| InstallerStageError::RecoveryRequired)?
        .len();
    if size > maximum {
        return Err(InstallerStageError::RecoveryRequired);
    }
    let identity = file_identity(&file)?;
    require_named_file_identity(parent, name, identity, false)?;
    Ok(OpenedLeaf {
        file,
        identity,
        size,
    })
}

pub(crate) fn read_bounded_file(
    file: &std::fs::File,
    maximum: usize,
) -> Result<Vec<u8>, InstallerStageError> {
    let bytes = read_pending_file(file, maximum)?;
    if bytes.is_empty() {
        return Err(InstallerStageError::RecoveryRequired);
    }
    Ok(bytes)
}

pub(crate) fn read_pending_file(
    file: &std::fs::File,
    maximum: usize,
) -> Result<Vec<u8>, InstallerStageError> {
    let mut reader = file
        .try_clone()
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    let limit = u64::try_from(maximum)
        .map_err(|_| InstallerStageError::RecoveryRequired)?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum);
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| InstallerStageError::RecoveryRequired)?;
    if bytes.len() > maximum {
        Err(InstallerStageError::RecoveryRequired)
    } else {
        Ok(bytes)
    }
}

/// This filesystem snapshot is read-only; the owning caller must bind selected state and journals.
pub(crate) fn resume_state_bound_install(
    destination: &Path,
    input: &StagingInput<'_>,
) -> Result<(StagedApplication, InstallRecoveryPhase), InstallerStageError> {
    kitrove_windows_security::require_unelevated_process()
        .map_err(|_| InstallerStageError::UnsafeDestination)?;
    resume_with_kind(
        destination,
        input,
        None,
        RecoveryKind::StateBoundInstallation,
        || Ok(()),
    )
}

fn retained_phase_names(
    operation: &std::fs::File,
) -> Result<Vec<&'static OsStr>, InstallerStageError> {
    let directory = Dir::from_std_file(
        operation
            .try_clone()
            .map_err(|_| InstallerStageError::RecoveryRequired)?,
    );
    let mut names = Vec::new();
    for phase in InstallPhase::all() {
        for name in [phase.file_name(), phase.pending_file_name()] {
            match directory.symlink_metadata(name) {
                Ok(_) => names.push(OsStr::new(name)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(InstallerStageError::RecoveryRequired),
            }
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::INSTALLER_STATE_DIRECTORY;
    use crate::staging_policy::{OPERATION_RECORD, STAGED_EXECUTABLE};
    use crate::windows_staging::stage_after_security_preflight_for_tests;
    use crate::windows_test_support::{authenticated_executable, destination, inventory};

    fn staged_operation(
        destination: &Path,
    ) -> (
        kitrove_release_provenance::AuthenticatedApplicationExecutable,
        std::path::PathBuf,
    ) {
        let executable = authenticated_executable();
        let staged =
            stage_after_security_preflight_for_tests(destination, &StagingInput::from(&executable))
                .unwrap();
        let operation = destination
            .join(INSTALLER_STATE_DIRECTORY)
            .join(staged.record().operation_id());
        drop(staged);
        (executable, operation)
    }

    #[test]
    fn upgrade_preparation_inventory_is_distinct_and_preserves_pending_phase_bytes() {
        let destination = destination();
        let (executable, operation) = staged_operation(destination.path());
        kitrove_windows_security::ensure_private_directory_for_tests(
            &operation.join(crate::rollback_kit::ROLLBACK_DIRECTORY),
        )
        .unwrap();
        kitrove_windows_security::write_current_user_owned_file_for_tests(
            &operation.join(crate::upgrade_record::UPGRADE_RECORD),
            b"not yet authenticated",
        )
        .unwrap();
        let input = StagingInput::from(&executable);
        assert!(resume_after_security_preflight(destination.path(), &input, || Ok(())).is_err());
        // This helper authenticates candidate staging only. The owning recovery
        // path must separately authenticate the kit, prior and upgrade record.
        let (staged, phase) = resume_with_kind(
            destination.path(),
            &input,
            Some(InstallRecoveryPhase::Prepared),
            RecoveryKind::UpgradePreparation,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(phase, InstallRecoveryPhase::Prepared);
        drop(staged);
        let pending = operation.join(InstallPhase::Replaced.pending_file_name());
        kitrove_windows_security::write_current_user_owned_file_for_tests(&pending, b"partial")
            .unwrap();
        assert!(
            resume_with_kind(
                destination.path(),
                &input,
                Some(InstallRecoveryPhase::Prepared),
                RecoveryKind::UpgradePreparation,
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(std::fs::read(pending).unwrap(), b"partial");
    }

    #[test]
    fn partial_phase_bytes_are_discarded_only_after_authentication() {
        for phase in InstallPhase::all() {
            let destination = destination();
            let (executable, operation) = staged_operation(destination.path());
            let pending = operation.join(phase.pending_file_name());
            kitrove_windows_security::write_current_user_owned_file_for_tests(
                &pending,
                b"{partial",
            )
            .unwrap();
            let mut wrong_input = StagingInput::from(&executable);
            wrong_input.source_commit = "ffffffffffffffffffffffffffffffffffffffff";
            assert!(
                resume_after_security_preflight(destination.path(), &wrong_input, || Ok(()))
                    .is_err()
            );
            assert_eq!(std::fs::read(&pending).unwrap(), b"{partial");
            let resumed = resume_after_security_preflight(
                destination.path(),
                &StagingInput::from(&executable),
                || Ok(()),
            )
            .unwrap();
            assert!(!pending.exists());
            assert_eq!(
                inventory(&operation),
                vec![
                    OsString::from(STAGED_EXECUTABLE),
                    OsString::from(OPERATION_RECORD)
                ]
            );
            drop(resumed);
        }
    }

    #[test]
    fn pending_cleanup_is_refused_after_a_final_inventory_race() {
        let destination = destination();
        let (executable, operation) = staged_operation(destination.path());
        let pending = operation.join(InstallPhase::Replaced.pending_file_name());
        kitrove_windows_security::write_current_user_owned_file_for_tests(&pending, b"partial")
            .unwrap();
        let mut reached = false;
        assert!(
            resume_after_security_preflight(
                destination.path(),
                &StagingInput::from(&executable),
                || {
                    reached = true;
                    std::fs::write(operation.join("foreign"), b"foreign").unwrap();
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(reached);
        assert_eq!(std::fs::read(pending).unwrap(), b"partial");
        assert_eq!(
            std::fs::read(operation.join("foreign")).unwrap(),
            b"foreign"
        );
    }

    #[test]
    fn ambiguous_or_oversized_pending_records_are_retained() {
        for multiple in [false, true] {
            let destination = destination();
            let (executable, operation) = staged_operation(destination.path());
            let pending = operation.join(InstallPhase::Replaced.pending_file_name());
            let bytes = vec![
                b'x';
                if multiple {
                    1
                } else {
                    MAX_PHASE_RECORD_BYTES + 1
                }
            ];
            kitrove_windows_security::write_current_user_owned_file_for_tests(&pending, &bytes)
                .unwrap();
            if multiple {
                kitrove_windows_security::write_current_user_owned_file_for_tests(
                    &operation.join(InstallPhase::Verified.pending_file_name()),
                    b"partial",
                )
                .unwrap();
            }
            let before = inventory(&operation);
            assert!(
                resume_after_security_preflight(
                    destination.path(),
                    &StagingInput::from(&executable),
                    || Ok(())
                )
                .is_err()
            );
            assert_eq!(std::fs::read(pending).unwrap(), bytes);
            assert_eq!(inventory(&operation), before);
        }
    }

    #[test]
    fn resumes_one_exact_authenticated_prepared_operation() {
        let destination = destination();
        let (executable, operation) = staged_operation(destination.path());
        let operation_id = operation.file_name().unwrap().to_str().unwrap().to_owned();

        let resumed = resume_after_security_preflight(
            destination.path(),
            &StagingInput::from(&executable),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(resumed.record().operation_id(), operation_id);
        assert_eq!(
            inventory(&operation),
            vec![
                OsString::from(STAGED_EXECUTABLE),
                OsString::from(OPERATION_RECORD)
            ]
        );
    }

    #[test]
    fn live_staging_guard_blocks_resume() {
        let destination = destination();
        let executable = authenticated_executable();
        let _staged = stage_after_security_preflight_for_tests(
            destination.path(),
            &StagingInput::from(&executable),
        )
        .unwrap();

        assert!(matches!(
            resume_after_security_preflight(
                destination.path(),
                &StagingInput::from(&executable),
                || Ok(())
            ),
            Err(InstallerStageError::Conflict)
        ));
    }

    #[test]
    fn changed_record_executable_and_authority_never_rebind() {
        for changed in ["record", "executable", "authority"] {
            let destination = destination();
            let (executable, operation) = staged_operation(destination.path());
            let mut input = StagingInput::from(&executable);
            match changed {
                "record" => std::fs::write(operation.join(OPERATION_RECORD), b"{}").unwrap(),
                "executable" => {
                    let path = operation.join(STAGED_EXECUTABLE);
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes[0] ^= 1;
                    std::fs::write(path, bytes).unwrap();
                }
                "authority" => {
                    input.source_commit = "ffffffffffffffffffffffffffffffffffffffff";
                }
                _ => unreachable!(),
            }

            assert_eq!(
                resume_after_security_preflight(destination.path(), &input, || Ok(())).unwrap_err(),
                InstallerStageError::UnsafeState,
            );
            assert!(operation.exists());
        }
    }

    #[test]
    fn ambiguous_inventory_is_preserved_for_guarded_cleanup() {
        let destination = destination();
        let (executable, operation) = staged_operation(destination.path());
        std::fs::write(operation.join("foreign"), b"foreign").unwrap();

        assert!(matches!(
            resume_after_security_preflight(
                destination.path(),
                &StagingInput::from(&executable),
                || Ok(())
            ),
            Err(InstallerStageError::RecoveryRequired)
        ));
        assert!(operation.join("foreign").exists());
        assert!(operation.join(STAGED_EXECUTABLE).exists());
        assert!(operation.join(OPERATION_RECORD).exists());
    }

    #[test]
    fn final_rebind_rejects_a_hardlink_race_without_cleanup() {
        let destination = destination();
        let (executable, operation) = staged_operation(destination.path());
        let foreign = destination.path().join("foreign-link");
        let result = resume_after_security_preflight(
            destination.path(),
            &StagingInput::from(&executable),
            || {
                std::fs::hard_link(operation.join(STAGED_EXECUTABLE), &foreign).unwrap();
                Ok(())
            },
        );

        assert!(matches!(result, Err(InstallerStageError::UnsafeState)));
        assert!(foreign.exists());
        assert!(operation.join(STAGED_EXECUTABLE).exists());
        assert!(operation.join(OPERATION_RECORD).exists());
    }
}
