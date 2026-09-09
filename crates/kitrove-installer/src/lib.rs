#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;
#[cfg(any(unix, windows))]
use std::path::PathBuf;

use kitrove_release_policy::ParsedReleaseManifest;
use kitrove_release_provenance::AuthenticatedApplicationExecutable;

#[cfg(any(unix, windows))]
mod command;

/// Runs the offline installer command line without downloading artifacts.
#[cfg(any(unix, windows))]
pub fn main_entry() -> std::process::ExitCode {
    match command::run(std::env::args_os().skip(1)) {
        Ok(message) => {
            println!("{message}");
            std::process::ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(any(unix, windows))]
mod install_phase;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Archived inspection and explicit synchronization; public history commands remain separate.
mod installation_history;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// State-bound installation remains internal until fresh recovery and public CLI integration.
mod installation_state;
mod record;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Local-file intake is internal until the public installer commands are integrated.
mod release_intake;
#[cfg(any(unix, windows))]
mod replacement_direction;
#[cfg(unix)]
mod replacement_phase;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Internal until the complete upgrade transaction and recovery record are integrated.
mod rollback_kit;
#[cfg(any(unix, windows))]
mod staging_policy;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Internal until the owning upgrade transaction and public root selection are integrated.
mod state_preflight;
#[cfg(unix)]
mod unix_history;
#[cfg(unix)]
#[allow(dead_code)]
// Kept internal until lifecycle-lock and state-preflight integration is complete.
mod unix_install;
#[cfg(unix)]
mod unix_recovery;
#[cfg(unix)]
mod unix_staging;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Internal until the complete existing-binary replacement transaction is integrated.
mod upgrade_precondition;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// State-bound preparation is not replacement or fresh recovery authority by itself.
mod upgrade_record;
#[cfg(any(unix, windows))]
#[allow(dead_code)]
// Internal until guarded replacement and fresh offline recovery are complete.
mod upgrade_transaction;
#[cfg(windows)]
#[allow(dead_code)]
// Kept internal until crash recovery and the public installer entry point are complete.
mod windows_install;
#[cfg(windows)]
mod windows_recovery;
#[cfg(windows)]
mod windows_staging;
#[cfg(all(test, windows))]
mod windows_test_support;

pub use record::{
    InstallerOperationPhase, InstallerOperationRecord, InvalidInstallerOperationRecord,
    NativeFileIdentity, UnverifiedInstallerOperationRecord,
};

#[cfg(any(unix, windows))]
const INSTALLER_STATE_DIRECTORY: &str = ".kitrove-installer";
#[cfg(any(unix, windows))]
const INSTALLER_HISTORY_DIRECTORY: &str = ".kitrove-installer-history";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerStageError {
    UnsupportedPlatform,
    TargetMismatch,
    UnsafeDestination,
    UnsafeState,
    Conflict,
    DestinationOccupied,
    IncompatibleUpgrade,
    WriteFailed,
    VerificationFailed,
    RecoveryRequired,
}

impl fmt::Display for InstallerStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "application staging is unsupported on this platform",
            Self::TargetMismatch => "release target does not match this installer",
            Self::UnsafeDestination => "installer destination authority is unsafe",
            Self::UnsafeState => "installer state authority is unsafe",
            Self::Conflict => "installer operation identifier already exists",
            Self::DestinationOccupied => "application destination is already occupied",
            Self::IncompatibleUpgrade => {
                "requested replacement lacks declared release compatibility"
            }
            Self::WriteFailed => "installer staging write failed",
            Self::VerificationFailed => "installed application verification failed",
            Self::RecoveryRequired => "installer staging failed and requires guarded recovery",
        })
    }
}

impl std::error::Error for InstallerStageError {}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct InstalledApplication {
    record: InstallerOperationRecord,
    manifest: ParsedReleaseManifest,
    path: PathBuf,
}

#[cfg(any(unix, windows))]
impl InstalledApplication {
    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(any(unix, windows))]
fn verify_installed_application(
    path: &Path,
    expected: &semver::Version,
) -> Result<kitrove_model::ContentHash, InstallerStageError> {
    kitrove_version_probe::probe_application_version(path, expected)
        .map(|verified| verified.executable_hash().clone())
        .map_err(|_| InstallerStageError::VerificationFailed)
}

/// A prepared executable and operation record retained through open capabilities.
pub struct StagedApplication {
    record: InstallerOperationRecord,
    manifest: ParsedReleaseManifest,
    #[cfg(any(unix, windows))]
    executable_content_hash: kitrove_model::ContentHash,
    #[cfg(unix)]
    _retained: unix_staging::RetainedStage,
    #[cfg(windows)]
    _retained: windows_staging::RetainedStage,
}

#[cfg(any(unix, windows))]
struct StagingInput<'a> {
    target: &'a str,
    archive_name: &'a str,
    archive_sha256: [u8; 32],
    executable_name: &'a str,
    executable_sha256: [u8; 32],
    executable_bytes: &'a [u8],
    release_tag: &'a str,
    release_version: String,
    source_commit: &'a str,
    signer_identity: &'a str,
    attestation_bundle_sha256: [u8; 32],
    trust_root_sha256: [u8; 32],
    manifest: ParsedReleaseManifest,
    manifest_sha256: [u8; 32],
}

#[cfg(any(unix, windows))]
impl<'a> From<&'a AuthenticatedApplicationExecutable> for StagingInput<'a> {
    fn from(executable: &'a AuthenticatedApplicationExecutable) -> Self {
        let subject = executable.subject();
        Self {
            target: subject.spec().target(),
            archive_name: subject.spec().archive_name(),
            archive_sha256: subject.archive_sha256(),
            executable_name: subject.spec().executable_name(),
            executable_sha256: executable.executable_sha256(),
            executable_bytes: executable.bytes(),
            release_tag: subject.release_tag(),
            release_version: subject.release_version().to_string(),
            source_commit: subject.source_commit(),
            signer_identity: subject.signer_identity(),
            attestation_bundle_sha256: subject.attestation_bundle_sha256(),
            trust_root_sha256: subject.trust_root_sha256(),
            manifest: executable.manifest().clone(),
            manifest_sha256: executable.manifest_sha256(),
        }
    }
}

impl StagedApplication {
    #[must_use]
    pub const fn record(&self) -> &InstallerOperationRecord {
        &self.record
    }

    #[must_use]
    pub const fn manifest(&self) -> &ParsedReleaseManifest {
        &self.manifest
    }
}

impl fmt::Debug for StagedApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedApplication")
            .field("record", &self.record)
            .field("retained_capabilities", &true)
            .finish()
    }
}

/// Stages one authenticated executable without replacing the installed binary.
pub fn stage_authenticated_application(
    destination_parent: &Path,
    executable: &AuthenticatedApplicationExecutable,
) -> Result<StagedApplication, InstallerStageError> {
    require_compiled_target(executable)?;
    #[cfg(unix)]
    {
        unix_staging::stage(destination_parent, &StagingInput::from(executable))
    }
    #[cfg(windows)]
    {
        windows_staging::stage(destination_parent, &StagingInput::from(executable))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (destination_parent, executable);
        Err(InstallerStageError::UnsupportedPlatform)
    }
}

/// Reopens and reauthenticates one complete retained staging operation.
///
/// Incomplete or ambiguous state is preserved for explicit guarded cleanup.
pub fn resume_authenticated_application_staging(
    destination_parent: &Path,
    executable: &AuthenticatedApplicationExecutable,
) -> Result<StagedApplication, InstallerStageError> {
    require_compiled_target(executable)?;
    #[cfg(unix)]
    {
        unix_recovery::resume(destination_parent, &StagingInput::from(executable))
    }
    #[cfg(windows)]
    {
        windows_recovery::resume(destination_parent, &StagingInput::from(executable))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (destination_parent, executable);
        Err(InstallerStageError::UnsupportedPlatform)
    }
}

#[cfg(any(unix, windows))]
fn require_current_user_installation() -> Result<(), InstallerStageError> {
    #[cfg(unix)]
    {
        unix_staging::require_unprivileged_process()
    }
    #[cfg(windows)]
    {
        kitrove_windows_security::require_unelevated_process()
            .map_err(|_| InstallerStageError::UnsafeDestination)
    }
}

fn require_compiled_target(
    executable: &AuthenticatedApplicationExecutable,
) -> Result<(), InstallerStageError> {
    if executable.subject().spec().target() == compiled_release_target()? {
        Ok(())
    } else {
        Err(InstallerStageError::TargetMismatch)
    }
}

fn compiled_release_target() -> Result<&'static str, InstallerStageError> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        _ => Err(InstallerStageError::UnsupportedPlatform),
    }
}

#[cfg(all(test, any(unix, windows)))]
#[path = "test_support.rs"]
mod test_support;

#[cfg(all(test, any(unix, windows), debug_assertions))]
#[path = "../test-fixtures/release_archive.rs"]
mod release_archive_fixture;
