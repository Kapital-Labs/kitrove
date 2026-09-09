#![forbid(unsafe_code)]
//! The single reviewed boundary for bounded local executable version inspection.

use std::fmt::{self, Display, Formatter};
use std::path::Path;
#[cfg(any(unix, windows))]
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

#[cfg(unix)]
use std::env;
#[cfg(windows)]
use std::ffi::OsString;
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
#[cfg(unix)]
use std::fs::{self, File};
#[cfg(any(unix, windows))]
use std::io::Read;
#[cfg(unix)]
use std::io::{Seek as _, SeekFrom};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
#[cfg(unix)]
use std::process::{Child, Command, ExitStatus, Stdio};
#[cfg(any(unix, windows))]
use std::sync::mpsc::{self, Receiver};
#[cfg(any(unix, windows))]
use std::thread;

use kitrove_adapter_api::VerifiedVersionEvidence;
#[cfg(any(unix, windows))]
use kitrove_adapter_api::{EvidenceRef, HarnessVersion, PolicyLine};
use kitrove_model::ContentHash;
#[cfg(any(unix, windows))]
use kitrove_model::HarnessId;
#[cfg(any(unix, windows, test))]
use semver::{Version, VersionReq};
#[cfg(unix)]
use wait_timeout::ChildExt as _;

#[cfg(any(unix, windows))]
const MAX_PROBE_OUTPUT_BYTES: usize = 4096;
#[cfg(any(unix, windows))]
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(any(unix, windows, test))]
const PI_VERSION_REQUIREMENT: &str = ">=0.79.0, <1.0.0";
#[cfg(all(any(unix, windows), not(test)))]
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(all(any(unix, windows), test))]
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(any(unix, windows))]
const OUTPUT_READER_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(any(unix, windows))]
const PI_PROBE_ENVIRONMENT: &[(&str, &str)] =
    &[("PI_OFFLINE", "1"), ("PI_SKIP_VERSION_CHECK", "1")];
#[cfg(any(unix, windows))]
const OPENCODE_PROBE_ENVIRONMENT: &[(&str, &str)] = &[
    ("OPENCODE_DISABLE_AUTOUPDATE", "1"),
    ("OPENCODE_DISABLE_PROJECT_CONFIG", "1"),
];

/// A stable, user-facing failure from the reviewed probe boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeError {
    code: &'static str,
    message: &'static str,
}

/// A reviewed harness version-probe identity selected solely from an exact binary name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionProbeKind {
    Pi,
    OpenCodeV2,
}

/// Classifies an explicit probe path without inspecting or executing it.
#[must_use]
pub fn classify_version_probe_binary(binary: &Path) -> Option<VersionProbeKind> {
    let name = binary.file_name().and_then(std::ffi::OsStr::to_str)?;
    #[cfg(windows)]
    {
        if name.eq_ignore_ascii_case("pi.exe") {
            Some(VersionProbeKind::Pi)
        } else if name.eq_ignore_ascii_case("opencode2.exe") {
            Some(VersionProbeKind::OpenCodeV2)
        } else {
            None
        }
    }
    #[cfg(not(windows))]
    {
        match name {
            "pi" | "pi.exe" => Some(VersionProbeKind::Pi),
            "opencode2" | "opencode2.exe" => Some(VersionProbeKind::OpenCodeV2),
            _ => None,
        }
    }
}

impl ProbeError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Display for ProbeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ProbeError {}

/// Opaque proof that the exact selected Pi executable produced a reviewed version.
///
/// Production callers cannot construct this type from claimed evidence. They can only receive it
/// from [`probe_pi_version`], which binds the observation to a safely opened executable identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPiVersion {
    evidence: VerifiedVersionEvidence,
    executable_hash: ContentHash,
}

impl VerifiedPiVersion {
    #[must_use]
    pub const fn evidence(&self) -> &VerifiedVersionEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn executable_hash(&self) -> &ContentHash {
        &self.executable_hash
    }
}

/// Opaque proof that the exact selected OpenCode V2 executable identified itself as V2.
///
/// OpenCode publishes V2 as the separate `opencode2` executable. Production callers cannot
/// construct this type from a version claim; they can only receive it from
/// [`probe_opencode_v2_version`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOpenCodeV2Version {
    evidence: VerifiedVersionEvidence,
    executable_hash: ContentHash,
}

/// Opaque proof that one exact KitRove executable reported the expected release version.
#[cfg(any(unix, windows))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedApplicationVersion {
    version: Version,
    executable_hash: ContentHash,
}

#[cfg(any(unix, windows))]
impl VerifiedApplicationVersion {
    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }

    #[must_use]
    pub const fn executable_hash(&self) -> &ContentHash {
        &self.executable_hash
    }
}

impl VerifiedOpenCodeV2Version {
    #[must_use]
    pub const fn evidence(&self) -> &VerifiedVersionEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn executable_hash(&self) -> &ContentHash {
        &self.executable_hash
    }
}

/// Executes one explicitly selected Pi binary under the reviewed bounded probe policy.
pub fn probe_pi_version(binary: &Path) -> Result<VerifiedPiVersion, ProbeError> {
    validate_probe_target(binary, VersionProbeKind::Pi)?;
    #[cfg(not(any(unix, windows)))]
    return Err(ProbeError::new(
        "version.probe_platform_unsupported",
        "executable-bound harness version probing is not yet supported on this platform",
    ));
    #[cfg(any(unix, windows))]
    {
        let (observed, executable_hash) = probe_version(binary, PI_PROBE_ENVIRONMENT)?;
        verified_pi_version(observed.trim(), executable_hash)
    }
}

/// Executes one explicitly selected OpenCode V2 binary under the reviewed bounded probe policy.
pub fn probe_opencode_v2_version(binary: &Path) -> Result<VerifiedOpenCodeV2Version, ProbeError> {
    validate_probe_target(binary, VersionProbeKind::OpenCodeV2)?;
    #[cfg(not(any(unix, windows)))]
    return Err(ProbeError::new(
        "version.probe_platform_unsupported",
        "executable-bound harness version probing is not yet supported on this platform",
    ));
    #[cfg(any(unix, windows))]
    {
        let (observed, executable_hash) = probe_version(binary, OPENCODE_PROBE_ENVIRONMENT)?;
        verified_opencode_v2_version(observed.trim(), executable_hash)
    }
}

/// Executes one explicit KitRove binary under the reviewed bounded probe policy.
///
/// The expected version is authenticated release authority supplied by the caller. The probe is
/// supplementary behavior evidence and never authenticates executable bytes by itself. Unix
/// pathname launch follows KitRove's documented current-user trust boundary: parent authority and
/// bytes are rebound before and after execution, but another process running as that same user is
/// not treated as an independent adversary.
#[cfg(any(unix, windows))]
pub fn probe_application_version(
    binary: &Path,
    expected: &Version,
) -> Result<VerifiedApplicationVersion, ProbeError> {
    validate_application_probe_target(binary)?;
    let (observed, executable_hash) = probe_version(binary, &[])?;
    let version = parse_application_version(observed.trim())?;
    if &version != expected {
        return Err(ProbeError::new(
            "version.probe_unexpected_application_version",
            "the KitRove executable reported an unexpected release version",
        ));
    }
    Ok(VerifiedApplicationVersion {
        version,
        executable_hash,
    })
}

#[cfg(unix)]
fn probe_version(
    binary: &Path,
    isolated_environment: &[(&str, &str)],
) -> Result<(String, ContentHash), ProbeError> {
    let binary = fs::canonicalize(binary).map_err(|_| probe_binary_unsafe())?;
    let mut executable = open_executable(&binary)?;
    let before = hash_open_executable(&mut executable)?;
    require_same_opened_executable(&binary, &executable)?;
    let launch_path = validated_launch_path(&mut executable)?;
    let mut command = Command::new(&binary);
    command
        .process_group(0)
        .env_clear()
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in isolated_environment {
        command.env(name, value);
    }
    inherit_launch_environment(&mut command, launch_path.as_deref());

    let child = command.spawn().map_err(|_| probe_failed())?;
    let mut process = ProbeProcess::new(child)?;
    let stdout = spawn_output_reader(process.take_stdout()?)?;
    let stderr = spawn_output_reader(process.take_stderr()?)?;
    let status = process.wait_bounded()?;
    process.terminate_remaining_group()?;
    let stdout = receive_probe_output(stdout)?;
    let stderr = receive_probe_output(stderr)?;
    if !status.success() {
        return Err(ProbeError::new(
            "version.probe_failed",
            "the harness version probe did not exit successfully",
        ));
    }
    if !stderr.is_empty() {
        return Err(invalid_output());
    }
    let after = hash_open_executable(&mut executable)?;
    require_same_opened_executable(&binary, &executable)?;
    if before != after {
        return Err(ProbeError::new(
            "version.probe_binary_changed",
            "the harness executable changed during the version probe",
        ));
    }
    Ok((stdout, before))
}

#[cfg(windows)]
fn probe_version(
    binary: &Path,
    isolated_environment: &[(&str, &str)],
) -> Result<(String, ContentHash), ProbeError> {
    use kitrove_windows_process::{LaunchRequest, launch_contained};
    use kitrove_windows_security::{validate_executable_path, validated_system_launch_directory};

    let executable = validate_executable_path(binary).map_err(|_| probe_binary_unsafe())?;
    let working_directory =
        validated_system_launch_directory().map_err(|_| probe_binary_unsafe())?;
    let before = hash_validated_windows_executable(&executable)?;
    executable
        .revalidate_path_identity()
        .map_err(|_| probe_binary_unsafe())?;
    let arguments = [OsString::from("--version")];
    let environment: Vec<(OsString, OsString)> = isolated_environment
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect();
    let mut process = launch_contained(LaunchRequest {
        executable: &executable,
        working_directory: &working_directory,
        arguments: &arguments,
        environment: &environment,
    })
    .map_err(|_| probe_failed())?;
    let stdout = spawn_output_reader(process.take_stdout().map_err(|_| probe_failed())?)?;
    let stderr = spawn_output_reader(process.take_stderr().map_err(|_| probe_failed())?)?;
    let deadline = Instant::now()
        .checked_add(PROBE_TIMEOUT)
        .ok_or_else(probe_failed)?;
    let status = process.wait_until(deadline).map_err(|error| {
        use kitrove_windows_process::ContainedProcessFailure;
        match error.kind() {
            ContainedProcessFailure::Timeout => ProbeError::new(
                "version.probe_timeout",
                "the harness version probe did not finish within the time limit",
            ),
            ContainedProcessFailure::Cleanup => termination_failed(),
            ContainedProcessFailure::Failed => probe_failed(),
        }
    })?;
    let stdout = receive_probe_output(stdout)?;
    let stderr = receive_probe_output(stderr)?;
    if !status.success() {
        return Err(ProbeError::new(
            "version.probe_failed",
            "the harness version probe did not exit successfully",
        ));
    }
    if !stderr.is_empty() {
        return Err(invalid_output());
    }
    let after = hash_validated_windows_executable(&executable)?;
    executable
        .revalidate_path_identity()
        .map_err(|_| probe_binary_unsafe())?;
    if before != after {
        return Err(ProbeError::new(
            "version.probe_binary_changed",
            "the harness executable changed during the version probe",
        ));
    }
    Ok((stdout, before))
}

#[cfg(windows)]
fn hash_validated_windows_executable(
    executable: &kitrove_windows_security::ValidatedExecutable,
) -> Result<ContentHash, ProbeError> {
    executable
        .read_executable(hash_executable_reader)
        .map_err(|_| probe_binary_unsafe())?
}

#[cfg(any(unix, windows))]
fn verified_pi_version(
    observed: &str,
    executable_hash: ContentHash,
) -> Result<VerifiedPiVersion, ProbeError> {
    let observed = parse_pi_version(observed)?;
    let hash_suffix = executable_hash
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(probe_failed)?;
    let evidence = EvidenceRef::parse(format!("local.version_probe.pi.blake3.{hash_suffix}"))
        .map_err(|_| probe_failed())?;
    let evidence = VerifiedVersionEvidence::new(
        HarnessId::Pi,
        HarnessVersion::parse(observed.to_owned()).map_err(|_| invalid_output())?,
        PolicyLine::PiLatest,
        evidence,
    )
    .map_err(|_| invalid_output())?;
    Ok(VerifiedPiVersion {
        evidence,
        executable_hash,
    })
}

#[cfg(any(unix, windows))]
fn verified_opencode_v2_version(
    observed: &str,
    executable_hash: ContentHash,
) -> Result<VerifiedOpenCodeV2Version, ProbeError> {
    let observed = parse_opencode_v2_version(observed)?;
    let hash_suffix = executable_hash
        .as_str()
        .strip_prefix("blake3:")
        .ok_or_else(probe_failed)?;
    let evidence = EvidenceRef::parse(format!(
        "local.version_probe.opencode_v2.blake3.{hash_suffix}"
    ))
    .map_err(|_| probe_failed())?;
    let evidence = VerifiedVersionEvidence::new(
        HarnessId::OpenCode,
        HarnessVersion::parse(observed.to_owned()).map_err(|_| invalid_output())?,
        PolicyLine::OpenCodeV2,
        evidence,
    )
    .map_err(|_| invalid_output())?;
    Ok(VerifiedOpenCodeV2Version {
        evidence,
        executable_hash,
    })
}

#[cfg(any(unix, windows, test))]
fn parse_pi_version(output: &str) -> Result<&str, ProbeError> {
    let observed = parse_single_line(output)?;
    if observed.split_whitespace().count() != 1 {
        return Err(invalid_output());
    }
    let version_text = observed.strip_prefix('v').unwrap_or(observed);
    let version = Version::parse(version_text).map_err(|_| invalid_output())?;
    if VersionReq::parse(PI_VERSION_REQUIREMENT)
        .expect("compiled Pi version requirement")
        .matches(&version)
    {
        Ok(observed)
    } else {
        Err(ProbeError::new(
            "version.probe_policy_unsupported",
            "the observed Pi version does not select the reviewed project-trust policy",
        ))
    }
}

#[cfg(any(unix, windows, test))]
fn parse_opencode_v2_version(output: &str) -> Result<&str, ProbeError> {
    let observed = parse_single_line(output)?;
    let version_text = observed
        .strip_prefix("opencode2 v")
        .ok_or_else(invalid_output)?;
    if version_text.split_whitespace().count() != 1 {
        return Err(invalid_output());
    }
    Version::parse(version_text).map_err(|_| invalid_output())?;
    Ok(observed)
}

#[cfg(any(unix, windows))]
fn parse_application_version(output: &str) -> Result<Version, ProbeError> {
    let observed = parse_single_line(output)?;
    let version = observed
        .strip_prefix("kitrove ")
        .ok_or_else(invalid_output)?;
    if version.split_whitespace().count() != 1 {
        return Err(invalid_output());
    }
    Version::parse(version).map_err(|_| invalid_output())
}

#[cfg(any(unix, windows, test))]
fn parse_single_line(output: &str) -> Result<&str, ProbeError> {
    let observed = output.trim();
    if observed.is_empty() || observed.len() > 128 || observed.lines().count() != 1 {
        return Err(invalid_output());
    }
    Ok(observed)
}

fn validate_probe_target(binary: &Path, expected: VersionProbeKind) -> Result<(), ProbeError> {
    if !binary.is_absolute() {
        return Err(ProbeError::new(
            "version.probe_binary_relative",
            "the version probe binary must be an explicit absolute path",
        ));
    }
    if classify_version_probe_binary(binary) != Some(expected) {
        return Err(ProbeError::new(
            "version.probe_binary_name_invalid",
            "the explicit version probe binary does not match the selected harness",
        ));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn validate_application_probe_target(binary: &Path) -> Result<(), ProbeError> {
    if !binary.is_absolute() {
        return Err(ProbeError::new(
            "version.probe_binary_relative",
            "the version probe binary must be an explicit absolute path",
        ));
    }
    let name = binary
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(probe_binary_unsafe)?;
    #[cfg(unix)]
    let matches = name == "kitrove";
    #[cfg(windows)]
    let matches = name.eq_ignore_ascii_case("kitrove.exe");
    if matches {
        Ok(())
    } else {
        Err(ProbeError::new(
            "version.probe_binary_name_invalid",
            "the explicit version probe binary is not the KitRove application",
        ))
    }
}

#[cfg(unix)]
fn inherit_launch_environment(command: &mut Command, launch_path: Option<&OsStr>) {
    for name in [
        "HOME",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    ] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(path) = launch_path {
        command.env("PATH", path);
    }
}

#[cfg(unix)]
fn validated_launch_path(file: &mut File) -> Result<Option<OsString>, ProbeError> {
    let path = sanitized_path(env::var_os("PATH").as_deref())?;
    let shebang = read_shebang(file)?;
    let Some(shebang) = shebang else {
        return Ok(path);
    };
    let mut parts = shebang.split_ascii_whitespace();
    let interpreter = parts.next().ok_or_else(probe_binary_unsafe)?;
    if !Path::new(interpreter).is_absolute() {
        return Err(probe_binary_unsafe());
    }
    validate_interpreter(Path::new(interpreter))?;
    if Path::new(interpreter).file_name() == Some(OsStr::new("env")) {
        let command = parts.next().ok_or_else(probe_binary_unsafe)?;
        if command.starts_with('-') || parts.next().is_some() {
            return Err(probe_binary_unsafe());
        }
        let path_value = path.as_deref().ok_or_else(probe_binary_unsafe)?;
        validate_path_interpreter(command, path_value)?;
    }
    Ok(path)
}

#[cfg(unix)]
fn read_shebang(file: &mut File) -> Result<Option<String>, ProbeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| probe_binary_unsafe())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(4096)
        .read_to_end(&mut bytes)
        .map_err(|_| probe_binary_unsafe())?;
    let Some(rest) = bytes.strip_prefix(b"#!") else {
        return Ok(None);
    };
    let line = rest
        .split(|byte| *byte == b'\n' || *byte == b'\r')
        .next()
        .unwrap_or_default();
    let line = std::str::from_utf8(line).map_err(|_| probe_binary_unsafe())?;
    Ok(Some(line.trim().to_owned()))
}

#[cfg(unix)]
fn sanitized_path(path: Option<&OsStr>) -> Result<Option<OsString>, ProbeError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let directories = env::split_paths(path)
        .filter_map(|entry| {
            let canonical = fs::canonicalize(entry).ok()?;
            validate_path_directory(&canonical).ok()?;
            Some(canonical)
        })
        .collect::<Vec<_>>();
    if directories.is_empty() {
        return Ok(None);
    }
    env::join_paths(directories)
        .map(Some)
        .map_err(|_| probe_binary_unsafe())
}

#[cfg(unix)]
fn validate_path_directory(path: &Path) -> Result<(), ProbeError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(path).map_err(|_| probe_binary_unsafe())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !trusted_owner(metadata.uid())
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(probe_binary_unsafe());
    }
    validate_directory_chain(path.parent().ok_or_else(probe_binary_unsafe)?)
}

#[cfg(unix)]
fn validate_path_interpreter(command: &str, path: &OsStr) -> Result<(), ProbeError> {
    if command.contains('/') {
        return Err(probe_binary_unsafe());
    }
    for directory in env::split_paths(path) {
        let candidate = directory.join(command);
        if fs::symlink_metadata(&candidate).is_ok() {
            return validate_interpreter(&candidate);
        }
    }
    Err(probe_binary_unsafe())
}

#[cfg(unix)]
fn validate_interpreter(path: &Path) -> Result<(), ProbeError> {
    let canonical = fs::canonicalize(path).map_err(|_| probe_binary_unsafe())?;
    open_executable(&canonical).map(|_| ())
}

#[cfg(unix)]
struct ProbeProcess {
    child: Child,
    process_group: rustix::process::Pid,
    group_armed: bool,
    reaped: bool,
}

#[cfg(unix)]
impl ProbeProcess {
    fn new(child: Child) -> Result<Self, ProbeError> {
        let process_group = i32::try_from(child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(probe_failed)?;
        Ok(Self {
            child,
            process_group,
            group_armed: true,
            reaped: false,
        })
    }

    fn take_stdout(&mut self) -> Result<std::process::ChildStdout, ProbeError> {
        self.child.stdout.take().ok_or_else(probe_failed)
    }

    fn take_stderr(&mut self) -> Result<std::process::ChildStderr, ProbeError> {
        self.child.stderr.take().ok_or_else(probe_failed)
    }

    fn wait_bounded(&mut self) -> Result<ExitStatus, ProbeError> {
        match self.child.wait_timeout(PROBE_TIMEOUT) {
            Ok(Some(status)) => {
                self.reaped = true;
                Ok(status)
            }
            Ok(None) => {
                self.terminate_group()?;
                Err(ProbeError::new(
                    "version.probe_timeout",
                    "the harness version probe did not finish within the time limit",
                ))
            }
            Err(_) => {
                self.terminate_group()?;
                Err(probe_failed())
            }
        }
    }

    fn terminate_remaining_group(&mut self) -> Result<(), ProbeError> {
        self.signal_group()?;
        self.group_armed = false;
        Ok(())
    }

    fn terminate_group(&mut self) -> Result<(), ProbeError> {
        self.signal_group()?;
        self.group_armed = false;
        if !self.reaped {
            self.child.wait().map_err(|_| termination_failed())?;
            self.reaped = true;
        }
        Ok(())
    }

    fn signal_group(&self) -> Result<(), ProbeError> {
        match rustix::process::kill_process_group(self.process_group, rustix::process::Signal::KILL)
        {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(_) => Err(termination_failed()),
        }
    }
}

#[cfg(unix)]
impl Drop for ProbeProcess {
    fn drop(&mut self) {
        if self.group_armed {
            let _ = self.signal_group();
            self.group_armed = false;
        }
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

#[cfg(unix)]
fn open_executable(path: &Path) -> Result<File, ProbeError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(path).map_err(|_| probe_binary_unsafe())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_EXECUTABLE_BYTES
        || !trusted_owner(metadata.uid())
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(probe_binary_unsafe());
    }
    validate_executable_parent_chain(path)?;
    let file = File::open(path).map_err(|_| probe_binary_unsafe())?;
    require_same_opened_executable(path, &file)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_executable_parent_chain(path: &Path) -> Result<(), ProbeError> {
    validate_directory_chain(path.parent().ok_or_else(probe_binary_unsafe)?)
}

#[cfg(unix)]
fn validate_directory_chain(path: &Path) -> Result<(), ProbeError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut current = path;
    loop {
        let metadata = fs::symlink_metadata(current).map_err(|_| probe_binary_unsafe())?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !trusted_owner(metadata.uid())
            || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & 0o1000 != 0))
        {
            return Err(probe_binary_unsafe());
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent;
    }
    Ok(())
}

#[cfg(unix)]
fn require_same_opened_executable(path: &Path, file: &File) -> Result<(), ProbeError> {
    use std::os::unix::fs::MetadataExt as _;

    let selected = fs::symlink_metadata(path).map_err(|_| probe_binary_unsafe())?;
    let opened = file.metadata().map_err(|_| probe_binary_unsafe())?;
    if selected.file_type().is_symlink()
        || !selected.is_file()
        || selected.dev() != opened.dev()
        || selected.ino() != opened.ino()
        || selected.len() != opened.len()
        || selected.modified().ok() != opened.modified().ok()
    {
        return Err(probe_binary_unsafe());
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_owner(owner: u32) -> bool {
    owner == 0 || owner == rustix::process::geteuid().as_raw()
}

#[cfg(unix)]
fn hash_open_executable(file: &mut File) -> Result<ContentHash, ProbeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| probe_binary_unsafe())?;
    let before = file.metadata().map_err(|_| probe_binary_unsafe())?;
    let hash = hash_executable_reader(file)?;
    let after = file.metadata().map_err(|_| probe_binary_unsafe())?;
    if after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        return Err(probe_binary_unsafe());
    }
    Ok(hash)
}

#[cfg(any(unix, windows))]
fn hash_executable_reader(reader: &mut dyn Read) -> Result<ContentHash, ProbeError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| probe_binary_unsafe())?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| probe_binary_unsafe())?)
            .ok_or_else(probe_binary_unsafe)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(probe_binary_unsafe());
        }
        hasher.update(&buffer[..read]);
    }
    ContentHash::parse(format!("blake3:{}", hasher.finalize().to_hex())).map_err(|_| probe_failed())
}

#[cfg(any(unix, windows))]
fn spawn_output_reader(
    mut output: impl Read + Send + 'static,
) -> Result<Receiver<Result<String, ProbeError>>, ProbeError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("kitrove-version-output".to_owned())
        .spawn(move || {
            let result = read_probe_output(&mut output);
            let _ = sender.send(result);
        })
        .map_err(|_| probe_failed())?;
    Ok(receiver)
}

#[cfg(any(unix, windows))]
fn receive_probe_output(
    receiver: Receiver<Result<String, ProbeError>>,
) -> Result<String, ProbeError> {
    receiver
        .recv_timeout(OUTPUT_READER_TIMEOUT)
        .map_err(|_| probe_failed())?
}

#[cfg(any(unix, windows))]
fn read_probe_output(mut output: impl Read) -> Result<String, ProbeError> {
    let mut bytes = Vec::new();
    output
        .by_ref()
        .take(
            u64::try_from(MAX_PROBE_OUTPUT_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes)
        .map_err(|_| probe_failed())?;
    if bytes.len() > MAX_PROBE_OUTPUT_BYTES {
        return Err(ProbeError::new(
            "version.probe_output_limit",
            "the harness version probe output exceeds the supported bound",
        ));
    }
    String::from_utf8(bytes).map_err(|_| invalid_output())
}

#[cfg(any(unix, windows))]
fn termination_failed() -> ProbeError {
    ProbeError::new(
        "version.probe_termination_failed",
        "the contained harness version process could not be terminated safely",
    )
}

#[cfg(any(unix, windows))]
fn probe_binary_unsafe() -> ProbeError {
    ProbeError::new(
        "version.probe_binary_unsafe",
        "the harness version probe binary could not be verified as a bounded regular executable",
    )
}

#[cfg(any(unix, windows))]
fn probe_failed() -> ProbeError {
    ProbeError::new(
        "version.probe_failed",
        "the harness version probe could not be completed safely",
    )
}

#[cfg(any(unix, windows, test))]
fn invalid_output() -> ProbeError {
    ProbeError::new(
        "version.probe_output_invalid",
        "the harness version probe output is not a reviewed version form",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_version_policy_accepts_only_the_reviewed_security_boundary() {
        for accepted in ["0.79.0\n", "v0.83.0\n", "0.99.1"] {
            assert!(parse_pi_version(accepted).is_ok());
        }
        for rejected in ["0.78.9", "1.0.0", "pi 0.83.0", "0.83.0\nextra", ""] {
            assert!(parse_pi_version(rejected).is_err());
        }
    }

    #[test]
    fn opencode_v2_requires_the_explicit_v2_identity_and_semver_output() {
        for accepted in [
            "opencode2 v0.0.0-beta-18387\n",
            "opencode2 v0.0.0-next-17403",
            "opencode2 v2.0.0",
        ] {
            assert!(parse_opencode_v2_version(accepted).is_ok());
        }
        for rejected in [
            "1.18.20",
            "opencode v1.18.20",
            "opencode2 0.0.0-beta-18387",
            "opencode2 vlocal",
            "opencode2 v0.0.0-next-1\nextra",
            "",
        ] {
            assert!(parse_opencode_v2_version(rejected).is_err());
        }
    }

    #[test]
    fn version_probe_requires_an_explicit_absolute_pi_binary() {
        assert_eq!(
            validate_probe_target(Path::new("pi"), VersionProbeKind::Pi)
                .unwrap_err()
                .code(),
            "version.probe_binary_relative"
        );
        let wrong = if cfg!(windows) {
            std::path::PathBuf::from(r"C:\tools\other.exe")
        } else {
            std::path::PathBuf::from("/tools/other")
        };
        assert_eq!(
            validate_probe_target(&wrong, VersionProbeKind::Pi)
                .unwrap_err()
                .code(),
            "version.probe_binary_name_invalid"
        );
    }

    #[test]
    fn opencode_v2_probe_requires_the_dedicated_binary_name() {
        let binary = if cfg!(windows) {
            Path::new(r"C:\tools\opencode.exe")
        } else {
            Path::new("/tools/opencode")
        };
        assert_eq!(
            validate_probe_target(binary, VersionProbeKind::OpenCodeV2)
                .unwrap_err()
                .code(),
            "version.probe_binary_name_invalid"
        );
    }

    #[cfg(unix)]
    fn probe_script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("pi");
        fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        (root, binary)
    }

    #[cfg(unix)]
    fn named_probe_script(name: &str, body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join(name);
        fs::write(&binary, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        (root, binary)
    }

    #[cfg(unix)]
    fn probe_error_code(binary: &Path) -> &'static str {
        probe_pi_version(binary).unwrap_err().code()
    }

    #[cfg(unix)]
    #[test]
    fn bounded_probe_binds_the_entry_hash() {
        let (_root, binary) = probe_script("printf '0.83.0\\n'");
        let result = probe_pi_version(&binary).unwrap();
        assert_eq!(result.evidence().observed().as_str(), "0.83.0");
        assert!(
            result.evidence().evidence().as_str().ends_with(
                result
                    .executable_hash()
                    .as_str()
                    .trim_start_matches("blake3:")
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn opencode_v2_probe_binds_identity_and_entry_hash() {
        let (_root, binary) = named_probe_script(
            "opencode2",
            "[ \"$OPENCODE_DISABLE_AUTOUPDATE\" = 1 ] || exit 1
             [ \"$OPENCODE_DISABLE_PROJECT_CONFIG\" = 1 ] || exit 1
             printf 'opencode2 v0.0.0-beta-18387\\n'",
        );
        let result = probe_opencode_v2_version(&binary).unwrap();
        assert_eq!(
            result.evidence().observed().as_str(),
            "opencode2 v0.0.0-beta-18387"
        );
        assert_eq!(result.evidence().policy_line(), PolicyLine::OpenCodeV2);
        assert!(
            result.evidence().evidence().as_str().ends_with(
                result
                    .executable_hash()
                    .as_str()
                    .trim_start_matches("blake3:")
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn application_probe_reuses_containment_and_requires_the_authenticated_version() {
        let (_root, binary) = named_probe_script("kitrove", "printf 'kitrove 1.2.3\\n'");
        let expected = Version::new(1, 2, 3);
        let result = probe_application_version(&binary, &expected).unwrap();
        assert_eq!(result.version(), &expected);
        assert!(result.executable_hash().as_str().starts_with("blake3:"));
        assert_eq!(
            probe_application_version(&binary, &Version::new(1, 2, 4))
                .unwrap_err()
                .code(),
            "version.probe_unexpected_application_version"
        );

        let (_wrong_root, wrong_name) =
            named_probe_script("kitrove-other", "printf 'kitrove 1.2.3\\n'");
        assert_eq!(
            probe_application_version(&wrong_name, &expected)
                .unwrap_err()
                .code(),
            "version.probe_binary_name_invalid"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_bounds_runtime_and_both_output_streams() {
        let (_root, binary) = probe_script("while :; do :; done");
        assert_eq!(probe_error_code(&binary), "version.probe_timeout");

        let (_root, binary) =
            probe_script("i=0; while [ \"$i\" -lt 5000 ]; do printf x; i=$((i + 1)); done");
        assert_eq!(probe_error_code(&binary), "version.probe_output_limit");

        let (_root, binary) = probe_script("printf diagnostic >&2; printf '0.83.0\\n'");
        assert_eq!(probe_error_code(&binary), "version.probe_output_invalid");
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_forked_descendants() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("descendant-marker");
        let body = format!(
            "(sleep 2; printf survived > '{}') & while :; do :; done",
            marker.display()
        );
        let (_binary_root, binary) = probe_script(&body);
        assert_eq!(probe_error_code(&binary), "version.probe_timeout");
        thread::sleep(Duration::from_millis(2_100));
        assert!(
            !marker.exists(),
            "a forked probe descendant survived cleanup"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_refuses_an_executable_in_a_shared_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, binary) = probe_script("printf '0.83.0\\n'");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(probe_error_code(&binary), "version.probe_binary_unsafe");
    }

    #[cfg(unix)]
    #[test]
    fn launch_path_excludes_shared_writable_interpreter_authority() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let safe = root.path().join("safe-bin");
        let unsafe_directory = root.path().join("unsafe-bin");
        fs::create_dir(&safe).unwrap();
        fs::create_dir(&unsafe_directory).unwrap();
        fs::set_permissions(&safe, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777)).unwrap();
        let fake_node = unsafe_directory.join("node");
        fs::write(&fake_node, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_node, fs::Permissions::from_mode(0o700)).unwrap();
        let ambient = env::join_paths([&unsafe_directory, &safe]).unwrap();
        let filtered = sanitized_path(Some(&ambient)).unwrap().unwrap();
        assert_eq!(
            env::split_paths(&filtered).collect::<Vec<_>>(),
            vec![fs::canonicalize(&safe).unwrap()]
        );
        assert_eq!(
            validate_path_interpreter("node", &ambient)
                .unwrap_err()
                .code(),
            "version.probe_binary_unsafe"
        );
        assert!(
            sanitized_path(Some(OsStr::new("/tmp"))).unwrap().is_none(),
            "a root-owned sticky directory is safe only as an ancestor, never as a PATH leaf"
        );
    }

    #[cfg(unix)]
    #[test]
    fn probe_does_not_expose_ambient_secret_environment() {
        if env::var_os("KITROVE_ENV_CANARY_HELPER").is_some() {
            let (_root, binary) = probe_script(
                "test -z \"${KITROVE_AMBIENT_SECRET+x}\" || exit 91; printf '0.83.0\\n'",
            );
            probe_pi_version(&binary).unwrap();
            return;
        }
        let status = Command::new(env::current_exe().unwrap())
            .arg("tests::probe_does_not_expose_ambient_secret_environment")
            .arg("--exact")
            .arg("--nocapture")
            .env("KITROVE_ENV_CANARY_HELPER", "1")
            .env("KITROVE_AMBIENT_SECRET", "must-not-cross-boundary")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
