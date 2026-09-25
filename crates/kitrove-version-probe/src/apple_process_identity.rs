//! Bounded native identity checks, not provenance or permission to resume a child.
//! The caller must already trust this executing verifier and the system runtime.
use super::{InspectionFailure, ProbeProcess, receive_probe_output, spawn_output_reader};
use kitrove_macos_process::{SuspendedSelf, SystemVerifier};
use kitrove_release_policy::native_signature::AppleProcessIdentityCandidate;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(15);
const OUTPUT_LIMIT: usize = 4096;

/// Redacted refusal. No partial identity, native output or execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityRefused;
impl std::fmt::Display for IdentityRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native process identity refused")
    }
}
impl std::error::Error for IdentityRefused {}

enum Operation<'a> {
    DisplaySelf,
    Verify {
        pid: u32,
        identity: &'a AppleProcessIdentityCandidate,
    },
}

/// Capture this process's candidate and dynamically check it before returning.
/// This does not independently authenticate this process's first execution.
pub fn capture_self_candidate() -> Result<AppleProcessIdentityCandidate, IdentityRefused> {
    let deadline = Instant::now() + DEADLINE;
    let verifier = SystemVerifier::open().map_err(|_| IdentityRefused)?;
    let detail =
        inspect(&verifier, Operation::DisplaySelf, deadline).map_err(|_| IdentityRefused)?;
    let identity = AppleProcessIdentityCandidate::from_display(detail.as_bytes())
        .map_err(|_| IdentityRefused)?;
    inspect(
        &verifier,
        Operation::Verify {
            pid: std::process::id(),
            identity: &identity,
        },
        deadline,
    )
    .map_err(|_| IdentityRefused)?;
    Ok(identity)
}

/// Dynamically match an owned suspended child to the supplied exact candidate.
/// Ownership remains with the caller. Success neither resumes nor authenticates
/// provenance; the caller must bind the candidate to an independently trusted self.
pub fn verify_suspended_child(
    child: &SuspendedSelf,
    identity: &AppleProcessIdentityCandidate,
) -> Result<(), IdentityRefused> {
    let deadline = Instant::now() + DEADLINE;
    let verifier = SystemVerifier::open().map_err(|_| IdentityRefused)?;
    let pid = u32::try_from(child.id()).map_err(|_| IdentityRefused)?;
    inspect(&verifier, Operation::Verify { pid, identity }, deadline)
        .map_err(|_| IdentityRefused)?;
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, InspectionFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(InspectionFailure::Timeout)
}

fn inspect(
    verifier: &SystemVerifier,
    operation: Operation<'_>,
    deadline: Instant,
) -> Result<String, InspectionFailure> {
    verifier
        .revalidate()
        .map_err(|_| InspectionFailure::Failed)?;
    remaining(deadline)?;
    let mut command = Command::new(verifier.path());
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let display = matches!(operation, Operation::DisplaySelf);
    match operation {
        Operation::DisplaySelf => {
            command
                .args(["--display", "--verbose=4"])
                .arg(std::process::id().to_string());
        }
        Operation::Verify { pid, identity } => {
            command
                .args(["--verify", "-R"])
                .arg(identity.exact_requirement())
                .arg(pid.to_string());
        }
    }
    let mut process = ProbeProcess::spawn_anchored(&mut command)?;
    let stdout = spawn_output_reader(process.take_stdout()?, OUTPUT_LIMIT)?;
    let stderr = spawn_output_reader(process.take_stderr()?, OUTPUT_LIMIT)?;
    let status = process.wait_bounded(remaining(deadline)?)?;
    process.terminate_remaining_group()?;
    let stdout = receive_probe_output(stdout, remaining(deadline)?)?;
    let stderr = receive_probe_output(stderr, remaining(deadline)?)?;
    verifier
        .revalidate()
        .map_err(|_| InspectionFailure::Failed)?;
    remaining(deadline)?;
    if !status.success() || !stdout.is_empty() || (!display && !stderr.is_empty()) {
        return Err(InspectionFailure::InvalidOutput);
    }
    Ok(stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_deadline_refuses_before_launch() {
        let verifier = SystemVerifier::open().unwrap();
        assert_eq!(
            inspect(&verifier, Operation::DisplaySelf, Instant::now()),
            Err(InspectionFailure::Timeout)
        );
    }

    #[test]
    fn refusal_does_not_expose_native_diagnostics() {
        assert_eq!(
            IdentityRefused.to_string(),
            "native process identity refused"
        );
    }
}
