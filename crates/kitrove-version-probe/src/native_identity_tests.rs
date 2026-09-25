//! Operator-only native evidence using reviewed-source test code, never a download.
#![cfg(target_os = "macos")]
use super::{InspectionFailure, ProbeProcess, receive_probe_output, spawn_output_reader};
use kitrove_macos_process::{SuspendedSelf, SystemVerifier};
use kitrove_release_policy::native_signature::AppleProcessIdentityCandidate;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

enum Operation<'a> {
    DisplaySelf,
    Verify {
        pid: u32,
        identity: &'a AppleProcessIdentityCandidate,
    },
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
) -> Result<(bool, String), InspectionFailure> {
    verifier
        .revalidate()
        .map_err(|_| InspectionFailure::Failed)?;
    remaining(deadline)?;
    let anchor = SuspendedSelf::spawn().map_err(|_| InspectionFailure::Failed)?;
    let mut command = Command::new(verifier.path());
    command
        .env_clear()
        .current_dir("/")
        .process_group(anchor.id())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let child = command.spawn().map_err(|_| InspectionFailure::Failed)?;
    let mut process = ProbeProcess::with_suspended_anchor(child, anchor)?;
    let stdout = spawn_output_reader(process.take_stdout()?, 4096)?;
    let stderr = spawn_output_reader(process.take_stderr()?, 4096)?;
    let status = process.wait_bounded(remaining(deadline)?)?;
    process.terminate_remaining_group()?;
    let stdout = receive_probe_output(stdout, remaining(deadline)?)?;
    let stderr = receive_probe_output(stderr, remaining(deadline)?)?;
    verifier
        .revalidate()
        .map_err(|_| InspectionFailure::Failed)?;
    remaining(deadline)?;
    if !stdout.is_empty() {
        return Err(InspectionFailure::InvalidOutput);
    }
    Ok((status.success(), stderr))
}

#[test]
#[ignore = "operator-only: requires native signed source-built test executable"]
fn bounded_native_verifier_binds_self_and_rejects_wrong_suspended_identity() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let verifier = SystemVerifier::open().unwrap();
    let (success, detail) = inspect(&verifier, Operation::DisplaySelf, deadline).unwrap();
    assert!(success);
    let identity = AppleProcessIdentityCandidate::from_display(detail.as_bytes())
        .expect("bounded display must provide one identity candidate");
    let (success, stderr) = inspect(
        &verifier,
        Operation::Verify {
            pid: std::process::id(),
            identity: &identity,
        },
        deadline,
    )
    .unwrap();
    assert!(
        success && stderr.is_empty(),
        "current process must match captured identity"
    );

    let child = SuspendedSelf::spawn().unwrap();
    let pid = u32::try_from(child.id()).unwrap();
    let matched = inspect(
        &verifier,
        Operation::Verify {
            pid,
            identity: &identity,
        },
        deadline,
    );
    let wrong = AppleProcessIdentityCandidate::from_display(
        b"CDHash=0000000000000000000000000000000000000000\n",
    )
    .unwrap();
    let refused = inspect(
        &verifier,
        Operation::Verify {
            pid,
            identity: &wrong,
        },
        deadline,
    );
    // Always explicitly kill/reap before asserting verifier outcomes. There is no
    // resume operation; the helper cannot run its internal argument or test body.
    child.terminate().unwrap();
    let (success, stderr) = matched.unwrap();
    assert!(
        success && stderr.is_empty(),
        "suspended child must match executing self"
    );
    assert!(
        !refused.unwrap().0,
        "wrong exact identity must fail native verification"
    );
}
