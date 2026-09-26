//! Bounded owned native inspection, not provenance or installer readiness.
//! The caller must already trust this executing verifier and the system runtime.
use super::{InspectionFailure, ProbeProcess, receive_probe_output, spawn_output_reader};
use kitrove_macos_process::{
    AnchoredSuspendedSelf, InspectionTransport, SuspendedSelf, SystemVerifier,
};
use kitrove_macos_signature::{ExchangeProgress, InspectionExchange};
use kitrove_release_policy::apple_code_directory::AppleSignatureCandidate;
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

/// Owns the exact suspended child whose identity matched the executing verifier.
/// Private ownership prevents substituting another child after verification.
/// A separate suspended anchor retains its group independently of worker exit.
/// This does not authenticate first execution. Only a bound request can be run.
pub struct VerifiedSuspendedSelf {
    child: AnchoredSuspendedSelf,
    transport: InspectionTransport,
    deadline: Instant,
}

impl VerifiedSuspendedSelf {
    /// Bind one fixed inspection request to this exact owned child and transport.
    /// Preserves the identity-check deadline, rather than starting a fresh budget.
    /// The candidate remains untrusted; this neither resumes nor grants readiness.
    pub fn bind_inspection(
        self,
        path: &std::path::Path,
        candidate: &AppleSignatureCandidate,
    ) -> Result<PreparedInspection, IdentityRefused> {
        self.bind_exchange(|deadline| {
            InspectionExchange::new(path, candidate, deadline).map_err(|_| IdentityRefused)
        })
    }

    fn bind_exchange(
        self,
        build: impl FnOnce(Instant) -> Result<InspectionExchange, IdentityRefused>,
    ) -> Result<PreparedInspection, IdentityRefused> {
        remaining(self.deadline).map_err(|_| IdentityRefused)?;
        let exchange = build(self.deadline)?;
        remaining(self.deadline).map_err(|_| IdentityRefused)?;
        Ok(PreparedInspection {
            verified: self,
            exchange,
        })
    }

    /// Terminate the retained child and confirm reaping; failure stays redacted.
    pub fn terminate(self) -> Result<(), IdentityRefused> {
        let Self {
            child, transport, ..
        } = self;
        drop(transport);
        child.terminate().map_err(|_| IdentityRefused)
    }

    fn run_operation(
        mut self,
        mut poll: impl FnMut(&mut InspectionTransport) -> Result<ExchangeProgress, IdentityRefused>,
    ) -> Result<(), IdentityRefused> {
        let result = self.drive_operation(&mut poll);
        // Cleanup is required even after framing, exit, deadline or transport refusal.
        let cleanup = self.terminate();
        result.and(cleanup)
    }

    fn drive_operation(
        &mut self,
        poll: &mut impl FnMut(&mut InspectionTransport) -> Result<ExchangeProgress, IdentityRefused>,
    ) -> Result<(), IdentityRefused> {
        remaining(self.deadline).map_err(|_| IdentityRefused)?;
        self.child
            .resume_owned_worker_once()
            .map_err(|_| IdentityRefused)?;
        let mut framed = false;
        loop {
            remaining(self.deadline).map_err(|_| IdentityRefused)?;
            if !framed {
                framed = poll(&mut self.transport)? == ExchangeProgress::Framed;
            }
            let exit = self.child.poll_exit().map_err(|_| IdentityRefused)?;
            let budget = remaining(self.deadline).map_err(|_| IdentityRefused)?;
            if let Some(status) = exit {
                if !status.success() {
                    return Err(IdentityRefused);
                }
                if framed {
                    return Ok(());
                }
            }
            std::thread::sleep(budget.min(Duration::from_millis(5)));
        }
    }
}

/// Request, exact verified child and transport are retained behind one owner.
/// No descriptor or child substitution interface is exposed.
/// Payload authentication and retained-file revalidation remain caller obligations.
pub struct PreparedInspection {
    verified: VerifiedSuspendedSelf,
    exchange: InspectionExchange,
}

impl PreparedInspection {
    /// Run the fixed request, requiring exact framing, successful worker exit and
    /// confirmed cleanup. Uses the original identity-check deadline; cleanup has
    /// its own bounded budget. Success is native inspection only, not provenance,
    /// authenticated payload binding, executable publication or installer readiness.
    pub fn inspect_native(self) -> Result<(), IdentityRefused> {
        let Self {
            verified,
            mut exchange,
        } = self;
        verified.run_operation(|transport| exchange.poll(transport).map_err(|_| IdentityRefused))
    }

    pub fn terminate(self) -> Result<(), IdentityRefused> {
        let Self { verified, exchange } = self;
        drop(exchange);
        verified.terminate()
    }
}

/// Capture and check self identity, then spawn and check the retained child under
/// one inspection deadline. Refusal drops the child and attempts bounded cleanup.
/// The caller must independently trust this process before calling this function.
/// Only the reviewed standalone cooperative-launch contract is supported; foreign
/// or embedding-runtime launches outside the shared gate are not covered.
pub fn prepare_verified_suspended_self() -> Result<VerifiedSuspendedSelf, IdentityRefused> {
    let deadline = Instant::now() + DEADLINE;
    let verifier = SystemVerifier::open().map_err(|_| IdentityRefused)?;
    let identity = capture_candidate(&verifier, deadline).map_err(|_| IdentityRefused)?;
    remaining(deadline).map_err(|_| IdentityRefused)?;
    let (child, transport) =
        AnchoredSuspendedSelf::spawn_with_transport().map_err(|_| IdentityRefused)?;
    bind_child(&verifier, child, transport, &identity, deadline).map_err(|_| IdentityRefused)
}

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
    capture_candidate(&verifier, deadline).map_err(|_| IdentityRefused)
}

fn capture_candidate(
    verifier: &SystemVerifier,
    deadline: Instant,
) -> Result<AppleProcessIdentityCandidate, InspectionFailure> {
    let detail = inspect(verifier, Operation::DisplaySelf, deadline)?;
    let identity = AppleProcessIdentityCandidate::from_display(detail.as_bytes())
        .map_err(|_| InspectionFailure::InvalidOutput)?;
    inspect(
        verifier,
        Operation::Verify {
            pid: std::process::id(),
            identity: &identity,
        },
        deadline,
    )?;
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
    inspect_child_id(&verifier, child.id(), identity, deadline).map_err(|_| IdentityRefused)
}

fn remaining(deadline: Instant) -> Result<Duration, InspectionFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(InspectionFailure::Timeout)
}

fn bind_child(
    verifier: &SystemVerifier,
    child: AnchoredSuspendedSelf,
    transport: InspectionTransport,
    identity: &AppleProcessIdentityCandidate,
    deadline: Instant,
) -> Result<VerifiedSuspendedSelf, InspectionFailure> {
    inspect_child_id(verifier, child.id(), identity, deadline)?;
    Ok(VerifiedSuspendedSelf {
        child,
        transport,
        deadline,
    })
}

fn inspect_child_id(
    verifier: &SystemVerifier,
    owned_child_id: i32,
    identity: &AppleProcessIdentityCandidate,
    deadline: Instant,
) -> Result<(), InspectionFailure> {
    let pid = u32::try_from(owned_child_id).map_err(|_| InspectionFailure::Failed)?;
    inspect(verifier, Operation::Verify { pid, identity }, deadline)?;
    Ok(())
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

    fn retain_outputs(transport: &InspectionTransport) -> [rustix::fd::OwnedFd; 2] {
        [transport.output(), transport.error()]
            .map(|fd| rustix::io::fcntl_dupfd_cloexec(fd, 3).unwrap())
    }

    fn assert_outputs_closed(outputs: [rustix::fd::OwnedFd; 2]) {
        for output in outputs {
            assert_eq!(rustix::io::read(&output, &mut [0]).unwrap(), 0);
        }
    }

    #[test]
    fn request_binding_refusal_preserves_deadline_and_cleans_owned_resources() {
        for expired in [false, true] {
            let (child, transport) = AnchoredSuspendedSelf::spawn_with_transport().unwrap();
            let pid = rustix::process::Pid::from_raw(child.id()).unwrap();
            let outputs = retain_outputs(&transport);
            let deadline = if expired {
                Instant::now()
            } else {
                Instant::now() + DEADLINE
            };
            // Ownership-only fixture: deliberately does not claim native verification.
            let fixture = VerifiedSuspendedSelf {
                child,
                transport,
                deadline,
            };
            let mut called = false;
            let result = fixture.bind_exchange(|observed| {
                called = true;
                assert_eq!(observed, deadline);
                Err(IdentityRefused)
            });
            assert!(result.is_err());
            assert_eq!(called, !expired);
            assert_outputs_closed(outputs);
            assert_eq!(
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
                    .unwrap_err(),
                rustix::io::Errno::CHILD
            );
        }
    }

    #[test]
    fn expired_binding_reaps_the_owned_suspended_child() {
        let verifier = SystemVerifier::open().unwrap();
        let (child, transport) = AnchoredSuspendedSelf::spawn_with_transport().unwrap();
        let outputs = retain_outputs(&transport);
        let pid = rustix::process::Pid::from_raw(child.id()).unwrap();
        let identity = AppleProcessIdentityCandidate::from_display(
            b"CDHash=0000000000000000000000000000000000000000\n",
        )
        .unwrap();
        assert!(matches!(
            bind_child(&verifier, child, transport, &identity, Instant::now()),
            Err(InspectionFailure::Timeout)
        ));
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
        assert_outputs_closed(outputs);
    }

    #[test]
    #[ignore = "operator-only: requires native signed source-built test executable"]
    fn wrong_identity_binding_cleans_the_anchored_worker() {
        let verifier = SystemVerifier::open().unwrap();
        let (child, transport) = AnchoredSuspendedSelf::spawn_with_transport().unwrap();
        let outputs = retain_outputs(&transport);
        let pid = rustix::process::Pid::from_raw(child.id()).unwrap();
        let identity = AppleProcessIdentityCandidate::from_display(
            b"CDHash=0000000000000000000000000000000000000000\n",
        )
        .unwrap();
        assert!(
            bind_child(
                &verifier,
                child,
                transport,
                &identity,
                Instant::now() + DEADLINE
            )
            .is_err()
        );
        assert_outputs_closed(outputs);
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    #[ignore = "operator-only: requires native signed source-built test executable"]
    fn verified_owner_drop_reaps_the_exact_suspended_child() {
        let verified = prepare_verified_suspended_self().unwrap();
        let pid = rustix::process::Pid::from_raw(verified.child.id()).unwrap();
        let outputs = retain_outputs(&verified.transport);
        for output in &outputs {
            assert_eq!(
                rustix::io::read(output, &mut [0]),
                Err(rustix::io::Errno::AGAIN)
            );
        }
        drop(verified);
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
        assert_outputs_closed(outputs);
    }

    #[test]
    #[ignore = "operator-only: requires native signed source-built test executable"]
    fn verified_owner_termination_closes_transport_and_reaps_child() {
        let verified = prepare_verified_suspended_self().unwrap();
        let pid = rustix::process::Pid::from_raw(verified.child.id()).unwrap();
        let outputs = retain_outputs(&verified.transport);
        verified.terminate().unwrap();
        assert_outputs_closed(outputs);
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    fn expired_operation_never_polls_and_reaps_worker() {
        let (child, transport) = AnchoredSuspendedSelf::spawn_with_transport().unwrap();
        let pid = rustix::process::Pid::from_raw(child.id()).unwrap();
        let outputs = retain_outputs(&transport);
        // Ownership-only fixture; expiration must refuse before continuation.
        let fixture = VerifiedSuspendedSelf {
            child,
            transport,
            deadline: Instant::now(),
        };
        assert_eq!(
            fixture.run_operation(|_| panic!("expired operation must not poll")),
            Err(IdentityRefused)
        );
        assert_outputs_closed(outputs);
        assert_eq!(
            rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG).unwrap_err(),
            rustix::io::Errno::CHILD
        );
    }

    #[test]
    #[ignore = "operator-only: requires native signed source-built test executable"]
    fn verified_operation_refusal_and_failed_exit_both_reap_worker() {
        for transport_refuses in [true, false] {
            let verified = prepare_verified_suspended_self().unwrap();
            let pid = rustix::process::Pid::from_raw(verified.child.id()).unwrap();
            // The source-built libtest executable rejects the fixed helper flag.
            // Even simulated complete framing cannot turn its failure into success.
            assert_eq!(
                verified.run_operation(|_| {
                    if transport_refuses {
                        Err(IdentityRefused)
                    } else {
                        Ok(ExchangeProgress::Framed)
                    }
                }),
                Err(IdentityRefused)
            );
            assert_eq!(
                rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
                    .unwrap_err(),
                rustix::io::Errno::CHILD
            );
        }
    }

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
