//! The only production command is the parent's closed read-only validation.
use super::{Refused, deadline::Deadline};
use std::io::Write as _;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

#[path = "../../../support/native-inspection/src/bounded_output.rs"]
mod bounded_output;
#[path = "../../../support/native-inspection/src/inspection_failure.rs"]
mod inspection_failure;
#[path = "../../../support/native-inspection/src/unix_process.rs"]
mod unix_process;

struct OwnedResult {
    output: Output,
    _cleanup: unix_process::ConfirmedCleanup,
}

static NEXT_OWNER: AtomicU8 = AtomicU8::new(1);

fn emit_owner(ordinal: u8, finished: bool) -> Result<(), Refused> {
    let line = super::owner::record(ordinal, finished).ok_or(Refused::Native)?;
    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "{line}")
        .and_then(|()| stderr.flush())
        .map_err(|_| Refused::Native)
}

pub(super) fn validate(file: &std::path::Path) -> Result<Output, Refused> {
    let parent = std::env::var("KITROVE_NATIVE_TICKET_DEADLINE_NS");
    let parent = match parent {
        Ok(ref value) => Some(value.as_str()),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err(Refused::Deadline),
    };
    let deadline = Deadline::new(now()?, parent)?;
    with_retained(file, deadline, || {
        let ordinal = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value <= 8).then(|| value + 1)
            })
            .map_err(|_| Refused::Native)?;
        emit_owner(ordinal, false)?;
        // A normal native denial still yields a complete owned result. Launch,
        // timeout, output or cleanup uncertainty never emits a confirmed finish.
        let owned = execute(&mut super::command(file), deadline)?;
        let OwnedResult {
            output,
            _cleanup: proof,
        } = owned;
        let _proof = proof;
        emit_owner(ordinal, true)?;
        Ok(output)
    })
}

fn with_retained<T>(
    file: &std::path::Path,
    deadline: Deadline,
    action: impl FnOnce() -> Result<T, Refused>,
) -> Result<T, Refused> {
    deadline.remaining(now()?)?;
    let mut retained =
        super::super::super::read_bounded_archive(file, false).map_err(|_| Refused::Native)?;
    retained.revalidate().map_err(|_| Refused::Native)?;
    deadline.remaining(now()?)?;
    let outcome = action();
    retained.revalidate().map_err(|_| Refused::Native)?;
    deadline.remaining(now()?)?;
    outcome
}

fn now() -> Result<u64, Refused> {
    let current = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let seconds = u64::try_from(current.tv_sec).map_err(|_| Refused::Deadline)?;
    let nanos = u64::try_from(current.tv_nsec).map_err(|_| Refused::Deadline)?;
    if nanos >= 1_000_000_000 {
        return Err(Refused::Deadline);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(Refused::Deadline)
}

fn execute(command: &mut Command, deadline: Deadline) -> Result<OwnedResult, Refused> {
    // Existing lifecycle cleanup/Drop has finite5-second bounds. Reserve20s of
    // this SAME window, rather than adding a new cleanup lifetime after expiry.
    const CLEANUP_RESERVE: Duration = Duration::from_secs(20);
    deadline
        .remaining(now()?)?
        .checked_sub(CLEANUP_RESERVE)
        .filter(|value| !value.is_zero())
        .ok_or(Refused::Deadline)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process =
        unix_process::ProbeProcess::spawn_anchored(command).map_err(|_| Refused::Native)?;
    let stdout = bounded_output::spawn_output_reader(
        process.take_stdout().map_err(|_| Refused::Native)?,
        256 * 1024,
    )
    .map_err(|_| Refused::Native)?;
    let stderr = bounded_output::spawn_output_reader(
        process.take_stderr().map_err(|_| Refused::Native)?,
        256 * 1024,
    )
    .map_err(|_| Refused::Native)?;
    let wait = deadline
        .remaining(now()?)?
        .checked_sub(CLEANUP_RESERVE)
        .filter(|value| !value.is_zero())
        .ok_or(Refused::Deadline)?;
    let status = process.wait_bounded(wait).map_err(|_| Refused::Native)?;
    let cleanup = process
        .finish_confirmed(deadline.remaining(now()?)?.min(Duration::from_secs(5)))
        .map_err(|_| Refused::Native)?;
    let stdout = bounded_output::receive_probe_output(stdout, deadline.remaining(now()?)?)
        .map_err(|_| Refused::Native)?
        .into_bytes();
    let stderr = bounded_output::receive_probe_output(stderr, deadline.remaining(now()?)?)
        .map_err(|_| Refused::Native)?
        .into_bytes();
    deadline.remaining(now()?)?;
    if stdout.len().saturating_add(stderr.len()) > 256 * 1024 {
        return Err(Refused::Native);
    }
    Ok(OwnedResult {
        output: Output {
            status,
            stdout,
            stderr,
        },
        _cleanup: cleanup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn owned_harmless_exit_keeps_bounded_complete_output() {
        let mut request = Command::new("/bin/echo");
        request.arg("owned-fixture").env_clear();
        let current = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let now = u64::try_from(current.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(current.tv_nsec).unwrap();
        let deadline = Deadline::new(now, None).unwrap();
        assert_eq!(deadline.remaining(now), Ok(Duration::from_secs(60)));
        let result = execute(&mut request, deadline);
        assert!(result.is_ok(), "no owned validation executor exists yet");
        let output = result.unwrap().output;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"owned-fixture\n");
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn expired_owner_does_not_launch() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("must-not-exist");
        let mut request = Command::new("/usr/bin/touch");
        request.arg(&marker).env_clear();
        assert!(execute(&mut request, Deadline::new(100, Some("200")).unwrap()).is_err());
        assert!(!marker.exists());
        assert!(Duration::from_nanos(100) < Duration::from_secs(1));
    }

    #[test]
    fn one_shortened_window_times_out_and_reaps_the_exact_child() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("owned-child.pid");
        let mut request = Command::new("/bin/sh");
        request
            .args([
                "-c",
                "printf '%s' $$ > \"$1\"; exec /bin/sleep 30",
                "fixture",
            ])
            .arg(&marker)
            .env_clear();
        let start = now().unwrap();
        let parent = (start + 21_000_000_000).to_string();
        let deadline = Deadline::new(start, Some(&parent)).unwrap();
        assert!(execute(&mut request, deadline).is_err());
        let pid = std::fs::read_to_string(marker)
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
        assert!(
            deadline.remaining(now().unwrap()).is_ok(),
            "cleanup consumed a new lifetime"
        );
    }

    #[test]
    fn normal_native_denial_is_not_a_launch_or_cleanup_failure() {
        let mut request = Command::new("/bin/sh");
        request
            .args(["-c", "printf bounded >&2; exit 68"])
            .env_clear();
        let result = execute(&mut request, Deadline::new(now().unwrap(), None).unwrap()).unwrap();
        assert_eq!(result.output.status.code(), Some(68));
        assert_eq!(result.output.stderr, b"bounded");
    }

    #[test]
    fn closed_environment_removes_ambient_and_explicit_overrides() {
        let mut request = Command::new("/usr/bin/env");
        request.env("KITROVE_TEST_OVERRIDE", "PRIVATE_ENV_CANARY");
        super::super::closed_environment(&mut request);
        let result = execute(&mut request, Deadline::new(now().unwrap(), None).unwrap()).unwrap();
        let output = String::from_utf8(result.output.stdout).unwrap();
        assert!(!output.contains("PRIVATE_ENV_CANARY"));
        let values: std::collections::BTreeSet<_> = output.lines().collect();
        assert_eq!(
            values,
            ["LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn live_descendants_are_stopped_before_output_is_accepted() {
        let mut request = Command::new("/bin/sh");
        request
            .args(["-c", "/bin/sleep 30 & printf owner-ended"])
            .env_clear();
        let result = execute(&mut request, Deadline::new(now().unwrap(), None).unwrap()).unwrap();
        assert!(result.output.status.success());
        assert_eq!(result.output.stdout, b"owner-ended");
    }

    #[test]
    fn combined_output_limit_and_non_utf8_refuse() {
        for script in [
            "/usr/bin/head -c 150000 /dev/zero; /usr/bin/head -c 150000 /dev/zero >&2",
            "printf '\\377'",
        ] {
            let mut request = Command::new("/bin/sh");
            request.args(["-c", script]).env_clear();
            assert!(execute(&mut request, Deadline::new(now().unwrap(), None).unwrap()).is_err());
        }
    }

    #[test]
    fn retained_bytes_and_name_are_checked_on_both_sides_of_operation() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("fixture.dmg");
        std::fs::write(&file, b"fixture, never mounted or executed").unwrap();
        assert_eq!(
            with_retained(&file, Deadline::new(now().unwrap(), None).unwrap(), || Ok(
                7
            )),
            Ok(7)
        );
        assert!(
            with_retained(&file, Deadline::new(now().unwrap(), None).unwrap(), || {
                std::fs::write(&file, b"changed").unwrap();
                Ok(7)
            })
            .is_err()
        );
        assert!(
            with_retained(&file, Deadline::new(now().unwrap(), None).unwrap(), || {
                let replacement = directory.path().join("replacement");
                std::fs::write(&replacement, b"changed").unwrap();
                std::fs::rename(&replacement, &file).unwrap();
                Ok(7)
            })
            .is_err()
        );
        std::fs::remove_file(&file).unwrap();
        let called = std::cell::Cell::new(false);
        assert!(
            with_retained(&file, Deadline::new(now().unwrap(), None).unwrap(), || {
                called.set(true);
                Ok(7)
            })
            .is_err()
        );
        assert!(!called.get());
    }

    #[test]
    fn retained_operation_cannot_grant_a_late_result() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("fixture.dmg");
        std::fs::write(&file, b"fixture, never mounted or executed").unwrap();
        let start = now().unwrap();
        let parent = (start + 500_000_000).to_string();
        let deadline = Deadline::new(start, Some(&parent)).unwrap();
        let result = with_retained(&file, deadline, || {
            std::thread::sleep(Duration::from_secs(1));
            Ok(7)
        });
        assert!(
            result.is_err(),
            "retained-file checks must consume the same absolute deadline"
        );
    }
}
