//! Retained-file adapter. The operational callback is closed to validate-v.
use super::{Deadline, OwnedResult, Refused};
use crate::release_archive::signing::ticket_validation::{
    Cleanup, Completion, Operation, TicketOutcome, parse_evidence,
    recovery::{Recovery, Runner, Stop, recover},
};
use std::path::Path;
use std::sync::atomic::AtomicU8;

pub(in crate::release_archive::signing::native_inspection) fn inspect(
    file: &Path,
) -> Result<(String, Recovery), Refused> {
    inspect_with(
        file,
        super::parent_deadline()?,
        &super::NEXT_OWNER,
        |image, deadline| super::execute(&mut super::super::command(image), deadline),
    )
}

struct Retained<'a, P> {
    file: &'a Path,
    original: crate::release_archive::RetainedFile,
    deadline: Deadline,
    absolute_end: u64,
    counter: &'a AtomicU8,
    perform: P,
}

impl<P: FnMut(&Path, Deadline) -> Result<OwnedResult, Refused>> Runner for Retained<'_, P> {
    fn now_ns(&mut self) -> Result<u64, Stop> {
        super::now().map_err(|_| Stop::Deadline)
    }

    fn revalidate(&mut self) -> Result<(), Stop> {
        self.original.revalidate().map_err(|_| Stop::Identity)
    }

    fn validate(&mut self, absolute_deadline_ns: u64) -> Result<TicketOutcome, Stop> {
        if absolute_deadline_ns != self.absolute_end {
            return Err(Stop::Deadline);
        }
        let owner = super::next_owner(self.counter).map_err(|_| Stop::Unconfirmed)?;
        super::emit_owner(owner, false).map_err(|_| Stop::Unconfirmed)?;
        let OwnedResult {
            output,
            _cleanup: proof,
        } = (self.perform)(self.file, self.deadline).map_err(|_| Stop::Unconfirmed)?;
        let _confirmed = proof;
        super::emit_owner(owner, true).map_err(|_| Stop::Unconfirmed)?;
        let completion = match output.status.code() {
            Some(code) => Completion::Exited(
                u8::try_from(code).map_err(|_| Stop::Denied)?,
                Cleanup::Confirmed,
            ),
            None => Completion::Terminated(Cleanup::Confirmed),
        };
        Ok(TicketOutcome {
            operation: Operation::Validate,
            completion,
            evidence: parse_evidence(&output.stdout, &output.stderr),
        })
    }

    fn sleep_ns(&mut self, duration_ns: u64) -> Result<(), Stop> {
        if !matches!(duration_ns, 1_000_000_000 | 2_000_000_000) {
            return Err(Stop::Deadline);
        }
        let remaining = self
            .deadline
            .remaining(super::now().map_err(|_| Stop::Deadline)?)
            .map_err(|_| Stop::Deadline)?;
        if remaining
            <= std::time::Duration::from_nanos(
                crate::release_archive::signing::ticket_validation::CLEANUP_RESERVE_NS
                    + duration_ns,
            )
        {
            return Err(Stop::Deadline);
        }
        std::thread::sleep(std::time::Duration::from_nanos(duration_ns));
        self.deadline
            .remaining(super::now().map_err(|_| Stop::Deadline)?)
            .map_err(|_| Stop::Deadline)?;
        Ok(())
    }
}

fn inspect_with(
    file: &Path,
    deadline: Deadline,
    counter: &AtomicU8,
    perform: impl FnMut(&Path, Deadline) -> Result<OwnedResult, Refused>,
) -> Result<(String, Recovery), Refused> {
    let started = super::now()?;
    let remaining = deadline.remaining(started)?;
    let absolute_end = started
        .checked_add(u64::try_from(remaining.as_nanos()).map_err(|_| Refused::Deadline)?)
        .ok_or(Refused::Deadline)?;
    let mut original =
        crate::release_archive::read_bounded_archive(file, false).map_err(|_| Refused::Native)?;
    original.revalidate().map_err(|_| Refused::Native)?;
    let digest = crate::release_archive::sha256_hex(&original.bytes);
    deadline.remaining(super::now()?)?;
    let mut runner = Retained {
        file,
        original,
        deadline,
        absolute_end,
        counter,
        perform,
    };
    let report = recover(&mut runner, absolute_end);
    Ok((digest, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::Ordering;

    #[test]
    fn owned_recovery_reuses_original_file_and_deadline_for_two_harmless_children() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("synthetic-image.dmg");
        std::fs::write(&file, b"fixed-image").unwrap();
        let deadline = Deadline::new(super::super::now().unwrap(), None).unwrap();
        let counter = AtomicU8::new(1);
        let mut calls = 0;
        let result = inspect_with(&file, deadline, &counter, |_image, same_deadline| {
            assert_eq!(same_deadline, deadline);
            calls += 1;
            let script = if calls == 1 {
                "printf '%s' 'Error Domain=NSURLErrorDomain Code=-1005 \"The network connection was lost.\"'; exit 68"
            } else {
                "exit 0"
            };
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]).env_clear();
            super::super::execute(&mut command, same_deadline)
        });
        assert!(
            result.is_ok(),
            "no retained owned recovery adapter exists yet"
        );
        let (hash, report) = result.unwrap();
        assert!(report.accepted());
        assert_eq!(calls, 2);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
        assert_eq!(hash, crate::release_archive::sha256_hex(b"fixed-image"));
        assert_eq!(std::fs::read(&file).unwrap(), b"fixed-image");
        assert_eq!(report.attempts.len(), 2);
    }

    #[test]
    fn original_baseline_refuses_a_change_after_a_real_child_returns_zero() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("synthetic-image.dmg");
        std::fs::write(&file, b"fixed-image").unwrap();
        let deadline = Deadline::new(super::super::now().unwrap(), None).unwrap();
        let counter = AtomicU8::new(1);
        let mut calls = 0;
        let (hash, report) = inspect_with(&file, deadline, &counter, |image, same_deadline| {
            calls += 1;
            assert_eq!(same_deadline, deadline);
            let mut command = Command::new("/usr/bin/true");
            command.env_clear();
            let result = super::super::execute(&mut command, same_deadline)?;
            std::fs::write(image, b"changed-image").unwrap();
            Ok(result)
        })
        .unwrap();
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"changed-image",
            "fixture must actually change the retained bytes"
        );
        assert!(
            !report.accepted(),
            "a later file must not become the next baseline"
        );
        assert_eq!(report.refusal, Some(Stop::Identity));
        assert_eq!(calls, 1);
        assert_eq!(hash, crate::release_archive::sha256_hex(b"fixed-image"));
        assert_eq!(
            report.attempts[0].outcome.as_ref().unwrap().completion,
            Completion::Exited(0, Cleanup::Confirmed)
        );
    }

    #[test]
    fn reaped_signalled_child_stays_denied_without_losing_cleanup_proof() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("synthetic-image.dmg");
        std::fs::write(&file, b"fixed-image").unwrap();
        let deadline = Deadline::new(super::super::now().unwrap(), None).unwrap();
        let counter = AtomicU8::new(1);
        let mut calls = 0;
        let (hash, report) = inspect_with(&file, deadline, &counter, |_image, same_deadline| {
            calls += 1;
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "kill -TERM $$"]).env_clear();
            super::super::execute(&mut command, same_deadline)
        })
        .unwrap();
        assert!(!report.accepted());
        assert_eq!(calls, 1);
        let line = crate::release_archive::signing::ticket_validation::recovery::trace::render(
            &"a".repeat(40),
            &hash,
            &report,
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(line.split_once(' ').unwrap().1).unwrap();
        assert!(value["native_exit"].is_null());
        assert_eq!(
            value["attempts"][0]["cleanup_confirmed"], true,
            "a reaped group's actual proof must not disappear on a signal"
        );
        assert_eq!(report.refusal, Some(Stop::Denied));
    }
}
