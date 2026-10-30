//! Ticket-phase success is not complete container acceptance.
use super::{native_inspection::Refused, ticket_validation::recovery::Recovery};

pub(super) fn finish(
    source: &str,
    inspection: Result<(String, Recovery), Refused>,
    signature: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let (image, report) = inspection.map_err(|_| {
        "Apple ticket validation ownership refused; no release archive was prepared".to_owned()
    })?;
    let line = super::ticket_validation::recovery::trace::render(source, &image, &report)
        .map_err(|_| "Apple ticket validation evidence refused".to_owned())?;
    eprintln!("{line}");
    if !report.accepted() {
        let detail = report
            .attempts
            .last()
            .and_then(|attempt| attempt.outcome.as_ref())
            .and_then(|outcome| match outcome.completion {
                super::ticket_validation::Completion::Exited(code, _) if code > 0 => {
                    Some(format!(" [native-exit={code}]"))
                }
                super::ticket_validation::Completion::Terminated(_) => {
                    Some(" [native-termination]".to_owned())
                }
                _ => None,
            })
            .unwrap_or_default();
        return Err(format!(
            "Apple ticket validation failed; no release archive was prepared{detail}"
        ));
    }
    signature()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_archive::signing::ticket_validation::{
        Cleanup, Completion, Operation, TicketOutcome, parse_evidence,
        recovery::{Attempt, Stop},
    };
    use std::cell::Cell;

    fn report(refusal: Option<Stop>) -> Recovery {
        Recovery {
            attempts: vec![Attempt {
                ordinal: 1,
                started_ns: 0,
                finished_ns: 1_000_000,
                outcome: Some(TicketOutcome {
                    operation: Operation::Validate,
                    completion: Completion::Exited(0, Cleanup::Confirmed),
                    evidence: parse_evidence(b"", b""),
                }),
            }],
            backoffs_ns: vec![],
            window_ns: 60_000_000_000,
            elapsed_ns: 1_000_000,
            refusal,
        }
    }

    #[test]
    fn ticket_success_still_runs_and_requires_the_original_strict_signature() {
        for signature_ok in [false, true] {
            let calls = Cell::new(0);
            let result = finish(&"a".repeat(40), Ok(("b".repeat(64), report(None))), || {
                calls.set(calls.get() + 1);
                if signature_ok {
                    Ok(())
                } else {
                    Err("signature refused".into())
                }
            });
            assert_eq!(
                calls.get(),
                1,
                "ticket success must not skip strict signature checks"
            );
            assert_eq!(result.is_ok(), signature_ok);
        }
    }

    #[test]
    fn zero_after_identity_failure_or_invalid_binding_never_reaches_signature() {
        for (source, inspection) in [
            (
                "a".repeat(40),
                Ok(("b".repeat(64), report(Some(Stop::Identity)))),
            ),
            ("invalid".into(), Ok(("b".repeat(64), report(None)))),
            ("a".repeat(40), Err(Refused::Deadline)),
        ] {
            let calls = Cell::new(0);
            assert!(
                finish(&source, inspection, || {
                    calls.set(1);
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(calls.get(), 0);
        }
    }
}
