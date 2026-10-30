//! Closed attempt evidence; raw provider output never leaves the parser.
use super::super::super::ticket_diagnostic::{DOMAINS, PHRASES};
use super::super::{Cleanup, Completion, Operation, TicketOutcome};
use super::{Recovery, Stop};
use serde_json::{Value, json};

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn closed(outcome: &TicketOutcome) -> bool {
    let evidence = &outcome.evidence;
    outcome.operation == Operation::Validate
        && evidence.errors.len() <= 32
        && evidence.http_statuses.len() <= 32
        && evidence
            .errors
            .iter()
            .all(|(domain, code)| DOMAINS.contains(domain) && (-999999..=999999).contains(code))
        && evidence
            .http_statuses
            .iter()
            .all(|code| (100..=599).contains(code))
        && evidence.observations.iter().all(|name| {
            *name == "signature-denied" || PHRASES.iter().any(|(known, _)| known == name)
        })
        && (evidence.bounded
            || (!evidence.complete
                && evidence.errors.is_empty()
                && evidence.observations.is_empty()
                && evidence.http_statuses.is_empty()))
}

fn status(outcome: Option<&TicketOutcome>) -> (Option<u8>, bool) {
    match outcome.map(|value| value.completion) {
        Some(Completion::Exited(code, cleanup)) => (Some(code), cleanup == Cleanup::Confirmed),
        Some(Completion::Terminated(cleanup)) => (None, cleanup == Cleanup::Confirmed),
        _ => (None, false),
    }
}

fn reason(stop: Stop) -> &'static str {
    match stop {
        Stop::Deadline => "deadline",
        Stop::Identity => "identity",
        #[cfg(test)]
        Stop::Interrupted => "interrupted",
        Stop::Unconfirmed => "unconfirmed",
        Stop::Denied => "denied",
        Stop::Exhausted => "exhausted",
    }
}

pub(in crate::release_archive::signing) fn render(
    source: &str,
    image: &str,
    report: &Recovery,
) -> Result<String, ()> {
    if !hex(source, 40)
        || !hex(image, 64)
        || report.window_ns > 60_000_000_000
        || report.elapsed_ns > report.window_ns
        || report.attempts.len() > 3
        || report.backoffs_ns.len() > 2
        || report.backoffs_ns.len() > report.attempts.len()
        || (!report.accepted() && report.refusal.is_none())
    {
        return Err(());
    }
    let last_retryable = report
        .attempts
        .last()
        .and_then(|attempt| attempt.outcome.as_ref())
        .is_some_and(super::super::retryable_validation);
    let last_requests_backoff =
        !report.backoffs_ns.is_empty() && report.backoffs_ns.len() == report.attempts.len();
    if report
        .backoffs_ns
        .iter()
        .enumerate()
        .any(|(index, delay)| *delay != (index as u64 + 1) * 1_000_000_000)
        || (last_requests_backoff && (report.accepted() || !last_retryable))
        || (report.refusal == Some(Stop::Exhausted)
            && (report.attempts.len() != 3 || !last_retryable || last_requests_backoff))
        || (report.attempts.is_empty()
            && !matches!(
                report.refusal,
                Some(Stop::Deadline | Stop::Identity | Stop::Unconfirmed)
            ))
    {
        return Err(());
    }
    let mut records: Vec<Value> = Vec::new();
    for (index, attempt) in report.attempts.iter().enumerate() {
        if usize::from(attempt.ordinal) != index + 1
            || attempt.started_ns > attempt.finished_ns
            || attempt.finished_ns > report.elapsed_ns
            || report.window_ns.saturating_sub(attempt.started_ns)
                <= super::super::CLEANUP_RESERVE_NS
            || attempt.outcome.as_ref().is_some_and(|value| !closed(value))
        {
            return Err(());
        }
        if report.backoffs_ns.get(index).is_some_and(|delay| {
            report.window_ns.saturating_sub(attempt.finished_ns)
                <= super::super::CLEANUP_RESERVE_NS + delay
        }) {
            return Err(());
        }
        if index > 0 {
            let previous = &report.attempts[index - 1];
            let delay = index as u64 * 1_000_000_000;
            if report.backoffs_ns.get(index - 1) != Some(&delay)
                || !previous
                    .outcome
                    .as_ref()
                    .is_some_and(super::super::retryable_validation)
                || attempt.started_ns < previous.finished_ns.saturating_add(delay)
            {
                return Err(());
            }
        }
        let evidence = attempt.outcome.as_ref().map(|value| &value.evidence);
        let (code, cleanup) = status(attempt.outcome.as_ref());
        let observations = evidence
            .map(|v| v.observations.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let errors = evidence
            .map(|v| {
                v.errors
                    .iter()
                    .map(|(domain, code)| json!({"domain":domain,"code":code}))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let http = evidence
            .map(|v| v.http_statuses.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        records.push(json!({"attempt":attempt.ordinal,"started_ms":attempt.started_ns/1_000_000,
            "finished_ms":attempt.finished_ns/1_000_000,"native_exit":code,"cleanup_confirmed":cleanup,
            "output_bounded":evidence.is_some_and(|e| e.bounded),
            "evidence_complete":evidence.is_some_and(|e| e.complete),"observations":observations,
            "native_error_codes":errors,"http_statuses":http,
            "backoff_requested_ms":report.backoffs_ns.get(index).map(|ns| ns/1_000_000)}));
    }
    let bounded = !report.attempts.is_empty()
        && report
            .attempts
            .iter()
            .all(|attempt| attempt.outcome.as_ref().is_some_and(|v| v.evidence.bounded));
    let code = status(
        report
            .attempts
            .last()
            .and_then(|attempt| attempt.outcome.as_ref()),
    )
    .0;
    let value = json!({"schema_version":2,"source_commit":source,"target":"aarch64-apple-darwin",
        "operation":"validate","image_sha256":image,"native_exit":code,"output_bounded":bounded,
        "elapsed_ms":report.elapsed_ns/1_000_000,"budget_ms":report.window_ns/1_000_000,
        "result":if report.accepted() {"validated"} else {"refused"},
        "refusal":report.refusal.map(reason),"attempts":records});
    let line = format!("KITROVE_APPLE_TICKET_V2 {value}");
    if line.len() > 16 * 1024 {
        return Err(());
    }
    Ok(line)
}
