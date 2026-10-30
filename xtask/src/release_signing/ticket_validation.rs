//! Conservative read-only recovery policy. No native execution or raw output.
use std::collections::BTreeSet;

pub(super) const CLEANUP_RESERVE_NS: u64 = 20_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Validate,
    #[cfg(test)] // Hostile synthetic input; the native adapter cannot issue staple.
    Staple,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cleanup {
    Confirmed,
    #[cfg(test)] // Real uncertain ownership is an error, never an owned result.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Completion {
    Exited(u8, Cleanup),
    #[cfg(test)]
    LaunchFailed,
    Terminated(Cleanup),
    #[cfg(test)]
    TimedOut,
    #[cfg(test)]
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) bounded: bool,
    pub(super) complete: bool,
    pub(super) observations: BTreeSet<&'static str>,
    pub(super) errors: BTreeSet<(&'static str, i32)>,
    pub(super) http_statuses: BTreeSet<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TicketOutcome {
    pub(super) operation: Operation,
    pub(super) completion: Completion,
    pub(super) evidence: Evidence,
}

fn number(suffix: &str) -> Option<i32> {
    let length = suffix
        .bytes()
        .take_while(|byte| byte.is_ascii_digit() || *byte == b'-')
        .count();
    let raw = suffix.get(..length)?;
    if raw.is_empty()
        || raw.trim_start_matches('-').len() > 6
        || suffix[length..]
            .chars()
            .next()
            .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '+' | '-' | '.'))
    {
        return None;
    }
    raw.parse().ok()
}

fn known_domain(value: &str) -> Option<&'static str> {
    super::ticket_diagnostic::DOMAINS
        .iter()
        .copied()
        .find(|known| *known == value)
}

pub(super) fn parse_evidence(stdout: &[u8], stderr: &[u8]) -> Evidence {
    let bounded = stdout.len().saturating_add(stderr.len()) <= 256 * 1024;
    let mut result = Evidence {
        bounded,
        complete: false,
        observations: BTreeSet::new(),
        errors: BTreeSet::new(),
        http_statuses: BTreeSet::new(),
    };
    if !bounded {
        return result;
    }
    let (Ok(stdout), Ok(stderr)) = (std::str::from_utf8(stdout), std::str::from_utf8(stderr))
    else {
        return result;
    };
    let text = format!("{stdout}\n{stderr}");
    let lower = text.to_ascii_lowercase();
    result.complete = true;
    for &(name, phrase) in super::ticket_diagnostic::PHRASES {
        if lower.contains(phrase) {
            result.observations.insert(name);
        }
    }
    if [
        "invalid code signature",
        "code signature is invalid",
        "signature validation failed",
        "signature check failed",
    ]
    .iter()
    .any(|phrase| lower.contains(phrase))
    {
        result.observations.insert("signature-denied");
    }
    // Reporting V1 may omit unknown/malformed fields. Retry authority must not:
    // every encountered standard NSError/status marker must be understood.
    for (position, _) in lower.match_indices("error domain=") {
        let suffix = &text[position + "error domain=".len()..];
        let length = suffix
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if known_domain(&suffix[..length]).is_none()
            || !suffix[length..].to_ascii_lowercase().starts_with(" code=")
        {
            result.complete = false;
        }
    }
    for (position, _) in lower.match_indices(" code=") {
        let before = &text[..position];
        let length = before
            .bytes()
            .rev()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        let domain = known_domain(&before[before.len() - length..]);
        match (domain, number(&text[position + " code=".len()..])) {
            (Some(domain), Some(code)) => {
                result.errors.insert((domain, code));
            }
            _ => result.complete = false,
        }
        if result.errors.len() > 32 {
            result.complete = false;
            result.errors.pop_last();
        }
    }
    for (position, _) in lower.match_indices(" code") {
        let suffix = &lower[position + " code".len()..];
        let trimmed = suffix.trim_start();
        if !suffix.starts_with('=')
            && (trimmed.starts_with(['=', ':', '-', '+'])
                || trimmed.as_bytes().first().is_some_and(u8::is_ascii_digit))
        {
            result.complete = false;
        }
    }
    for (position, _) in lower.match_indices("http/") {
        let prefix = ["http/1.1 ", "http/2 ", "http/3 "]
            .into_iter()
            .find(|prefix| lower[position..].starts_with(prefix));
        let code = prefix.and_then(|prefix| number(&text[position + prefix.len()..]));
        match code.filter(|code| (100..=599).contains(code)) {
            Some(code) => {
                result.http_statuses.insert(code as u16);
            }
            None => result.complete = false,
        }
    }
    for (position, _) in lower.match_indices("http status") {
        let prefix = "http status: ";
        let code = lower[position..]
            .starts_with(prefix)
            .then(|| number(&text[position + prefix.len()..]))
            .flatten();
        match code.filter(|code| (100..=599).contains(code)) {
            Some(code) => {
                result.http_statuses.insert(code as u16);
            }
            None => result.complete = false,
        }
    }
    if result.http_statuses.len() > 32 {
        result.complete = false;
        result.http_statuses = result.http_statuses.into_iter().take(32).collect();
    }
    result
}

fn retryable_validation(outcome: &TicketOutcome) -> bool {
    let evidence = &outcome.evidence;
    outcome.operation == Operation::Validate
        && outcome.completion == Completion::Exited(68, Cleanup::Confirmed)
        && evidence.bounded
        && evidence.complete
        && evidence.http_statuses.is_empty()
        && evidence.observations.contains("connection-lost")
        && evidence
            .observations
            .iter()
            .all(|value| matches!(*value, "connection-lost" | "cloudkit-unexpected-response"))
        && evidence.errors.contains(&("NSURLErrorDomain", -1005))
        && evidence.errors.iter().all(|(domain, code)| {
            *code == -1005 && matches!(*domain, "NSURLErrorDomain" | "kCFErrorDomainCFNetwork")
        })
}

#[cfg(test)]
#[path = "ticket_validation_tests.rs"]
mod tests;

#[path = "ticket_validation_loop.rs"]
pub(super) mod recovery;

#[path = "ticket_validation_binding.rs"]
pub(super) mod binding;
