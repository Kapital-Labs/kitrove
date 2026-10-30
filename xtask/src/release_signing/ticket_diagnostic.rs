//! Closed evidence from the actual ticket call, never raw provider text.
use std::collections::BTreeSet;
use std::process::Output;

pub(super) fn context(env: impl Fn(&str) -> Option<String>) -> Result<Option<String>, String> {
    let Some(enabled) = env("KITROVE_APPLE_TICKET_DIAGNOSTIC") else {
        return Ok(None);
    };
    let source = env("GITHUB_SHA").unwrap_or_default();
    let expected = [
        ("GITHUB_ACTIONS", "true"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("RUNNER_ARCH", "ARM64"),
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_REPOSITORY", "Kapital-Labs/kitrove"),
        ("GITHUB_REF", "refs/heads/main"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("DIST_TARGET", "aarch64-apple-darwin"),
        (
            "GITHUB_WORKFLOW_REF",
            "Kapital-Labs/kitrove/.github/workflows/apple-ticket-diagnostic.yml@refs/heads/main",
        ),
        ("KITROVE_SIGNING_REHEARSAL_SHA", source.as_str()),
        ("KITROVE_NOTARY_SOURCE_COMMIT", source.as_str()),
        ("KITROVE_DIAGNOSTIC_EXPECTED_SOURCE", source.as_str()),
    ];
    if enabled != "1"
        || source.len() != 40
        || !source
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || expected
            .iter()
            .any(|(key, value)| env(key).as_deref() != Some(value))
        || env("KITROVE_HOSTED_SIGNING_READY").is_some_and(|v| !v.is_empty())
    {
        return Err("unapproved Apple ticket diagnostic context".into());
    }
    Ok(Some(source))
}

pub(super) const DOMAINS: &[&str] = &[
    "NSURLErrorDomain",
    "kCFErrorDomainCFNetwork",
    "CKErrorDomain",
    "CKInternalErrorDomain",
    "NSCocoaErrorDomain",
    "NSPOSIXErrorDomain",
    "NSOSStatusErrorDomain",
];
pub(super) const PHRASES: &[(&str, &str)] = &[
    ("missing-stapled-ticket", "does not have a ticket stapled"),
    ("ticket-validation-failed", "could not validate ticket"),
    ("connection-lost", "the network connection was lost"),
    ("network-timeout", "the request timed out"),
    (
        "cloudkit-unexpected-response",
        "cloudkit's response is inconsistent",
    ),
    ("record-not-found", "record not found"),
    (
        "native-staple-success-text",
        "the staple and validate action worked",
    ),
    (
        "native-validation-success-text",
        "the validate action worked",
    ),
];

fn codes(text: &str, prefix: &str) -> BTreeSet<i32> {
    text.match_indices(prefix)
        .filter_map(|(position, _)| {
            let suffix = &text[position + prefix.len()..];
            let length = suffix
                .bytes()
                .take_while(|c| c.is_ascii_digit() || *c == b'-')
                .count();
            let number = suffix.get(..length)?;
            if number.is_empty()
                || number.trim_start_matches('-').len() > 6
                || suffix
                    .as_bytes()
                    .get(length)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                return None;
            }
            number.parse().ok()
        })
        .collect()
}

pub(super) fn render(source: &str, label: &str, output: &Output, elapsed: u128) -> String {
    let bounded = output.stdout.len().saturating_add(output.stderr.len()) <= 256 * 1024;
    // Unknown text never crosses this boundary, even when no classification matches.
    let text = if bounded {
        format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    } else {
        String::new()
    };
    let lower = text.to_ascii_lowercase();
    let observations: Vec<_> = PHRASES
        .iter()
        .filter(|(_, phrase)| lower.contains(phrase))
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let errors: BTreeSet<_> = DOMAINS
        .iter()
        .flat_map(|domain| {
            codes(&text, &format!("{domain} Code="))
                .into_iter()
                .map(|code| (*domain, code))
        })
        .collect();
    let errors: Vec<_> = errors
        .into_iter()
        .take(32)
        .map(|(domain, code)| serde_json::json!({"domain":domain,"code":code}))
        .collect();
    let http: BTreeSet<_> = [
        "HTTP/1.1 ",
        "HTTP/2 ",
        "HTTP/3 ",
        "HTTP status: ",
        "HTTP Status: ",
    ]
    .iter()
    .flat_map(|prefix| codes(&text, prefix))
    .filter(|code| (100..=599).contains(code))
    .collect();
    let record = serde_json::json!({"schema_version":1,"source_commit":source,
        "target":"aarch64-apple-darwin", "operation":if label == "Apple ticket stapling" {"staple"} else {"validate"},
        "native_exit":output.status.code(), "elapsed_ms":elapsed.min(1_500_000),
        "output_bounded":bounded,"observations":observations,
        "native_error_codes":errors,"http_statuses":http.into_iter().take(32).collect::<Vec<_>>()});
    format!("KITROVE_APPLE_TICKET_V1 {record}")
}

#[cfg(test)]
#[path = "ticket_diagnostic_tests.rs"]
mod tests;
