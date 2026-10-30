use super::*;
use std::collections::BTreeMap;

fn environment() -> BTreeMap<&'static str, String> {
    [
        ("KITROVE_APPLE_TICKET_DIAGNOSTIC", "1"),
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
    ]
    .into_iter()
    .map(|(k, v)| (k, v.to_owned()))
    .chain([
        ("GITHUB_SHA", "a".repeat(40)),
        ("KITROVE_SIGNING_REHEARSAL_SHA", "a".repeat(40)),
        ("KITROVE_NOTARY_SOURCE_COMMIT", "a".repeat(40)),
        ("KITROVE_DIAGNOSTIC_EXPECTED_SOURCE", "a".repeat(40)),
    ])
    .collect()
}

#[test]
fn evidence_requires_exact_manual_arm_attempt_one_and_absent_production_activation() {
    let env = environment();
    assert_eq!(
        context(|key| env.get(key).cloned()).unwrap(),
        Some("a".repeat(40))
    );
    for key in env.keys() {
        let mut wrong = env.clone();
        wrong.insert(key, "".into());
        assert!(context(|key| wrong.get(key).cloned()).is_err(), "{key}");
    }
    for (key, value) in [
        ("KITROVE_HOSTED_SIGNING_READY", "false"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("DIST_TARGET", "x86_64-apple-darwin"),
        ("GITHUB_SHA", "a"),
    ] {
        let mut wrong = env.clone();
        wrong.insert(key, value.into());
        assert!(context(|key| wrong.get(key).cloned()).is_err());
    }
    assert_eq!(context(|_| None).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn native_record_keeps_closed_service_evidence_not_account_path_or_arbitrary_fields() {
    use std::os::unix::process::ExitStatusExt as _;
    let output = Output {
        status: std::process::ExitStatus::from_raw(68 << 8),
        stdout: b"PRIVATE_ACCOUNT /private/SECRET NSURLErrorDomain Code=-1005 HTTP/2 503 The network connection was lost".to_vec(),
        stderr: b"CKErrorDomain Code=6 PRIVATE_URL https://secret.invalid/SECRET".to_vec(),
    };
    let rendered = render(&"a".repeat(40), "Apple ticket stapling", &output, 123);
    let value: serde_json::Value =
        serde_json::from_str(rendered.strip_prefix("KITROVE_APPLE_TICKET_V1 ").unwrap()).unwrap();
    assert_eq!(value["native_exit"], 68);
    assert_eq!(value["elapsed_ms"], 123);
    assert_eq!(value["operation"], "staple");
    assert_eq!(
        value["observations"],
        serde_json::json!(["connection-lost"])
    );
    assert_eq!(value["http_statuses"], serde_json::json!([503]));
    assert_eq!(
        value["native_error_codes"],
        serde_json::json!([
            {"domain":"CKErrorDomain", "code":6}, {"domain":"NSURLErrorDomain", "code":-1005}
        ])
    );
    for forbidden in ["PRIVATE", "SECRET", "https", "secret.invalid"] {
        assert!(!rendered.contains(forbidden));
    }
}

#[cfg(unix)]
#[test]
fn oversized_output_is_explicitly_refused_without_copying_or_guessing() {
    use std::os::unix::process::ExitStatusExt as _;
    let output = Output {
        status: std::process::ExitStatus::from_raw(65 << 8),
        stdout: vec![b'x'; 262145],
        stderr: vec![],
    };
    let line = render(&"a".repeat(40), "Apple ticket validation", &output, 0);
    let value: serde_json::Value =
        serde_json::from_str(line.strip_prefix("KITROVE_APPLE_TICKET_V1 ").unwrap()).unwrap();
    assert_eq!(value["output_bounded"], false);
    assert_eq!(value["observations"], serde_json::json!([]));
    assert_eq!(value["native_exit"], 65);
    assert_eq!(value["operation"], "validate");
    assert!(line.len() < 2048);
}
