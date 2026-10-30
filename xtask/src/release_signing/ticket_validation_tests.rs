use super::*;

fn observed_loss() -> TicketOutcome {
    TicketOutcome {
        operation: Operation::Validate,
        completion: Completion::Exited(68, Cleanup::Confirmed),
        evidence: Evidence {
            bounded: true,
            complete: true,
            observations: ["cloudkit-unexpected-response", "connection-lost"].into(),
            errors: [
                ("NSURLErrorDomain", -1005),
                ("kCFErrorDomainCFNetwork", -1005),
            ]
            .into(),
            http_statuses: BTreeSet::new(),
        },
    }
}

#[test]
fn exact_observed_validation_loss_is_retryable_but_success_is_not() {
    let mut outcome = observed_loss();
    assert!(retryable_validation(&outcome));
    outcome.completion = Completion::Exited(0, Cleanup::Confirmed);
    assert!(!retryable_validation(&outcome));
}

#[test]
fn every_nonconfirmed_process_outcome_and_side_effecting_operation_refuses() {
    for completion in [
        Completion::LaunchFailed,
        Completion::Terminated(Cleanup::Uncertain),
        Completion::TimedOut,
        Completion::Cancelled,
        Completion::Exited(68, Cleanup::Uncertain),
        Completion::Exited(65, Cleanup::Confirmed),
        Completion::Exited(1, Cleanup::Confirmed),
    ] {
        let mut outcome = observed_loss();
        outcome.completion = completion;
        assert!(!retryable_validation(&outcome), "{completion:?}");
    }
    let mut outcome = observed_loss();
    outcome.operation = Operation::Staple;
    assert!(!retryable_validation(&outcome));
}

#[test]
fn missing_unknown_mixed_errors_http_and_unbounded_evidence_refuse() {
    let mut cases = Vec::new();
    let mut value = observed_loss();
    value.evidence.bounded = false;
    cases.push(value);
    let mut value = observed_loss();
    value.evidence.complete = false;
    cases.push(value);
    let mut value = observed_loss();
    value.evidence.errors.clear();
    cases.push(value);
    let mut value = observed_loss();
    value.evidence.errors.remove(&("NSURLErrorDomain", -1005));
    cases.push(value);
    for error in [
        ("NSURLErrorDomain", -1001),
        ("CKErrorDomain", 17),
        ("UnknownDomain", -1005),
    ] {
        let mut value = observed_loss();
        value.evidence.errors.insert(error);
        cases.push(value);
    }
    for status in [403, 429, 503] {
        let mut value = observed_loss();
        value.evidence.http_statuses.insert(status);
        cases.push(value);
    }
    for (index, outcome) in cases.iter().enumerate() {
        assert!(!retryable_validation(outcome), "case{index}");
    }
}

#[test]
fn connection_loss_is_required_and_every_contradictory_observation_refuses() {
    let mut outcome = observed_loss();
    outcome.evidence.observations.remove("connection-lost");
    assert!(!retryable_validation(&outcome));
    for observation in [
        "missing-stapled-ticket",
        "record-not-found",
        "network-timeout",
        "ticket-validation-failed",
        "signature-denied",
        "native-validation-success-text",
        "native-staple-success-text",
        "unknown-observation",
    ] {
        let mut outcome = observed_loss();
        outcome.evidence.observations.insert(observation);
        assert!(!retryable_validation(&outcome), "{observation}");
    }
    let mut minimum = observed_loss();
    minimum
        .evidence
        .observations
        .remove("cloudkit-unexpected-response");
    minimum
        .evidence
        .errors
        .remove(&("kCFErrorDomainCFNetwork", -1005));
    assert!(retryable_validation(&minimum));
}

const LOSS: &[u8] = b"Error Domain=NSURLErrorDomain Code=-1005 \"The network connection was lost.\" UserInfo={Underlying=Error Domain=kCFErrorDomainCFNetwork Code=-1005}; CloudKit's response is inconsistent.";

#[test]
fn bounded_actual_error_shapes_parse_without_retaining_private_text() {
    let private = b"PRIVATE_PROVIDER_CANARY /private/account user@example.invalid";
    let evidence = parse_evidence(LOSS, private);
    assert!(evidence.bounded && evidence.complete);
    let mut outcome = observed_loss();
    outcome.evidence = evidence;
    assert!(retryable_validation(&outcome));
    let rendered = format!("{outcome:?}");
    for canary in ["PRIVATE_PROVIDER", "/private", "example.invalid"] {
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn malformed_or_unknown_error_and_http_markers_never_disappear_before_policy() {
    for extra in [
        "Error Domain=UnrecognizedDomain Code=-1",
        "Error Domain=NSURLErrorDomain Code=-1x",
        "Error Domain=NSURLErrorDomain Code=",
        "Error Domain=NSURLErrorDomain Code=--1005",
        "Error Domain=NSURLErrorDomain Code=+1005",
        "Error Domain=NSURLErrorDomain Code=99999999999999",
        "Error Domain=NSURLErrorDomain Code =-1005",
        "CKErrorDomain Code =17",
        "UnrecognizedDomain Code:17",
        "NSURLErrorDomain Code -1200",
        "HTTP/2 403x",
        "HTTP/4 503",
        "HTTP/2 unknown",
    ] {
        let mut outcome = observed_loss();
        outcome.evidence = parse_evidence(LOSS, extra.as_bytes());
        assert!(!outcome.evidence.complete, "{extra}");
        assert!(!retryable_validation(&outcome));
    }
    for extra in [
        "HTTP/1.1 403",
        "HTTP/2 429",
        "HTTP/3 503",
        "HTTP status: 503",
        "Error Domain=NSURLErrorDomain Code=-1200",
        "Error Domain=CKErrorDomain Code=17",
    ] {
        let mut outcome = observed_loss();
        outcome.evidence = parse_evidence(LOSS, extra.as_bytes());
        assert!(outcome.evidence.complete, "{extra}");
        assert!(!retryable_validation(&outcome), "{extra}");
    }
}

#[test]
fn output_bounds_invalid_utf8_and_excess_error_sets_refuse() {
    let over = vec![b'x'; 256 * 1024 + 1];
    assert!(!parse_evidence(&over, b"").bounded);
    assert!(!parse_evidence(LOSS, &[255]).complete);
    let many = (0..40)
        .map(|code| format!("Error Domain=NSURLErrorDomain Code=-{code}\n"))
        .collect::<String>();
    let evidence = parse_evidence(LOSS, many.as_bytes());
    assert!(evidence.bounded);
    assert!(!evidence.complete);
    assert!(evidence.errors.len() <= 32);
}

#[test]
fn denials_are_classified_before_retry_and_success_text_cannot_override_them() {
    for phrase in [
        "does not have a ticket stapled",
        "record not found",
        "the request timed out",
        "could not validate ticket",
        "invalid code signature",
        "the validate action worked",
    ] {
        let mut outcome = observed_loss();
        outcome.evidence = parse_evidence(LOSS, phrase.as_bytes());
        assert!(!retryable_validation(&outcome), "{phrase}");
    }
}
