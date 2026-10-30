use super::*;
use crate::release_archive::signing::ticket_validation::Evidence;
use std::collections::{BTreeSet, VecDeque};

const SECOND: u64 = 1_000_000_000;

fn outcome(code: u8) -> TicketOutcome {
    TicketOutcome {
        operation: Operation::Validate,
        completion: Completion::Exited(code, Cleanup::Confirmed),
        evidence: Evidence {
            bounded: true,
            complete: true,
            observations: if code == 68 {
                ["connection-lost"].into()
            } else {
                BTreeSet::new()
            },
            errors: if code == 68 {
                [("NSURLErrorDomain", -1005)].into()
            } else {
                BTreeSet::new()
            },
            http_statuses: BTreeSet::new(),
        },
    }
}

struct Scripted {
    now: u64,
    queue: VecDeque<Result<TicketOutcome, Stop>>,
    deadlines: Vec<u64>,
    sleeps: Vec<u64>,
    checks: usize,
    fail_check: Option<usize>,
    interrupt_sleep: bool,
    native_cost_ns: u64,
    rewind_native_clock: bool,
}

impl Scripted {
    fn new(codes: &[u8]) -> Self {
        Self {
            now: SECOND,
            queue: codes.iter().map(|code| Ok(outcome(*code))).collect(),
            deadlines: Vec::new(),
            sleeps: Vec::new(),
            checks: 0,
            fail_check: None,
            interrupt_sleep: false,
            native_cost_ns: SECOND / 10,
            rewind_native_clock: false,
        }
    }
    fn run(&mut self) -> Recovery {
        recover(self, 61 * SECOND)
    }
}

impl Runner for Scripted {
    fn now_ns(&mut self) -> Result<u64, Stop> {
        Ok(self.now)
    }
    fn revalidate(&mut self) -> Result<(), Stop> {
        self.checks += 1;
        if self.fail_check == Some(self.checks) {
            Err(Stop::Identity)
        } else {
            Ok(())
        }
    }
    fn validate(&mut self, deadline: u64) -> Result<TicketOutcome, Stop> {
        self.deadlines.push(deadline);
        self.now = if self.rewind_native_clock {
            0
        } else {
            self.now + self.native_cost_ns
        };
        self.queue
            .pop_front()
            .expect("no unplanned fourth validation")
    }
    fn sleep_ns(&mut self, duration: u64) -> Result<(), Stop> {
        self.sleeps.push(duration);
        if self.interrupt_sleep {
            return Err(Stop::Interrupted);
        }
        self.now += duration;
        Ok(())
    }
}

#[test]
fn observed_loss_then_success_revalidates_and_keeps_the_failed_attempt() {
    let mut runner = Scripted::new(&[68, 0]);
    let result = runner.run();
    assert!(
        result.accepted(),
        "no read-only validation recovery exists yet"
    );
    assert_eq!(runner.deadlines, [61 * SECOND; 2]);
    assert_eq!(runner.sleeps, [SECOND]);
    assert_eq!(result.backoffs_ns, runner.sleeps);
    assert_eq!(result.window_ns, 60 * SECOND);
    assert_eq!(result.attempts.len(), 2);
    assert_eq!(
        result.attempts[0].outcome.as_ref().unwrap().completion,
        Completion::Exited(68, Cleanup::Confirmed)
    );
    assert_eq!(result.attempts[1].ordinal, 2);
    assert_eq!(result.elapsed_ns, SECOND + SECOND / 5);
    assert!(result.attempts[1].started_ns >= result.attempts[0].finished_ns + SECOND);
    assert_eq!(runner.checks, 6);
}

#[test]
fn two_losses_back_off_one_then_two_and_never_extend_the_deadline() {
    let mut runner = Scripted::new(&[68, 68, 0]);
    let result = runner.run();
    assert!(result.accepted());
    assert_eq!(runner.deadlines, [61 * SECOND; 3]);
    assert_eq!(runner.sleeps, [SECOND, 2 * SECOND]);
    assert_eq!(
        result
            .attempts
            .iter()
            .map(|a| a.ordinal)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(result.elapsed_ns, 3 * SECOND + 3 * SECOND / 10);
}

#[test]
fn three_losses_exhaust_and_never_consume_a_fourth_success() {
    let mut runner = Scripted::new(&[68, 68, 68, 0]);
    let result = runner.run();
    assert!(!result.accepted());
    assert_eq!(result.refusal, Some(Stop::Exhausted));
    assert_eq!(runner.deadlines.len(), 3);
    assert_eq!(runner.sleeps, [SECOND, 2 * SECOND]);
    assert_eq!(runner.queue.len(), 1);
}

#[test]
fn denial_unknown_error_and_uncertain_cleanup_never_reach_a_second_call() {
    for first in [
        Ok(outcome(65)),
        Err(Stop::Unconfirmed),
        {
            let mut value = outcome(68);
            value.evidence.complete = false;
            Ok(value)
        },
        {
            let mut value = outcome(0);
            value.completion = Completion::Exited(0, Cleanup::Uncertain);
            Ok(value)
        },
    ] {
        let mut runner = Scripted::new(&[0]);
        runner.queue.push_front(first);
        let result = runner.run();
        assert!(!result.accepted());
        assert_eq!(runner.deadlines.len(), 1);
        assert!(runner.sleeps.is_empty());
        assert_eq!(runner.queue.len(), 1);
    }
}

#[test]
fn changed_image_before_after_or_across_backoff_stops_without_another_call() {
    for (check, calls, sleeps) in [(1, 0, 0), (2, 1, 0), (3, 1, 0), (4, 1, 1)] {
        let mut runner = Scripted::new(&[68, 0]);
        runner.fail_check = Some(check);
        let result = runner.run();
        assert!(!result.accepted());
        assert_eq!(result.refusal, Some(Stop::Identity));
        assert_eq!(runner.deadlines.len(), calls);
        assert_eq!(runner.sleeps.len(), sleeps);
    }
}

#[test]
fn interrupted_backoff_preserves_failure_and_stops() {
    let mut runner = Scripted::new(&[68, 0]);
    runner.interrupt_sleep = true;
    let result = runner.run();
    assert!(!result.accepted());
    assert_eq!(result.refusal, Some(Stop::Interrupted));
    assert_eq!(runner.deadlines.len(), 1);
    assert_eq!(result.attempts.len(), 1);
}

#[test]
fn insufficient_remaining_budget_does_not_borrow_another_window() {
    let mut runner = Scripted::new(&[68, 0]);
    let result = recover(&mut runner, 22 * SECOND + SECOND / 20);
    assert!(!result.accepted());
    assert_eq!(result.refusal, Some(Stop::Deadline));
    assert_eq!(runner.deadlines.len(), 1);
    assert!(runner.sleeps.is_empty());
    for deadline in [0, SECOND, 62 * SECOND, u64::MAX] {
        let mut runner = Scripted::new(&[0]);
        assert_eq!(recover(&mut runner, deadline).refusal, Some(Stop::Deadline));
        assert!(runner.deadlines.is_empty());
    }
}

#[test]
fn late_success_and_backwards_clock_cannot_create_acceptance() {
    for rewind in [false, true] {
        let mut runner = Scripted::new(&[0]);
        runner.native_cost_ns = 60 * SECOND;
        runner.rewind_native_clock = rewind;
        let result = runner.run();
        assert!(!result.accepted());
        assert_eq!(result.refusal, Some(Stop::Deadline));
        assert_eq!(runner.deadlines.len(), 1);
    }
}

#[test]
fn closed_producer_matches_the_same_fixture_as_the_python_consumer() {
    let report = Scripted::new(&[68, 0]).run();
    let line = super::trace::render(&"a".repeat(40), &"b".repeat(64), &report)
        .expect("no closed V2 producer exists yet");
    let value: serde_json::Value =
        serde_json::from_str(line.strip_prefix("KITROVE_APPLE_TICKET_V2 ").unwrap()).unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../scripts/fixtures/apple-ticket-validation-v2.json"
    ))
    .unwrap();
    assert_eq!(value, expected);
}

#[test]
fn closed_producer_refuses_private_strings_unknown_domains_or_bad_bindings() {
    let mut report = Scripted::new(&[0]).run();
    for (source, image) in [
        ("PRIVATE_PROVIDER_CANARY".into(), "b".repeat(64)),
        ("a".repeat(40), "/private/synthetic".into()),
    ] {
        assert!(super::trace::render(&source, &image, &report).is_err());
    }
    report.attempts[0]
        .outcome
        .as_mut()
        .unwrap()
        .evidence
        .errors
        .insert(("PRIVATE_PROVIDER_CANARY", -1));
    assert!(super::trace::render(&"a".repeat(40), &"b".repeat(64), &report).is_err());
}

#[test]
fn a_native_zero_after_identity_failure_is_reported_but_never_validated() {
    let mut runner = Scripted::new(&[68, 0]);
    runner.fail_check = Some(6);
    let report = runner.run();
    assert!(!report.accepted());
    let line = super::trace::render(&"a".repeat(40), &"b".repeat(64), &report).unwrap();
    let value: serde_json::Value = serde_json::from_str(line.split_once(' ').unwrap().1).unwrap();
    assert_eq!(value["native_exit"], 0);
    assert_eq!(value["result"], "refused");
    assert_eq!(value["refusal"], "identity");
}

#[test]
fn producer_refuses_impossible_success_backoff_or_exhaustion_metadata() {
    let mut report = Scripted::new(&[0]).run();
    report.backoffs_ns.push(1_000_000_000);
    assert!(super::trace::render(&"a".repeat(40), &"b".repeat(64), &report).is_err());
    report.backoffs_ns.clear();
    report.refusal = Some(Stop::Exhausted);
    assert!(super::trace::render(&"a".repeat(40), &"b".repeat(64), &report).is_err());
}

#[test]
fn producer_refuses_timing_that_could_not_reserve_cleanup_before_launch_or_backoff() {
    let source = "a".repeat(40);
    let image = "b".repeat(64);
    let mut zero = Scripted::new(&[0]).run();
    zero.window_ns = 0;
    zero.elapsed_ns = 0;
    zero.attempts[0].finished_ns = 0;
    assert!(super::trace::render(&source, &image, &zero).is_err());

    let mut late = Scripted::new(&[68, 0]).run();
    late.attempts[0].finished_ns = 40_001_000_000;
    late.attempts[1].started_ns = 41_001_000_000;
    late.attempts[1].finished_ns = 41_002_000_000;
    late.elapsed_ns = 41_002_000_000;
    assert!(super::trace::render(&source, &image, &late).is_err());

    let mut backoff = Scripted::new(&[68, 0]).run();
    backoff.attempts.pop();
    backoff.attempts[0].finished_ns = 39_500_000_000;
    backoff.elapsed_ns = 39_500_000_000;
    backoff.refusal = Some(Stop::Interrupted);
    assert!(super::trace::render(&source, &image, &backoff).is_err());
}
