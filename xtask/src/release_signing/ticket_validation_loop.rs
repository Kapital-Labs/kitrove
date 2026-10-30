//! Read-only validation recovery inside one retained-file/deadline window.
use super::{Cleanup, Completion, Operation, TicketOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::release_archive::signing) enum Stop {
    Deadline,
    Identity,
    #[cfg(test)] // Actual outer cancellation terminates/refuses the owned operation.
    Interrupted,
    Unconfirmed,
    Denied,
    Exhausted,
}

pub(in crate::release_archive::signing) trait Runner {
    fn now_ns(&mut self) -> Result<u64, Stop>;
    fn revalidate(&mut self) -> Result<(), Stop>;
    fn validate(&mut self, absolute_deadline_ns: u64) -> Result<TicketOutcome, Stop>;
    fn sleep_ns(&mut self, duration_ns: u64) -> Result<(), Stop>;
}

#[derive(Debug)]
pub(in crate::release_archive::signing) struct Attempt {
    pub(in crate::release_archive::signing) ordinal: u8,
    pub(in crate::release_archive::signing) started_ns: u64,
    pub(in crate::release_archive::signing) finished_ns: u64,
    pub(in crate::release_archive::signing) outcome: Option<TicketOutcome>,
}

#[derive(Debug)]
pub(in crate::release_archive::signing) struct Recovery {
    pub(in crate::release_archive::signing) attempts: Vec<Attempt>,
    pub(in crate::release_archive::signing) backoffs_ns: Vec<u64>,
    pub(in crate::release_archive::signing) window_ns: u64,
    pub(in crate::release_archive::signing) elapsed_ns: u64,
    pub(in crate::release_archive::signing) refusal: Option<Stop>,
}

fn successful(outcome: &TicketOutcome) -> bool {
    outcome.operation == Operation::Validate
        && outcome.completion == Completion::Exited(0, Cleanup::Confirmed)
        && outcome.evidence.bounded
}

impl Recovery {
    pub(in crate::release_archive::signing) fn accepted(&self) -> bool {
        self.refusal.is_none()
            && self
                .attempts
                .last()
                .and_then(|attempt| attempt.outcome.as_ref())
                .is_some_and(successful)
    }
}

struct Window {
    origin: u64,
    last: u64,
    end: u64,
}

impl Window {
    fn new(runner: &mut impl Runner, end: u64) -> Result<Self, Stop> {
        let origin = runner.now_ns()?;
        let budget = end.checked_sub(origin).ok_or(Stop::Deadline)?;
        if budget == 0 || budget > 60_000_000_000 {
            return Err(Stop::Deadline);
        }
        Ok(Self {
            origin,
            last: origin,
            end,
        })
    }

    fn tick(&mut self, runner: &mut impl Runner) -> Result<u64, Stop> {
        let now = runner.now_ns()?;
        if now < self.last {
            return Err(Stop::Deadline);
        }
        self.last = now;
        if now >= self.end {
            return Err(Stop::Deadline);
        }
        Ok(now)
    }

    fn check(&mut self, runner: &mut impl Runner) -> Result<u64, Stop> {
        self.tick(runner)?;
        runner.revalidate()?;
        self.tick(runner)
    }

    fn elapsed(&self) -> u64 {
        // Late operations still refuse. Their closed elapsed record is bounded
        // by this original window, never interpreted as successful completion.
        self.last
            .saturating_sub(self.origin)
            .min(self.end - self.origin)
    }
}

fn run_window(
    runner: &mut impl Runner,
    window: &mut Window,
    report: &mut Recovery,
) -> Result<(), Stop> {
    // Same existing cleanup reserve, INSIDE the single parent-clamped window.
    const RESERVE: u64 = super::CLEANUP_RESERVE_NS;
    for ordinal in 1..=3 {
        let started = window.check(runner)?;
        if window.end - started <= RESERVE {
            return Err(Stop::Deadline);
        }
        let outcome = runner.validate(window.end);
        let clock = window.tick(runner);
        report.attempts.push(Attempt {
            ordinal,
            started_ns: started - window.origin,
            finished_ns: window.elapsed(),
            outcome: outcome.as_ref().ok().cloned(),
        });
        let outcome = outcome?;
        if !matches!(
            outcome.completion,
            Completion::Exited(_, Cleanup::Confirmed) | Completion::Terminated(Cleanup::Confirmed)
        ) {
            return Err(Stop::Unconfirmed);
        }
        clock?;
        let identity = window.check(runner);
        report.attempts.last_mut().unwrap().finished_ns = window.elapsed();
        identity?;
        if successful(&outcome) {
            return Ok(());
        }
        if !super::retryable_validation(&outcome) {
            return Err(Stop::Denied);
        }
        if ordinal == 3 {
            return Err(Stop::Exhausted);
        }
        let before = window.check(runner)?;
        let delay = u64::from(ordinal) * 1_000_000_000;
        if window.end - before <= RESERVE + delay {
            return Err(Stop::Deadline);
        }
        report.backoffs_ns.push(delay);
        runner.sleep_ns(delay)?;
        let after = window.check(runner)?;
        if after < before + delay {
            return Err(Stop::Deadline);
        }
    }
    Err(Stop::Exhausted)
}

pub(in crate::release_archive::signing) fn recover(
    runner: &mut impl Runner,
    absolute_deadline_ns: u64,
) -> Recovery {
    let mut report = Recovery {
        attempts: Vec::new(),
        backoffs_ns: Vec::new(),
        window_ns: 0,
        elapsed_ns: 0,
        refusal: None,
    };
    match Window::new(runner, absolute_deadline_ns) {
        Err(reason) => report.refusal = Some(reason),
        Ok(mut window) => {
            report.window_ns = window.end - window.origin;
            report.refusal = run_window(runner, &mut window, &mut report).err();
            report.elapsed_ns = window.elapsed();
        }
    }
    report
}

#[cfg(test)]
#[path = "ticket_validation_loop_tests.rs"]
mod tests;

#[path = "ticket_validation_trace.rs"]
pub(in crate::release_archive::signing) mod trace;
