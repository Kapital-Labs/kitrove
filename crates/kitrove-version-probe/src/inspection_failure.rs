//! Private lifecycle outcomes; each closed operation supplies its own error policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InspectionFailure {
    Failed,
    Timeout,
    Cleanup,
    OutputLimit,
    InvalidOutput,
}
