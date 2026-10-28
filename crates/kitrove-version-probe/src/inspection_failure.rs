//! Private lifecycle outcomes; each closed operation supplies its own error policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InspectionOperation {
    #[cfg(unix)]
    Launch,
    OutputReaderStart,
    OutputRead,
    #[cfg(unix)]
    Wait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InspectionFailure {
    Failed,
    Io {
        operation: InspectionOperation,
        kind: std::io::ErrorKind,
    },
    OutputWaitTimedOut,
    OutputChannelClosed,
    Timeout,
    Cleanup,
    OutputLimit,
    InvalidOutput,
}

impl InspectionFailure {
    pub(super) fn io(operation: InspectionOperation, error: &std::io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
        }
    }
}
