use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// A stable, actionable violation of a Kitrove domain contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    code: &'static str,
    message: String,
}

impl ValidationError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the stable machine-readable error category.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the human-readable error detail.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for ValidationError {}
