#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

/// A stable, actionable failure from Agent Skills capture or parsing.
#[derive(Debug)]
pub struct SkillError {
    code: &'static str,
    path: PathBuf,
    message: String,
}

impl SkillError {
    /// Creates a stable capture-domain failure without exposing source bytes in the message.
    pub fn new(code: &'static str, path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }

    /// Returns the stable machine-readable error category.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the path associated with the failure.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the human-readable error detail.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for SkillError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.code,
            self.path.display(),
            self.message
        )
    }
}

impl Error for SkillError {}
