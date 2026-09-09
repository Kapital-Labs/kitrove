#![forbid(unsafe_code)]

/// Default maximum number of files accepted by production tree capture.
pub const DEFAULT_MAX_CAPTURE_FILES: usize = 512;

/// Upper bounds applied while capturing an Agent Skill tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_CAPTURE_FILES,
            max_file_bytes: 4 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024,
        }
    }
}
