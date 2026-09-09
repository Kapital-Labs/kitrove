#![forbid(unsafe_code)]

use kitrove_agent_skills::CaptureLimits;

#[test]
fn default_limits_are_bounded() {
    let limits = CaptureLimits::default();
    assert_eq!(limits.max_files, 512);
    assert_eq!(limits.max_file_bytes, 4 * 1024 * 1024);
    assert_eq!(limits.max_total_bytes, 32 * 1024 * 1024);
    assert!(limits.max_file_bytes < limits.max_total_bytes);
}
