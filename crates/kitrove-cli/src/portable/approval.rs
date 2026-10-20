use crate::args::{ApprovalMode, CliError};
use kitrove_model::ContentHash;

/// False means preview only; true means the typed plan may proceed to revalidation.
pub(super) fn review(
    mode: &ApprovalMode,
    digest: &ContentHash,
    output: &str,
    confirm: &mut impl FnMut(&str) -> bool,
    confirmation_code: &'static str,
) -> Result<bool, CliError> {
    match mode {
        ApprovalMode::Preview => Ok(false),
        ApprovalMode::Confirm(expected) if expected == digest => Ok(true),
        ApprovalMode::Confirm(_) => Err(CliError::new(
            "adoption.plan_stale",
            "the adoption plan differs from --confirm; obtain fresh approval",
        )),
        ApprovalMode::Interactive if confirm(output) => Ok(true),
        ApprovalMode::Interactive => Err(CliError::new(
            confirmation_code,
            "the plan was not confirmed; no changes were made",
        )),
    }
}
