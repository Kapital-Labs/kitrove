use crate::args::{ApprovalMode, CliError};
use kitrove_model::ContentHash;

pub(super) fn require_no_recovery(
    mode: &ApprovalMode,
    root: &std::path::Path,
) -> Result<(), CliError> {
    if !matches!(mode, ApprovalMode::Interactive)
        && !matches!(
            kitrove_core::inspect_portable_journal(root)
                .map_err(|error| CliError::new(error.code(), error.message()))?,
            kitrove_core::PortableJournalStatus::Absent
        )
    {
        return Err(CliError::new(
            "pack.recovery_required",
            "pending or invalid recovery requires operator handling and fresh approval",
        ));
    }
    Ok(())
}

pub(super) fn review(
    mode: &ApprovalMode,
    assume_yes: bool,
    digest: &ContentHash,
    output: &str,
    confirm: &mut impl FnMut(&str) -> bool,
    confirmation_code: &'static str,
) -> Result<bool, CliError> {
    match mode {
        ApprovalMode::Preview => Ok(false),
        ApprovalMode::Confirm(expected) if expected == digest => Ok(true),
        ApprovalMode::Confirm(_) => Err(CliError::new(
            "pack.plan_stale",
            "the pack plan differs from --confirm; obtain fresh approval",
        )),
        ApprovalMode::Interactive if assume_yes || confirm(output) => Ok(true),
        ApprovalMode::Interactive => Err(CliError::new(
            confirmation_code,
            "the pack plan was not confirmed; no changes were made",
        )),
    }
}
