use super::{CliError, ContentHash, OsString, required_value};

#[derive(Debug)]
pub(crate) enum ApprovalMode {
    Interactive,
    Preview,
    Confirm(ContentHash),
}

pub(super) fn parse_approval_flag(
    flag: &str,
    mode: &mut ApprovalMode,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), CliError> {
    if !matches!(mode, ApprovalMode::Interactive) {
        return Err(CliError::new(
            "cli.approval_repeated",
            "--plan and --confirm are mutually exclusive and may be supplied only once",
        ));
    }
    *mode = match flag {
        "--plan" => ApprovalMode::Preview,
        "--confirm" => {
            ApprovalMode::Confirm(ContentHash::parse(required_value(arguments)?).map_err(|_| {
                CliError::new(
                    "cli.approval_invalid",
                    "--confirm requires a valid plan digest",
                )
            })?)
        }
        _ => unreachable!("only explicit approval flags reach this parser"),
    };
    Ok(())
}
