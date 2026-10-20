use super::{
    ApprovalMode, CliError, ContentHash, HarnessScope, OsString, PackRemoveArgs, PathBuf,
    RemoveArgs, next_utf8, parse_approval_flag, parse_asset_id, parse_harness,
    parse_materialize_scope, repeated_json, required_os_value, required_value, set_environment,
};

pub(super) fn parse_pack_remove(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PackRemoveArgs, CliError> {
    let mut pack_id = None;
    let mut expected_prior = None;
    let mut environment = None;
    let mut json = false;
    let mut approval = ApprovalMode::Interactive;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--plan" | "--confirm" => {
                parse_approval_flag(&argument, &mut approval, &mut arguments)?
            }
            "--pack" if pack_id.is_none() => {
                pack_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--pack")?);
            }
            "--expected-prior" if expected_prior.is_none() => {
                expected_prior = Some(
                    ContentHash::parse(required_value(&mut arguments)?).map_err(|_| {
                        CliError::new(
                            "cli.pack_expected_prior_invalid",
                            "--expected-prior is invalid",
                        )
                    })?,
                );
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.pack_remove_argument_unknown",
                    "the pack remove argument is not recognized or was repeated",
                ));
            }
        }
    }
    Ok(PackRemoveArgs {
        pack_id: pack_id
            .ok_or_else(|| CliError::new("cli.pack_required", "pack remove requires one --pack"))?,
        expected_prior: expected_prior.ok_or_else(|| {
            CliError::new(
                "cli.pack_expected_prior_required",
                "pack remove requires --expected-prior",
            )
        })?,
        environment,
        json,
        approval,
    })
}

pub(super) fn parse_remove(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<RemoveArgs, CliError> {
    let mut asset_id = None;
    let mut target = None;
    let mut scope = None;
    let mut project_root = None;
    let mut environment = None;
    let mut json = false;
    let mut approval = ApprovalMode::Interactive;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--plan" | "--confirm" => {
                parse_approval_flag(&argument, &mut approval, &mut arguments)?
            }
            "--asset" if asset_id.is_none() => {
                asset_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--asset")?);
            }
            "--target" if target.is_none() => {
                target = Some(parse_harness(&required_value(&mut arguments)?)?);
            }
            "--scope" if scope.is_none() => {
                scope = Some(parse_materialize_scope(&required_value(&mut arguments)?)?);
            }
            "--project-root" if project_root.is_none() => {
                project_root = Some(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.remove_argument_unknown",
                    "the remove argument is not recognized or was repeated",
                ));
            }
        }
    }
    Ok(RemoveArgs {
        asset_id: asset_id.ok_or_else(|| {
            CliError::new("cli.remove_asset_required", "remove requires one --asset")
        })?,
        target: target.ok_or_else(|| {
            CliError::new("cli.remove_target_required", "remove requires one --target")
        })?,
        scope: scope.unwrap_or(HarnessScope::User),
        project_root,
        environment,
        json,
        approval,
    })
}
