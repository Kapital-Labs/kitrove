use super::{
    ApprovalMode, AssetId, BTreeSet, CliError, ContentHash, OsString, PackCreateArgs,
    PackUpdateArgs, PathBuf, next_utf8, parse_approval_flag, parse_asset_id, repeated_json,
    required_value, set_environment,
};

#[derive(Clone, Copy)]
enum PackMemberOperation {
    Create,
    Update,
}

struct ParsedPackMutation {
    authored: bool,
    pack_id: AssetId,
    expected_prior: Option<ContentHash>,
    members: BTreeSet<AssetId>,
    environment: Option<PathBuf>,
    json: bool,
    approval: ApprovalMode,
}

pub(super) fn parse_pack_create(
    arguments: impl Iterator<Item = OsString>,
) -> Result<PackCreateArgs, CliError> {
    let parsed = parse_pack_member_mutation(arguments, PackMemberOperation::Create)?;
    Ok(PackCreateArgs {
        authored: parsed.authored,
        pack_id: parsed.pack_id,
        members: parsed.members,
        environment: parsed.environment,
        json: parsed.json,
        approval: parsed.approval,
    })
}

pub(super) fn parse_pack_update(
    arguments: impl Iterator<Item = OsString>,
) -> Result<PackUpdateArgs, CliError> {
    let parsed = parse_pack_member_mutation(arguments, PackMemberOperation::Update)?;
    let expected_prior = parsed.expected_prior.ok_or_else(|| {
        CliError::new(
            "cli.pack_expected_prior_required",
            "pack update requires --expected-prior",
        )
    })?;
    Ok(PackUpdateArgs {
        pack_id: parsed.pack_id,
        expected_prior,
        members: parsed.members,
        environment: parsed.environment,
        json: parsed.json,
        approval: parsed.approval,
    })
}

fn parse_pack_member_mutation(
    mut arguments: impl Iterator<Item = OsString>,
    operation: PackMemberOperation,
) -> Result<ParsedPackMutation, CliError> {
    let mut pack_id = None;
    let mut authored = false;
    let mut expected_prior = None;
    let mut members = BTreeSet::new();
    let mut environment = None;
    let mut json = false;
    let mut approval = ApprovalMode::Interactive;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--authored" if matches!(operation, PackMemberOperation::Create) && !authored => {
                authored = true;
            }
            "--plan" | "--confirm" => {
                parse_approval_flag(&argument, &mut approval, &mut arguments)?
            }
            "--pack" if pack_id.is_none() => {
                pack_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--pack")?);
            }
            "--pack" => {
                return Err(CliError::new(
                    "cli.pack_repeated",
                    "--pack may be supplied only once",
                ));
            }
            "--member" => {
                let member = parse_asset_id(&required_value(&mut arguments)?, "--member")?;
                if !members.insert(member) {
                    return Err(CliError::new(
                        "cli.pack_member_repeated",
                        "--member values must be unique",
                    ));
                }
            }
            "--expected-prior"
                if matches!(operation, PackMemberOperation::Update) && expected_prior.is_none() =>
            {
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
                    match operation {
                        PackMemberOperation::Create => "cli.pack_create_argument_unknown",
                        PackMemberOperation::Update => "cli.pack_update_argument_unknown",
                    },
                    "the pack mutation argument is not recognized or was repeated",
                ));
            }
        }
    }
    let pack_id = pack_id.ok_or_else(|| {
        CliError::new(
            "cli.pack_required",
            match operation {
                PackMemberOperation::Create => "pack create requires one --pack",
                PackMemberOperation::Update => "pack update requires one --pack",
            },
        )
    })?;
    if members.is_empty() {
        return Err(CliError::new(
            "cli.pack_member_required",
            "pack mutation requires at least one --member",
        ));
    }
    if matches!(operation, PackMemberOperation::Update) && expected_prior.is_none() {
        return Err(CliError::new(
            "cli.pack_expected_prior_required",
            "pack update requires --expected-prior",
        ));
    }
    Ok(ParsedPackMutation {
        authored,
        pack_id,
        expected_prior,
        members,
        environment,
        json,
        approval,
    })
}
