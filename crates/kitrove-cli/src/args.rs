use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use kitrove_adapter_api::{ExplicitRoot, ScopeSelection};
use kitrove_model::{AssetId, ContentHash, HarnessId, HarnessScope, ProfileId};

#[derive(Debug)]
pub(crate) enum Command {
    Init(InitArgs),
    Scan(ScanArgs),
    Adopt(AdoptArgs),
    Remove(RemoveArgs),
    Status(EnvironmentArgs),
    Lock(EnvironmentArgs),
    Plan(MaterializeArgs),
    Apply(MaterializeArgs),
    SyncPlan(SyncArgs),
    SyncApply(SyncArgs),
    TrustPlan(TrustPlanArgs),
    TrustApply(TrustApplyArgs),
    TrustAudit(TrustAuditArgs),
    PackCreate(PackCreateArgs),
    PackDiscover(PackDiscoverArgs),
    PackAdopt(PackAdoptArgs),
    PackUpdate(PackUpdateArgs),
    PackRollback(PackRollbackArgs),
    PackRemove(PackRemoveArgs),
    PackList(EnvironmentArgs),
    PackInspect(PackInspectArgs),
    VersionProbe(VersionProbeArgs),
    About,
    NorthStar,
    Invariants,
    Help,
    Version,
}

#[derive(Debug)]
pub(crate) struct EnvironmentArgs {
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct MaterializeArgs {
    pub profile: Option<ProfileId>,
    pub assets: BTreeSet<AssetId>,
    pub packs: BTreeSet<AssetId>,
    pub targets: BTreeSet<HarnessId>,
    pub scope: HarnessScope,
    pub project_root: Option<PathBuf>,
    pub version_binaries: Vec<PathBuf>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct RemoveArgs {
    pub asset_id: AssetId,
    pub target: HarnessId,
    pub scope: HarnessScope,
    pub project_root: Option<PathBuf>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct InitArgs {
    pub machine_id: Option<kitrove_model::MachineId>,
    pub project_root: Option<PathBuf>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct AdoptArgs {
    pub observation_id: String,
    pub asset_id: Option<AssetId>,
    pub update_asset_id: Option<AssetId>,
    pub expected_prior: Option<ContentHash>,
    pub binding: Option<kitrove_model::BindingName>,
    pub harnesses: BTreeSet<HarnessId>,
    pub scope: ScopeSelection,
    pub project_root: Option<PathBuf>,
    pub roots: Vec<ExplicitRoot>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct ScanArgs {
    pub harnesses: BTreeSet<HarnessId>,
    pub scope: ScopeSelection,
    pub project_root: Option<PathBuf>,
    pub roots: Vec<ExplicitRoot>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

pub(crate) fn tier_one_harnesses() -> BTreeSet<HarnessId> {
    BTreeSet::from([
        HarnessId::Claude,
        HarnessId::Codex,
        HarnessId::Pi,
        HarnessId::OpenCode,
    ])
}

#[derive(Debug)]
pub(crate) struct SyncArgs {
    pub remote: SyncRemoteArgs,
    pub environment: Option<PathBuf>,
    pub confirm: Option<ContentHash>,
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustDecisionArg {
    Trusted,
    Denied,
}

#[derive(Debug)]
pub(crate) struct TrustPlanArgs {
    pub asset_id: AssetId,
    pub decision: TrustDecisionArg,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct TrustApplyArgs {
    pub asset_id: AssetId,
    pub decision: TrustDecisionArg,
    pub confirm: ContentHash,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct TrustAuditArgs {
    pub asset_id: Option<AssetId>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackInspectArgs {
    pub pack_id: AssetId,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct VersionProbeArgs {
    pub harness: HarnessId,
    pub binary: PathBuf,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackDiscoverArgs {
    pub remote: SyncRemoteArgs,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackAdoptArgs {
    pub pack_id: AssetId,
    pub remote: SyncRemoteArgs,
    pub environment: Option<PathBuf>,
    pub assume_yes: bool,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackRemoveArgs {
    pub pack_id: AssetId,
    pub expected_prior: ContentHash,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackCreateArgs {
    pub pack_id: AssetId,
    pub members: BTreeSet<AssetId>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackUpdateArgs {
    pub pack_id: AssetId,
    pub expected_prior: ContentHash,
    pub members: BTreeSet<AssetId>,
    pub environment: Option<PathBuf>,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) struct PackRollbackArgs {
    pub pack_id: AssetId,
    pub expected_prior: ContentHash,
    pub target_revision: ContentHash,
    pub remote: SyncRemoteArgs,
    pub environment: Option<PathBuf>,
    pub assume_yes: bool,
    pub json: bool,
}

#[derive(Debug)]
pub(crate) enum SyncRemoteArgs {
    Filesystem(PathBuf),
    Git {
        url: String,
        credentials: GitCredentialSource,
    },
    Ssh {
        url: String,
        known_hosts: PathBuf,
    },
}

#[derive(Default)]
struct ParsedRemoteArgs {
    filesystem: Option<PathBuf>,
    git: Option<String>,
    ssh: Option<String>,
    known_hosts: Option<PathBuf>,
    git_env_credentials: bool,
}

impl ParsedRemoteArgs {
    fn consume(
        &mut self,
        argument: &str,
        arguments: &mut impl Iterator<Item = OsString>,
    ) -> Result<bool, CliError> {
        match argument {
            "--filesystem" if self.filesystem.is_none() => {
                self.filesystem = Some(PathBuf::from(required_os_value(arguments)?));
            }
            "--filesystem" => return Err(remote_option_repeated("--filesystem")),
            "--git" if self.git.is_none() => {
                self.git = Some(required_value(arguments)?);
            }
            "--git" => return Err(remote_option_repeated("--git")),
            "--ssh" if self.ssh.is_none() => {
                self.ssh = Some(required_value(arguments)?);
            }
            "--ssh" => return Err(remote_option_repeated("--ssh")),
            "--known-hosts" if self.known_hosts.is_none() => {
                self.known_hosts = Some(PathBuf::from(required_os_value(arguments)?));
            }
            "--known-hosts" => return Err(remote_option_repeated("--known-hosts")),
            "--git-env-credentials" if !self.git_env_credentials => {
                self.git_env_credentials = true;
            }
            "--git-env-credentials" => {
                return Err(remote_option_repeated("--git-env-credentials"));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> Result<SyncRemoteArgs, CliError> {
        match (
            self.filesystem,
            self.git,
            self.ssh,
            self.known_hosts,
            self.git_env_credentials,
        ) {
            (Some(path), None, None, None, false) => Ok(SyncRemoteArgs::Filesystem(path)),
            (None, Some(url), None, None, credentials) => Ok(SyncRemoteArgs::Git {
                url,
                credentials: if credentials {
                    GitCredentialSource::Environment
                } else {
                    GitCredentialSource::Terminal
                },
            }),
            (None, None, Some(url), Some(known_hosts), false) => {
                Ok(SyncRemoteArgs::Ssh { url, known_hosts })
            }
            (None, None, None, None, false) => Err(CliError::new(
                "cli.sync_remote_missing",
                "the operation requires exactly one --filesystem, --git, or --ssh remote",
            )),
            (None, None, Some(_), None, false) | (None, None, None, Some(_), false) => {
                Err(CliError::new(
                    "cli.sync_known_hosts_required",
                    "--ssh and --known-hosts must be supplied together",
                ))
            }
            _ => Err(CliError::new(
                "cli.sync_remote_conflict",
                "remote and credential options cannot be combined",
            )),
        }
    }
}

fn remote_option_repeated(option: &str) -> CliError {
    match option {
        "--filesystem" => CliError::new(
            "cli.sync_filesystem_repeated",
            "--filesystem may be supplied only once",
        ),
        "--git" => CliError::new("cli.sync_git_repeated", "--git may be supplied only once"),
        "--ssh" => CliError::new("cli.sync_ssh_repeated", "--ssh may be supplied only once"),
        "--known-hosts" => CliError::new(
            "cli.sync_known_hosts_repeated",
            "--known-hosts may be supplied only once",
        ),
        "--git-env-credentials" => CliError::new(
            "cli.sync_git_credentials_repeated",
            "--git-env-credentials may be supplied only once",
        ),
        _ => unreachable!("only compiled remote options are dispatched"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GitCredentialSource {
    Terminal,
    Environment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CliError {
    pub code: &'static str,
    message: &'static str,
}

impl CliError {
    pub(crate) const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

pub(crate) fn parse_args(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<Command, CliError> {
    let mut arguments = arguments.into_iter();
    let Some(command) = next_utf8(&mut arguments)? else {
        return Ok(Command::Help);
    };
    match command.as_str() {
        "help" | "--help" | "-h" => finish_information(arguments, Command::Help),
        "about" => finish_information(arguments, Command::About),
        "north-star" => finish_information(arguments, Command::NorthStar),
        "invariants" => finish_information(arguments, Command::Invariants),
        "--version" | "-V" => finish_information(arguments, Command::Version),
        "init" => parse_init(arguments).map(Command::Init),
        "scan" => parse_scan(arguments).map(Command::Scan),
        "adopt" => parse_adopt(arguments).map(Command::Adopt),
        "remove" => parse_remove(arguments).map(Command::Remove),
        "status" => parse_environment(arguments, "status").map(Command::Status),
        "lock" => parse_environment(arguments, "lock").map(Command::Lock),
        "plan" => parse_materialize(arguments, "plan").map(Command::Plan),
        "apply" => parse_materialize(arguments, "apply").map(Command::Apply),
        "sync" => parse_sync(arguments),
        "trust" => parse_trust(arguments),
        "pack" => parse_pack(arguments),
        "versions" => parse_versions(arguments),
        _ => Err(CliError::new(
            "cli.command_unknown",
            "the requested command is not recognized",
        )),
    }
}

fn parse_versions(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let operation = next_utf8(&mut arguments)?.ok_or_else(|| {
        CliError::new(
            "cli.version_operation_missing",
            "versions requires the probe operation",
        )
    })?;
    if operation != "probe" {
        return Err(CliError::new(
            "cli.version_operation_unknown",
            "the requested versions operation is not recognized",
        ));
    }
    let mut harness = None;
    let mut binary = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--harness" if harness.is_none() => {
                harness = Some(parse_harness(&required_value(&mut arguments)?)?);
            }
            "--binary" if binary.is_none() => {
                binary = Some(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.version_probe_argument_unknown",
                    "the version probe argument is not recognized or was repeated",
                ));
            }
        }
    }
    let harness = harness.ok_or_else(|| {
        CliError::new(
            "cli.version_harness_required",
            "version probe requires one --harness",
        )
    })?;
    if harness != HarnessId::Pi && harness != HarnessId::OpenCode {
        return Err(CliError::new(
            "cli.version_harness_unsupported",
            "the selected harness has no reviewed version probe",
        ));
    }
    Ok(Command::VersionProbe(VersionProbeArgs {
        harness,
        binary: binary.ok_or_else(|| {
            CliError::new(
                "cli.version_binary_required",
                "version probe requires one explicit --binary path",
            )
        })?,
        json,
    }))
}

fn parse_pack(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let operation = next_utf8(&mut arguments)?.ok_or_else(|| {
        CliError::new(
            "cli.pack_operation_missing",
            "pack requires the discover, adopt, create, update, rollback, remove, list, or inspect operation",
        )
    })?;
    match operation.as_str() {
        "discover" => parse_pack_discover(arguments).map(Command::PackDiscover),
        "adopt" => parse_pack_adopt(arguments).map(Command::PackAdopt),
        "create" => parse_pack_create(arguments).map(Command::PackCreate),
        "update" => parse_pack_update(arguments).map(Command::PackUpdate),
        "rollback" => parse_pack_rollback(arguments).map(Command::PackRollback),
        "remove" => parse_pack_remove(arguments).map(Command::PackRemove),
        "list" => parse_environment(arguments, "pack list").map(Command::PackList),
        "inspect" => parse_pack_inspect(arguments).map(Command::PackInspect),
        _ => Err(CliError::new(
            "cli.pack_operation_unknown",
            "the requested pack operation is not recognized",
        )),
    }
}

fn parse_pack_discover(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PackDiscoverArgs, CliError> {
    let mut remote = ParsedRemoteArgs::default();
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        if remote.consume(&argument, &mut arguments)? {
            continue;
        }
        match argument.as_str() {
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.pack_discover_argument_unknown",
                    "the pack discover argument is not recognized or was repeated",
                ));
            }
        }
    }
    Ok(PackDiscoverArgs {
        remote: remote.finish()?,
        json,
    })
}

fn parse_pack_adopt(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PackAdoptArgs, CliError> {
    let mut pack_id = None;
    let mut remote = ParsedRemoteArgs::default();
    let mut environment = None;
    let mut assume_yes = false;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        if remote.consume(&argument, &mut arguments)? {
            continue;
        }
        match argument.as_str() {
            "--pack" if pack_id.is_none() => {
                pack_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--pack")?);
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--yes" if !assume_yes => assume_yes = true,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.pack_adopt_argument_unknown",
                    "the pack adopt argument is not recognized or was repeated",
                ));
            }
        }
    }
    Ok(PackAdoptArgs {
        pack_id: pack_id
            .ok_or_else(|| CliError::new("cli.pack_required", "pack adopt requires one --pack"))?,
        remote: remote.finish()?,
        environment,
        assume_yes,
        json,
    })
}

fn parse_pack_rollback(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PackRollbackArgs, CliError> {
    let mut pack_id = None;
    let mut expected_prior = None;
    let mut target_revision = None;
    let mut remote = ParsedRemoteArgs::default();
    let mut environment = None;
    let mut assume_yes = false;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        if remote.consume(&argument, &mut arguments)? {
            continue;
        }
        match argument.as_str() {
            "--pack" if pack_id.is_none() => {
                pack_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--pack")?);
            }
            "--expected-prior" if expected_prior.is_none() => {
                expected_prior = Some(parse_pack_revision(
                    &mut arguments,
                    "--expected-prior is invalid",
                )?);
            }
            "--to" if target_revision.is_none() => {
                target_revision = Some(parse_pack_revision(&mut arguments, "--to is invalid")?);
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--yes" if !assume_yes => assume_yes = true,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.pack_rollback_argument_unknown",
                    "the pack rollback argument is not recognized or was repeated",
                ));
            }
        }
    }
    Ok(PackRollbackArgs {
        pack_id: pack_id.ok_or_else(|| {
            CliError::new("cli.pack_required", "pack rollback requires one --pack")
        })?,
        expected_prior: expected_prior.ok_or_else(|| {
            CliError::new(
                "cli.pack_expected_prior_required",
                "pack rollback requires --expected-prior",
            )
        })?,
        target_revision: target_revision.ok_or_else(|| {
            CliError::new(
                "cli.pack_rollback_target_required",
                "pack rollback requires --to",
            )
        })?,
        remote: remote.finish()?,
        environment,
        assume_yes,
        json,
    })
}

fn parse_pack_revision(
    arguments: &mut impl Iterator<Item = OsString>,
    message: &'static str,
) -> Result<ContentHash, CliError> {
    ContentHash::parse(required_value(arguments)?)
        .map_err(|_| CliError::new("cli.pack_revision_invalid", message))
}

fn parse_pack_remove(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PackRemoveArgs, CliError> {
    let mut pack_id = None;
    let mut expected_prior = None;
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
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
    })
}

#[derive(Clone, Copy)]
enum PackMemberOperation {
    Create,
    Update,
}

struct ParsedPackMutation {
    pack_id: AssetId,
    expected_prior: Option<ContentHash>,
    members: BTreeSet<AssetId>,
    environment: Option<PathBuf>,
    json: bool,
}

fn parse_pack_create(
    arguments: impl Iterator<Item = OsString>,
) -> Result<PackCreateArgs, CliError> {
    let parsed = parse_pack_member_mutation(arguments, PackMemberOperation::Create)?;
    Ok(PackCreateArgs {
        pack_id: parsed.pack_id,
        members: parsed.members,
        environment: parsed.environment,
        json: parsed.json,
    })
}

fn parse_pack_update(
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
    })
}

fn parse_pack_member_mutation(
    mut arguments: impl Iterator<Item = OsString>,
    operation: PackMemberOperation,
) -> Result<ParsedPackMutation, CliError> {
    let mut pack_id = None;
    let mut expected_prior = None;
    let mut members = BTreeSet::new();
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
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
        pack_id,
        expected_prior,
        members,
        environment,
        json,
    })
}

fn parse_pack_inspect(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<PackInspectArgs, CliError> {
    let mut pack_id = None;
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--pack" if pack_id.is_none() => {
                pack_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--pack")?);
            }
            "--pack" => {
                return Err(CliError::new(
                    "cli.pack_repeated",
                    "--pack may be supplied only once",
                ));
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.pack_inspect_argument_unknown",
                    "the pack inspect argument is not recognized",
                ));
            }
        }
    }
    Ok(PackInspectArgs {
        pack_id: pack_id.ok_or_else(|| {
            CliError::new("cli.pack_required", "pack inspect requires one --pack")
        })?,
        environment,
        json,
    })
}

fn parse_remove(mut arguments: impl Iterator<Item = OsString>) -> Result<RemoveArgs, CliError> {
    let mut asset_id = None;
    let mut target = None;
    let mut scope = None;
    let mut project_root = None;
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
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
    })
}

fn parse_trust(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let operation = next_utf8(&mut arguments)?.ok_or_else(|| {
        CliError::new(
            "cli.trust_operation_missing",
            "trust requires either the plan or audit operation",
        )
    })?;
    let operation = match operation.as_str() {
        "plan" => TrustOperation::Plan,
        "apply" => TrustOperation::Apply,
        "audit" => TrustOperation::Audit,
        _ => {
            return Err(CliError::new(
                "cli.trust_operation_unknown",
                "the requested trust operation is not recognized",
            ));
        }
    };
    let mut asset_id = None;
    let mut decision = None;
    let mut confirm = None;
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--asset" => {
                if asset_id.is_some() {
                    return Err(CliError::new(
                        "cli.trust_asset_repeated",
                        "--asset may be supplied only once",
                    ));
                }
                asset_id = Some(parse_asset_id(&required_value(&mut arguments)?, "--asset")?);
            }
            "--decision" if operation != TrustOperation::Audit => {
                if decision.is_some() {
                    return Err(CliError::new(
                        "cli.trust_decision_repeated",
                        "--decision may be supplied only once",
                    ));
                }
                decision = Some(match required_value(&mut arguments)?.as_str() {
                    "trusted" => TrustDecisionArg::Trusted,
                    "denied" => TrustDecisionArg::Denied,
                    _ => {
                        return Err(CliError::new(
                            "cli.trust_decision_invalid",
                            "--decision must be trusted or denied",
                        ));
                    }
                });
            }
            "--decision" => {
                return Err(CliError::new(
                    "cli.trust_decision_forbidden",
                    "trust audit does not accept --decision",
                ));
            }
            "--confirm" if operation == TrustOperation::Apply => {
                if confirm.is_some() {
                    return Err(CliError::new(
                        "cli.trust_confirm_repeated",
                        "--confirm may be supplied only once",
                    ));
                }
                confirm = Some(ContentHash::parse(required_value(&mut arguments)?).map_err(
                    |_| {
                        CliError::new(
                            "cli.trust_confirm_invalid",
                            "--confirm must be an algorithm-qualified plan digest",
                        )
                    },
                )?);
            }
            "--confirm" => {
                return Err(CliError::new(
                    "cli.trust_confirm_forbidden",
                    "only trust apply accepts --confirm",
                ));
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.trust_argument_unknown",
                    "the trust argument is not recognized",
                ));
            }
        }
    }
    match operation {
        TrustOperation::Plan => Ok(Command::TrustPlan(TrustPlanArgs {
            asset_id: required_trust_asset(asset_id, "trust plan requires --asset")?,
            decision: required_trust_decision(decision, "trust plan requires --decision")?,
            environment,
            json,
        })),
        TrustOperation::Apply => Ok(Command::TrustApply(TrustApplyArgs {
            asset_id: required_trust_asset(asset_id, "trust apply requires --asset")?,
            decision: required_trust_decision(decision, "trust apply requires --decision")?,
            confirm: confirm.ok_or_else(|| {
                CliError::new(
                    "cli.trust_confirm_missing",
                    "trust apply requires --confirm with the exact plan digest",
                )
            })?,
            environment,
            json,
        })),
        TrustOperation::Audit => Ok(Command::TrustAudit(TrustAuditArgs {
            asset_id,
            environment,
            json,
        })),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TrustOperation {
    Plan,
    Apply,
    Audit,
}

fn required_trust_asset(
    asset_id: Option<AssetId>,
    message: &'static str,
) -> Result<AssetId, CliError> {
    asset_id.ok_or_else(|| CliError::new("cli.trust_asset_missing", message))
}

fn required_trust_decision(
    decision: Option<TrustDecisionArg>,
    message: &'static str,
) -> Result<TrustDecisionArg, CliError> {
    decision.ok_or_else(|| CliError::new("cli.trust_decision_missing", message))
}

fn parse_sync(mut arguments: impl Iterator<Item = OsString>) -> Result<Command, CliError> {
    let operation = next_utf8(&mut arguments)?.ok_or_else(|| {
        CliError::new(
            "cli.sync_operation_missing",
            "sync requires either the plan or apply operation",
        )
    })?;
    let apply = match operation.as_str() {
        "plan" => false,
        "apply" => true,
        _ => {
            return Err(CliError::new(
                "cli.sync_operation_unknown",
                "the requested sync operation is not recognized",
            ));
        }
    };
    let mut remote = ParsedRemoteArgs::default();
    let mut environment = None;
    let mut confirm = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        if remote.consume(&argument, &mut arguments)? {
            continue;
        }
        match argument.as_str() {
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--confirm" if apply => {
                if confirm.is_some() {
                    return Err(CliError::new(
                        "cli.sync_confirm_repeated",
                        "--confirm may be supplied only once",
                    ));
                }
                confirm = Some(ContentHash::parse(required_value(&mut arguments)?).map_err(
                    |_| {
                        CliError::new(
                            "cli.sync_confirm_invalid",
                            "--confirm must be an algorithm-qualified plan digest",
                        )
                    },
                )?);
            }
            "--confirm" => {
                return Err(CliError::new(
                    "cli.sync_confirm_forbidden",
                    "sync plan does not accept --confirm",
                ));
            }
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.sync_argument_unknown",
                    "the sync argument is not recognized",
                ));
            }
        }
    }
    let arguments = SyncArgs {
        remote: remote.finish()?,
        environment,
        confirm,
        json,
    };
    if apply && arguments.confirm.is_none() {
        return Err(CliError::new(
            "cli.sync_confirm_missing",
            "sync apply requires --confirm with the exact plan digest",
        ));
    }
    Ok(if apply {
        Command::SyncApply(arguments)
    } else {
        Command::SyncPlan(arguments)
    })
}

fn parse_materialize(
    mut arguments: impl Iterator<Item = OsString>,
    command: &'static str,
) -> Result<MaterializeArgs, CliError> {
    let mut assets = BTreeSet::new();
    let mut packs = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut profile = None;
    let mut scope = None;
    let mut project_root = None;
    let mut version_binaries = Vec::new();
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--profile" => {
                if profile.is_some() {
                    return Err(CliError::new(
                        "cli.profile_repeated",
                        "--profile may be supplied only once",
                    ));
                }
                profile = Some(
                    ProfileId::parse(required_value(&mut arguments)?).map_err(|_| {
                        CliError::new("cli.profile_invalid", "--profile is invalid")
                    })?,
                );
            }
            "--asset" => {
                assets.insert(parse_asset_id(&required_value(&mut arguments)?, "--asset")?);
            }
            "--pack" => {
                packs.insert(parse_asset_id(&required_value(&mut arguments)?, "--pack")?);
            }
            "--target" => {
                targets.insert(parse_harness(&required_value(&mut arguments)?)?);
            }
            "--scope" => {
                if scope.is_some() {
                    return Err(CliError::new(
                        "cli.scope_repeated",
                        "--scope may be supplied only once",
                    ));
                }
                scope = Some(parse_materialize_scope(&required_value(&mut arguments)?)?);
            }
            "--project-root" => {
                if project_root.is_some() {
                    return Err(CliError::new(
                        "cli.project_root_repeated",
                        "--project-root may be supplied only once",
                    ));
                }
                project_root = Some(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--version-binary" => {
                version_binaries.push(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.materialize_argument_unknown",
                    match command {
                        "plan" => "the plan argument is not recognized",
                        _ => "the apply argument is not recognized",
                    },
                ));
            }
        }
    }
    if profile.is_some() && (!assets.is_empty() || !packs.is_empty() || !targets.is_empty()) {
        return Err(CliError::new(
            "cli.profile_selection_conflict",
            "--profile cannot be combined with --asset, --pack, or --target",
        ));
    }
    Ok(MaterializeArgs {
        profile,
        assets,
        packs,
        targets,
        scope: scope.unwrap_or(HarnessScope::User),
        project_root,
        version_binaries,
        environment,
        json,
    })
}

fn parse_init(mut arguments: impl Iterator<Item = OsString>) -> Result<InitArgs, CliError> {
    let mut machine_id = None;
    let mut project_root = None;
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--machine-id" => {
                if machine_id.is_some() {
                    return Err(CliError::new(
                        "cli.machine_id_repeated",
                        "--machine-id may be supplied only once",
                    ));
                }
                machine_id = Some(
                    kitrove_model::MachineId::parse(required_value(&mut arguments)?).map_err(
                        |_| CliError::new("cli.machine_id_invalid", "--machine-id is invalid"),
                    )?,
                );
            }
            "--project-root" => {
                if project_root.is_some() {
                    return Err(CliError::new(
                        "cli.project_root_repeated",
                        "--project-root may be supplied only once",
                    ));
                }
                project_root = Some(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.init_argument_unknown",
                    "the init argument is not recognized",
                ));
            }
        }
    }
    Ok(InitArgs {
        machine_id,
        project_root,
        environment,
        json,
    })
}

fn parse_environment(
    mut arguments: impl Iterator<Item = OsString>,
    command: &'static str,
) -> Result<EnvironmentArgs, CliError> {
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            _ => {
                return Err(CliError::new(
                    "cli.command_argument_unknown",
                    match command {
                        "status" => "the status argument is not recognized",
                        "pack list" => "the pack list argument is not recognized",
                        _ => "the lock argument is not recognized",
                    },
                ));
            }
        }
    }
    Ok(EnvironmentArgs { environment, json })
}

fn parse_adopt(mut arguments: impl Iterator<Item = OsString>) -> Result<AdoptArgs, CliError> {
    let mut observation_id = None;
    let mut asset_id = None;
    let mut update_asset_id = None;
    let mut expected_prior = None;
    let mut binding = None;
    let mut harnesses = BTreeSet::new();
    let mut scope = None;
    let mut project_root = None;
    let mut roots = Vec::new();
    let mut environment = None;
    let mut json = false;
    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--id" => {
                if asset_id.is_some() {
                    return Err(CliError::new(
                        "cli.asset_id_repeated",
                        "--id may be supplied only once",
                    ));
                }
                asset_id = Some(
                    AssetId::parse(required_value(&mut arguments)?).map_err(|_| {
                        CliError::new(
                            "cli.asset_id_invalid",
                            "--id must be a valid portable asset identifier",
                        )
                    })?,
                );
            }
            "--update" => {
                if update_asset_id.is_some() {
                    return Err(CliError::new(
                        "cli.update_repeated",
                        "--update may be supplied only once",
                    ));
                }
                update_asset_id = Some(parse_asset_id(
                    &required_value(&mut arguments)?,
                    "--update",
                )?);
            }
            "--expected-prior" => {
                if expected_prior.is_some() {
                    return Err(CliError::new(
                        "cli.expected_prior_repeated",
                        "--expected-prior may be supplied only once",
                    ));
                }
                expected_prior = Some(
                    ContentHash::parse(required_value(&mut arguments)?).map_err(|_| {
                        CliError::new(
                            "cli.expected_prior_invalid",
                            "--expected-prior must be a valid algorithm-qualified content hash",
                        )
                    })?,
                );
            }
            "--binding" => {
                if binding.is_some() {
                    return Err(CliError::new(
                        "cli.binding_repeated",
                        "--binding may be supplied only once",
                    ));
                }
                binding = Some(
                    kitrove_model::BindingName::parse(required_value(&mut arguments)?).map_err(
                        |_| {
                            CliError::new(
                                "cli.binding_invalid",
                                "--binding must be a valid symbolic binding name",
                            )
                        },
                    )?,
                );
            }
            "--harness" => {
                let value = required_value(&mut arguments)?;
                harnesses.insert(parse_harness(&value)?);
            }
            "--scope" => {
                if scope.is_some() {
                    return Err(CliError::new(
                        "cli.scope_repeated",
                        "--scope may be supplied only once",
                    ));
                }
                scope = Some(parse_scope(&required_value(&mut arguments)?)?);
            }
            "--root" => roots.push(parse_root(&required_value(&mut arguments)?)?),
            "--project-root" => {
                if project_root.is_some() {
                    return Err(CliError::new(
                        "cli.project_root_repeated",
                        "--project-root may be supplied only once",
                    ));
                }
                project_root = Some(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--environment" => set_environment(&mut environment, &mut arguments)?,
            "--json" if !json => json = true,
            "--json" => return Err(repeated_json()),
            value if !value.starts_with('-') && observation_id.is_none() => {
                observation_id = Some(value.to_owned());
            }
            _ => {
                return Err(CliError::new(
                    "cli.adopt_argument_unknown",
                    "the adopt argument is not recognized",
                ));
            }
        }
    }
    let observation_id = observation_id.ok_or_else(|| {
        CliError::new(
            "cli.observation_required",
            "adopt requires one observation identifier from a current scan",
        )
    })?;
    if asset_id.is_some() && update_asset_id.is_some() {
        return Err(CliError::new(
            "cli.adopt_mode_conflict",
            "--id and --update cannot be used together",
        ));
    }
    if update_asset_id.is_some() != expected_prior.is_some() {
        return Err(CliError::new(
            "cli.update_authority_incomplete",
            "--update and --expected-prior must be supplied together",
        ));
    }
    if harnesses.is_empty() {
        harnesses = tier_one_harnesses();
    }
    Ok(AdoptArgs {
        observation_id,
        asset_id,
        update_asset_id,
        expected_prior,
        binding,
        harnesses,
        scope: scope.unwrap_or(ScopeSelection::All),
        project_root,
        roots,
        environment,
        json,
    })
}

fn parse_asset_id(value: &str, option: &'static str) -> Result<AssetId, CliError> {
    AssetId::parse(value).map_err(|_| {
        CliError::new(
            "cli.asset_id_invalid",
            match option {
                "--update" => "--update must name a valid portable asset identifier",
                "--asset" => "--asset must name a valid portable asset identifier",
                "--pack" => "--pack must name a valid portable asset identifier",
                _ => "--id must be a valid portable asset identifier",
            },
        )
    })
}

fn set_environment(
    environment: &mut Option<PathBuf>,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<(), CliError> {
    if environment.is_some() {
        return Err(CliError::new(
            "cli.environment_repeated",
            "--environment may be supplied only once",
        ));
    }
    *environment = Some(PathBuf::from(required_os_value(arguments)?));
    Ok(())
}

const fn repeated_json() -> CliError {
    CliError::new("cli.json_repeated", "--json may be supplied only once")
}

fn finish_information(
    mut arguments: impl Iterator<Item = OsString>,
    command: Command,
) -> Result<Command, CliError> {
    if arguments.next().is_some() {
        return Err(CliError::new(
            "cli.arguments_unexpected",
            "this informational command does not accept arguments",
        ));
    }
    Ok(command)
}

fn parse_scan(mut arguments: impl Iterator<Item = OsString>) -> Result<ScanArgs, CliError> {
    let mut harnesses = BTreeSet::new();
    let mut scope = None;
    let mut project_root = None;
    let mut roots = Vec::new();
    let mut environment = None;
    let mut json = false;

    while let Some(argument) = next_utf8(&mut arguments)? {
        match argument.as_str() {
            "--harness" => {
                let value = required_value(&mut arguments)?;
                harnesses.insert(parse_harness(&value)?);
            }
            "--scope" => {
                if scope.is_some() {
                    return Err(CliError::new(
                        "cli.scope_repeated",
                        "--scope may be supplied only once",
                    ));
                }
                scope = Some(parse_scope(&required_value(&mut arguments)?)?);
            }
            "--root" => roots.push(parse_root(&required_value(&mut arguments)?)?),
            "--project-root" => {
                if project_root.is_some() {
                    return Err(CliError::new(
                        "cli.project_root_repeated",
                        "--project-root may be supplied only once",
                    ));
                }
                project_root = Some(PathBuf::from(required_os_value(&mut arguments)?));
            }
            "--environment" => {
                set_environment(&mut environment, &mut arguments)?;
            }
            "--json" => {
                if json {
                    return Err(repeated_json());
                }
                json = true;
            }
            _ => {
                return Err(CliError::new(
                    "cli.scan_argument_unknown",
                    "the scan argument is not recognized",
                ));
            }
        }
    }

    if harnesses.is_empty() {
        harnesses = tier_one_harnesses();
    }

    Ok(ScanArgs {
        harnesses,
        scope: scope.unwrap_or(ScopeSelection::All),
        project_root,
        roots,
        environment,
        json,
    })
}

fn required_value(arguments: &mut impl Iterator<Item = OsString>) -> Result<String, CliError> {
    let Some(value) = next_utf8(arguments)? else {
        return Err(missing_value());
    };
    if value.starts_with("--") {
        return Err(missing_value());
    }
    Ok(value)
}

fn required_os_value(arguments: &mut impl Iterator<Item = OsString>) -> Result<OsString, CliError> {
    let Some(value) = arguments.next() else {
        return Err(missing_value());
    };
    if value.is_empty() || value.to_str().is_some_and(|value| value.starts_with("--")) {
        return Err(missing_value());
    }
    Ok(value)
}

const fn missing_value() -> CliError {
    CliError::new(
        "cli.option_value_missing",
        "the preceding option requires a value",
    )
}

fn next_utf8(arguments: &mut impl Iterator<Item = OsString>) -> Result<Option<String>, CliError> {
    arguments
        .next()
        .map(|argument| {
            argument.into_string().map_err(|_| {
                CliError::new(
                    "cli.argument_encoding_invalid",
                    "command arguments must use the platform text encoding",
                )
            })
        })
        .transpose()
}

fn parse_harness(value: &str) -> Result<HarnessId, CliError> {
    match value {
        "claude" => Ok(HarnessId::Claude),
        "codex" => Ok(HarnessId::Codex),
        "pi" => Ok(HarnessId::Pi),
        "opencode" => Ok(HarnessId::OpenCode),
        _ => Err(CliError::new(
            "cli.harness_invalid",
            "--harness must name claude, codex, pi, or opencode",
        )),
    }
}

fn parse_scope(value: &str) -> Result<ScopeSelection, CliError> {
    match value {
        "user" => Ok(ScopeSelection::User),
        "project" => Ok(ScopeSelection::Project),
        "all" => Ok(ScopeSelection::All),
        _ => Err(CliError::new(
            "cli.scope_invalid",
            "--scope must be user, project, or all",
        )),
    }
}

fn parse_materialize_scope(value: &str) -> Result<HarnessScope, CliError> {
    match value {
        "user" => Ok(HarnessScope::User),
        "project" => Ok(HarnessScope::Project),
        _ => Err(CliError::new(
            "cli.scope_invalid",
            "--scope must be user or project for plan and apply",
        )),
    }
}

fn parse_root(value: &str) -> Result<ExplicitRoot, CliError> {
    let mut parts = value.splitn(3, ':');
    let harness = parts.next().and_then(|part| parse_harness(part).ok());
    let scope = match parts.next() {
        Some("user") => Some(HarnessScope::User),
        Some("project") => Some(HarnessScope::Project),
        _ => None,
    };
    let path = parts.next().filter(|path| !path.is_empty());
    match (harness, scope, path) {
        (Some(harness), Some(scope), Some(path)) => {
            Ok(ExplicitRoot::new(harness, scope, PathBuf::from(path)))
        }
        _ => Err(CliError::new(
            "cli.root_invalid",
            "--root must use <harness>:<user|project>:<path>",
        )),
    }
}

pub(crate) const HELP: &str = "Kitrove agent capability portability\n\nUSAGE:\n    kitrove <COMMAND>\n    kitrove init [OPTIONS]\n    kitrove scan [OPTIONS]\n    kitrove adopt [OPTIONS] <observation-id>\n    kitrove adopt --update <asset-id> --expected-prior <content-hash> [OPTIONS] <observation-id>\n    kitrove remove --asset <asset-id> --target <harness> [OPTIONS]\n    kitrove plan [--profile <profile-id> | --asset <asset-id> | --pack <pack-id>]... [--target <harness>]... [OPTIONS]\n    kitrove apply [--profile <profile-id> | --asset <asset-id> | --pack <pack-id>]... [--target <harness>]... [OPTIONS]\n    kitrove sync plan (--filesystem <path> | --git <https-url>) [OPTIONS]\n    kitrove sync apply (--filesystem <path> | --git <https-url>) --confirm <plan-digest> [OPTIONS]\n    kitrove trust plan --asset <asset-id> --decision <trusted|denied> [OPTIONS]\n    kitrove trust apply --asset <asset-id> --decision <trusted|denied> --confirm <plan-digest> [OPTIONS]\n    kitrove trust audit [--asset <asset-id>] [OPTIONS]\n    kitrove versions probe --harness <pi|opencode> --binary <absolute-path> [--json]\n    kitrove status [--environment <path>] [--json]\n    kitrove lock [--environment <path>] [--json]\n\nCOMMANDS:\n    init         Create empty portable and machine-local authority after a read-only scan\n    scan         Inspect local harness capabilities without making changes\n    adopt        Adopt or explicitly update one current accepted observation\n    remove       Remove one exact receipt-backed local projection\n    plan         Plan receipt-backed materialization without writing\n    apply        Confirm and atomically commit selected materializations\n    sync         Plan or apply conditional cross-machine synchronization\n    trust        Plan, apply, or audit machine-local exact-content executable trust\n    versions     Explicitly probe reviewed harness version evidence\n    status       Verify manifest, generated lock, objects, and recovery state\n    lock         Regenerate only the manifest-derived lock\n    about        Show the product description\n    north-star   Print the durable product invariants\n    invariants   Print the architectural invariants\n    help         Show this help\n\nSCAN AND ADOPT SELECTION OPTIONS:\n    --harness <claude|codex|pi|opencode>    Select a harness; may repeat\n    --scope <user|project|all>              Select one scope\n    --root <harness>:<user|project>:<path>  Add an explicit root; may repeat\n\nPLAN, APPLY, AND REMOVE SELECTION OPTIONS:\n    --profile <profile-id>                  Select one inherited portable profile\n    --asset <asset-id>                      Select an asset; may repeat for plan/apply\n    --pack <pack-id>                        Select a pack; may repeat for plan/apply\n    --target <claude|codex|pi|opencode>     Select a target; may repeat for plan/apply\n    --scope <user|project>                  Select destination scope (default: user)\n    --version-binary <absolute-path>        Supply a required harness binary; may repeat\n\nINIT OPTIONS:\n    --machine-id <machine-id>               Set the local machine identity\n\nSYNC OPTIONS:\n    --filesystem <path>                     Select an existing filesystem remote\n    --git <https-url>                       Select a canonical HTTPS Git remote\n    --confirm <plan-digest>                 Confirm the exact recomputed sync plan\n\nTRUST OPTIONS:\n    --asset <asset-id>                      Select one native executable asset\n    --decision <trusted|denied>             Select the planned local decision\n    --confirm <plan-digest>                 Confirm the exact recomputed trust plan\n\nSHARED OPTIONS:\n    --project-root <path>                   Supply the project boundary\n    --environment <path>                    Select a Kitrove environment\n    --json                                  Emit canonical JSON\n\nADOPT OPTIONS:\n    --id <asset-id>                         Choose an ID for first adoption\n    --update <asset-id>                     Explicitly update an existing asset\n    --expected-prior <content-hash>         Require the exact prior asset revision\n";

pub(crate) const ADDITIONAL_MCP_HELP: &str = "\nADDITIONAL MCP ADOPT OPTIONS:\n    --binding <binding-name>    Map a native MCP environment reference to a logical binding\n";

pub(crate) const ADDITIONAL_SYNC_HELP: &str = "\nADDITIONAL SYNC OPTIONS:\n    kitrove sync plan --git <https-url> --git-env-credentials [OPTIONS]\n    kitrove sync plan --ssh <ssh-url> --known-hosts <path> [OPTIONS]\n    kitrove sync apply --ssh <ssh-url> --known-hosts <path> --confirm <plan-digest> [OPTIONS]\n\n    --git-env-credentials    Read KITROVE_GIT_USERNAME and KITROVE_GIT_TOKEN\n    --ssh <ssh-url>          Select a canonical SSH Git remote\n    --known-hosts <path>     Select explicit SSH host-key authority\n";

pub(crate) const ADDITIONAL_PACK_HELP: &str = "\nPACK COMMANDS:\n    kitrove pack discover (--filesystem <path> | --git <https-url> | --ssh <ssh-url> --known-hosts <path>) [--json]\n    kitrove pack adopt --pack <pack-id> (--filesystem <path> | --git <https-url> | --ssh <ssh-url> --known-hosts <path>) [OPTIONS]\n    kitrove pack create --pack <pack-id> --member <asset-or-pack-id>... [OPTIONS]\n    kitrove pack update --pack <pack-id> --expected-prior <content-hash> --member <asset-or-pack-id>... [OPTIONS]\n    kitrove pack rollback --pack <pack-id> --expected-prior <content-hash> --to <content-hash> (--filesystem <path> | --git <https-url> | --ssh <ssh-url> --known-hosts <path>) [OPTIONS]\n    kitrove pack remove --pack <pack-id> --expected-prior <content-hash> [OPTIONS]\n    kitrove pack list [--environment <path>] [--json]\n    kitrove pack inspect --pack <pack-id> [--environment <path>] [--json]\n\n    discover              List packs in current verified distribution authority without mutation\n    adopt                 Import one exact pack closure and its verified immutable objects\n    create                Group members sharing one exact non-harness distribution source\n    update                Replace exact-prior membership and re-derive affected parent packs\n    rollback              Restore one exact pack revision from verified remote history\n    remove                Release exact local pack claims and remove unshared projections\n    list                  List first-class packs without expanding their components\n    inspect               Inspect one validated pack and its bounded component graph\n    --pack <pack-id>      Select one first-class pack\n    --member <id>         Select a direct pack member; may repeat\n    --expected-prior      Require the exact current pack revision for update, rollback, or removal\n    --to <content-hash>   Select the exact historical pack revision\n    --yes                 Confirm adoption or rollback non-interactively\n";

#[cfg(test)]
mod tests {
    use super::{AssetId, Command, GitCredentialSource, SyncRemoteArgs, parse_args};

    #[test]
    fn root_path_retains_later_colons() {
        let command = parse_args([
            "scan".into(),
            "--root".into(),
            "pi:user:/tmp/one:two:three".into(),
        ])
        .unwrap();
        let Command::Scan(arguments) = command else {
            panic!("expected scan command");
        };
        assert_eq!(
            arguments.roots[0].path.to_string_lossy(),
            "/tmp/one:two:three"
        );
    }

    #[test]
    fn version_probe_requires_an_explicit_reviewed_harness_and_binary() {
        let binary = if cfg!(windows) {
            r"C:\tools\pi.exe"
        } else {
            "/tools/pi"
        };
        let command = parse_args([
            "versions".into(),
            "probe".into(),
            "--harness".into(),
            "pi".into(),
            "--binary".into(),
            binary.into(),
            "--json".into(),
        ])
        .unwrap();
        let Command::VersionProbe(arguments) = command else {
            panic!("expected version probe command");
        };
        assert_eq!(arguments.harness, kitrove_model::HarnessId::Pi);
        assert_eq!(arguments.binary, std::path::PathBuf::from(binary));
        assert!(arguments.json);

        let opencode_binary = if cfg!(windows) {
            r"C:\tools\opencode2.exe"
        } else {
            "/tools/opencode2"
        };
        let command = parse_args([
            "versions".into(),
            "probe".into(),
            "--harness".into(),
            "opencode".into(),
            "--binary".into(),
            opencode_binary.into(),
        ])
        .unwrap();
        let Command::VersionProbe(arguments) = command else {
            panic!("expected version probe command");
        };
        assert_eq!(arguments.harness, kitrove_model::HarnessId::OpenCode);
        assert_eq!(arguments.binary, std::path::PathBuf::from(opencode_binary));

        for invalid in [
            vec!["versions", "probe", "--harness", "pi"],
            vec!["versions", "probe", "--binary", binary],
            vec![
                "versions",
                "probe",
                "--harness",
                "codex",
                "--binary",
                binary,
            ],
        ] {
            assert!(parse_args(invalid.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn portable_commands_reject_ambiguous_or_repeated_arguments() {
        for arguments in [
            vec!["adopt", "one", "two"],
            vec!["adopt"],
            vec!["adopt", "--id", "Bad", "observation"],
            vec!["status", "--json", "--json"],
            vec!["lock", "unexpected"],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn pack_commands_have_exact_nonconflicting_selection() {
        let command = parse_args([
            "pack".into(),
            "create".into(),
            "--pack".into(),
            "tooling".into(),
            "--member".into(),
            "beta".into(),
            "--member".into(),
            "alpha".into(),
        ])
        .unwrap();
        let Command::PackCreate(arguments) = command else {
            panic!("expected pack create command");
        };
        assert_eq!(arguments.pack_id.as_str(), "tooling");
        assert_eq!(
            arguments
                .members
                .iter()
                .map(AssetId::as_str)
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );

        let prior = format!("blake3:{}", "a".repeat(64));
        let command = parse_args([
            "pack".into(),
            "update".into(),
            "--pack".into(),
            "tooling".into(),
            "--expected-prior".into(),
            prior.clone().into(),
            "--member".into(),
            "alpha".into(),
        ])
        .unwrap();
        let Command::PackUpdate(arguments) = command else {
            panic!("expected pack update command");
        };
        assert_eq!(arguments.expected_prior.as_str(), prior);

        let target = format!("blake3:{}", "b".repeat(64));
        let command = parse_args([
            "pack".into(),
            "rollback".into(),
            "--pack".into(),
            "tooling".into(),
            "--expected-prior".into(),
            prior.clone().into(),
            "--to".into(),
            target.clone().into(),
            "--filesystem".into(),
            "/tmp/kitrove-history".into(),
            "--yes".into(),
        ])
        .unwrap();
        let Command::PackRollback(arguments) = command else {
            panic!("expected pack rollback command");
        };
        assert_eq!(arguments.pack_id.as_str(), "tooling");
        assert_eq!(arguments.expected_prior.as_str(), prior);
        assert_eq!(arguments.target_revision.as_str(), target);
        assert!(arguments.assume_yes);
        assert!(matches!(arguments.remote, SyncRemoteArgs::Filesystem(_)));

        let command = parse_args([
            "pack".into(),
            "remove".into(),
            "--pack".into(),
            "tooling".into(),
            "--expected-prior".into(),
            prior.clone().into(),
        ])
        .unwrap();
        let Command::PackRemove(arguments) = command else {
            panic!("expected pack remove command");
        };
        assert_eq!(arguments.pack_id.as_str(), "tooling");
        assert_eq!(arguments.expected_prior.as_str(), prior);

        let command = parse_args(["pack".into(), "list".into(), "--json".into()]).unwrap();
        let Command::PackList(arguments) = command else {
            panic!("expected pack list command");
        };
        assert!(arguments.json);

        let command = parse_args([
            "pack".into(),
            "inspect".into(),
            "--pack".into(),
            "tooling".into(),
        ])
        .unwrap();
        let Command::PackInspect(arguments) = command else {
            panic!("expected pack inspect command");
        };
        assert_eq!(arguments.pack_id.as_str(), "tooling");

        for arguments in [
            vec!["pack"],
            vec!["pack", "unknown"],
            vec!["pack", "create", "--pack", "tooling"],
            vec!["pack", "create", "--member", "alpha"],
            vec!["pack", "update", "--pack", "tooling", "--member", "alpha"],
            vec![
                "pack",
                "rollback",
                "--pack",
                "tooling",
                "--expected-prior",
                &prior,
                "--filesystem",
                "/tmp/history",
            ],
            vec!["pack", "remove", "--pack", "tooling"],
            vec![
                "pack",
                "update",
                "--pack",
                "tooling",
                "--expected-prior",
                "invalid",
                "--member",
                "alpha",
            ],
            vec![
                "pack", "create", "--pack", "tooling", "--member", "alpha", "--member", "alpha",
            ],
            vec!["pack", "list", "--pack", "tooling"],
            vec!["pack", "inspect"],
            vec!["pack", "inspect", "--pack", "one", "--pack", "two"],
            vec!["pack", "inspect", "--pack", "Bad"],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn profile_selection_is_exact_and_cannot_merge_ad_hoc_selectors() {
        let command = parse_args(
            ["apply", "--profile", "workstation"]
                .into_iter()
                .map(Into::into),
        )
        .unwrap();
        let Command::Apply(arguments) = command else {
            panic!("expected apply command");
        };
        assert_eq!(arguments.profile.unwrap().as_str(), "workstation");

        let command = parse_args(
            [
                "plan", "--asset", "review", "--pack", "tooling", "--pack", "nested",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::Plan(arguments) = command else {
            panic!("expected plan command");
        };
        assert_eq!(
            arguments
                .packs
                .iter()
                .map(AssetId::as_str)
                .collect::<Vec<_>>(),
            ["nested", "tooling"]
        );

        for arguments in [
            vec!["plan", "--profile", "workstation", "--asset", "review"],
            vec!["plan", "--profile", "workstation", "--pack", "tooling"],
            vec!["apply", "--profile", "workstation", "--target", "codex"],
            vec!["apply", "--profile", "one", "--profile", "two"],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn materialization_accepts_one_explicit_version_binary_per_selected_harness() {
        let command = parse_args(
            [
                "plan",
                "--target",
                "pi",
                "--target",
                "opencode",
                "--version-binary",
                "/tools/pi",
                "--version-binary",
                "/tools/opencode2",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::Plan(arguments) = command else {
            panic!("expected plan command");
        };
        assert_eq!(
            arguments.version_binaries,
            [
                std::path::PathBuf::from("/tools/pi"),
                std::path::PathBuf::from("/tools/opencode2")
            ]
        );
    }

    #[test]
    fn update_adoption_requires_complete_nonconflicting_authority() {
        let hash = format!("blake3:{}", "a".repeat(64));
        let command = parse_args(
            [
                "adopt",
                "--update",
                "asset",
                "--expected-prior",
                &hash,
                "observation",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::Adopt(arguments) = command else {
            panic!("expected adopt command");
        };
        assert_eq!(arguments.update_asset_id.unwrap().as_str(), "asset");
        assert_eq!(arguments.expected_prior.unwrap().as_str(), hash);

        for arguments in [
            vec!["adopt", "--update", "asset", "observation"],
            vec!["adopt", "--expected-prior", &hash, "observation"],
            vec![
                "adopt",
                "--id",
                "new",
                "--update",
                "asset",
                "--expected-prior",
                &hash,
                "observation",
            ],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn mcp_binding_is_one_valid_symbolic_name() {
        let command = parse_args(
            ["adopt", "--binding", "company_mcp_token", "blake3:entry"]
                .into_iter()
                .map(Into::into),
        )
        .unwrap();
        let Command::Adopt(arguments) = command else {
            panic!("expected adopt command");
        };
        assert_eq!(arguments.binding.unwrap().as_str(), "company_mcp_token");

        for arguments in [
            vec!["adopt", "--binding", "Bad Name", "entry"],
            vec!["adopt", "--binding", "one", "--binding", "two", "entry"],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn sync_apply_requires_one_exact_confirmation_and_one_remote() {
        let hash = format!("blake3:{}", "a".repeat(64));
        let command = parse_args(
            [
                "sync",
                "apply",
                "--filesystem",
                "/tmp/remote",
                "--confirm",
                &hash,
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::SyncApply(arguments) = command else {
            panic!("expected sync apply command");
        };
        assert_eq!(arguments.confirm.unwrap().as_str(), hash);

        let command = parse_args(
            [
                "sync",
                "plan",
                "--git",
                "https://example.com/owner/repo.git",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::SyncPlan(arguments) = command else {
            panic!("expected sync plan command");
        };
        assert!(matches!(
            arguments.remote,
            SyncRemoteArgs::Git {
                credentials: GitCredentialSource::Terminal,
                ..
            }
        ));

        let command = parse_args(
            [
                "sync",
                "plan",
                "--git",
                "https://example.com/owner/repo.git",
                "--git-env-credentials",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::SyncPlan(arguments) = command else {
            panic!("expected sync plan command");
        };
        assert!(matches!(
            arguments.remote,
            SyncRemoteArgs::Git {
                credentials: GitCredentialSource::Environment,
                ..
            }
        ));

        let command = parse_args(
            [
                "sync",
                "plan",
                "--ssh",
                "ssh://git@example.com/owner/repo.git",
                "--known-hosts",
                "/tmp/known_hosts",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::SyncPlan(arguments) = command else {
            panic!("expected sync plan command");
        };
        assert!(matches!(arguments.remote, SyncRemoteArgs::Ssh { .. }));

        for arguments in [
            vec!["sync"],
            vec!["sync", "plan"],
            vec![
                "sync",
                "plan",
                "--filesystem",
                "/tmp/remote",
                "--confirm",
                &hash,
            ],
            vec!["sync", "apply", "--filesystem", "/tmp/remote"],
            vec!["sync", "apply", "--confirm", &hash],
            vec![
                "sync",
                "plan",
                "--filesystem",
                "/tmp/remote",
                "--git",
                "https://example.com/owner/repo.git",
            ],
            vec![
                "sync",
                "plan",
                "--ssh",
                "ssh://git@example.com/owner/repo.git",
            ],
            vec!["sync", "plan", "--known-hosts", "/tmp/known_hosts"],
            vec!["sync", "plan", "--git-env-credentials"],
            vec![
                "sync",
                "plan",
                "--filesystem",
                "/tmp/remote",
                "--git-env-credentials",
            ],
            vec![
                "sync",
                "plan",
                "--git",
                "https://example.com/owner/repo.git",
                "--git-env-credentials",
                "--git-env-credentials",
            ],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn trust_apply_requires_explicit_asset_decision_and_confirmation() {
        let hash = format!("blake3:{}", "a".repeat(64));
        let command = parse_args(
            [
                "trust",
                "apply",
                "--asset",
                "native-review",
                "--decision",
                "trusted",
                "--confirm",
                &hash,
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::TrustApply(arguments) = command else {
            panic!("expected trust apply command");
        };
        assert_eq!(arguments.asset_id.as_str(), "native-review");
        assert_eq!(arguments.confirm.as_str(), hash);

        for arguments in [
            vec!["trust"],
            vec!["trust", "plan", "--asset", "native-review"],
            vec!["trust", "plan", "--decision", "trusted"],
            vec![
                "trust",
                "apply",
                "--asset",
                "native-review",
                "--decision",
                "trusted",
            ],
            vec!["trust", "audit", "--decision", "denied"],
            vec!["trust", "audit", "--confirm", &hash],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }

    #[test]
    fn remove_requires_one_asset_and_one_target() {
        let command = parse_args(
            [
                "remove", "--asset", "review", "--target", "codex", "--scope", "project",
            ]
            .into_iter()
            .map(Into::into),
        )
        .unwrap();
        let Command::Remove(arguments) = command else {
            panic!("expected remove command");
        };
        assert_eq!(arguments.asset_id.as_str(), "review");
        assert_eq!(arguments.target, kitrove_model::HarnessId::Codex);
        assert_eq!(arguments.scope, kitrove_model::HarnessScope::Project);

        for arguments in [
            vec!["remove", "--target", "codex"],
            vec!["remove", "--asset", "review"],
            vec![
                "remove", "--asset", "review", "--target", "codex", "--target", "pi",
            ],
        ] {
            assert!(parse_args(arguments.into_iter().map(Into::into)).is_err());
        }
    }
}
