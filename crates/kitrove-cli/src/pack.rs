use std::fmt::Write as _;

use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    FilesystemSyncBackend, GitSyncBackend, PackComponentKind, PackDistributionPlan, PackInspection,
    PackMutationPlan, PackRollbackPlan, PortableManifestCommitOutcome, SshGitSyncBackend,
    SyncBackend, SyncBackendRead, VerifiedRemoteHistory, commit_pack_creation,
    commit_pack_distribution_adoption, commit_pack_rollback, commit_pack_update, inspect_pack,
    plan_pack_creation, plan_pack_distribution_adoption, plan_pack_rollback, plan_pack_update,
    select_pack_distribution, select_pack_rollback_snapshot,
};
use kitrove_model::{
    AssetId, AssetKind, BlockedRequirement, ContentClass, EnvironmentManifest, FidelityResult,
    Pack, Source, SyncLimits,
};
use serde_json::{Value, json};

use crate::args::{
    CliError, EnvironmentArgs, PackAdoptArgs, PackCreateArgs, PackDiscoverArgs, PackInspectArgs,
    PackRollbackArgs, PackUpdateArgs, SyncRemoteArgs,
};
use crate::portable::{CompletedCommand, fidelity, load_manifest, serialization_error};
use crate::scan::resolve_required_environment_root;
use crate::sync::{backend_error, open_git_backend};

pub(crate) fn run_pack_list(arguments: EnvironmentArgs) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    Ok(CompletedCommand {
        output: render_pack_list(&manifest, arguments.json)?,
        status: 0,
    })
}

pub(crate) fn run_pack_discover(arguments: PackDiscoverArgs) -> Result<CompletedCommand, CliError> {
    match arguments.remote {
        SyncRemoteArgs::Filesystem(path) => {
            let backend = FilesystemSyncBackend::open(&path).map_err(backend_error)?;
            discover_with_backend(backend, arguments.json)
        }
        SyncRemoteArgs::Git { url, credentials } => {
            let backend: GitSyncBackend = open_git_backend(&url, credentials)?;
            discover_with_backend(backend, arguments.json)
        }
        SyncRemoteArgs::Ssh { url, known_hosts } => {
            let backend = SshGitSyncBackend::open(&url, known_hosts).map_err(backend_error)?;
            discover_with_backend(backend, arguments.json)
        }
    }
}

fn discover_with_backend<B: SyncBackend>(
    backend: B,
    json_output: bool,
) -> Result<CompletedCommand, CliError> {
    let limits = SyncLimits::default();
    let mut read = backend.begin_read(limits).map_err(backend_error)?;
    let history = read.inspect_history(limits).map_err(backend_error)?;
    let output = render_pack_discovery(&history, json_output)?;
    Ok(CompletedCommand { output, status: 0 })
}

pub(crate) fn run_pack_adopt(
    arguments: PackAdoptArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let PackAdoptArgs {
        pack_id,
        remote,
        environment,
        assume_yes,
        json,
    } = arguments;
    let request = PackAdoptionRequest {
        environment,
        pack_id,
        assume_yes,
        json_output: json,
    };
    match remote {
        SyncRemoteArgs::Filesystem(path) => {
            let backend = FilesystemSyncBackend::open(&path).map_err(backend_error)?;
            adopt_with_backend(request, backend, &mut confirm)
        }
        SyncRemoteArgs::Git { url, credentials } => {
            let backend: GitSyncBackend = open_git_backend(&url, credentials)?;
            adopt_with_backend(request, backend, &mut confirm)
        }
        SyncRemoteArgs::Ssh { url, known_hosts } => {
            let backend = SshGitSyncBackend::open(&url, known_hosts).map_err(backend_error)?;
            adopt_with_backend(request, backend, &mut confirm)
        }
    }
}

struct PackAdoptionRequest {
    environment: Option<std::path::PathBuf>,
    pack_id: AssetId,
    assume_yes: bool,
    json_output: bool,
}

fn adopt_with_backend<B: SyncBackend>(
    request: PackAdoptionRequest,
    backend: B,
    confirm: &mut impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(request.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let limits = SyncLimits::default();
    let mut read = backend.begin_read(limits).map_err(backend_error)?;
    let history = read.inspect_history(limits).map_err(backend_error)?;
    let selection = select_pack_distribution(&history, &request.pack_id)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let plan = plan_pack_distribution_adoption(&manifest, &selection)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let mut objects = Vec::with_capacity(plan.required_objects().len());
    for descriptor in plan.required_objects() {
        let object = read
            .fetch_object(descriptor, limits)
            .map_err(backend_error)?;
        if object.descriptor() != descriptor {
            return Err(CliError::new(
                "pack_adopt.object_mismatch",
                "the distribution backend returned an object outside selected authority",
            ));
        }
        objects.push(object);
    }
    if read.inspect_history(limits).map_err(backend_error)? != history {
        return Err(CliError::new(
            "pack_adopt.history_stale",
            "distribution history changed while pack adoption was planned",
        ));
    }
    drop(read);

    let rendered = render_pack_adoption_plan(&plan, request.json_output)?;
    if !request.assume_yes && !confirm(&rendered) {
        return Err(CliError::new(
            "pack_adopt.confirmation_required",
            "the pack adoption plan was not confirmed; no changes were made",
        ));
    }
    let outcome =
        commit_pack_distribution_adoption(&plan, &objects, &root, CaptureLimits::default())
            .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_adoption_result(&plan, outcome, request.json_output)?,
        status: 0,
    })
}

pub(crate) fn run_pack_create(
    arguments: PackCreateArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let plan = plan_pack_creation(&manifest, arguments.pack_id, arguments.members)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let rendered = render_pack_mutation_plan(&plan, arguments.json)?;
    if !confirm(&rendered) {
        return Err(CliError::new(
            "pack_create.confirmation_required",
            "the pack creation plan was not confirmed; no changes were made",
        ));
    }
    let outcome = commit_pack_creation(&plan, &root, CaptureLimits::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_mutation_result(&plan, outcome, arguments.json)?,
        status: 0,
    })
}

pub(crate) fn run_pack_update(
    arguments: PackUpdateArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let plan = plan_pack_update(
        &manifest,
        arguments.pack_id,
        arguments.expected_prior,
        arguments.members,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let rendered = render_pack_mutation_plan(&plan, arguments.json)?;
    if !confirm(&rendered) {
        return Err(CliError::new(
            "pack_update.confirmation_required",
            "the pack update plan was not confirmed; no changes were made",
        ));
    }
    let outcome = commit_pack_update(&plan, &root, CaptureLimits::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_mutation_result(&plan, outcome, arguments.json)?,
        status: 0,
    })
}

pub(crate) fn run_pack_rollback(
    arguments: PackRollbackArgs,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let PackRollbackArgs {
        pack_id,
        expected_prior,
        target_revision,
        remote,
        environment,
        assume_yes,
        json,
    } = arguments;
    let request = PackRollbackRequest {
        environment,
        pack_id,
        expected_prior,
        target_revision,
        assume_yes,
        json_output: json,
    };
    match remote {
        SyncRemoteArgs::Filesystem(path) => {
            let backend = FilesystemSyncBackend::open(&path).map_err(backend_error)?;
            run_pack_rollback_with_backend(request, backend, &mut confirm)
        }
        SyncRemoteArgs::Git { url, credentials } => {
            let backend: GitSyncBackend = open_git_backend(&url, credentials)?;
            run_pack_rollback_with_backend(request, backend, &mut confirm)
        }
        SyncRemoteArgs::Ssh { url, known_hosts } => {
            let backend = SshGitSyncBackend::open(&url, known_hosts).map_err(backend_error)?;
            run_pack_rollback_with_backend(request, backend, &mut confirm)
        }
    }
}

struct PackRollbackRequest {
    environment: Option<std::path::PathBuf>,
    pack_id: AssetId,
    expected_prior: kitrove_model::ContentHash,
    target_revision: kitrove_model::ContentHash,
    assume_yes: bool,
    json_output: bool,
}

fn run_pack_rollback_with_backend<B: SyncBackend>(
    request: PackRollbackRequest,
    backend: B,
    confirm: &mut impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(request.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let limits = SyncLimits::default();
    let mut read = backend.begin_read(limits).map_err(backend_error)?;
    let history = read.inspect_history(limits).map_err(backend_error)?;
    let selection = select_pack_rollback_snapshot(
        &history,
        &request.pack_id,
        &request.expected_prior,
        &request.target_revision,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let plan = plan_pack_rollback(&manifest, &selection)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let mut objects = Vec::with_capacity(plan.required_objects().len());
    for descriptor in plan.required_objects() {
        let object = read
            .fetch_object(descriptor, limits)
            .map_err(backend_error)?;
        if object.descriptor() != descriptor {
            return Err(CliError::new(
                "pack_rollback.object_mismatch",
                "the rollback backend returned an object outside selected history authority",
            ));
        }
        objects.push(object);
    }
    if read.inspect_history(limits).map_err(backend_error)? != history {
        return Err(CliError::new(
            "pack_rollback.history_stale",
            "remote history changed while pack rollback was planned",
        ));
    }
    drop(read);

    let rendered = render_pack_rollback_plan(&plan, request.json_output)?;
    if !request.assume_yes && !confirm(&rendered) {
        return Err(CliError::new(
            "pack_rollback.confirmation_required",
            "the pack rollback plan was not confirmed; no changes were made",
        ));
    }
    let outcome = commit_pack_rollback(&plan, &objects, &root, CaptureLimits::default())
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(CompletedCommand {
        output: render_pack_rollback_result(&plan, outcome, request.json_output)?,
        status: 0,
    })
}

pub(crate) fn run_pack_inspect(arguments: PackInspectArgs) -> Result<CompletedCommand, CliError> {
    let root = resolve_required_environment_root(arguments.environment.as_deref())?;
    let manifest = load_manifest(&root)?;
    let inspection = inspect_pack(&manifest, &arguments.pack_id)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    let output = if arguments.json {
        render_pack_inspection_json(&inspection)?
    } else {
        render_pack_inspection_text(&inspection)
    };
    Ok(CompletedCommand { output, status: 0 })
}

fn render_pack_list(manifest: &EnvironmentManifest, json_output: bool) -> Result<String, CliError> {
    if json_output {
        let packs = manifest.packs.values().map(pack_json).collect::<Vec<_>>();
        return serialize(&json!({
            "schema_version": 1,
            "operation": "pack_list",
            "packs": packs,
        }));
    }

    let mut output = format!("packs: {}\n", manifest.packs.len());
    for pack in manifest.packs.values() {
        writeln!(
            output,
            "pack {} {} {} members={}",
            pack.id,
            pack.content_hash,
            content_class(pack.content_class),
            pack.members.len(),
        )
        .expect("writing to a string cannot fail");
    }
    Ok(output)
}

fn render_pack_discovery(
    history: &VerifiedRemoteHistory,
    json_output: bool,
) -> Result<String, CliError> {
    let head = history.snapshots().first().ok_or_else(|| {
        CliError::new(
            "pack_discover.history_invalid",
            "pack discovery requires current verified distribution authority",
        )
    })?;
    let packs = head
        .snapshot()
        .manifest()
        .packs
        .values()
        .map(pack_json)
        .collect::<Vec<_>>();
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": "pack_discover",
            "backend_revision": head.revision().as_str(),
            "snapshot_digest": head.snapshot().snapshot_digest().as_str(),
            "packs": packs,
        }));
    }
    let mut output = format!(
        "distribution packs: {}\nbackend revision: {}\nsnapshot: {}\n",
        packs.len(),
        head.revision().as_str(),
        head.snapshot().snapshot_digest().as_str(),
    );
    for pack in head.snapshot().manifest().packs.values() {
        writeln!(
            output,
            "pack {} {} {} members={}",
            pack.id,
            pack.content_hash,
            content_class(pack.content_class),
            pack.members.len(),
        )
        .expect("writing to a string cannot fail");
    }
    Ok(output)
}

fn render_pack_adoption_plan(
    plan: &PackDistributionPlan,
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": "pack_adopt_plan",
            "digest": plan.digest().as_str(),
            "pack_id": plan.selection().pack_id().as_str(),
            "pack_revision": plan.selection().target_revision().as_str(),
            "backend_revision": plan.selection().backend_revision().as_str(),
            "snapshot_digest": plan.selection().snapshot_digest().as_str(),
            "required_objects": plan.required_objects().len(),
            "affected_packs": plan.affected_packs().len(),
        }));
    }
    Ok(format!(
        "pack adoption plan\ndigest: {}\npack: {}\nrevision: {}\nsnapshot: {}\nobjects: {}\nsemantics: exact verified closure import; no capability content is executed\n",
        plan.digest(),
        plan.selection().pack_id(),
        plan.selection().target_revision(),
        plan.selection().snapshot_digest().as_str(),
        plan.required_objects().len(),
    ))
}

fn render_pack_adoption_result(
    plan: &PackDistributionPlan,
    outcome: PortableManifestCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    let outcome = match outcome {
        PortableManifestCommitOutcome::Committed => "committed",
        PortableManifestCommitOutcome::Recovered => "recovered",
    };
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": "pack_adopt",
            "outcome": outcome,
            "digest": plan.digest().as_str(),
            "pack_id": plan.selection().pack_id().as_str(),
            "pack_revision": plan.selection().target_revision().as_str(),
        }));
    }
    Ok(format!(
        "pack adoption {outcome}\npack: {}\nrevision: {}\n",
        plan.selection().pack_id(),
        plan.selection().target_revision(),
    ))
}

fn render_pack_mutation_plan(
    plan: &PackMutationPlan,
    json_output: bool,
) -> Result<String, CliError> {
    let operation = plan.operation().as_str();
    let affected = plan
        .affected_packs()
        .iter()
        .map(|(id, change)| {
            json!({
                "pack_id": id.as_str(),
                "prior_revision": change.prior().map(|revision| revision.as_str()),
                "proposed_revision": change.proposed().as_str(),
            })
        })
        .collect::<Vec<_>>();
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": format!("pack_{operation}_plan"),
            "digest": plan.digest().as_str(),
            "pack": pack_json(plan.pack()),
            "members": plan.pack().members.keys().map(AssetId::as_str).collect::<Vec<_>>(),
            "added_members": plan.added_members().iter().map(AssetId::as_str).collect::<Vec<_>>(),
            "removed_members": plan.removed_members().iter().map(AssetId::as_str).collect::<Vec<_>>(),
            "affected_packs": affected,
        }));
    }
    let mut output = format!(
        "pack {operation} plan\ndigest: {}\npack: {}\nsource: {}\nsource revision: {}\nmembers: {}\n",
        plan.digest(),
        plan.pack().id,
        source_text(&plan.pack().source),
        plan.pack().revision,
        plan.pack()
            .members
            .keys()
            .map(AssetId::as_str)
            .collect::<Vec<_>>()
            .join(","),
    );
    for (id, change) in plan.affected_packs() {
        writeln!(
            output,
            "affected pack: {id} {} -> {}",
            change
                .prior()
                .map_or("absent", |revision| revision.as_str()),
            change.proposed(),
        )
        .expect("writing to a string cannot fail");
    }
    writeln!(
        output,
        "added members: {}",
        plan.added_members()
            .iter()
            .map(AssetId::as_str)
            .collect::<Vec<_>>()
            .join(",")
    )
    .expect("writing to a string cannot fail");
    writeln!(
        output,
        "removed members: {}",
        plan.removed_members()
            .iter()
            .map(AssetId::as_str)
            .collect::<Vec<_>>()
            .join(",")
    )
    .expect("writing to a string cannot fail");
    Ok(output)
}

fn render_pack_mutation_result(
    plan: &PackMutationPlan,
    outcome: PortableManifestCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    let operation = plan.operation().as_str();
    let outcome = match outcome {
        PortableManifestCommitOutcome::Committed => "committed",
        PortableManifestCommitOutcome::Recovered => "recovered",
    };
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": format!("pack_{operation}"),
            "outcome": outcome,
            "digest": plan.digest().as_str(),
            "pack": pack_json(plan.pack()),
        }));
    }
    Ok(format!(
        "pack {operation} {outcome}\npack: {}\nrevision: {}\n",
        plan.pack().id,
        plan.pack().content_hash,
    ))
}

fn render_pack_rollback_plan(
    plan: &PackRollbackPlan,
    json_output: bool,
) -> Result<String, CliError> {
    let affected = plan
        .affected_packs()
        .iter()
        .map(|(id, change)| {
            json!({
                "pack_id": id.as_str(),
                "prior_revision": change.prior().map(|revision| revision.as_str()),
                "proposed_revision": change.proposed().as_str(),
            })
        })
        .collect::<Vec<_>>();
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": "pack_rollback_plan",
            "digest": plan.digest().as_str(),
            "pack_id": plan.selection().pack_id().as_str(),
            "current_revision": plan.selection().current_revision().as_str(),
            "target_revision": plan.selection().target_revision().as_str(),
            "snapshot_digest": plan.selection().snapshot_digest().as_str(),
            "required_objects": plan.required_objects().len(),
            "affected_packs": affected,
        }));
    }
    let mut output = format!(
        "pack rollback plan\ndigest: {}\npack: {}\ncurrent revision: {}\ntarget revision: {}\nsnapshot: {}\nrequired objects: {}\n",
        plan.digest(),
        plan.selection().pack_id(),
        plan.selection().current_revision(),
        plan.selection().target_revision(),
        plan.selection().snapshot_digest().as_str(),
        plan.required_objects().len(),
    );
    for (id, change) in plan.affected_packs() {
        writeln!(
            output,
            "affected pack: {id} {} -> {}",
            change
                .prior()
                .map_or("absent", |revision| revision.as_str()),
            change.proposed(),
        )
        .expect("writing to a string cannot fail");
    }
    Ok(output)
}

fn render_pack_rollback_result(
    plan: &PackRollbackPlan,
    outcome: PortableManifestCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    let outcome = match outcome {
        PortableManifestCommitOutcome::Committed => "committed",
        PortableManifestCommitOutcome::Recovered => "recovered",
    };
    if json_output {
        return serialize(&json!({
            "schema_version": 1,
            "operation": "pack_rollback",
            "outcome": outcome,
            "digest": plan.digest().as_str(),
            "pack_id": plan.selection().pack_id().as_str(),
            "revision": plan.selection().target_revision().as_str(),
            "snapshot_digest": plan.selection().snapshot_digest().as_str(),
        }));
    }
    Ok(format!(
        "pack rollback {outcome}\npack: {}\nrevision: {}\nsnapshot: {}\n",
        plan.selection().pack_id(),
        plan.selection().target_revision(),
        plan.selection().snapshot_digest().as_str(),
    ))
}

fn render_pack_inspection_json(inspection: &PackInspection) -> Result<String, CliError> {
    let components = inspection
        .components()
        .iter()
        .map(|component| {
            let (kind, asset_kind) = match component.kind() {
                PackComponentKind::Asset(kind) => ("asset", Some(asset_kind(kind))),
                PackComponentKind::Pack => ("pack", None),
            };
            json!({
                "id": component.id().as_str(),
                "revision": component.revision().as_str(),
                "kind": kind,
                "asset_kind": asset_kind,
                "direct": component.is_direct(),
                "parents": component.parents().iter().map(|id| id.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    serialize(&json!({
        "schema_version": 1,
        "operation": "pack_inspect",
        "pack": pack_json(inspection.pack()),
        "components": components,
    }))
}

fn render_pack_inspection_text(inspection: &PackInspection) -> String {
    let pack = inspection.pack();
    let direct_count = inspection
        .components()
        .iter()
        .filter(|component| component.is_direct())
        .count();
    let mut output = format!(
        "pack: {}\nrevision: {}\nsource: {}\nsource revision: {}\nexact source hash: {}\ncontent class: {}\ndirect members: {}\ntransitive components: {}\n",
        pack.id,
        pack.content_hash,
        source_text(&pack.source),
        pack.revision,
        pack.exact_source_hash,
        content_class(pack.content_class),
        direct_count,
        inspection.components().len(),
    );
    if !pack.required_bindings.is_empty() {
        writeln!(
            output,
            "required bindings: {}",
            pack.required_bindings
                .iter()
                .map(|binding| binding.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .expect("writing to a string cannot fail");
    }
    for (harness, result) in &pack.compatibility {
        writeln!(
            output,
            "target {}: {} reasons={}",
            harness,
            fidelity(result.fidelity()),
            result
                .reasons()
                .iter()
                .map(|reason| reason.code.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .expect("writing to a string cannot fail");
    }
    for component in inspection.components() {
        let kind = match component.kind() {
            PackComponentKind::Asset(kind) => format!("asset/{}", asset_kind(kind)),
            PackComponentKind::Pack => "pack".to_owned(),
        };
        writeln!(
            output,
            "component {} {} direct={} parents={} revision={}",
            component.id(),
            kind,
            component.is_direct(),
            component
                .parents()
                .iter()
                .map(|parent| parent.as_str())
                .collect::<Vec<_>>()
                .join(","),
            component.revision(),
        )
        .expect("writing to a string cannot fail");
    }
    output
}

fn pack_json(pack: &Pack) -> Value {
    let compatibility = pack
        .compatibility
        .iter()
        .map(|(harness, result)| (harness.as_str().to_owned(), fidelity_json(result)))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "id": pack.id.as_str(),
        "revision": pack.content_hash.as_str(),
        "source": &pack.source,
        "source_revision": pack.revision.as_str(),
        "exact_source_hash": pack.exact_source_hash.as_str(),
        "content_class": content_class(pack.content_class),
        "direct_member_count": pack.members.len(),
        "required_bindings": pack.required_bindings.iter().map(|binding| binding.as_str()).collect::<Vec<_>>(),
        "compatibility": compatibility,
    })
}

fn fidelity_json(result: &FidelityResult) -> Value {
    json!({
        "fidelity": fidelity(result.fidelity()),
        "reason_codes": result.reasons().iter().map(|reason| reason.code.as_str()).collect::<Vec<_>>(),
        "blocked_requirements": result.blocked_requirements().iter().map(blocked_requirement).collect::<Vec<_>>(),
        "adapter_version": result.adapter_version(),
        "harness_version": result.harness_version(),
    })
}

fn blocked_requirement(requirement: &BlockedRequirement) -> String {
    match requirement {
        BlockedRequirement::Binding { name } => format!("binding:{}", name.as_str()),
        BlockedRequirement::ExecutableTrust => "executable_trust".to_owned(),
    }
}

const fn asset_kind(kind: AssetKind) -> &'static str {
    match kind {
        AssetKind::Skill => "skill",
        AssetKind::Instruction => "instruction",
        AssetKind::Agent => "agent",
        AssetKind::Command => "command",
        AssetKind::Hook => "hook",
        AssetKind::Mcp => "mcp",
        AssetKind::Plugin => "plugin",
        AssetKind::Extension => "extension",
        AssetKind::Pack => "pack",
    }
}

const fn content_class(class: ContentClass) -> &'static str {
    match class {
        ContentClass::DataOnly => "data_only",
        ContentClass::AgentActive => "agent_active",
        ContentClass::Executable => "executable",
    }
}

fn source_text(source: &Source) -> String {
    match source {
        Source::Harness { harness, origin } => format!("harness:{harness}:{origin}"),
        Source::Local { path } => format!("local:{path}"),
        Source::Git {
            repository,
            subdirectory,
        } => format!(
            "git:{}{}",
            repository,
            subdirectory
                .as_ref()
                .map(|path| format!("#{}", path.as_str()))
                .unwrap_or_default(),
        ),
    }
}

fn serialize(value: &Value) -> Result<String, CliError> {
    serde_json::to_string(value)
        .map(|value| format!("{value}\n"))
        .map_err(serialization_error)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use kitrove_core::{derive_lockfile, inspect_pack};
    use kitrove_model::{
        Asset, AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, Pack,
        PortablePath, Revision, SchemaVersion, Source,
    };

    use crate::args::PackCreateArgs;

    use super::{render_pack_inspection_text, render_pack_list, run_pack_create};

    fn manifest() -> EnvironmentManifest {
        let mut asset = Asset {
            id: AssetId::parse("alpha").unwrap(),
            kind: AssetKind::Skill,
            content_hash: ContentHash::digest(b"pending-pack-cli-asset"),
            provenance: BTreeMap::new(),
            portable: None,
            native_variants: BTreeMap::new(),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        };
        asset.refresh_content_hash();
        let pack_id = AssetId::parse("tooling").unwrap();
        let pack = Pack {
            id: pack_id.clone(),
            source: Source::Local {
                path: PortablePath::parse("packs/tooling").unwrap(),
            },
            revision: Revision::parse("local:tooling").unwrap(),
            exact_source_hash: ContentHash::digest(b"tooling-source"),
            content_hash: ContentHash::digest(b"pending-pack-cli-pack"),
            members: BTreeMap::from([(asset.id.clone(), asset.content_hash.clone())]),
            compatibility: BTreeMap::new(),
            content_class: ContentClass::DataOnly,
            required_bindings: BTreeSet::new(),
        };
        let mut manifest = EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::from([(asset.id.clone(), asset)]),
            packs: BTreeMap::from([(pack_id, pack)]),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        };
        manifest.refresh_pack_revisions().unwrap();
        manifest
    }

    #[test]
    fn list_json_is_stable_and_contains_no_component_expansion() {
        let output = render_pack_list(&manifest(), true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["operation"], "pack_list");
        assert_eq!(value["packs"][0]["id"], "tooling");
        assert_eq!(value["packs"][0]["direct_member_count"], 1);
        assert!(value["packs"][0].get("members").is_none());
    }

    #[test]
    fn inspect_text_reports_pack_and_component_authority() {
        let manifest = manifest();
        let inspection = inspect_pack(&manifest, &AssetId::parse("tooling").unwrap()).unwrap();
        let output = render_pack_inspection_text(&inspection);
        assert!(output.contains("pack: tooling\n"));
        assert!(output.contains("direct members: 1\n"));
        assert!(output.contains("component alpha asset/skill direct=true parents=tooling"));
    }

    #[test]
    fn unconfirmed_creation_is_byte_for_byte_nonmutating() {
        let temporary = tempfile::tempdir().unwrap();
        let environment_path = temporary.path().join("environment");
        fs::create_dir(&environment_path).unwrap();
        let environment = fs::canonicalize(environment_path).unwrap();
        let manifest = manifest();
        let manifest_text = manifest.to_toml().unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        fs::write(environment.join("kitrove.toml"), &manifest_text).unwrap();
        fs::write(environment.join("kitrove.lock.json"), &lock_text).unwrap();

        let result = run_pack_create(
            PackCreateArgs {
                pack_id: AssetId::parse("suite").unwrap(),
                members: [AssetId::parse("tooling").unwrap()].into_iter().collect(),
                environment: Some(environment.clone()),
                json: false,
            },
            |_| false,
        );
        let Err(error) = result else {
            panic!("unconfirmed creation must fail");
        };

        assert_eq!(error.code, "pack_create.confirmation_required");
        assert_eq!(
            fs::read_to_string(environment.join("kitrove.toml")).unwrap(),
            manifest_text
        );
        assert_eq!(
            fs::read_to_string(environment.join("kitrove.lock.json")).unwrap(),
            lock_text
        );
        assert_eq!(fs::read_dir(environment).unwrap().count(), 2);
    }
}
