use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, IsTerminal as _, Write as _};

use kitrove_agent_skills::CaptureLimits;
use kitrove_core::{
    FilesystemSyncBackend, GitBasicCredential, GitCredentialProvider, GitSyncBackend,
    PortableSnapshotV1, RetainedSyncBase, SshGitSyncBackend, SyncBackend, SyncBackendRead,
    SyncBaseStore, SyncCommitOutcome, SyncDisposition, SyncPlan, SyncPlanOutcome,
    SyncRecoveryOutcome, VerifiedDocumentObject, VerifiedObjectEnvelope,
    VerifiedSkillObjectCatalog, commit_sync_transaction, load_native_agent_object,
    load_native_extension_object_bounded, load_native_instruction_object, load_native_mcp_object,
    load_native_prompt_command_object, load_native_skill_object_bounded,
    load_portable_agent_object, load_portable_instruction_object_bounded, load_portable_mcp_object,
    load_portable_prompt_command_object, load_portable_skill_object_bounded,
    native_snapshot_object_kind, plan_sync, portable_snapshot_object_kind,
    recover_sync_transaction, sync_transaction_journal_path,
};
use kitrove_model::{ContentHash, EnvironmentManifest, PublicationId, RemoteKey, SyncLimits};
use serde_json::json;

use crate::adapters::tier_one_capabilities;
use crate::args::{CliError, GitCredentialSource, SyncArgs, SyncRemoteArgs};
use crate::portable::CompletedCommand;
use crate::scan::{
    read_portable_text, resolve_required_environment_root, resolve_required_state_root,
};

const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn run_sync_plan(arguments: SyncArgs) -> Result<CompletedCommand, CliError> {
    let SyncArgs {
        remote,
        environment,
        confirm: _,
        json,
    } = arguments;
    match remote {
        SyncRemoteArgs::Filesystem(path) => {
            let backend = FilesystemSyncBackend::open(&path).map_err(backend_error)?;
            let remote_key = backend.remote_key().clone();
            run_sync_plan_with_backend(environment, json, backend, remote_key)
        }
        SyncRemoteArgs::Git { url, credentials } => {
            let backend = open_git_backend(&url, credentials)?;
            let remote_key = backend.remote_key().clone();
            run_sync_plan_with_backend(environment, json, backend, remote_key)
        }
        SyncRemoteArgs::Ssh { url, known_hosts } => {
            let backend = SshGitSyncBackend::open(&url, known_hosts).map_err(backend_error)?;
            let remote_key = backend.remote_key().clone();
            run_sync_plan_with_backend(environment, json, backend, remote_key)
        }
    }
}

fn run_sync_plan_with_backend<B: SyncBackend>(
    environment: Option<std::path::PathBuf>,
    json: bool,
    backend: B,
    remote_key: RemoteKey,
) -> Result<CompletedCommand, CliError> {
    let planned = build_plan(environment, backend, remote_key)?;
    Ok(match planned.outcome {
        SyncPlanOutcome::Ready(plan) => CompletedCommand {
            output: render_ready(&plan, json)?,
            status: 0,
        },
        SyncPlanOutcome::Blocked(conflicts) => CompletedCommand {
            output: render_blocked(&conflicts, json)?,
            status: 3,
        },
    })
}

pub(crate) fn run_sync_apply(arguments: SyncArgs) -> Result<CompletedCommand, CliError> {
    let SyncArgs {
        remote,
        environment,
        confirm,
        json,
    } = arguments;
    let expected = confirm.ok_or_else(|| {
        CliError::new(
            "sync.confirmation_required",
            "sync apply requires the exact confirmed plan digest",
        )
    })?;
    match remote {
        SyncRemoteArgs::Filesystem(path) => {
            let backend = FilesystemSyncBackend::open(&path).map_err(backend_error)?;
            let remote_key = backend.remote_key().clone();
            run_sync_apply_with_backend(environment, json, expected, backend, remote_key)
        }
        SyncRemoteArgs::Git { url, credentials } => {
            let backend = open_git_backend(&url, credentials)?;
            let remote_key = backend.remote_key().clone();
            run_sync_apply_with_backend(environment, json, expected, backend, remote_key)
        }
        SyncRemoteArgs::Ssh { url, known_hosts } => {
            let backend = SshGitSyncBackend::open(&url, known_hosts).map_err(backend_error)?;
            let remote_key = backend.remote_key().clone();
            run_sync_apply_with_backend(environment, json, expected, backend, remote_key)
        }
    }
}

pub(crate) fn open_git_backend(
    url: &str,
    credentials: GitCredentialSource,
) -> Result<GitSyncBackend, CliError> {
    let provider = match credentials {
        GitCredentialSource::Terminal => GitCredentialProvider::terminal(prompt_git_credential),
        GitCredentialSource::Environment => {
            GitCredentialProvider::operation_local(environment_git_credential)
        }
    };
    GitSyncBackend::open_with_credentials(url, SyncLimits::default(), provider)
        .map_err(backend_error)
}

fn environment_git_credential() -> Option<GitBasicCredential> {
    git_credential_from_environment(|name| std::env::var(name).ok())
}

fn git_credential_from_environment(
    mut read: impl FnMut(&str) -> Option<String>,
) -> Option<GitBasicCredential> {
    let username = read("KITROVE_GIT_USERNAME")?;
    let token = read("KITROVE_GIT_TOKEN")?;
    GitBasicCredential::new(username, token).ok()
}

fn prompt_git_credential() -> Option<GitBasicCredential> {
    let input = io::stdin();
    let mut output = io::stderr();
    if !input.is_terminal() || !output.is_terminal() {
        return None;
    }
    eprint!("Git username: ");
    output.flush().ok()?;
    let mut username = String::new();
    input.read_line(&mut username).ok()?;
    while matches!(username.as_bytes().last(), Some(b'\n' | b'\r')) {
        username.pop();
    }
    let token = rpassword::prompt_password("Git token: ").ok()?;
    GitBasicCredential::new(username, token).ok()
}

fn run_sync_apply_with_backend<B: SyncBackend>(
    environment: Option<std::path::PathBuf>,
    json_output: bool,
    expected: ContentHash,
    backend: B,
    remote_key: RemoteKey,
) -> Result<CompletedCommand, CliError> {
    let environment_root = resolve_required_environment_root(environment.as_deref())?;
    let state_root = resolve_required_state_root()?;
    let journal_path = sync_transaction_journal_path(&remote_key).map_err(transaction_error)?;
    if read_portable_text(&state_root, journal_path.as_str(), MAX_CONTROL_BYTES)?.is_some() {
        match recover_sync_transaction(
            &environment_root,
            &state_root,
            &backend,
            &remote_key,
            SyncLimits::default(),
        )
        .map_err(transaction_error)?
        {
            SyncRecoveryOutcome::Completed => {
                return Ok(CompletedCommand {
                    output: render_recovered(json_output)?,
                    status: 0,
                });
            }
            SyncRecoveryOutcome::NoJournal => {
                return Err(CliError::new(
                    "sync.recovery_raced",
                    "the synchronization journal changed before recovery",
                ));
            }
        }
    }

    let planned = build_plan(environment, backend, remote_key)?;
    let SyncPlanOutcome::Ready(plan) = planned.outcome else {
        return Err(CliError::new(
            "sync.conflict",
            "the recomputed synchronization plan is blocked by conflicts",
        ));
    };
    if plan.digest() != &expected {
        return Err(CliError::new(
            "sync.plan_stale",
            "the recomputed synchronization plan does not match --confirm",
        ));
    }
    let merged_objects = select_merged_objects(&plan, &planned.objects)?;
    let publication = matches!(
        plan.disposition(),
        SyncDisposition::Publish | SyncDisposition::Merge
    )
    .then(|| publication_id(plan.digest()))
    .transpose()?;
    let outcome = commit_sync_transaction(
        &planned.environment_root,
        &planned.state_root,
        &planned.backend,
        &planned.remote_key,
        &plan,
        &merged_objects,
        publication,
        SyncLimits::default(),
    )
    .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_applied(&plan, outcome, json_output)?,
        status: 0,
    })
}

struct PlannedSync<B> {
    outcome: SyncPlanOutcome,
    environment_root: std::path::PathBuf,
    state_root: std::path::PathBuf,
    backend: B,
    remote_key: RemoteKey,
    objects: BTreeMap<kitrove_model::ObjectDescriptor, VerifiedObjectEnvelope>,
}

struct ObjectReadBudget {
    remaining_count: usize,
    remaining_bytes: u64,
}

impl ObjectReadBudget {
    const fn new(limits: SyncLimits) -> Self {
        Self {
            remaining_count: limits.max_object_count(),
            remaining_bytes: limits.max_total_object_bytes(),
        }
    }

    fn charge(
        &mut self,
        descriptor: &kitrove_model::ObjectDescriptor,
        limits: SyncLimits,
    ) -> Result<(), CliError> {
        if self.remaining_count == 0
            || descriptor.encoded_len() > limits.max_object_bytes()
            || descriptor.encoded_len() > self.remaining_bytes
        {
            return Err(object_budget_exceeded());
        }
        self.remaining_count -= 1;
        self.remaining_bytes -= descriptor.encoded_len();
        Ok(())
    }

    fn capture_limits(&self, limits: SyncLimits) -> Result<CaptureLimits, CliError> {
        let allowance = self.local_envelope_allowance(limits)?;
        Ok(CaptureLimits {
            max_files: limits.max_components(),
            max_file_bytes: allowance,
            max_total_bytes: allowance,
        })
    }

    fn local_envelope_allowance(&self, limits: SyncLimits) -> Result<u64, CliError> {
        if self.remaining_count == 0 || self.remaining_bytes == 0 {
            return Err(object_budget_exceeded());
        }
        Ok(limits.max_object_bytes().min(self.remaining_bytes))
    }

    fn narrowed_sync_limits(&self, limits: SyncLimits) -> Result<SyncLimits, CliError> {
        if self.remaining_count == 0 || self.remaining_bytes == 0 {
            return Err(object_budget_exceeded());
        }
        SyncLimits::new(
            limits.max_snapshot_bytes(),
            limits.max_control_bytes(),
            limits.max_manifest_bytes(),
            limits.max_lock_bytes(),
            self.remaining_count,
            limits.max_object_bytes().min(self.remaining_bytes),
            self.remaining_bytes,
            limits.max_conflicts(),
            limits.max_components(),
            limits.max_backend_history(),
        )
        .map_err(|_| object_budget_exceeded())
    }
}

fn build_plan<B: SyncBackend>(
    environment: Option<std::path::PathBuf>,
    backend: B,
    remote_key: RemoteKey,
) -> Result<PlannedSync<B>, CliError> {
    let limits = SyncLimits::default();
    let environment_root = resolve_required_environment_root(environment.as_deref())?;
    let state_root = resolve_required_state_root()?;
    let journal_path = sync_transaction_journal_path(&remote_key).map_err(transaction_error)?;
    if read_portable_text(&state_root, journal_path.as_str(), MAX_CONTROL_BYTES)?.is_some() {
        return Err(CliError::new(
            "sync.recovery_required",
            "an interrupted synchronization must be recovered with sync apply",
        ));
    }
    let mut budget = ObjectReadBudget::new(limits);
    let (local, local_objects) = load_local_snapshot(&environment_root, limits, &mut budget)?;
    let retained = load_retained_base(&state_root, &remote_key, limits, &mut budget)?;
    let mut read = backend.begin_read(limits).map_err(backend_error)?;
    let remote = read.inspect(limits).map_err(backend_error)?;
    let mut objects = descriptor_map(local_objects)?;
    if let Some(snapshot) = remote.snapshot() {
        fetch_remote_objects(
            &mut read,
            snapshot.objects(),
            &mut objects,
            &mut budget,
            limits,
        )?;
    }
    let retained = if let Some(retained) = retained {
        let (input, retained_objects) = retained.into_parts();
        for object in retained_objects {
            insert_object(&mut objects, object)?;
        }
        Some(input)
    } else {
        None
    };
    let final_remote = read.inspect(limits).map_err(backend_error)?;
    if final_remote != remote {
        return Err(CliError::new(
            "sync.remote_stale",
            "remote authority changed while synchronization was planned",
        ));
    }
    drop(read);
    let catalog = catalog(&objects)?;
    let outcome = plan_sync(
        local,
        retained,
        remote,
        &catalog,
        &tier_one_capabilities()?,
        limits,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    Ok(PlannedSync {
        outcome,
        environment_root,
        state_root,
        backend,
        remote_key,
        objects,
    })
}

fn load_local_snapshot(
    root: &std::path::Path,
    limits: SyncLimits,
    budget: &mut ObjectReadBudget,
) -> Result<(PortableSnapshotV1, Vec<VerifiedObjectEnvelope>), CliError> {
    let manifest_text =
        read_portable_text(root, "kitrove.toml", MAX_CONTROL_BYTES)?.ok_or_else(|| {
            CliError::new(
                "cli.environment_manifest_missing",
                "the selected environment does not contain kitrove.toml",
            )
        })?;
    let lock_text =
        read_portable_text(root, "kitrove.lock.json", MAX_CONTROL_BYTES)?.ok_or_else(|| {
            CliError::new(
                "sync.lock_missing",
                "sync requires the generated environment lockfile",
            )
        })?;
    let manifest = EnvironmentManifest::from_toml(&manifest_text).map_err(|_| {
        CliError::new(
            "cli.environment_manifest_invalid",
            "the selected environment manifest is invalid",
        )
    })?;
    let mut objects = Vec::new();
    for (asset_id, asset) in &manifest.assets {
        if let Some(portable) = asset.portable.as_ref() {
            let capture_limits = budget.capture_limits(limits)?;
            let encoded_limit = budget.local_envelope_allowance(limits)?;
            let object = match portable_snapshot_object_kind(&portable.format) {
                Some(kitrove_model::SnapshotObjectKind::PortableSkillTree) => {
                    VerifiedObjectEnvelope::portable(
                        portable.root.clone(),
                        load_portable_skill_object_bounded(
                            &manifest,
                            asset_id,
                            root,
                            capture_limits,
                            encoded_limit,
                        )
                        .map_err(object_error)?,
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::PortableInstruction) => {
                    VerifiedObjectEnvelope::document(
                        portable.root.clone(),
                        VerifiedDocumentObject::PortableInstruction(
                            load_portable_instruction_object_bounded(
                                &manifest,
                                asset_id,
                                root,
                                capture_limits,
                                encoded_limit,
                            )
                            .map_err(object_error)?,
                        ),
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::PortablePromptCommand) => {
                    VerifiedObjectEnvelope::document(
                        portable.root.clone(),
                        VerifiedDocumentObject::PortablePromptCommand(
                            load_portable_prompt_command_object(
                                &manifest,
                                asset_id,
                                root,
                                capture_limits,
                            )
                            .map_err(object_error)?,
                        ),
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::PortableAgent) => {
                    VerifiedObjectEnvelope::document(
                        portable.root.clone(),
                        VerifiedDocumentObject::PortableAgent(
                            load_portable_agent_object(&manifest, asset_id, root, capture_limits)
                                .map_err(object_error)?,
                        ),
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::PortableMcp) => {
                    VerifiedObjectEnvelope::document(
                        portable.root.clone(),
                        VerifiedDocumentObject::PortableMcp(
                            load_portable_mcp_object(&manifest, asset_id, root, capture_limits)
                                .map_err(object_error)?,
                        ),
                    )
                }
                _ => {
                    return Err(CliError::new(
                        "sync.local_object_format_unsupported",
                        "the local manifest references an unsupported portable object format",
                    ));
                }
            }
            .map_err(backend_error)?;
            budget.charge(object.descriptor(), limits)?;
            objects.push(object);
        }
        for (harness, native) in &asset.native_variants {
            let capture_limits = budget.capture_limits(limits)?;
            let encoded_limit = budget.local_envelope_allowance(limits)?;
            let object = match native_snapshot_object_kind(&native.format) {
                Some(kitrove_model::SnapshotObjectKind::NativeSkillObject) => {
                    VerifiedObjectEnvelope::native(
                        native.root.clone(),
                        load_native_skill_object_bounded(
                            &manifest,
                            asset_id,
                            harness,
                            root,
                            capture_limits,
                            encoded_limit,
                        )
                        .map_err(object_error)?,
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::NativeExtensionObject) => {
                    VerifiedObjectEnvelope::native_extension(
                        native.root.clone(),
                        load_native_extension_object_bounded(
                            &manifest,
                            asset_id,
                            harness,
                            root,
                            capture_limits,
                            encoded_limit,
                        )
                        .map_err(object_error)?,
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::NativeInstruction) => {
                    VerifiedObjectEnvelope::document(
                        native.root.clone(),
                        VerifiedDocumentObject::NativeInstruction(
                            load_native_instruction_object(
                                &manifest,
                                asset_id,
                                harness,
                                root,
                                capture_limits,
                            )
                            .map_err(object_error)?,
                        ),
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::NativePromptCommand) => {
                    VerifiedObjectEnvelope::document(
                        native.root.clone(),
                        VerifiedDocumentObject::NativePromptCommand(
                            load_native_prompt_command_object(
                                &manifest,
                                asset_id,
                                harness,
                                root,
                                capture_limits,
                            )
                            .map_err(object_error)?,
                        ),
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::NativeAgent) => {
                    VerifiedObjectEnvelope::document(
                        native.root.clone(),
                        VerifiedDocumentObject::NativeAgent(
                            load_native_agent_object(
                                &manifest,
                                asset_id,
                                harness,
                                root,
                                capture_limits,
                            )
                            .map_err(object_error)?,
                        ),
                    )
                }
                Some(kitrove_model::SnapshotObjectKind::NativeMcp) => {
                    VerifiedObjectEnvelope::document(
                        native.root.clone(),
                        VerifiedDocumentObject::NativeMcp(
                            load_native_mcp_object(
                                &manifest,
                                asset_id,
                                harness,
                                root,
                                capture_limits,
                            )
                            .map_err(object_error)?,
                        ),
                    )
                }
                _ => {
                    return Err(CliError::new(
                        "sync.local_object_format_unsupported",
                        "the local manifest references an unsupported native object format",
                    ));
                }
            }
            .map_err(backend_error)?;
            budget.charge(object.descriptor(), limits)?;
            objects.push(object);
        }
    }
    let objects = descriptor_map(objects)?;
    let snapshot = PortableSnapshotV1::new(manifest, objects.keys().cloned().collect(), limits)
        .map_err(|error| CliError::new(error.code(), error.message()))?;
    if snapshot.manifest_toml() != manifest_text || snapshot.lock_json() != lock_text {
        return Err(CliError::new(
            "sync.local_authority_invalid",
            "manifest, generated lock, and local objects are not one exact snapshot",
        ));
    }
    Ok((snapshot, objects.into_values().collect()))
}

pub(crate) fn load_local_snapshot_exact(
    root: &std::path::Path,
    limits: SyncLimits,
) -> Result<(PortableSnapshotV1, Vec<VerifiedObjectEnvelope>), CliError> {
    load_local_snapshot(root, limits, &mut ObjectReadBudget::new(limits))
}

fn load_retained_base(
    state_root: &std::path::Path,
    remote_key: &kitrove_model::RemoteKey,
    limits: SyncLimits,
    budget: &mut ObjectReadBudget,
) -> Result<Option<RetainedSyncBase>, CliError> {
    match std::fs::symlink_metadata(state_root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(CliError::new(
            "sync.local_state_unreadable",
            "machine-local synchronization state could not be inspected safely",
        )),
        Ok(_) => {
            let store = SyncBaseStore::open(state_root).map_err(base_error)?;
            if !store
                .has_selected_base(remote_key, limits)
                .map_err(base_error)?
            {
                return Ok(None);
            }
            let retained = store
                .inspect(remote_key, budget.narrowed_sync_limits(limits)?)
                .map_err(base_error)?
                .ok_or_else(|| {
                    CliError::new(
                        "sync.base_stale",
                        "the selected retained synchronization base changed during planning",
                    )
                })?;
            for object in retained.objects() {
                budget.charge(object.descriptor(), limits)?;
            }
            Ok(Some(retained))
        }
    }
}

fn fetch_remote_objects(
    read: &mut impl SyncBackendRead,
    descriptors: &std::collections::BTreeSet<kitrove_model::ObjectDescriptor>,
    objects: &mut BTreeMap<kitrove_model::ObjectDescriptor, VerifiedObjectEnvelope>,
    budget: &mut ObjectReadBudget,
    limits: SyncLimits,
) -> Result<(), CliError> {
    for descriptor in descriptors {
        budget.charge(descriptor, limits)?;
        let object = read
            .fetch_object(descriptor, remote_fetch_limits(descriptor, limits)?)
            .map_err(backend_error)?;
        insert_object(objects, object)?;
    }
    Ok(())
}

fn remote_fetch_limits(
    descriptor: &kitrove_model::ObjectDescriptor,
    limits: SyncLimits,
) -> Result<SyncLimits, CliError> {
    SyncLimits::new(
        limits.max_snapshot_bytes(),
        limits.max_control_bytes(),
        limits.max_manifest_bytes(),
        limits.max_lock_bytes(),
        1,
        descriptor.encoded_len(),
        descriptor.encoded_len(),
        limits.max_conflicts(),
        limits.max_components(),
        limits.max_backend_history(),
    )
    .map_err(|_| object_budget_exceeded())
}

fn descriptor_map(
    objects: Vec<VerifiedObjectEnvelope>,
) -> Result<BTreeMap<kitrove_model::ObjectDescriptor, VerifiedObjectEnvelope>, CliError> {
    let mut mapped = BTreeMap::new();
    for object in objects {
        insert_object(&mut mapped, object)?;
    }
    Ok(mapped)
}

fn insert_object(
    mapped: &mut BTreeMap<kitrove_model::ObjectDescriptor, VerifiedObjectEnvelope>,
    object: VerifiedObjectEnvelope,
) -> Result<(), CliError> {
    use std::collections::btree_map::Entry;

    match mapped.entry(object.descriptor().clone()) {
        Entry::Vacant(entry) => {
            entry.insert(object);
        }
        Entry::Occupied(entry) if entry.get() != &object => {
            return Err(CliError::new(
                "sync.object_alias",
                "distinct verified objects claim one synchronization descriptor",
            ));
        }
        Entry::Occupied(_) => {}
    }
    Ok(())
}

fn catalog(
    objects: &BTreeMap<kitrove_model::ObjectDescriptor, VerifiedObjectEnvelope>,
) -> Result<VerifiedSkillObjectCatalog, CliError> {
    let portable = objects.values().filter_map(|object| match object {
        VerifiedObjectEnvelope::Portable { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Native { .. } => None,
        VerifiedObjectEnvelope::NativeExtension { .. } => None,
        VerifiedObjectEnvelope::Document { .. } => None,
    });
    let native = objects.values().filter_map(|object| match object {
        VerifiedObjectEnvelope::Native { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Portable { .. } => None,
        VerifiedObjectEnvelope::NativeExtension { .. } => None,
        VerifiedObjectEnvelope::Document { .. } => None,
    });
    let native_extensions = objects.values().filter_map(|object| match object {
        VerifiedObjectEnvelope::NativeExtension { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Portable { .. } | VerifiedObjectEnvelope::Native { .. } => None,
        VerifiedObjectEnvelope::Document { .. } => None,
    });
    let documents = objects.values().filter_map(|object| match object {
        VerifiedObjectEnvelope::Document { object, .. } => Some(object.clone()),
        VerifiedObjectEnvelope::Portable { .. }
        | VerifiedObjectEnvelope::Native { .. }
        | VerifiedObjectEnvelope::NativeExtension { .. } => None,
    });
    VerifiedSkillObjectCatalog::new_with_documents(portable, native, native_extensions, documents)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

fn select_merged_objects(
    plan: &SyncPlan,
    objects: &BTreeMap<kitrove_model::ObjectDescriptor, VerifiedObjectEnvelope>,
) -> Result<Vec<VerifiedObjectEnvelope>, CliError> {
    plan.merged()
        .objects()
        .iter()
        .map(|descriptor| {
            objects.get(descriptor).cloned().ok_or_else(|| {
                CliError::new(
                    "sync.object_missing",
                    "the merged snapshot object catalog is incomplete",
                )
            })
        })
        .collect()
}

fn publication_id(digest: &ContentHash) -> Result<PublicationId, CliError> {
    let suffix = digest.as_str().rsplit(':').next().ok_or_else(|| {
        CliError::new(
            "sync.plan_invalid",
            "the synchronization plan digest is invalid",
        )
    })?;
    PublicationId::parse(format!("publication:blake3:{suffix}")).map_err(|_| {
        CliError::new(
            "sync.plan_invalid",
            "the synchronization plan digest is invalid",
        )
    })
}

fn render_ready(plan: &SyncPlan, json_output: bool) -> Result<String, CliError> {
    if json_output {
        let mut encoded = serde_json::to_string_pretty(&json!({
            "status": "ready",
            "disposition": disposition(plan.disposition()),
            "plan_digest": plan.digest().as_str(),
            "upload_objects": plan.upload().len(),
            "download_objects": plan.download().len(),
        }))
        .map_err(render_error)?;
        encoded.push('\n');
        return Ok(encoded);
    }
    Ok(format!(
        "Sync plan: {}\nPlan digest: {}\nUpload objects: {}\nDownload objects: {}\n",
        disposition(plan.disposition()),
        plan.digest().as_str(),
        plan.upload().len(),
        plan.download().len()
    ))
}

fn render_blocked(
    conflicts: &[kitrove_model::SyncConflict],
    json_output: bool,
) -> Result<String, CliError> {
    if json_output {
        let mut encoded = serde_json::to_string_pretty(&json!({
            "status": "blocked",
            "conflicts": conflicts,
        }))
        .map_err(render_error)?;
        encoded.push('\n');
        return Ok(encoded);
    }
    let mut output = String::from("Sync plan: blocked\n");
    for conflict in conflicts {
        writeln!(
            output,
            "- {}: {}",
            conflict.code.as_str(),
            conflict.code.message()
        )
        .map_err(|_| render_error(serde_json::Error::io(io::Error::other("format"))))?;
    }
    Ok(output)
}

fn render_applied(
    plan: &SyncPlan,
    outcome: SyncCommitOutcome,
    json_output: bool,
) -> Result<String, CliError> {
    let outcome = match outcome {
        SyncCommitOutcome::Committed => "committed",
        SyncCommitOutcome::Recovered => "recovered",
    };
    if json_output {
        let mut encoded = serde_json::to_string_pretty(&json!({
            "status": outcome,
            "disposition": disposition(plan.disposition()),
            "plan_digest": plan.digest().as_str(),
        }))
        .map_err(render_error)?;
        encoded.push('\n');
        Ok(encoded)
    } else {
        Ok(format!(
            "Sync {outcome}: {} ({})\n",
            disposition(plan.disposition()),
            plan.digest().as_str()
        ))
    }
}

fn render_recovered(json_output: bool) -> Result<String, CliError> {
    if json_output {
        let mut encoded =
            serde_json::to_string_pretty(&json!({"status": "recovered"})).map_err(render_error)?;
        encoded.push('\n');
        Ok(encoded)
    } else {
        Ok("Sync recovered the interrupted transaction.\n".to_owned())
    }
}

const fn disposition(value: SyncDisposition) -> &'static str {
    match value {
        SyncDisposition::Publish => "publish",
        SyncDisposition::Receive => "receive",
        SyncDisposition::Merge => "merge",
        SyncDisposition::EstablishBase => "establish_base",
        SyncDisposition::Unchanged => "unchanged",
    }
}

pub(crate) fn backend_error(_: kitrove_core::BackendError) -> CliError {
    CliError::new(
        "sync.backend_failed",
        "the filesystem synchronization backend failed safely",
    )
}

fn base_error(error: kitrove_core::SyncBaseStoreError) -> CliError {
    if error.code() == "sync_base.object_budget_exceeded" {
        return object_budget_exceeded();
    }
    CliError::new(
        "sync.base_failed",
        "the retained synchronization base could not be inspected safely",
    )
}

fn object_error(_: kitrove_core::MaterializationError) -> CliError {
    CliError::new(
        "sync.object_invalid",
        "a manifest-authorized synchronization object is invalid",
    )
}

fn object_budget_exceeded() -> CliError {
    CliError::new(
        "sync.object_budget_exceeded",
        "the request-global synchronization object budget was exceeded",
    )
}

fn transaction_error(error: kitrove_core::SyncTransactionError) -> CliError {
    CliError::new(error.code(), error.message())
}

fn render_error(_: serde_json::Error) -> CliError {
    CliError::new(
        "sync.render_failed",
        "the synchronization result could not be rendered",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use kitrove_agent_skills::{CapturedFile, CapturedTree, FileMode, StoredSkillTree, hash_tree};
    use kitrove_model::{ObjectDescriptor, PortablePath, RemoteRevision, SnapshotObjectKind};

    #[test]
    fn environment_credentials_use_only_fixed_names_and_fail_closed() {
        let mut requested = Vec::new();
        let credential = git_credential_from_environment(|name| {
            requested.push(name.to_owned());
            match name {
                "KITROVE_GIT_USERNAME" => Some("operator".to_owned()),
                "KITROVE_GIT_TOKEN" => Some("token".to_owned()),
                _ => None,
            }
        });
        assert!(credential.is_some());
        assert_eq!(requested, ["KITROVE_GIT_USERNAME", "KITROVE_GIT_TOKEN"]);
        assert!(git_credential_from_environment(|_| None).is_none());
        assert!(
            git_credential_from_environment(|name| match name {
                "KITROVE_GIT_USERNAME" => Some("operator".to_owned()),
                "KITROVE_GIT_TOKEN" => Some("invalid token".to_owned()),
                _ => None,
            })
            .is_none()
        );
    }

    struct CountingRead {
        fetches: usize,
        received_limits: Vec<SyncLimits>,
        objects: Vec<VerifiedObjectEnvelope>,
    }

    impl SyncBackendRead for CountingRead {
        fn inspect(
            &mut self,
            _limits: SyncLimits,
        ) -> Result<kitrove_core::RemoteSnapshot, kitrove_core::BackendError> {
            Ok(kitrove_core::RemoteSnapshot::absent(
                RemoteRevision::parse("counting:v1").unwrap(),
            ))
        }

        fn fetch_object(
            &mut self,
            _descriptor: &ObjectDescriptor,
            limits: SyncLimits,
        ) -> Result<VerifiedObjectEnvelope, kitrove_core::BackendError> {
            self.fetches += 1;
            self.received_limits.push(limits);
            if self.objects.is_empty() {
                panic!("the over-budget object must not be fetched");
            }
            Ok(self.objects.remove(0))
        }
    }

    fn descriptor(root: &str, marker: u8, encoded_len: u64) -> ObjectDescriptor {
        ObjectDescriptor::new(
            SnapshotObjectKind::PortableSkillTree,
            PortablePath::parse(root).unwrap(),
            ContentHash::parse(format!(
                "blake3:{}",
                char::from(marker).to_string().repeat(64)
            ))
            .unwrap(),
            encoded_len,
        )
        .unwrap()
    }

    #[test]
    fn combined_object_budget_refuses_before_fetching_the_crossing_remote_object() {
        let limits = SyncLimits::new(2048, 1024, 512, 512, 2, 8, 10, 8, 8, 8).unwrap();
        let mut budget = ObjectReadBudget::new(limits);
        budget
            .charge(&descriptor("local", b'a', 6), limits)
            .unwrap();
        let remote = BTreeSet::from([descriptor("remote", b'b', 6)]);
        let mut read = CountingRead {
            fetches: 0,
            received_limits: Vec::new(),
            objects: Vec::new(),
        };
        let mut objects = BTreeMap::new();

        let error = fetch_remote_objects(&mut read, &remote, &mut objects, &mut budget, limits)
            .unwrap_err();

        assert_eq!(error.code, "sync.object_budget_exceeded");
        assert_eq!(read.fetches, 0);
        assert!(objects.is_empty());
    }

    #[test]
    fn local_envelope_allowance_preserves_the_per_object_ceiling() {
        let limits = SyncLimits::new(2048, 1024, 512, 512, 4, 2, 10, 8, 8, 8).unwrap();
        let budget = ObjectReadBudget::new(limits);

        assert_eq!(budget.local_envelope_allowance(limits).unwrap(), 2);
        assert_eq!(budget.capture_limits(limits).unwrap().max_total_bytes, 2);
    }

    #[test]
    fn in_budget_remote_fetch_receives_only_its_reserved_envelope_allowance() {
        let path = PortablePath::parse("SKILL.md").unwrap();
        let files = BTreeMap::from([(
            path,
            CapturedFile {
                mode: FileMode::Regular,
                bytes: b"bounded\n".to_vec(),
            },
        )]);
        let object = StoredSkillTree::new(CapturedTree {
            hash: hash_tree(&files),
            files,
        })
        .unwrap();
        let envelope =
            VerifiedObjectEnvelope::portable(PortablePath::parse("remote-object").unwrap(), object)
                .unwrap();
        let remote_descriptor = envelope.descriptor().clone();
        let total = remote_descriptor.encoded_len() + 1;
        let limits = SyncLimits::new(4096, 2048, 1024, 1024, 2, total, total, 8, 8, 8).unwrap();
        let mut budget = ObjectReadBudget::new(limits);
        budget
            .charge(&descriptor("local", b'a', 1), limits)
            .unwrap();
        let remote = BTreeSet::from([remote_descriptor.clone()]);
        let mut read = CountingRead {
            fetches: 0,
            received_limits: Vec::new(),
            objects: vec![envelope],
        };
        let mut objects = BTreeMap::new();

        fetch_remote_objects(&mut read, &remote, &mut objects, &mut budget, limits).unwrap();

        assert_eq!(read.fetches, 1);
        assert_eq!(read.received_limits.len(), 1);
        assert_eq!(
            read.received_limits[0].max_object_bytes(),
            remote_descriptor.encoded_len()
        );
        assert_eq!(
            read.received_limits[0].max_total_object_bytes(),
            remote_descriptor.encoded_len()
        );
        assert_eq!(objects.len(), 1);
    }
}
