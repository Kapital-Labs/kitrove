use super::*;

pub(crate) fn run_adopt(
    arguments: AdoptArgs,
    registry: &PolicyRegistry,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let AdoptArgs {
        approval,
        observation_id,
        asset_id,
        update_asset_id,
        expected_prior,
        binding,
        harnesses,
        scope,
        project_root,
        roots,
        environment,
        json,
    } = arguments;
    let root = resolve_required_environment_root(environment.as_deref())?;
    let selection = AdoptionSelection {
        harnesses,
        scope,
        project_root,
        roots,
    };
    if !matches!(approval, ApprovalMode::Interactive) {
        match inspect_portable_journal(&root).map_err(transaction_error)? {
            PortableJournalStatus::Absent => {}
            PortableJournalStatus::Pending | PortableJournalStatus::Invalid => {
                return Err(CliError::new(
                    "adoption.recovery_required",
                    "pending or invalid recovery requires operator handling and fresh approval",
                ));
            }
        }
    } else if update_asset_id.is_some() {
        match inspect_portable_journal(&root).map_err(transaction_error)? {
            PortableJournalStatus::Pending => {
                let state_root = resolve_required_state_root()?;
                let recovered =
                    recover_update_adoption(&root, &state_root, CaptureLimits::default())
                        .map_err(transaction_error)?;
                return Ok(CompletedCommand {
                    output: render_update_recovery(recovered, json)?,
                    status: 0,
                });
            }
            PortableJournalStatus::Invalid => {
                return Err(CliError::new(
                    "transaction.journal_invalid",
                    "the portable transaction journal is invalid and cannot be recovered",
                ));
            }
            PortableJournalStatus::Absent => {}
        }
    }
    let manifest = load_manifest(&root)?;
    let scan_arguments = adoption_scan_args(root.clone(), &selection);
    let report = scan_report(scan_arguments, registry)?;
    let observation_id = crate::scan_display::resolve_skill_name(&report, &observation_id)?;
    if let Some((entry, observation, selected_entry_hash)) =
        select_mcp_observation(&report, &observation_id)
    {
        let capabilities = tier_one_mcp_capabilities()?;
        if let (Some(update_asset_id), Some(expected_prior)) =
            (update_asset_id.as_ref(), expected_prior.as_ref())
        {
            let (manifest_text, lock_text) = read_update_authority(&root)?;
            let plan = plan_mcp_update(
                observation,
                selected_entry_hash,
                update_asset_id,
                expected_prior,
                binding.as_ref(),
                &manifest_text,
                &manifest,
                lock_text.as_deref(),
                &capabilities,
            )
            .map_err(|error| CliError::new(error.code(), error.message()))?;
            let output = render_mcp_update_plan(&plan, json)?;
            if !review(
                &approval,
                plan.digest(),
                &output,
                &mut confirm,
                "update.confirmation_required",
            )? {
                return Ok(CompletedCommand { output, status: 0 });
            }
            let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
            let (_, current, _) =
                select_mcp_observation(&reread, plan.selected_entry_hash().as_str())
                    .ok_or_else(update_observation_stale)?;
            let commit = if matches!(approval, ApprovalMode::Interactive) {
                commit_mcp_update
            } else {
                kitrove_core::commit_approved_mcp_update
            };
            let committed = commit(&plan, current, &root, CaptureLimits::default())
                .map_err(transaction_error)?;
            return Ok(CompletedCommand {
                output: render_mcp_update_result(&plan, committed, json)?,
                status: 0,
            });
        }
        let asset_id = match asset_id {
            Some(asset_id) => asset_id,
            None => {
                kitrove_model::AssetId::parse(entry.portable_name.as_deref().ok_or_else(|| {
                    CliError::new(
                        "mcp_adoption.asset_id_required",
                        "the blocked MCP entry requires an explicit --id",
                    )
                })?)
                .map_err(|_| {
                    CliError::new(
                        "mcp_adoption.asset_id_required",
                        "the MCP name is not a valid default asset identifier; use --id",
                    )
                })?
            }
        };
        let outcome = plan_mcp_adoption(
            observation,
            selected_entry_hash,
            &asset_id,
            binding.as_ref(),
            &manifest,
            &capabilities,
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let plan = match outcome {
            McpAdoptionOutcome::Ready(plan) => plan,
            McpAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_mcp_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let output = render_mcp_adoption_plan(&plan, json)?;
        if !review(
            &approval,
            plan.digest(),
            &output,
            &mut confirm,
            "adoption.confirmation_required",
        )? {
            return Ok(CompletedCommand { output, status: 0 });
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let (_, current, _) = select_mcp_observation(&reread, plan.selected_entry_hash().as_str())
            .ok_or_else(observation_stale)?;
        let commit = if matches!(approval, ApprovalMode::Interactive) {
            commit_mcp_adoption
        } else {
            kitrove_core::commit_approved_mcp_adoption
        };
        let committed =
            commit(&plan, current, &root, CaptureLimits::default()).map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_mcp_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if binding.is_some() {
        return Err(CliError::new(
            "mcp_adoption.binding_unexpected",
            "--binding is valid only when selecting an MCP declaration",
        ));
    }
    let prompt_command_observation = if update_asset_id.is_none() {
        select_prompt_command_observation(&report, &observation_id)
    } else {
        None
    };
    if let Some(observation) = prompt_command_observation {
        if expected_prior.is_some() {
            return Err(CliError::new(
                "prompt_command_update.authority_incomplete",
                "prompt-command updates require both --update and --expected-prior",
            ));
        }
        let asset_id = match asset_id {
            Some(asset_id) => asset_id,
            None => kitrove_model::AssetId::parse(observation.observed().name().as_str()).map_err(
                |_| {
                    CliError::new(
                        "prompt_command_adoption.asset_id_required",
                        "the prompt-command name is not a valid default asset identifier; use --id",
                    )
                },
            )?,
        };
        let capabilities = tier_one_prompt_command_capabilities()?;
        let outcome =
            plan_prompt_command_adoption(observation, &asset_id, &manifest, &capabilities)
                .map_err(|error| CliError::new(error.code(), error.message()))?;
        let plan = match outcome {
            PromptCommandAdoptionOutcome::Ready(plan) => plan,
            PromptCommandAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_prompt_command_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let output = render_prompt_command_adoption_plan(&plan, json)?;
        if !review(
            &approval,
            plan.digest(),
            &output,
            &mut confirm,
            "adoption.confirmation_required",
        )? {
            return Ok(CompletedCommand { output, status: 0 });
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let current = select_prompt_command_observation(&reread, observation.identity().as_str())
            .ok_or_else(observation_stale)?;
        let commit = if matches!(approval, ApprovalMode::Interactive) {
            commit_prompt_command_adoption
        } else {
            kitrove_core::commit_approved_prompt_command_adoption
        };
        let committed =
            commit(&plan, current, &root, CaptureLimits::default()).map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_prompt_command_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if let (Some(update_asset_id), Some(expected_prior)) =
        (update_asset_id.as_ref(), expected_prior.as_ref())
    {
        if let Some(observation) = select_prompt_command_observation(&report, &observation_id) {
            return run_prompt_command_update(
                observation.clone(),
                update_asset_id,
                expected_prior,
                selection,
                root,
                manifest,
                registry,
                json,
                approval,
                confirm,
            );
        }
        if let Some(observation) = select_agent_observation(&report, &observation_id) {
            return run_agent_update(
                observation.clone(),
                update_asset_id,
                expected_prior,
                selection,
                root,
                manifest,
                registry,
                json,
                approval,
                confirm,
            );
        }
    }
    let agent_observation = if update_asset_id.is_none() {
        report
            .agent_observations()
            .iter()
            .find(|observation| observation.identity().as_str() == observation_id)
    } else {
        None
    };
    if let Some(observation) = agent_observation {
        if expected_prior.is_some() {
            return Err(CliError::new(
                "agent_update.authority_incomplete",
                "agent updates require both --update and --expected-prior",
            ));
        }
        let asset_id = match asset_id {
            Some(asset_id) => asset_id,
            None => kitrove_model::AssetId::parse(observation.observed().name().as_str()).map_err(
                |_| {
                    CliError::new(
                        "agent_adoption.asset_id_required",
                        "the agent name is not a valid default asset identifier; use --id",
                    )
                },
            )?,
        };
        let outcome = plan_agent_adoption(
            observation,
            &asset_id,
            &manifest,
            &tier_one_agent_capabilities()?,
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let plan = match outcome {
            AgentAdoptionOutcome::Ready(plan) => plan,
            AgentAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_agent_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let output = render_agent_adoption_plan(&plan, json)?;
        if !review(
            &approval,
            plan.digest(),
            &output,
            &mut confirm,
            "adoption.confirmation_required",
        )? {
            return Ok(CompletedCommand { output, status: 0 });
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let current = reread
            .agent_observations()
            .iter()
            .find(|candidate| candidate.identity() == observation.identity())
            .ok_or_else(observation_stale)?;
        let commit = if matches!(approval, ApprovalMode::Interactive) {
            commit_agent_adoption
        } else {
            kitrove_core::commit_approved_agent_adoption
        };
        let committed =
            commit(&plan, current, &root, CaptureLimits::default()).map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_agent_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if let Some(observation) = report
        .native_extension_observations()
        .iter()
        .find(|observation| observation.identity().as_str() == observation_id)
    {
        let plan = match (update_asset_id, expected_prior) {
            (Some(asset_id), Some(expected_prior)) => {
                plan_native_extension_update(observation, asset_id, expected_prior, &manifest)
            }
            (None, None) => plan_native_extension_adoption(observation, asset_id, &manifest),
            _ => {
                return Err(CliError::new(
                    "native_extension.update_authority_incomplete",
                    "native extension updates require both --update and --expected-prior",
                ));
            }
        }
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let output = render_native_extension_adoption_plan(&plan, json)?;
        if !review(
            &approval,
            plan.digest(),
            &output,
            &mut confirm,
            "adoption.confirmation_required",
        )? {
            return Ok(CompletedCommand { output, status: 0 });
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let current = reread
            .native_extension_observations()
            .iter()
            .find(|candidate| candidate.identity() == observation.identity())
            .ok_or_else(observation_stale)?;
        let native = &plan.asset().native_variants[&HarnessId::Pi];
        let envelope = VerifiedObjectEnvelope::native_extension(
            native.root.clone(),
            plan.native_object().clone(),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        let (_, current_objects) = load_local_snapshot_exact(&root, SyncLimits::default())?;
        let proposed_objects = proposed_extension_catalog(
            &manifest,
            plan.asset().id.clone(),
            current_objects.as_slice(),
            envelope,
        )?;
        let commit = if matches!(approval, ApprovalMode::Interactive) {
            commit_native_extension_plan
        } else {
            kitrove_core::commit_approved_native_extension_plan
        };
        commit(
            &root,
            &plan,
            current,
            &current_objects,
            &proposed_objects,
            SyncLimits::default(),
        )
        .map_err(|error| CliError::new(error.code(), error.message()))?;
        return Ok(CompletedCommand {
            output: render_native_extension_adoption_result(&plan, json)?,
            status: 0,
        });
    }
    if let Some((observation, observed_asset_id)) =
        select_instruction_observation(&report, &observation_id)
    {
        if let (Some(update_asset_id), Some(expected_prior)) =
            (update_asset_id.as_ref(), expected_prior.as_ref())
        {
            if update_asset_id != observed_asset_id {
                return Err(CliError::new(
                    "instruction_update.asset_id_mismatch",
                    "--update must match the selected managed instruction region",
                ));
            }
            let observation_revision = observation
                .region(observed_asset_id)
                .ok_or_else(observation_stale)?
                .observation_revision()
                .clone();
            let update_asset_id = update_asset_id.clone();
            let expected_prior = expected_prior.clone();
            return run_instruction_update(
                observation_revision,
                &update_asset_id,
                &expected_prior,
                selection,
                root,
                manifest,
                report,
                registry,
                json,
                approval,
                confirm,
            );
        }
        if update_asset_id.is_some() || expected_prior.is_some() {
            return Err(CliError::new(
                "instruction_update.authority_incomplete",
                "standing-instruction updates require both --update and --expected-prior",
            ));
        }
        let selected_asset_id = asset_id.as_ref().unwrap_or(observed_asset_id);
        if selected_asset_id != observed_asset_id {
            return Err(CliError::new(
                "instruction_adoption.asset_id_mismatch",
                "--id must match the asset identifier in the selected managed region",
            ));
        }
        let capabilities = tier_one_instruction_capabilities()?;
        let outcome =
            plan_instruction_adoption(observation, selected_asset_id, &manifest, &capabilities)
                .map_err(instruction_adoption_error)?;
        let plan = match outcome {
            InstructionAdoptionOutcome::Ready(plan) => plan,
            InstructionAdoptionOutcome::Blocked(blocked) => {
                return Ok(CompletedCommand {
                    output: render_instruction_adoption_block(&blocked, json)?,
                    status: 1,
                });
            }
        };
        let plan_output = render_instruction_adoption_plan(&plan, json)?;
        if !review(
            &approval,
            plan.digest(),
            &plan_output,
            &mut confirm,
            "adoption.confirmation_required",
        )? {
            return Ok(CompletedCommand {
                output: plan_output,
                status: 0,
            });
        }
        let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
        let (current, current_asset_id) =
            select_instruction_observation(&reread, plan.observation_revision().as_str())
                .ok_or_else(observation_stale)?;
        if current_asset_id != &plan.asset().id {
            return Err(observation_stale());
        }
        let commit = if matches!(approval, ApprovalMode::Interactive) {
            commit_instruction_adoption
        } else {
            kitrove_core::commit_approved_instruction_adoption
        };
        let committed =
            commit(&plan, current, &root, CaptureLimits::default()).map_err(transaction_error)?;
        return Ok(CompletedCommand {
            output: render_instruction_adoption_result(&plan, committed, json)?,
            status: 0,
        });
    }
    if let (Some(update_asset_id), Some(expected_prior)) = (update_asset_id, expected_prior) {
        return run_update_adoption(
            observation_id,
            update_asset_id,
            expected_prior,
            selection,
            root,
            manifest,
            report,
            registry,
            json,
            approval,
            confirm,
        );
    }
    let candidate = report
        .observations()
        .iter()
        .find_map(|candidate| match candidate {
            kitrove_core::ObservedCandidate::Accepted(candidate)
                if candidate.observation_id().as_str() == observation_id =>
            {
                Some(candidate.as_ref())
            }
            _ => None,
        })
        .ok_or_else(observation_unavailable)?;
    let capabilities = tier_one_capabilities()?;
    let outcome =
        plan_adoption(candidate, asset_id, &manifest, &capabilities).map_err(adoption_error)?;
    let plan = match outcome {
        AdoptionPlanOutcome::Ready(plan) => plan,
        AdoptionPlanOutcome::Blocked(blocked) => {
            return Ok(CompletedCommand {
                output: render_adoption_block(&blocked, json)?,
                status: 1,
            });
        }
    };
    let plan_output = render_adoption_plan(&plan, json)?;
    if !review(
        &approval,
        plan.digest(),
        &plan_output,
        &mut confirm,
        "adoption.confirmation_required",
    )? {
        return Ok(CompletedCommand {
            output: plan_output,
            status: 0,
        });
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let reread_candidate = reread
        .observations()
        .iter()
        .find_map(|candidate| match candidate {
            kitrove_core::ObservedCandidate::Accepted(candidate)
                if candidate.observation_id() == plan.observation_id() =>
            {
                Some(candidate.as_ref())
            }
            _ => None,
        })
        .ok_or_else(observation_stale)?;
    let commit = if matches!(approval, ApprovalMode::Interactive) {
        commit_adoption
    } else {
        kitrove_core::commit_approved_adoption
    };
    let committed = commit(&plan, reread_candidate, &root, CaptureLimits::default())
        .map_err(transaction_error)?;
    let output = render_adoption_result(&plan, committed, json)?;
    Ok(CompletedCommand { output, status: 0 })
}

#[allow(clippy::too_many_arguments)]
fn run_instruction_update(
    observation_revision: kitrove_model::ContentHash,
    asset_id: &kitrove_model::AssetId,
    expected_prior: &kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    report: kitrove_core::ScanReport,
    registry: &PolicyRegistry,
    json: bool,
    approval: ApprovalMode,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let state_root = resolve_required_state_root()?;
    let state_text = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let source = report
        .select_instruction_update_source(&observation_revision, asset_id, state_text.as_deref())
        .map_err(instruction_update_error)?;
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let capabilities = tier_one_instruction_capabilities()?;
    let plan = plan_instruction_update(
        &source,
        expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &capabilities,
    )
    .map_err(instruction_update_error)?;
    let output = render_instruction_update_plan(&plan, json)?;
    if !review(
        &approval,
        plan.digest(),
        &output,
        &mut confirm,
        "update.confirmation_required",
    )? {
        return Ok(CompletedCommand { output, status: 0 });
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let reread_state = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let reread_source = reread
        .select_instruction_update_source(&observation_revision, asset_id, reread_state.as_deref())
        .map_err(|_| update_observation_stale())?;
    if &reread_source != plan.source() {
        return Err(update_observation_stale());
    }
    let commit = if matches!(approval, ApprovalMode::Interactive) {
        commit_instruction_update
    } else {
        kitrove_core::commit_approved_instruction_update
    };
    let outcome = commit(
        &plan,
        reread_source.observation(),
        &root,
        &state_root,
        CaptureLimits::default(),
    )
    .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_instruction_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_prompt_command_update(
    observation: kitrove_core::PromptCommandObservation,
    asset_id: &kitrove_model::AssetId,
    expected_prior: &kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    registry: &PolicyRegistry,
    json: bool,
    approval: ApprovalMode,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let capabilities = tier_one_prompt_command_capabilities()?;
    let plan = plan_prompt_command_update(
        &observation,
        asset_id,
        expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &capabilities,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let output = render_prompt_command_update_plan(&plan, json)?;
    if !review(
        &approval,
        plan.digest(),
        &output,
        &mut confirm,
        "update.confirmation_required",
    )? {
        return Ok(CompletedCommand { output, status: 0 });
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let current =
        select_prompt_command_observation(&reread, plan.observation().identity().as_str())
            .ok_or_else(update_observation_stale)?;
    let commit = if matches!(approval, ApprovalMode::Interactive) {
        commit_prompt_command_update
    } else {
        kitrove_core::commit_approved_prompt_command_update
    };
    let outcome =
        commit(&plan, current, &root, CaptureLimits::default()).map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_prompt_command_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_agent_update(
    observation: kitrove_core::AgentObservation,
    asset_id: &kitrove_model::AssetId,
    expected_prior: &kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    registry: &PolicyRegistry,
    json: bool,
    approval: ApprovalMode,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let plan = plan_agent_update(
        &observation,
        asset_id,
        expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &tier_one_agent_capabilities()?,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))?;
    let output = render_agent_update_plan(&plan, json)?;
    if !review(
        &approval,
        plan.digest(),
        &output,
        &mut confirm,
        "update.confirmation_required",
    )? {
        return Ok(CompletedCommand { output, status: 0 });
    }
    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let current = select_agent_observation(&reread, plan.observation().identity().as_str())
        .ok_or_else(update_observation_stale)?;
    let commit = if matches!(approval, ApprovalMode::Interactive) {
        commit_agent_update
    } else {
        kitrove_core::commit_approved_agent_update
    };
    let outcome =
        commit(&plan, current, &root, CaptureLimits::default()).map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_agent_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

fn select_agent_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    identity: &str,
) -> Option<&'a kitrove_core::AgentObservation> {
    report
        .agent_observations()
        .iter()
        .find(|observation| observation.identity().as_str() == identity)
}

fn select_prompt_command_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    identity: &str,
) -> Option<&'a kitrove_core::PromptCommandObservation> {
    report
        .prompt_command_observations()
        .iter()
        .find(|observation| observation.identity().as_str() == identity)
}

fn select_mcp_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    exact_entry_hash: &str,
) -> Option<(
    &'a kitrove_core::McpScanEntry,
    &'a kitrove_core::McpDocumentObservation,
    &'a kitrove_model::ContentHash,
)> {
    let entry = report.mcp_servers.iter().find(|entry| {
        entry
            .exact_entry_hash
            .as_ref()
            .is_some_and(|hash| hash.as_str() == exact_entry_hash)
            && entry.precedence == kitrove_core::McpPrecedence::Effective
    })?;
    let selected_entry_hash = entry.exact_entry_hash.as_ref()?;
    let selected_document_hash = entry.exact_document_hash.as_ref()?;
    let observation = report.mcp_observations().iter().find(|observation| {
        observation.harness() == &entry.harness
            && observation.scope() == entry.scope
            && observation.destination() == &entry.destination
            && observation.parsed().is_some_and(|document| {
                document.exact_document_hash() == selected_document_hash
                    && document
                        .entries()
                        .iter()
                        .any(|observed| observed.exact_entry_hash() == selected_entry_hash)
            })
    })?;
    Some((entry, observation, selected_entry_hash))
}

fn read_update_authority(root: &std::path::Path) -> Result<(String, Option<String>), CliError> {
    let manifest_text =
        read_portable_text(root, "kitrove.toml", MAX_CONTROL_BYTES)?.ok_or_else(|| {
            CliError::new(
                "cli.environment_manifest_missing",
                "the selected environment does not contain kitrove.toml",
            )
        })?;
    let lock_text = read_portable_text(root, "kitrove.lock.json", MAX_CONTROL_BYTES)?;
    Ok((manifest_text, lock_text))
}

fn select_instruction_observation<'a>(
    report: &'a kitrove_core::ScanReport,
    revision: &str,
) -> Option<(
    &'a kitrove_core::InstructionDocumentObservation,
    &'a kitrove_model::AssetId,
)> {
    report
        .instruction_observations()
        .iter()
        .find_map(|observation| {
            observation.regions().find_map(|region| {
                (region.observation_revision().as_str() == revision)
                    .then_some((observation, region.asset_id()))
            })
        })
}

fn proposed_extension_catalog(
    manifest: &EnvironmentManifest,
    asset_id: kitrove_model::AssetId,
    current: &[VerifiedObjectEnvelope],
    proposed: VerifiedObjectEnvelope,
) -> Result<Vec<VerifiedObjectEnvelope>, CliError> {
    let replaced_root = manifest
        .assets
        .get(&asset_id)
        .and_then(|asset| asset.native_variants.get(&HarnessId::Pi))
        .map(|native| &native.root);
    let mut catalog = current
        .iter()
        .filter(|object| replaced_root != Some(object.descriptor().root()))
        .cloned()
        .map(|object| (object.descriptor().clone(), object))
        .collect::<BTreeMap<_, _>>();
    if catalog
        .insert(proposed.descriptor().clone(), proposed)
        .is_some()
    {
        return Err(CliError::new(
            "native_extension.object_catalog_invalid",
            "the proposed native extension object conflicts with existing object authority",
        ));
    }
    Ok(catalog.into_values().collect())
}

#[allow(clippy::too_many_arguments)]
fn run_update_adoption(
    observation_id: String,
    asset_id: kitrove_model::AssetId,
    expected_prior: kitrove_model::ContentHash,
    selection: AdoptionSelection,
    root: std::path::PathBuf,
    manifest: EnvironmentManifest,
    report: kitrove_core::ScanReport,
    registry: &PolicyRegistry,
    json: bool,
    approval: ApprovalMode,
    mut confirm: impl FnMut(&str) -> bool,
) -> Result<CompletedCommand, CliError> {
    let observation_id = report
        .observations()
        .iter()
        .find_map(|observation| {
            observation
                .observation_id()
                .filter(|id| id.as_str() == observation_id)
                .cloned()
        })
        .ok_or_else(update_observation_unavailable)?;
    let state_root = resolve_required_state_root()?;
    let state_text = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let source = report
        .select_update_source(&observation_id, &asset_id, state_text.as_deref())
        .map_err(update_selection_error)?;
    let (manifest_text, lock_text) = read_update_authority(&root)?;
    let retained_objects = load_retained_native_objects(&manifest, &asset_id, &root)?;
    let capabilities = tier_one_capabilities()?;
    let plan = plan_update_adoption(
        &source,
        &expected_prior,
        &manifest_text,
        &manifest,
        lock_text.as_deref(),
        &retained_objects,
        &capabilities,
        SyncLimits::default(),
    )
    .map_err(update_planning_error)?;
    let plan_output = render_update_plan(&plan, json)?;
    if !review(
        &approval,
        plan.digest(),
        &plan_output,
        &mut confirm,
        "update.confirmation_required",
    )? {
        return Ok(CompletedCommand {
            output: plan_output,
            status: 0,
        });
    }

    let reread = scan_report(adoption_scan_args(root.clone(), &selection), registry)?;
    let reread_state_text = read_portable_text(&state_root, "state.json", MAX_CONTROL_BYTES)?;
    let reread_source = reread
        .select_update_source(
            plan.source().selected().observation_id(),
            plan.source().asset_id(),
            reread_state_text.as_deref(),
        )
        .map_err(|_| update_observation_stale())?;
    if &reread_source != plan.source() {
        return Err(update_observation_stale());
    }
    let commit = if matches!(approval, ApprovalMode::Interactive) {
        commit_update_adoption
    } else {
        kitrove_core::commit_approved_update_adoption
    };
    let outcome = commit(
        &plan,
        reread_source.selected(),
        &root,
        &state_root,
        CaptureLimits::default(),
    )
    .map_err(transaction_error)?;
    Ok(CompletedCommand {
        output: render_update_result(&plan, outcome, json)?,
        status: 0,
    })
}

fn load_retained_native_objects(
    manifest: &EnvironmentManifest,
    asset_id: &kitrove_model::AssetId,
    root: &std::path::Path,
) -> Result<VerifiedSkillObjectCatalog, CliError> {
    let asset = manifest.assets.get(asset_id).ok_or_else(|| {
        CliError::new(
            "update.asset_missing",
            "the requested update asset does not exist",
        )
    })?;
    let native = asset
        .native_variants
        .keys()
        .map(|harness| {
            load_native_skill_object(manifest, asset_id, harness, root, CaptureLimits::default())
                .map_err(|error| CliError::new(error.code(), error.message()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    VerifiedSkillObjectCatalog::new(Vec::new(), native)
        .map_err(|error| CliError::new(error.code(), error.message()))
}

struct AdoptionSelection {
    harnesses: BTreeSet<HarnessId>,
    scope: ScopeSelection,
    project_root: Option<std::path::PathBuf>,
    roots: Vec<kitrove_adapter_api::ExplicitRoot>,
}

fn adoption_scan_args(environment: std::path::PathBuf, selection: &AdoptionSelection) -> ScanArgs {
    ScanArgs {
        harnesses: selection.harnesses.clone(),
        scope: selection.scope,
        project_root: selection.project_root.clone(),
        roots: selection.roots.clone(),
        environment: Some(environment),
        json: false,
        verbose: false,
    }
}
