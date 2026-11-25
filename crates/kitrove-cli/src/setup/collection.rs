//! Setup-only selection and presentation; existing exact adoption commits own writes.
use super::collection_selection::{self, Skipped};
use super::*;
use kitrove_core::{
    AdoptionBlockReason, AdoptionPlan, AdoptionPlanOutcome, ScanEntry, ScanReport, plan_adoption,
};
use kitrove_model::EnvironmentManifest;

const SELECTION_PROMPT: &str = concat!(
    "Choose skills to collect\n",
    "Enter         Preview eligible skills\n",
    "1,4,7         Preview specific skills\n",
    "from TOOL     Use only that tool's copies\n",
    "v             Browse source copies\n",
    "help          All selection commands\n",
    "n             Skip\n",
    "q             Quit",
);
const SELECTION_HELP: &str = concat!(
    "Collection selection help\n",
    "Enter         Preview eligible skills\n",
    "from TOOL     Use only that tool's copies (for example, from codex)\n",
    "1,4,7         Preview listed skills by number\n",
    "all,-3,-8     All except 3 and 8 (or -3,-8)\n",
    "from codex,-3 Use Codex copies except number 3\n",
    "v             Browse source copies (/name filters, next pages)\n",
    "n             Skip\n",
    "q             Quit",
);
const READY_PROMPT: &str = concat!(
    "Collect these skills?\n",
    "y             Save the previewed skills\n",
    "s             Choose again\n",
    "r             Review individually\n",
    "d             Full preview details\n",
    "Enter/n       Skip [default]\n",
    "q             Quit",
);
const EMPTY_PROMPT: &str = concat!(
    "No skills ready to collect\n",
    "Enter/s       Choose again\n",
    "r             Review individually\n",
    "d             Show all skipped-item details\n",
    "n             Skip\n",
    "q             Quit",
);
const INDIVIDUAL_PROMPT: &str = concat!(
    "Adopt this skill?\n",
    "y             Save this skill\n",
    "Enter/n       Skip [default]\n",
    "r             Rename\n",
    "q             Quit",
);

// Keep exact digests, not every hypothetical manifest and captured source tree.
// This is preview data, not authority until the user confirms the displayed set.
struct PreviewedItem {
    index: usize,
    id: AssetId,
    digest: ContentHash,
    details: Vec<String>,
}

fn label(entry: &ScanEntry) -> String {
    format!(
        "{} ({}, {:?})",
        safe(name(entry)),
        entry.harness.as_str(),
        entry.scope
    )
}

fn scan_args(root: &std::path::Path) -> ScanArgs {
    ScanArgs {
        harnesses: tier_one_harnesses(),
        scope: ScopeSelection::User,
        project_root: None,
        roots: Vec::new(),
        environment: Some(root.to_owned()),
        json: false,
        verbose: false,
    }
}

pub(super) fn collect<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    registry: &PolicyRegistry,
) -> Result<Vec<AssetId>, CliError> {
    let selection = scan_args(root);
    let report = scan_report(selection.clone(), registry)?;
    collect_report(dialog, root, registry, &report, &selection)
}

pub(super) fn collect_report<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    registry: &PolicyRegistry,
    report: &ScanReport,
    selection: &ScanArgs,
) -> Result<Vec<AssetId>, CliError> {
    let candidates: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| selectable(entry))
        .collect();
    let observed = report
        .entries
        .iter()
        .filter(|entry| !crate::scan_display::folder_issue(entry))
        .count();
    dialog.heading("Collect skills")?;
    dialog.say(&format!(
        "{observed} found · {} available to preview",
        candidates.len()
    ))?;
    if candidates.is_empty() {
        dialog.hint("Run kitrove scan to see why nothing is available to collect.")?;
        return Ok(Vec::new());
    }
    collection_selection::show_sources(dialog, &candidates)?;
    let mut next_selection = None;
    let mut inventory_start = 0;
    let mut inventory_filter = String::new();
    'selection: loop {
        let selected = if let Some(indices) = next_selection.take() {
            indices
        } else {
            loop {
                let prompt = if inventory_filter.is_empty() {
                    SELECTION_PROMPT.to_owned()
                } else {
                    format!(
                        "{SELECTION_PROMPT}\nSelection limited to names matching {}. Type / to clear.",
                        safe(&inventory_filter)
                    )
                };
                let mut response = dialog.ask(&prompt)?;
                while matches!(response.as_str(), "help" | "?") {
                    response = dialog.ask(SELECTION_HELP)?;
                }
                match response.as_str() {
                    "v" => {
                        super::collection_status::page(
                            dialog,
                            &candidates,
                            &inventory_filter,
                            &mut inventory_start,
                            false,
                        )?;
                        continue;
                    }
                    "next" => {
                        super::collection_status::page(
                            dialog,
                            &candidates,
                            &inventory_filter,
                            &mut inventory_start,
                            true,
                        )?;
                        continue;
                    }
                    value if value.starts_with('/') => {
                        inventory_filter = value[1..].trim().to_ascii_lowercase();
                        inventory_start = 0;
                        super::collection_status::page(
                            dialog,
                            &candidates,
                            &inventory_filter,
                            &mut inventory_start,
                            false,
                        )?;
                        continue;
                    }
                    _ => {}
                }
                let indices = if response.is_empty() {
                    Some((0..candidates.len()).collect::<Vec<_>>())
                } else {
                    collection_selection::select(&response, &candidates)
                };
                match indices {
                    Some(indices) => {
                        break indices
                            .into_iter()
                            .filter(|index| {
                                name(candidates[*index])
                                    .to_ascii_lowercase()
                                    .contains(&inventory_filter)
                            })
                            .collect::<Vec<_>>();
                    }
                    None => {
                        dialog.say("Use a displayed tool (from codex), shown numbers, all,-3,-8 or -3,-8. Do not mix positive and negative numbers. Nothing has changed.")?;
                    }
                }
            }
        };
        if selected.is_empty() {
            dialog.say("Collection skipped.")?;
            return Ok(Vec::new());
        }
        let (items, skipped) = preview(dialog, root, report, &candidates, &selected)?;
        let sources = if items.is_empty() && skipped.has_ambiguity() {
            collection_selection::source_choices(&candidates, &selected)
        } else {
            Vec::new()
        };
        let source_prompt = collection_selection::source_prompt(&sources);
        if items.is_empty() {
            dialog.say("No skills ready to collect. Nothing has changed.")?;
            if skipped.has_matching() {
                dialog.hint(
                    "Matching skills are already saved. Run kitrove apply to add them to a tool.",
                )?;
            } else if sources.is_empty() {
                dialog.hint("Choose r to review or rename selected skills, or s to choose different skills.")?;
            } else {
                dialog.say("The same skill names were found in more than one tool.")?;
                dialog.hint("Choosing a tool only previews; nothing is collected yet.")?;
            }
        }
        loop {
            let prompt = if !sources.is_empty() {
                &source_prompt
            } else if items.is_empty() {
                EMPTY_PROMPT
            } else {
                READY_PROMPT
            };
            let response = dialog.decision(prompt)?.to_ascii_lowercase();
            if let Some((_, indices)) = response
                .parse::<usize>()
                .ok()
                .filter(|number| response.len() == 1 && *number > 0)
                .and_then(|number| sources.get(number - 1))
            {
                next_selection = Some(indices.clone());
                continue 'selection;
            }
            match response.as_str() {
                "y" | "yes" if !items.is_empty() => {
                    for (completed, item) in items.iter().enumerate() {
                        if let Err(error) =
                            commit(root, candidates[item.index], item, registry, selection)
                        {
                            dialog.warning(&format!(
                                "Stopped after {completed} completed adoptions."
                            ))?;
                            if matches!(
                                error.code,
                                "transaction.cleanup_failed" | "transaction.cleanup_limit"
                            ) {
                                if super::storage::repair(dialog, root)? {
                                    dialog.hint("Storage checks passed. Collect again to review what remains.")?;
                                } else {
                                    dialog.hint(
                                        "Run kitrove doctor with this collection before retrying.",
                                    )?;
                                }
                            } else {
                                dialog.hint("Use kitrove status before continuing.")?;
                            }
                            return Err(error);
                        }
                        dialog.success(&format!("Adopted {}.", item.id.as_str()))?;
                    }
                    dialog.success(&format!(
                        "Adopted {} skills. Apply and sync remain separate choices.",
                        items.len()
                    ))?;
                    return Ok(items.into_iter().map(|item| item.id).collect());
                }
                "r" => {
                    return individually(
                        dialog,
                        root,
                        report,
                        &candidates,
                        &selected,
                        registry,
                        selection,
                    );
                }
                "s" => continue 'selection,
                "" if items.is_empty() => continue 'selection,
                "d" => {
                    for item in &items {
                        for line in &item.details {
                            dialog.detail(line)?;
                        }
                    }
                    skipped.all(dialog)?;
                }
                "" | "n" | "no" => {
                    dialog.say("Collection skipped.")?;
                    return Ok(Vec::new());
                }
                _ => dialog.say("Choose one of the displayed options. Nothing has changed.")?,
            }
        }
    }
}

fn plan(
    report: &ScanReport,
    entry: &ScanEntry,
    id: AssetId,
    manifest: &EnvironmentManifest,
) -> Result<AdoptionPlanOutcome, CliError> {
    let candidate = report
        .observations()
        .iter()
        .find_map(|candidate| match candidate {
            kitrove_core::ObservedCandidate::Accepted(candidate)
                if Some(candidate.observation_id()) == entry.observation_id.as_ref() =>
            {
                Some(candidate.as_ref())
            }
            _ => None,
        })
        .ok_or_else(|| {
            CliError::new(
                "setup.observation_missing",
                "the selected skill observation is unavailable; scan again",
            )
        })?;
    plan_adoption(
        candidate,
        Some(id),
        manifest,
        &crate::adapters::tier_one_capabilities()?,
    )
    .map_err(|error| CliError::new(error.code(), error.message()))
}

fn occupied(manifest: &EnvironmentManifest, id: &AssetId) -> bool {
    manifest.assets.contains_key(id) || manifest.packs.contains_key(id)
}

fn plan_details(index: usize, entry: &ScanEntry, plan: &AdoptionPlan) -> Vec<String> {
    let fidelity = plan
        .asset()
        .compatibility
        .iter()
        .map(|(harness, result)| format!("{}={:?}", harness.as_str(), result.fidelity()))
        .collect::<Vec<_>>()
        .join(", ");
    let mut details = vec![format!(
        "  {}. {} -> {} | {fidelity}",
        index + 1,
        label(entry),
        plan.asset().id.as_str()
    )];
    for (harness, result) in &plan.asset().compatibility {
        details.extend(result.reasons().iter().map(|reason| {
            format!(
                "     {}: {}: {}",
                harness.as_str(),
                safe(&reason.code),
                safe(&reason.message)
            )
        }));
    }
    details
}

fn preview<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    report: &ScanReport,
    candidates: &[&ScanEntry],
    selected: &[usize],
) -> Result<(Vec<PreviewedItem>, Skipped), CliError> {
    let mut manifest = load_manifest(root)?;
    let mut items = Vec::new();
    let mut skipped = Skipped::default();
    dialog.heading("Adoption preview (no writes)")?;
    for (index, entry) in candidates.iter().enumerate() {
        if !selected.contains(&index) {
            skipped.push(
                "excluded by selection",
                format!("Excluded: {}. {}", index + 1, label(entry)),
            );
            continue;
        }
        let id = AssetId::parse(name(entry).to_owned());
        let reason = match &id {
            Err(_) => Some("name needs an explicit rename; review individually"),
            Ok(id) if occupied(&manifest, id) => Some(super::collection_status::existing(
                root, &manifest, id, entry,
            )),
            Ok(_) => None,
        };
        let reason = reason.or_else(|| {
            if selected
                .iter()
                .any(|other| *other != index && name(candidates[*other]) == name(entry))
            {
                Some(collection_selection::AMBIGUOUS)
            } else {
                None
            }
        });
        if let Some(reason) = reason {
            skipped.push(
                reason,
                format!("Omitted: {}. {}: {reason}", index + 1, label(entry)),
            );
            continue;
        }
        let id = id.map_err(|_| io_error())?;
        match plan(report, entry, id.clone(), &manifest)? {
            AdoptionPlanOutcome::Ready(plan) => {
                items.push(PreviewedItem {
                    index,
                    id,
                    digest: plan.digest().clone(),
                    details: plan_details(index, entry, &plan),
                });
                manifest = plan.proposed_manifest().clone();
            }
            AdoptionPlanOutcome::Blocked(blocked) => skipped.blocked(format!(
                "{}: {}",
                label(entry),
                block_reason(blocked.reason())
            )),
        }
    }
    let selected_names = selected
        .iter()
        .map(|index| name(candidates[*index]))
        .collect::<BTreeSet<_>>()
        .len();
    skipped.summary(dialog, selected.len(), selected_names, items.len())?;
    if !items.is_empty() {
        for item in items.iter().take(6) {
            dialog.say(&format!("  Ready: {}", item.id.as_str()))?;
        }
        if items.len() > 6 {
            dialog.hint(&format!(
                "  {} more ready. Use d to see all names and per-tool compatibility.",
                items.len() - 6
            ))?;
        }
        dialog.hint("If collection stops partway, completed skills stay saved.")?;
    }
    Ok((items, skipped))
}

fn commit(
    root: &std::path::Path,
    entry: &ScanEntry,
    item: &PreviewedItem,
    registry: &PolicyRegistry,
    selection: &ScanArgs,
) -> Result<(), CliError> {
    let done = run_adopt(
        AdoptArgs {
            approval: crate::args::ApprovalMode::Confirm(item.digest.clone()),
            observation_id: entry
                .observation_id
                .as_ref()
                .ok_or_else(io_error)?
                .as_str()
                .to_owned(),
            asset_id: Some(item.id.clone()),
            update_asset_id: None,
            expected_prior: None,
            binding: None,
            harnesses: selection.harnesses.clone(),
            scope: selection.scope,
            project_root: selection.project_root.clone(),
            roots: selection.roots.clone(),
            environment: Some(root.to_owned()),
            json: true,
        },
        registry,
        |_| false,
    )?;
    if done.status != 0 {
        return Err(CliError::new(
            "setup.adoption_blocked",
            "the approved skill is now blocked; stop and obtain a fresh preview",
        ));
    }
    Ok(())
}

fn individually<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    report: &ScanReport,
    candidates: &[&ScanEntry],
    selected: &[usize],
    registry: &PolicyRegistry,
    selection: &ScanArgs,
) -> Result<Vec<AssetId>, CliError> {
    let mut adopted = Vec::new();
    let mut matching = 0;
    for &index in selected {
        let entry = candidates[index];
        let mut proposed_name = name(entry).to_owned();
        loop {
            let manifest = load_manifest(root)?;
            let id = AssetId::parse(proposed_name.clone());
            if proposed_name == name(entry)
                && let Ok(id) = &id
                && super::collection_status::existing(root, &manifest, id, entry)
                    == super::collection_status::MATCHING
            {
                matching += 1;
                break;
            }
            if id.as_ref().map_or(true, |id| occupied(&manifest, id)) {
                dialog.warning(&format!(
                    "{}: name invalid or already in use. Nothing is overwritten.",
                    label(entry)
                ))?;
                let response = dialog.ask("New collection name; n or - skips; q stops:")?;
                if matches!(response.as_str(), "n" | "-") {
                    break;
                }
                proposed_name = response;
                continue;
            }
            let id = id.map_err(|_| io_error())?;
            let plan = match plan(report, entry, id.clone(), &manifest)? {
                AdoptionPlanOutcome::Ready(plan) => plan,
                AdoptionPlanOutcome::Blocked(blocked) => {
                    dialog.warning(&format!(
                        "Skipped this skill: {}.",
                        block_reason(blocked.reason())
                    ))?;
                    break;
                }
            };
            dialog.heading("Adoption preview (no writes)")?;
            let details = plan_details(index, entry, &plan);
            for line in &details {
                dialog.detail(line)?;
            }
            let response = dialog.decision(INDIVIDUAL_PROMPT)?;
            match response.to_ascii_lowercase().as_str() {
                "y" | "yes" => {
                    commit(
                        root,
                        entry,
                        &PreviewedItem {
                            index,
                            id,
                            digest: plan.digest().clone(),
                            details: Vec::new(),
                        },
                        registry,
                        selection,
                    )?;
                    dialog.success(&format!("Adopted {}.", plan.asset().id.as_str()))?;
                    adopted.push(plan.asset().id.clone());
                    break;
                }
                "" | "n" | "no" | "-" => {
                    dialog.say("Skipped this skill.")?;
                    break;
                }
                "r" => proposed_name = dialog.ask("New collection name (q stops):")?,
                _ => dialog
                    .say("Choose y to save, r to rename, or Enter to skip. Nothing has changed.")?,
            }
        }
    }
    if matching > 0 {
        dialog.say(&format!(
            "Skipped {matching} already-collected skill copies; exact native content matches."
        ))?;
    }
    Ok(adopted)
}

fn block_reason(reason: AdoptionBlockReason) -> &'static str {
    match reason {
        AdoptionBlockReason::PortableProjectionUnavailable => {
            "cannot be converted to a portable skill"
        }
        AdoptionBlockReason::ScriptBundleUnsupported => {
            "contains unsupported executable content or native lifecycle directives"
        }
        AdoptionBlockReason::CredentialShapedNativeIdentity => {
            "the source identity looks like a credential; review it locally"
        }
        AdoptionBlockReason::AssetConflict => "conflicts with an existing collection item",
    }
}
