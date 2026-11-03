//! Setup-only selection and presentation; existing exact adoption commits own writes.
use super::*;
use kitrove_core::{AdoptionPlan, AdoptionPlanOutcome, ScanEntry, ScanReport, plan_adoption};
use kitrove_model::EnvironmentManifest;

// Keep exact digests, not every hypothetical manifest and captured source tree.
// This is preview data, not authority until the user confirms the displayed set.
struct PreviewedItem {
    index: usize,
    id: AssetId,
    digest: ContentHash,
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

pub(super) fn collect<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    let report = scan_report(scan_args(root), registry)?;
    let candidates: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| selectable(entry))
        .collect();
    dialog.say(&format!("Collection scan (read-only): {} skills observed; {} selectable; {} not selectable.\nOriginal files remain unchanged. No skills are applied, executed or synchronized.", report.entries.len(), candidates.len(), report.entries.len() - candidates.len()))?;
    for (index, entry) in candidates.iter().enumerate().take(20) {
        dialog.say(&format!("  {}. {}", index + 1, label(entry)))?;
    }
    if candidates.is_empty() {
        dialog.say("No skills available to collect. Use scan --verbose for findings.")?;
        return Ok(());
    }
    if candidates.len() > 20 {
        dialog
            .say("Showing the first 20; v shows the full inventory and numbered selection list.")?;
    }
    let selected = loop {
        let response = dialog.ask("Choose skills: Enter = recommended set; 1,4,7 = only these; all,-3,-8 or -3,-8 = all except; v = full inventory; n = skip; q = stop:")?;
        if response == "v" {
            dialog.say(&crate::scan_display::render(&report))?;
            for (index, entry) in candidates.iter().enumerate() {
                dialog.say(&format!("  {}. {}", index + 1, label(entry)))?;
            }
            continue;
        }
        if response.is_empty() {
            break (0..candidates.len()).collect::<Vec<_>>();
        }
        match selection(&response, candidates.len()) {
            Some(indices) => break indices,
            None => dialog.say("Use shown numbers, all,-3,-8 or -3,-8. Do not mix positive and negative numbers. Nothing has changed.")?,
        }
    };
    if selected.is_empty() {
        dialog.say("Collection skipped.")?;
        return Ok(());
    }
    let items = preview(dialog, root, &report, &candidates, &selected)?;
    loop {
        match dialog.ask("y/yes = adopt the previewed set; r = review selected skills individually; n = skip; q = stop (Enter does not approve bulk writes):")?.to_ascii_lowercase().as_str() {
            "y" | "yes" => {
                for (completed, item) in items.iter().enumerate() {
                    if let Err(error) = commit(root, candidates[item.index], item, registry) {
                        dialog.say(&format!("Stopped after {completed} completed adoptions; later items did not run. Use status before continuing."))?;
                        return Err(error);
                    }
                    dialog.say(&format!("Adopted {}.", item.id.as_str()))?;
                }
                return dialog.say(&format!("Adopted {} skills. Apply and sync remain separate choices.", items.len()));
            }
            "r" => return individually(dialog, root, &report, &candidates, &selected, registry),
            "n" | "no" => return dialog.say("Collection skipped."),
            _ => dialog.say("Choose y to adopt, r to review, or n to skip. Nothing has changed.")?,
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

fn show_plan<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    index: usize,
    entry: &ScanEntry,
    plan: &AdoptionPlan,
) -> Result<(), CliError> {
    let fidelity = plan
        .asset()
        .compatibility
        .iter()
        .map(|(harness, result)| format!("{}={:?}", harness.as_str(), result.fidelity()))
        .collect::<Vec<_>>()
        .join(", ");
    dialog.say(&format!(
        "  {}. {} -> {} | {fidelity}",
        index + 1,
        label(entry),
        plan.asset().id.as_str()
    ))?;
    for (harness, result) in &plan.asset().compatibility {
        for reason in result.reasons() {
            dialog.say(&format!(
                "     {}: {}: {}",
                harness.as_str(),
                safe(&reason.code),
                safe(&reason.message)
            ))?;
        }
    }
    Ok(())
}

fn preview<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    report: &ScanReport,
    candidates: &[&ScanEntry],
    selected: &[usize],
) -> Result<Vec<PreviewedItem>, CliError> {
    let mut manifest = load_manifest(root)?;
    let mut items = Vec::new();
    dialog.say("Adoption preview (no writes). Names and four-tool fidelity follow. Each item is a separate transaction; on failure completed items remain and later items stop.")?;
    for (index, entry) in candidates.iter().enumerate() {
        if !selected.contains(&index) {
            dialog.say(&format!("Excluded: {}. {}", index + 1, label(entry)))?;
            continue;
        }
        let reason = if selected
            .iter()
            .any(|other| *other != index && name(candidates[*other]) == name(entry))
        {
            Some("same name in multiple selected sources; review individually to choose or rename")
        } else {
            None
        };
        let id = AssetId::parse(name(entry).to_owned());
        let reason = reason.or_else(|| match &id {
            Err(_) => Some("name needs an explicit rename; review individually"),
            Ok(id) if occupied(&manifest, id) => {
                Some("collection name already in use; review individually to rename")
            }
            Ok(_) => None,
        });
        if let Some(reason) = reason {
            dialog.say(&format!(
                "Omitted: {}. {}: {reason}",
                index + 1,
                label(entry)
            ))?;
            continue;
        }
        let id = id.map_err(|_| io_error())?;
        match plan(report, entry, id.clone(), &manifest)? {
            AdoptionPlanOutcome::Ready(plan) => {
                show_plan(dialog, index, entry, &plan)?;
                items.push(PreviewedItem {
                    index,
                    id,
                    digest: plan.digest().clone(),
                });
                manifest = plan.proposed_manifest().clone();
            }
            AdoptionPlanOutcome::Blocked(blocked) => dialog.say(&format!(
                "Omitted: {}. {}: {:?}. No trust is granted.",
                index + 1,
                label(entry),
                blocked.reason()
            ))?,
        }
    }
    dialog.say(&format!(
        "{} ready; {} selected but omitted; {} excluded by selection.",
        items.len(),
        selected.len() - items.len(),
        candidates.len() - selected.len()
    ))?;
    Ok(items)
}

fn commit(
    root: &std::path::Path,
    entry: &ScanEntry,
    item: &PreviewedItem,
    registry: &PolicyRegistry,
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
            harnesses: BTreeSet::from([entry.harness.clone()]),
            scope: ScopeSelection::User,
            project_root: None,
            roots: Vec::new(),
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

fn individually<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    report: &ScanReport,
    candidates: &[&ScanEntry],
    selected: &[usize],
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    for &index in selected {
        let entry = candidates[index];
        let mut proposed_name = name(entry).to_owned();
        loop {
            let manifest = load_manifest(root)?;
            let id = AssetId::parse(proposed_name.clone());
            if id.as_ref().map_or(true, |id| occupied(&manifest, id)) {
                dialog.say(&format!(
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
                    dialog.say(&format!(
                        "Skipped this skill: {:?}. No trust is granted.",
                        blocked.reason()
                    ))?;
                    break;
                }
            };
            show_plan(dialog, index, entry, &plan)?;
            let response =
                dialog.ask("Enter/y = adopt this skill; n = skip; r = rename; q = stop:")?;
            match response.to_ascii_lowercase().as_str() {
                "" | "y" | "yes" => {
                    commit(
                        root,
                        entry,
                        &PreviewedItem {
                            index,
                            id,
                            digest: plan.digest().clone(),
                        },
                        registry,
                    )?;
                    dialog.say(&format!("Adopted {}.", plan.asset().id.as_str()))?;
                    break;
                }
                "n" | "no" | "-" => {
                    dialog.say("Skipped this skill.")?;
                    break;
                }
                "r" => proposed_name = dialog.ask("New collection name (q stops):")?,
                _ => dialog.say("Choose Enter/y, n, r or q. Nothing has changed.")?,
            }
        }
    }
    Ok(())
}
