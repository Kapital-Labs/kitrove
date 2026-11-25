//! Guided local installation; existing materialization plans retain all write authority.
use super::*;
use kitrove_model::{AssetKind, EnvironmentManifest};

const TOOLS: [HarnessId; 4] = [
    HarnessId::Claude,
    HarnessId::Codex,
    HarnessId::Pi,
    HarnessId::OpenCode,
];
const PAGE_SIZE: usize = 12;

#[derive(Default)]
struct ItemSelection {
    ids: Vec<AssetId>,
    bulk: bool,
}

impl From<Vec<AssetId>> for ItemSelection {
    fn from(ids: Vec<AssetId>) -> Self {
        Self { ids, bulk: false }
    }
}

pub(super) fn apply<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    suggested: &[AssetId],
) -> Result<(), CliError> {
    let manifest = load_manifest(root)?;
    if manifest.assets.is_empty() && manifest.packs.is_empty() {
        return dialog.say("Your collection is empty. Collect skills from this computer first.");
    }
    dialog.hint("Choose a tool, then preview what to add. Return here with kitrove apply.")?;
    let targets = choose_tools(dialog)?;
    if targets.is_empty() {
        return Ok(());
    }
    if targets.contains(&HarnessId::Codex) {
        dialog.hint("Pi and OpenCode may also find skills in Codex's shared folder.")?;
    }
    if targets.contains(&HarnessId::Claude) {
        dialog.hint("OpenCode may also find skills in Claude's folder.")?;
    }
    let scope_choice = navigation::choose(
        dialog,
        "Where should these items be available?",
        &[
            (b'1', "All projects on this computer"),
            (b'2', "This project only"),
            (b'n', "Back"),
        ],
        2,
    )?;
    let (scope, project_root) = match scope_choice {
        b'1' => (HarnessScope::User, None),
        b'2' => {
            let path = dialog.ask("Absolute project folder path (Enter goes back):")?;
            if path.is_empty() {
                return Ok(());
            }
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(CliError::new(
                    "setup.project_path_invalid",
                    "choose an absolute project folder path",
                ));
            }
            (HarnessScope::Project, Some(path))
        }
        _ => return Ok(()),
    };
    let target_labels = targets
        .iter()
        .map(HarnessId::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    dialog.heading(&format!("Add to {target_labels}"))?;
    if let Some(project) = &project_root {
        dialog.say(&format!(
            "Project · {}",
            safe(&project.display().to_string())
        ))?;
    } else {
        dialog.say("All projects on this computer")?;
    }
    let destination_args = MaterializeArgs {
        profile: None,
        assets: BTreeSet::new(),
        packs: BTreeSet::new(),
        targets,
        scope,
        project_root,
        version_binaries: Vec::new(),
        environment: Some(root.to_owned()),
        json: true,
    };
    let mut preview_ready: Option<Vec<AssetId>> = None;
    let mut browse_items = false;
    let mut retry_selection = None;
    loop {
        let manifest = load_manifest(root)?;
        let mut args = destination_args.clone();
        let ItemSelection { ids, bulk } = if let Some(selection) = retry_selection.take() {
            selection
        } else if let Some(previous) = preview_ready.take() {
            let ready = ready_items(root, &manifest, previous.iter(), &args);
            if ready.is_empty() {
                dialog.say("None of the selected skills are ready. Choose other items or check the reasons beside each skill.")?;
                continue;
            }
            dialog.say(&format!(
                "Previewing {} of {} selected items. The other items will be left out.",
                ready.len(),
                previous.len()
            ))?;
            ready.into()
        } else if browse_items {
            choose_items(dialog, root, &manifest, suggested, &args)?
        } else {
            browse_items = true;
            select_items(dialog, root, &manifest, suggested, &args)?
        };
        if ids.is_empty() {
            return Ok(());
        }
        for id in &ids {
            if manifest.packs.contains_key(id) {
                args.packs.insert(id.clone());
            } else if manifest.assets.contains_key(id) {
                args.assets.insert(id.clone());
            } else {
                return Err(CliError::new(
                    "apply.plan_stale",
                    "the collection changed during selection; choose items again",
                ));
            }
        }
        let mut assets = args.assets.clone();
        for leaves in kitrove_core::resolve_pack_asset_memberships(&manifest, &args.packs)
            .map_err(|error| CliError::new(error.code(), error.message()))?
            .into_values()
        {
            assets.extend(leaves);
        }
        if assets
            .iter()
            .any(|id| manifest.assets[id].kind == AssetKind::Extension)
        {
            dialog.warning("Extensions contain executable code and may run when the tool loads them. This flow does not grant trust; existing executable and project-trust gates still apply.")?;
        }
        let (pi, opencode) =
            crate::materialize::required_version_probes(&manifest, &assets, &args.targets);
        for (required, tool) in [(pi, "pi"), (opencode, "opencode2")] {
            if !required {
                continue;
            }
            dialog.hint("These selected items need verified tool-version evidence. Planning may run only the explicit local executable's bounded version probe; no tool or dependency is installed.")?;
            let path = dialog.ask(&format!(
                "Absolute trusted {tool} executable path (Enter skips):"
            ))?;
            if path.is_empty() {
                return Ok(());
            }
            args.version_binaries.push(PathBuf::from(path));
        }
        // Readiness is advisory. Only run_apply owns pending-batch recovery and the
        // final fresh plan; a separate preflight must not hide its authoritative error
        // or block recovery of a previously approved operation.
        super::application_preview::discovery(dialog, root, &manifest, &assets, &args)?;
        let mut prompt_error = None;
        let mut preview_offered = false;
        let mut result = apply_with_preview(
            dialog,
            root,
            &manifest,
            &assets,
            args.clone(),
            &mut prompt_error,
            &mut preview_offered,
        );
        if !bulk
            && !preview_offered
            && result
                .as_ref()
                .is_err_and(|error| error.code == "apply.skill_trust_required")
        {
            if !review_scripted_skills(dialog, root, &assets)? {
                return dialog.say(
                    "Selection was not applied. Earlier explicit local approvals remain saved.",
                );
            }
            result = apply_with_preview(
                dialog,
                root,
                &manifest,
                &assets,
                args,
                &mut prompt_error,
                &mut preview_offered,
            );
        }
        if let Some(error) = prompt_error {
            return Err(error);
        }
        return match result {
            Ok(done) => {
                dialog.success("Files added or already current at the previewed destinations.")?;
                dialog.hint("Tool loading has not been verified. Start or refresh the selected tool and check its skills; project trust and tool permissions may still apply.")?;
                let value: serde_json::Value =
                    serde_json::from_str(&done.output).map_err(|_| io_error())?;
                let count = value["items"].as_array().map_or(0, Vec::len);
                dialog.outcome(&serde_json::json!({"Destinations completed":count,"Check collection":"kitrove status"}).to_string())
            }
            Err(error) if error.code == "apply.confirmation_required" => {
                dialog.say("Application skipped.")
            }
            Err(error)
                if !preview_offered
                    && (error.code == "apply.compatibility_blocked"
                        || bulk
                            && matches!(
                                error.code,
                                "apply.destination_unmanaged" | "apply.skill_trust_required"
                            )) =>
            {
                let reason = match error.code {
                    "apply.compatibility_blocked" => {
                        "Some items are incompatible with the selected tools."
                    }
                    "apply.destination_unmanaged" => {
                        "A destination already contains a copy managed outside Kitrove."
                    }
                    _ => "Some skills need separate script approval.",
                };
                dialog.warning(&format!("{reason} No files changed."))?;
                loop {
                    match navigation::choose(
                        dialog,
                        "What would you like to do?",
                        &[
                            (b'r', "Preview ready items from this selection"),
                            (b's', "Choose different items"),
                            (b'd', "Show compatibility details"),
                            (b'n', "Back"),
                        ],
                        0,
                    )? {
                        b'r' => {
                            preview_ready = Some(ids);
                            break;
                        }
                        b'd' => super::application_preview::compatibility(
                            dialog,
                            &manifest,
                            &assets,
                            &destination_args.targets,
                        )?,
                        b's' => break,
                        _ => return Ok(()),
                    }
                }
                continue;
            }
            Err(error) if error.code == "apply.batch_storage_failed" => {
                dialog.warning("Storage prevented this selection from being added.")?;
                if super::storage::repair(dialog, root)? {
                    dialog.hint("Review a fresh preview before adding these items.")?;
                    retry_selection = Some(ItemSelection { ids, bulk });
                    continue;
                }
                dialog.hint("Run kitrove doctor with this collection to check storage.")?;
                Err(error)
            }
            Err(error) => Err(error),
        };
    }
}

fn select_items<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    suggested: &[AssetId],
    args: &MaterializeArgs,
) -> Result<ItemSelection, CliError> {
    let total = manifest.assets.len() + manifest.packs.len();
    dialog.say(&format!("{total} saved items"))?;
    let mut choices = Vec::new();
    if !suggested.is_empty() {
        choices.push((
            b'j',
            format!("Preview ready from {} just collected", suggested.len()),
        ));
    }
    choices.extend([
        (
            b'r',
            "Preview ready skills across this collection".to_owned(),
        ),
        (b's', "Choose specific items or review a blocker".to_owned()),
        (b'n', "Back".to_owned()),
    ]);
    let choice = navigation::choose(dialog, "What would you like to add?", &choices, 0)?;
    let candidates = match choice {
        b'j' => suggested.to_vec(),
        b'r' => manifest
            .assets
            .iter()
            .filter(|(_, asset)| asset.kind == AssetKind::Skill)
            .map(|(id, _)| id.clone())
            .collect(),
        b's' => return choose_items(dialog, root, manifest, suggested, args),
        _ => return Ok(ItemSelection::default()),
    };
    let ready = ready_items(root, manifest, candidates.iter(), args);
    dialog.say(&format!(
        "{} of {} selected skills ready to add",
        ready.len(),
        candidates.len()
    ))?;
    if ready.is_empty() {
        dialog.hint("No skills ready in this selection. Browse items to see their status.")?;
        return choose_items(dialog, root, manifest, suggested, args);
    }
    Ok(ready.into())
}

fn choose_items<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    suggested: &[AssetId],
    args: &MaterializeArgs,
) -> Result<ItemSelection, CliError> {
    let ids: Vec<_> = manifest
        .packs
        .keys()
        .chain(manifest.assets.keys())
        .cloned()
        .collect();
    let mut start = 0;
    let mut filter = String::new();
    loop {
        let shown: Vec<_> = ids
            .iter()
            .enumerate()
            .filter(|(_, id)| id.as_str().contains(&filter))
            .collect();
        if start >= shown.len() {
            start = 0;
        }
        let end = (start + PAGE_SIZE).min(shown.len());
        let checks: Vec<_> = shown[start..end]
            .iter()
            .map(|(_, id)| super::application_readiness::inspect(root, manifest, id, args))
            .collect();
        dialog.heading(&format!(
            "Skills and packs · {}–{} of {}",
            if shown.is_empty() { 0 } else { start + 1 },
            end,
            shown.len()
        ))?;
        let mut counts = [0usize; 7];
        for check in &checks {
            use super::application_readiness::Readiness;
            counts[match check {
                Readiness::Ready => 0,
                Readiness::Current => 1,
                Readiness::NeedsReview(error) if error.code == "apply.skill_trust_required" => 2,
                Readiness::NeedsReview(error) if error.code == "apply.destination_unmanaged" => 3,
                Readiness::NeedsReview(error) if error.code == "apply.compatibility_blocked" => 4,
                Readiness::NeedsReview(_) => 5,
                Readiness::AfterSelection => 6,
            }] += 1;
        }
        let summary: Vec<_> = counts
            .into_iter()
            .zip([
                "ready",
                "already current",
                "review scripts",
                "compare existing copy",
                "incompatible",
                "need attention",
                "checked after selection",
            ])
            .filter(|(count, _)| *count > 0)
            .map(|(count, label)| format!("{count} {label}"))
            .collect();
        dialog.say(&format!("This page: {}", summary.join(" · ")))?;
        for (&(index, id), readiness) in shown[start..end].iter().zip(&checks) {
            let kind = if let Some(pack) = manifest.packs.get(id) {
                format!(
                    "Pack · {} item{}",
                    pack.members.len(),
                    if pack.members.len() == 1 { "" } else { "s" }
                )
            } else {
                format!("{:?}", manifest.assets[id].kind)
            };
            let action =
                if let super::application_readiness::Readiness::NeedsReview(error) = readiness {
                    let command = match error.code {
                        "apply.skill_trust_required" => "review",
                        "apply.destination_unmanaged" => "compare",
                        _ => "why",
                    };
                    format!(" ({command} {})", index + 1)
                } else {
                    String::new()
                };
            dialog.say(&format!(
                "  {}. {} [{}]{} · {}{action}",
                index + 1,
                safe(id.as_str()),
                kind,
                if suggested.contains(id) {
                    " · just collected"
                } else {
                    ""
                },
                readiness.label()
            ))?;
        }
        let prompt = "Which saved items would you like to add?\nready        Preview skills ready to add or update\n1,4,7        Preview specific items\nhelp         All selection commands\nEnter        Skip adding items\nq            Quit";
        let paging = match (start > 0, end < shown.len()) {
            (true, true) => "\nnext/back    Browse pages",
            (false, true) => "\nnext         Next page",
            (true, false) => "\nback         Previous page",
            (false, false) => "",
        };
        let mut response = dialog.ask(&format!("{prompt}{paging}"))?;
        while matches!(response.as_str(), "help" | "?") {
            response = dialog.ask(
                "Selection help\nready        Preview ready skills across matching pages\n             Already-current skills, packs and blocked items are left out.\n1,4,7        Preview items by their listed numbers\nall          Preview all matching items if every item passes its checks\nall,-3,-8    All matching items except 3 and 8\n/word        Filter names (/ clears the filter)\nnext/back    Browse pages without changing item numbers\nreview N     Review a skill's scripts\ncompare N    Compare a copy at the destination\nwhy N        Explain an item's status\nn            Skip\nq            Quit",
            )?;
        }
        match response.as_str() {
            "next" => {
                if end < shown.len() {
                    start = end;
                }
            }
            "back" => start = start.saturating_sub(PAGE_SIZE),
            "" | "n" => return Ok(ItemSelection::default()),
            "ready" => {
                let ready = ready_items(root, manifest, shown.iter().map(|(_, id)| *id), args);
                if !ready.is_empty() {
                    return Ok(ready.into());
                }
                dialog.say("No ready skills match this view. Choose an item by number to check it, or type / to clear the filter.")?;
            }
            value
                if value.starts_with("review ")
                    || value.starts_with("compare ")
                    || value.starts_with("why ") =>
            {
                let (action, number) = value.split_once(' ').expect("matched action prefix");
                let selected = number
                    .trim()
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|index| shown.iter().position(|(candidate, _)| *candidate == index));
                let Some(position) = selected else {
                    dialog.say("Choose one original number in this filter. No files changed.")?;
                    continue;
                };
                let (index, id) = shown[position];
                if action == "compare" {
                    super::application_readiness::compare(dialog, root, manifest, id, args)?;
                    continue;
                }
                let off_page_check;
                let check = match position
                    .checked_sub(start)
                    .and_then(|offset| checks.get(offset))
                {
                    Some(check) => check,
                    None => {
                        off_page_check =
                            super::application_readiness::inspect(root, manifest, id, args);
                        &off_page_check
                    }
                };
                match action {
                    "review" if matches!(check, super::application_readiness::Readiness::NeedsReview(error) if error.code == "apply.skill_trust_required") => return Ok(vec![id.clone()].into()),
                    "review" => dialog.say("This item has no pending script-review check. Use why N for its reason, or select its number for a full plan.")?,
                    "why" => {
                        dialog.heading(&format!("Destination check: {}", safe(id.as_str())))?;
                        dialog.say(check.label())?;
                        if let Some(description) = description(root, manifest, id) {
                            dialog.say(&description)?;
                        }
                        if let super::application_readiness::Readiness::NeedsReview(error) = check {
                            dialog.detail(&format!("{}: {}", safe(error.code), safe(&error.to_string())))?;
                            match error.code {
                                "apply.compatibility_blocked" => {
                                    super::application_preview::compatibility(dialog, manifest, &BTreeSet::from([id.clone()]), &args.targets)?;
                                    dialog.hint("Choose another tool or leave this item out. Kitrove cannot preserve its behavior for this selection.")?;
                                }
                                "apply.skill_trust_required" => dialog.hint(&format!("Use review {} to inspect the exact stored bundle. Local script approval and file placement have separate confirmations.", index + 1))?,
                                "apply.destination_unmanaged" => dialog.hint(&format!("Use compare {} to compare bundle contents. Keep the existing copy and leave this item out, or choose another destination. Kitrove does not take over existing copies.", index + 1))?,
                                _ => dialog.hint("Resolve this destination check before retrying. Selecting the item still requires a fresh full plan and confirmation.")?,
                            }
                        }
                    }
                    _ => unreachable!("matched action prefix"),
                }
            }
            value if value.starts_with('/') => {
                filter = value[1..].to_owned();
                start = 0;
            }
            value => match selection(value, ids.len()) {
                Some(indices) => {
                    let bulk = value
                        .split(',')
                        .next()
                        .is_some_and(|head| head.trim() == "all" || head.trim().starts_with('-'));
                    let indices: Vec<_> = indices
                        .into_iter()
                        .filter(|index| !bulk || shown.iter().any(|(visible, _)| visible == index))
                        .collect();
                    // Positive numbers must remain visible; bulk expressions are narrowed to the filter.
                    if indices
                        .iter()
                        .any(|index| !shown.iter().any(|(visible, _)| visible == index))
                    {
                        dialog.say("Selection includes an item hidden by the filter. Clear the filter or use shown original numbers.")?;
                    } else {
                        return Ok(ItemSelection {
                            ids: indices
                                .into_iter()
                                .map(|index| ids[index].clone())
                                .collect(),
                            bulk,
                        });
                    }
                }
                None => {
                    dialog.say("Choose ready or enter item numbers. Type help for all commands.")?
                }
            },
        }
    }
}

fn ready_items<'a>(
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    ids: impl Iterator<Item = &'a AssetId>,
    args: &MaterializeArgs,
) -> Vec<AssetId> {
    ids.filter(|id| {
        matches!(
            super::application_readiness::inspect(root, manifest, id, args),
            super::application_readiness::Readiness::Ready
        )
    })
    .cloned()
    .collect()
}

fn description(
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    id: &AssetId,
) -> Option<String> {
    if let Some(pack) = manifest.packs.get(id) {
        let names: Vec<_> = pack
            .members
            .keys()
            .take(4)
            .map(|member| safe(member.as_str()))
            .collect();
        return Some(format!(
            "Includes: {}{}",
            names.join(", "),
            if pack.members.len() > 4 { ", …" } else { "" }
        ));
    }
    if manifest.assets.get(id)?.kind != AssetKind::Skill {
        return None;
    }
    let object =
        kitrove_core::load_portable_skill_object(manifest, id, root, CaptureLimits::default())
            .ok()?;
    let document = object
        .tree()
        .files
        .get(&kitrove_model::PortablePath::parse("SKILL.md").ok()?)?;
    let parsed = kitrove_agent_skills::parse_skill_document(
        std::path::Path::new("SKILL.md"),
        &document.bytes,
    )
    .ok()?;
    Some(description_excerpt(&parsed.manifest.description))
}

fn description_excerpt(value: &str) -> String {
    let prose = value.split_whitespace().collect::<Vec<_>>().join(" ");
    prose
        .chars()
        .flat_map(|character| {
            if character.is_ascii_graphic()
                || character == ' '
                || character.is_alphanumeric()
                || matches!(character, '—' | '–' | '…' | '‘' | '’' | '“' | '”')
            {
                character.to_string()
            } else {
                character.escape_default().to_string()
            }
            .chars()
            .collect::<Vec<_>>()
        })
        .take(180)
        .collect()
}

pub(super) fn offer<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    adopted: &[AssetId],
) -> Result<(), CliError> {
    match navigation::choose(
        dialog,
        "Next: add the collected skills to a tool?",
        &[(b'a', "Choose a tool"), (b'n', "Finish collection")],
        0,
    )? {
        b'a' => apply(dialog, root, adopted),
        _ => Ok(()),
    }
}

fn choose_tools<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
) -> Result<BTreeSet<HarnessId>, CliError> {
    let choice = navigation::choose(
        dialog,
        "Which AI tools should receive these items?",
        &[
            (b'1', "Claude Code"),
            (b'2', "Codex"),
            (b'3', "Pi"),
            (b'4', "OpenCode"),
            (b'm', "Multiple tools"),
            (b'n', "Back"),
        ],
        5,
    )?;
    match choice {
        b'1'..=b'4' => Ok(BTreeSet::from([TOOLS[usize::from(choice - b'1')].clone()])),
        b'm' => {
            let labels = ["Claude Code", "Codex", "Pi", "OpenCode"].map(str::to_owned);
            Ok(dialog
                .choose("Choose tools", &labels)?
                .into_iter()
                .map(|index| TOOLS[index].clone())
                .collect())
        }
        _ => Ok(BTreeSet::new()),
    }
}

fn apply_with_preview<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    assets: &BTreeSet<AssetId>,
    args: MaterializeArgs,
    prompt_error: &mut Option<CliError>,
    preview_offered: &mut bool,
) -> Result<crate::portable::CompletedCommand, CliError> {
    let targets = args.targets.clone();
    crate::materialize::run_apply(args, |plan| {
        *preview_offered = true;
        let decision = load_manifest(root).and_then(|current| {
            if &current != manifest {
                return Err(CliError::new(
                    "apply.plan_stale",
                    "the collection changed during selection; choose items again",
                ));
            }
            super::application_preview::compatibility(dialog, manifest, assets, &targets)?;
            super::application_preview::confirm(dialog, plan)
        });
        match decision {
            Ok(yes) => yes,
            Err(error) => {
                *prompt_error = Some(error);
                false
            }
        }
    })
}

fn review_scripted_skills<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    assets: &BTreeSet<AssetId>,
) -> Result<bool, CliError> {
    let mut changed = false;
    for id in assets {
        let Some(review) = crate::trust::prepare_skill_review(root, id)? else {
            continue;
        };
        dialog.heading(&format!("Script-containing skill: {}", safe(id.as_str())))?;
        dialog.warning("The selected AI tool may run these helpers with its own permissions. Kitrove stores and copies files; it does not run them or install their runtimes. Review and approve this exact bundle separately.")?;
        dialog.hint(&format!(
            "Bundle revision:\n  {}\n{} component files",
            review.revision(),
            review.files.len()
        ))?;
        let mut start = 0;
        loop {
            let end = (start + PAGE_SIZE).min(review.files.len());
            for (offset, file) in review.files[start..end].iter().enumerate() {
                dialog.say(&format!(
                    "  {}. {} / {}\n     {:?} · {} bytes",
                    start + offset + 1,
                    safe(&file.component),
                    safe(&file.path),
                    file.mode,
                    file.bytes
                ))?;
            }
            match dialog.decision("Approve this exact bundle on this computer?\ny        Approve local placement of this version\nv        Next file page\nf        Inspect a stored file\nEnter/n  Skip this selection\nq        Quit")?.as_str() {
                "y" => { review.commit()?; changed = true; dialog.success("Exact bundle approved locally. File placement still needs its own preview and approval.")?; break; }
                "f" => inspect_review_file(dialog, &review)?,
                "v" => start = if end == review.files.len() { 0 } else { end },
                _ => return Ok(false),
            }
        }
    }
    Ok(changed)
}

fn inspect_review_file<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    review: &crate::trust::SkillReview,
) -> Result<(), CliError> {
    let number = dialog.ask("Stored file number (Enter returns):")?;
    if number.is_empty() {
        return Ok(());
    }
    let Some(index) = number
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .filter(|n| *n < review.files.len())
    else {
        return dialog.say("Choose a displayed file number. Nothing has changed.");
    };
    let Some(text) = review
        .file_bytes(index)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
    else {
        return dialog
            .say("This file is not UTF-8 text. Its byte count and hash are listed above.");
    };
    let lines: Vec<String> = text
        .lines()
        .flat_map(|line| {
            let escaped = safe(line);
            if escaped.is_empty() {
                return vec![String::new()];
            }
            escaped
                .as_bytes()
                .chunks(76)
                .map(|chunk| String::from_utf8(chunk.to_vec()).expect("escaped source is ASCII"))
                .collect()
        })
        .collect();
    let mut start = 0;
    loop {
        dialog.hint(&format!(
            "Exact stored file hash:\n  {}",
            review.files[index].hash
        ))?;
        let end = (start + 20).min(lines.len());
        dialog.heading(&format!(
            "Stored file: {} / {} · view rows {}–{}",
            safe(&review.files[index].component),
            safe(&review.files[index].path),
            if lines.is_empty() { 0 } else { start + 1 },
            end
        ))?;
        for line in &lines[start..end] {
            dialog.say(&format!("  | {line}"))?;
        }
        match dialog.decision("Inspect file\nn        Next page\nb        Previous page\nEnter    Back to approval\nq        Quit")?.as_str() {
            "n" if end < lines.len() => start = end,
            "b" => start = start.saturating_sub(20),
            "n" => {},
            _ => return Ok(()),
        }
    }
}

#[cfg(test)]
mod description_tests {
    use super::description_excerpt;

    #[test]
    fn readable_prose_preserves_quotes_and_accents_but_escapes_terminal_controls() {
        assert_eq!(
            description_excerpt("Brandon's \"café\" — review.\nNext\tline."),
            "Brandon's \"café\" — review. Next line."
        );
        let hostile = description_excerpt("Skill\x1b[2J\u{202e}fake\u{200b}prompt\n? y");
        assert!(
            !hostile.contains('\x1b')
                && !hostile.contains('\u{202e}')
                && !hostile.contains('\u{200b}')
                && !hostile.contains('\n')
        );
        assert!(hostile.contains(r"\u{1b}") && hostile.contains(r"\u{202e}"));
        assert_eq!(description_excerpt(&"a".repeat(200)).chars().count(), 180);
    }
}
