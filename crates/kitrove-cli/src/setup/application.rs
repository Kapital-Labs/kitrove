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

pub(super) fn apply<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    suggested: &[AssetId],
) -> Result<(), CliError> {
    let manifest = load_manifest(root)?;
    if manifest.assets.is_empty() && manifest.packs.is_empty() {
        return dialog.say("Your collection is empty. Add skills from this computer first.");
    }
    dialog.hint(
        "Run kitrove apply to return here directly. Add skills or packs to tools on this computer. This does not run collected items or synchronize your collection.",
    )?;
    let targets = choose_tools(dialog)?;
    if targets.is_empty() {
        return Ok(());
    }
    if targets.contains(&HarnessId::Codex) {
        dialog.hint("Codex's skills folder is shared: Pi and OpenCode may also discover those files. Choosing a destination does not make a skill exclusive to that tool.")?;
    }
    if targets.contains(&HarnessId::Claude) {
        dialog.hint("OpenCode may also discover Claude's skills folder. Choosing a destination does not make a skill exclusive to that tool.")?;
    }
    let (scope, project_root) = match dialog.decision(
        "Where should these items be available?\n1. All projects on this computer\n2. This project only\nEnter/n  Not now\nq        Quit", b"12n", true)?.as_str() {
        "1" => (HarnessScope::User, None),
        "2" => {
            let path = dialog.ask("Absolute project folder path (Enter skips):")?;
            if path.is_empty() { return Ok(()); }
            let path = PathBuf::from(path);
            if !path.is_absolute() { return Err(CliError::new("setup.project_path_invalid", "choose an absolute project folder path")); }
            (HarnessScope::Project, Some(path))
        }
        _ => return Ok(()),
    };
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
    loop {
        let manifest = load_manifest(root)?;
        let mut args = destination_args.clone();
        let ids = choose_items(dialog, root, &manifest, suggested, &args)?;
        if ids.is_empty() {
            return Ok(());
        }
        dialog.say(&format!("Selected {} saved item(s). Checking the complete selection; one blocked item stops the batch.", ids.len()))?;
        for id in ids {
            if manifest.packs.contains_key(&id) {
                args.packs.insert(id);
            } else {
                args.assets.insert(id);
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
        super::application_preview::compatibility(dialog, &manifest, &assets, &args.targets)?;
        let mut prompt_error = None;
        let mut result =
            apply_with_preview(dialog, root, &manifest, args.clone(), &mut prompt_error);
        if result
            .as_ref()
            .is_err_and(|error| error.code == "apply.skill_trust_required")
        {
            if !review_scripted_skills(dialog, root, &assets)? {
                return dialog.say(
                    "Selection was not applied. Earlier explicit local approvals remain saved.",
                );
            }
            result = apply_with_preview(dialog, root, &manifest, args, &mut prompt_error);
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
                dialog.outcome(&serde_json::json!({"Destinations completed":count,"Inspect collection":"kitrove status"}).to_string())
            }
            Err(error) if error.code == "apply.confirmation_required" => {
                dialog.say("Application skipped.")
            }
            Err(error) if error.code == "apply.compatibility_blocked" => {
                dialog.warning("Selection not applied. Some selected skills cannot be transferred faithfully to these tools. Review the reasons above.")?;
                dialog.hint("Choose ready for compatible additions. Use why N to explain an incompatible item, review N for scripts, or compare N for an existing copy. All keeps blocked items in the selection.")?;
                match dialog.decision("Choose different items?\nEnter/s  Choose different items\nn        Return to setup\nq        Quit", b"sn", true)?.as_str() {
                    "" | "s" => continue,
                    _ => Ok(()),
                }
            }
            Err(error) => Err(error),
        };
    }
}

fn choose_items<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    suggested: &[AssetId],
    args: &MaterializeArgs,
) -> Result<Vec<AssetId>, CliError> {
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
        dialog.hint("Selections use all matching pages. Ready checks this destination folder; tools may find other copies. All does not bypass checks; one blocked item stops the batch.")?;
        let enter = if suggested.is_empty() {
            "Skip"
        } else {
            "Select just-collected items (may need review)"
        };
        let response = dialog.ask(&format!("Which saved items would you like to add?\n1,4,7        Select original numbers\nready        Skills ready to add or update (recommended)\nall          Every matching item, including blocked items\nreview N     Review scripts\ncompare N    Compare existing copy (read-only)\nwhy N        Explain incompatibility / show description\nall,-3,-8    Every matching item except these numbers\n/word        Filter names (/ clears)\nnext/back    Browse pages\nEnter        {enter}\nn            Skip\nq            Quit"))?;
        match response.as_str() {
            "next" => {
                if end < shown.len() {
                    start = end;
                }
            }
            "back" => start = start.saturating_sub(PAGE_SIZE),
            "" => {
                return Ok(ids
                    .iter()
                    .filter(|id| suggested.contains(id) && id.as_str().contains(&filter))
                    .cloned()
                    .collect());
            }
            "n" => return Ok(Vec::new()),
            "ready" => {
                let ready: Vec<_> = shown
                    .iter()
                    .enumerate()
                    .filter(|(position, (_, id))| {
                        let page_check = position
                            .checked_sub(start)
                            .and_then(|offset| checks.get(offset));
                        match page_check {
                            Some(check) => {
                                matches!(check, super::application_readiness::Readiness::Ready)
                            }
                            None => matches!(
                                super::application_readiness::inspect(root, manifest, id, args),
                                super::application_readiness::Readiness::Ready
                            ),
                        }
                    })
                    .map(|(_, (_, id))| (*id).clone())
                    .collect();
                if !ready.is_empty() {
                    dialog.say(&format!("Selected {} ready skill(s). Review the full preview before approving placement.", ready.len()))?;
                    return Ok(ready);
                }
                dialog.say("No ready skills in this filter. Version-gated items and packs need an explicit selection; no files changed.")?;
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
                    "review" if matches!(check, super::application_readiness::Readiness::NeedsReview(error) if error.code == "apply.skill_trust_required") => return Ok(vec![id.clone()]),
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
                        return Ok(indices
                            .into_iter()
                            .map(|index| ids[index].clone())
                            .collect());
                    }
                }
                None => {
                    dialog.say("Choose displayed numbers, all,-3,-8, a filter or next/back.")?
                }
            },
        }
    }
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
    match dialog.decision("Next: add the collected skills to a tool?\na        Choose a tool\nEnter/n  Finish collection\nq        Quit", b"an", true)?.as_str() {
        "a" => apply(dialog, root, adopted),
        _ => Ok(()),
    }
}

fn choose_tools<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
) -> Result<BTreeSet<HarnessId>, CliError> {
    loop {
        let response = dialog.decision("Which AI tools should receive these items?\n1. Claude Code\n2. Codex\n3. Pi\n4. OpenCode\nm        Multiple tools\nEnter/n  Skip\nq        Quit", b"1234mn", true)?;
        match response.as_str() {
            "" | "n" => return Ok(BTreeSet::new()),
            "m" => {
                let labels = ["Claude Code", "Codex", "Pi", "OpenCode"].map(str::to_owned);
                return Ok(dialog
                    .choose("Choose tools", &labels)?
                    .into_iter()
                    .map(|index| TOOLS[index].clone())
                    .collect());
            }
            "1" | "2" | "3" | "4" => {
                let index = response.as_bytes()[0] - b'1';
                return Ok(BTreeSet::from([TOOLS[usize::from(index)].clone()]));
            }
            _ => dialog.say("Choose a displayed tool, m for several, or n to skip.")?,
        }
    }
}

fn apply_with_preview<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    args: MaterializeArgs,
    prompt_error: &mut Option<CliError>,
) -> Result<crate::portable::CompletedCommand, CliError> {
    crate::materialize::run_apply(args, |plan| {
        let decision = load_manifest(root).and_then(|current| {
            if &current != manifest {
                return Err(CliError::new(
                    "apply.plan_stale",
                    "the collection changed during selection; choose items again",
                ));
            }
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
            match dialog.decision("Approve this exact bundle on this computer?\ny        Approve local placement of this version\nv        Next file page\nf        Inspect a stored file\nEnter/n  Skip this selection\nq        Quit", b"yvfn", true)?.as_str() {
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
        match dialog.decision("Inspect file\nn        Next page\nb        Previous page\nEnter    Back to approval\nq        Quit", b"nb", true)?.as_str() {
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
