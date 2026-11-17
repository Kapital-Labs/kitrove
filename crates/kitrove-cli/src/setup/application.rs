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
        "Add collection items to tools on this computer. This does not run collected items or synchronize your collection.",
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
    let mut args = MaterializeArgs {
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
    let ids = choose_items(dialog, root, &manifest, suggested, &args)?;
    if ids.is_empty() {
        return Ok(());
    }
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
    // Skill-only readiness uses the real destination planner, never cached compatibility as permission.
    if assets
        .iter()
        .all(|id| manifest.assets[id].kind == AssetKind::Skill)
    {
        let mut blocked = false;
        let mut ready = 0;
        dialog.heading("Destination check (no writes)")?;
        for id in &assets {
            let one = MaterializeArgs {
                profile: None,
                assets: BTreeSet::from([id.clone()]),
                packs: BTreeSet::new(),
                targets: args.targets.clone(),
                scope,
                project_root: args.project_root.clone(),
                version_binaries: Vec::new(),
                environment: Some(root.to_owned()),
                json: true,
            };
            match crate::materialize::run_plan(one) {
                Ok(_) => ready += 1,
                Err(error) => {
                    blocked = true;
                    dialog.warning(&format!(
                        "Needs review: {} — {} [{}]",
                        safe(id.as_str()),
                        safe(&error.to_string()),
                        error.code
                    ))?;
                }
            }
        }
        dialog.say(&format!("{ready} selected skills passed the destination check. The exact combined plan follows before any approval."))?;
        if blocked {
            return dialog.hint("No items were added. Choose different items or resolve the reported destination conflict, then preview again. Existing files are not overwritten.");
        }
    }
    super::application_preview::discovery(dialog, root, &manifest, &assets, &args)?;
    super::application_preview::compatibility(dialog, &manifest, &assets, &args.targets)?;
    let mut prompt_error = None;
    let result = crate::materialize::run_apply(args, |plan| {
        let decision = load_manifest(root).and_then(|current| {
            if current != manifest {
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
                prompt_error = Some(error);
                false
            }
        }
    });
    if let Some(error) = prompt_error {
        return Err(error);
    }
    match result {
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
        Err(error) => Err(error),
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
        .assets
        .keys()
        .chain(manifest.packs.keys())
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
        dialog.heading(&format!(
            "Saved items · {}–{} of {}",
            if shown.is_empty() { 0 } else { start + 1 },
            end,
            shown.len()
        ))?;
        for &(index, id) in &shown[start..end] {
            let kind = manifest
                .assets
                .get(id)
                .map_or("Pack".to_owned(), |asset| format!("{:?}", asset.kind));
            dialog.say(&format!(
                "  {}. {} [{}]{}",
                index + 1,
                safe(id.as_str()),
                kind,
                if suggested.contains(id) {
                    " · just collected"
                } else {
                    ""
                }
            ))?;
            let readiness = super::application_readiness::inspect(root, manifest, id, args);
            dialog.say(&format!("     {}", readiness.label()))?;
            if let super::application_readiness::Readiness::NeedsReview(error) = readiness {
                dialog.hint(&format!("     {}", safe(&error.to_string())))?;
            }
            if let Some(description) = description(root, manifest, id) {
                dialog.hint(&format!("     {description}"))?;
            }
        }
        let enter = if suggested.is_empty() {
            "Skip"
        } else {
            "Select just-collected items"
        };
        let response = dialog.ask(&format!("Which saved items would you like to add?\n1,4,7        Select original numbers\nall,-3,-8    All listed items except these\nready        Only skills ready to add/update\n/word        Filter names (/ clears)\nnext/back    Browse pages\nEnter        {enter}\nn            Skip\nq            Quit"))?;
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
                    .filter(|(_, id)| {
                        matches!(
                            super::application_readiness::inspect(root, manifest, id, args),
                            super::application_readiness::Readiness::Ready
                        )
                    })
                    .map(|(_, id)| (*id).clone())
                    .collect();
                if !ready.is_empty() {
                    return Ok(ready);
                }
                dialog.say("No ready skills in this filter. Version-gated items and packs need an explicit selection; no files changed.")?;
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
    Some(
        safe(&parsed.manifest.description)
            .chars()
            .take(180)
            .collect(),
    )
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
