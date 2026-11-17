//! Human presentation of existing plans, fidelity and read-only discovery observations.
use super::*;
use kitrove_model::EnvironmentManifest;
use serde_json::Value;

fn plan_items(value: &Value) -> Vec<&Value> {
    value
        .get("items")
        .and_then(Value::as_array)
        .map_or_else(|| vec![value], |items| items.iter().collect())
}

fn page<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    items: &[&Value],
) -> Result<(), CliError> {
    for item in items {
        let action = match item["disposition"].as_str().unwrap_or("") {
            "install" => "Add",
            "no_op" => "Already current (managed)",
            "restore" => "Restore managed copy",
            "managed_update" => "Update managed copy",
            _ => "Review",
        };
        let id = item["asset_id"].as_str().unwrap_or("shared document");
        let tool = item["target"].as_str().unwrap_or("");
        let destination = item["destination"]
            .as_str()
            .or_else(|| item["relative_destination"].as_str())
            .unwrap_or("see full details");
        dialog.say(&format!(
            "  {action}: {} {}\n    {}",
            safe(id),
            safe(tool),
            safe(destination)
        ))?;
        if let Some(effect) = item["effect"].as_str() {
            dialog.warning(&safe(effect))?;
        }
        for key in ["entries", "regions"] {
            if let Some(entries) = item[key].as_array() {
                for entry in entries {
                    let operation = entry["operation"]
                        .as_str()
                        .or_else(|| entry["disposition"].as_str())
                        .unwrap_or("review");
                    let targets = entry["target"].as_str().map(safe).unwrap_or_else(|| {
                        entry["targets"]
                            .as_array()
                            .map_or_else(String::new, |values| {
                                values
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(safe)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                    });
                    let native = entry["native_name"]
                        .as_str()
                        .map_or_else(String::new, |name| format!(" [{}]", safe(name)));
                    dialog.detail(&format!(
                        "    {}: {}{native} → {targets}",
                        safe(operation),
                        safe(entry["asset_id"].as_str().unwrap_or("item"))
                    ))?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn confirm<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    encoded: &str,
) -> Result<bool, CliError> {
    let value: Value = serde_json::from_str(encoded).map_err(|_| io_error())?;
    let items = plan_items(&value);
    // Connection effects stay visible even if their document is on a later page.
    let mut removals = 0;
    for item in &items {
        if let Some(effect) = item["effect"].as_str() {
            dialog.warning(&safe(effect))?;
        }
        for key in ["regions", "entries"] {
            if let Some(entries) = item[key].as_array() {
                removals += entries
                    .iter()
                    .filter(|entry| {
                        entry["operation"].as_str() == Some("remove")
                            || entry["disposition"].as_str() == Some("remove")
                    })
                    .count();
            }
        }
    }
    if removals > 0 {
        dialog.warning(&format!("This plan removes {removals} previously managed regions or entries as part of the update. Review the pages or full plan details before approving."))?;
    }
    let mut start = 0;
    loop {
        let end = (start + 12).min(items.len());
        dialog.heading("Add to tools — preview (no writes)")?;
        dialog.say(&format!(
            "{} destinations · showing {}–{end}",
            items.len(),
            if items.is_empty() { 0 } else { start + 1 }
        ))?;
        page(dialog, &items[start..end])?;
        match dialog.decision(&format!("Add the previewed items?\ny        Approve all {} destinations\nd        Full plan details\n] / [    Next / previous page\nEnter/n  Skip\nq        Quit", items.len()), b"ydn[]", true)?.as_str() {
            "y" | "yes" => return Ok(true),
            "" | "n" | "no" => return Ok(false),
            "d" => dialog.summary(encoded)?,
            "]" => { if end < items.len() { start = end; } },
            "[" => start = start.saturating_sub(12),
            _ => dialog.say("Choose y, d, a page key or n. Nothing has changed.")?,
        }
    }
}

pub(super) fn compatibility<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    manifest: &EnvironmentManifest,
    assets: &BTreeSet<AssetId>,
    targets: &BTreeSet<HarnessId>,
) -> Result<(), CliError> {
    for id in assets {
        for target in targets {
            if let Some(result) = manifest.assets[id].compatibility.get(target)
                && (!matches!(
                    result.fidelity(),
                    kitrove_model::Fidelity::Native | kitrove_model::Fidelity::Portable
                ) || !result.reasons().is_empty())
            {
                dialog.say(&format!(
                    "Collection fidelity: {} → {}: {:?}",
                    safe(id.as_str()),
                    target.as_str(),
                    result.fidelity()
                ))?;
                for reason in result.reasons() {
                    dialog.detail(&format!(
                        "  {}: {}",
                        safe(&reason.code),
                        safe(&reason.message)
                    ))?;
                }
            }
        }
    }
    Ok(())
}

pub(super) fn discovery<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    assets: &BTreeSet<AssetId>,
    args: &MaterializeArgs,
) -> Result<(), CliError> {
    let report = match scan_report(ScanArgs { harnesses: args.targets.clone(),
        scope: if args.scope == HarnessScope::Project { ScopeSelection::Project } else { ScopeSelection::User },
        project_root: args.project_root.clone(), roots: Vec::new(), environment: Some(root.to_owned()), json: false, verbose: false }, &crate::registry::try_tier_one_registry().map_err(|_| io_error())?) {
        Ok(report) => report,
        Err(error) => return dialog.warning(&format!("Other discovery locations were not verified [{}]. The exact destination plan still governs writes.", error.code)),
    };
    let observations: Vec<_> = assets
        .iter()
        .filter_map(|id| {
            if manifest.assets[id].kind != kitrove_model::AssetKind::Skill {
                return None;
            }
            let count = report
                .entries
                .iter()
                .filter(|entry| {
                    name(entry) == id.as_str()
                        && !(entry.classification
                            == kitrove_core::ScanClassification::ManagedUnchanged
                            && entry.asset_id.as_ref() == Some(id))
                })
                .count();
            (count > 0).then_some((id, count))
        })
        .collect();
    if !observations.is_empty() {
        dialog.warning(&format!("{} selected skill names were also observed in the selected tools' search locations. New copies may shadow or coexist with another copy; names do not prove equal contents or Kitrove ownership.", observations.len()))?;
        for (id, count) in observations.iter().take(12) {
            dialog.say(&format!(
                "  {}: {count} same-name observations",
                safe(id.as_str())
            ))?;
        }
        if observations.len() > 12 {
            dialog.hint("Showing the first 12 names. Use scan --verbose with the same tool and scope for full discovery details.")?;
        }
    }
    dialog.hint("Discovery is a filesystem observation. Tool settings, permissions, precedence and project trust may affect which copy loads.")
}
