//! Read-only inventory navigation with an explicit handoff to guided collection.
use std::io;

use kitrove_core::{PolicyRegistry, ScanClassification, ScanEntry, ScanReport};

use super::{
    Dialog, PromptInput, cancelled, collection, default_collection, initialization, navigation,
};
use crate::args::{CliError, ScanArgs};
use crate::scan::{report_needs_attention, resolve_required_environment_root, scan_report};
use crate::scan_display::{diagnostics, folder_issue, selectable, write_entry, write_folder_issue};

const PAGE_SIZE: usize = 12;

pub(crate) fn browse_scan(
    initial: &ScanReport,
    selection: &ScanArgs,
    registry: &PolicyRegistry,
) -> Result<u8, CliError> {
    let mut dialog = Dialog::terminal();
    let mut refreshed = None;
    loop {
        let report = refreshed.as_ref().unwrap_or(initial);
        let status = if report_needs_attention(report) { 3 } else { 0 };
        let action = match browse(&mut dialog, report) {
            Ok(action) => action,
            Err(error) if error.code == cancelled().code => Action::Finish,
            Err(_) => return Err(terminal_error()),
        };
        match action {
            Action::Retry => {
                dialog.hint("Scanning again with the same folders and filters...")?;
                refreshed = Some(scan_report(selection.clone(), registry)?);
            }
            Action::Finish => {
                dialog
                    .say("No files changed.")
                    .map_err(|_| terminal_error())?;
                return Ok(status);
            }
            Action::Collect => {
                dialog.hint("Add copies to your Kitrove collection. Your tool files stay in place; apply and sync are separate.")?;
                match collect_scanned(&mut dialog, report, selection, registry) {
                    Ok(()) => dialog.hint("Collection step finished. Tool installation and sync require separate approvals.")?,
                    Err(error) => {
                        dialog.hint("Previously confirmed steps are retained. No later step ran.")?;
                        if error.code != cancelled().code { return Err(error); }
                    }
                }
                return Ok(status);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Action {
    Finish,
    Retry,
    Collect,
}

fn collect_scanned(
    dialog: &mut Dialog<impl PromptInput, impl io::Write>,
    report: &ScanReport,
    selection: &ScanArgs,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    let suggestion = match resolve_required_environment_root(selection.environment.as_deref()) {
        Ok(root) => root,
        Err(error) if error.code == "cli.environment_missing" => default_collection()?,
        Err(error) => return Err(error),
    };
    let Some((root, _)) = initialization::select_with_suggestion(dialog, registry, suggestion)?
    else {
        return Ok(());
    };
    let adopted = collection::collect_report(dialog, &root, registry, report, selection)?;
    if adopted.is_empty() {
        return Ok(());
    }
    super::application::offer(dialog, &root, &adopted)
}

fn terminal_error() -> CliError {
    CliError::new(
        "scan.terminal_failed",
        "the scan menu could not safely read input or write output; try scan --verbose",
    )
}

fn browse(
    dialog: &mut Dialog<impl PromptInput, impl io::Write>,
    report: &ScanReport,
) -> Result<Action, CliError> {
    let mut available = Vec::new();
    let mut review = Vec::new();
    let mut managed = Vec::new();
    let mut issues = Vec::new();
    for entry in &report.entries {
        if folder_issue(entry) {
            issues.push(entry);
        } else if selectable(entry) {
            available.push(entry);
        } else if entry.classification == ScanClassification::ManagedUnchanged
            && entry.shadowed_by.is_none()
        {
            managed.push(entry);
        } else {
            review.push(entry);
        }
    }
    let can_collect = !available.is_empty();
    let groups = [
        (b'1', "Ready to preview", available),
        (b'2', "Skills needing review", review),
        (b'3', "Managed, unchanged", managed),
    ];
    dialog.heading("Kitrove inventory")?;
    let count = report.entries.len() - issues.len();
    let noun = if count == 1 { "skill" } else { "skills" };
    dialog.say(&format!("{count} {noun} listed"))?;
    if !issues.is_empty() {
        dialog.warning(&format!(
            "{} folder scan issues. The inventory is incomplete.",
            issues.len()
        ))?;
        if count == 0 {
            dialog.hint("No skills could be listed. View scan issues for the next step.")?;
        }
    }
    dialog.hint("Browsing makes no changes. Adding skills requires a preview and confirmation.")?;

    let mut choices = Vec::new();
    for (key, label, entries) in &groups {
        if !entries.is_empty() {
            choices.push((*key, format!("{label} ({})", entries.len())));
        }
    }
    if !issues.is_empty() {
        choices.push((b'i', format!("View scan issues ({})", issues.len())));
    }
    if can_collect {
        choices.push((b'a', "Add skills to collection".to_owned()));
    }
    choices.extend([
        (b'r', "Scan again".to_owned()),
        (b'd', "View diagnostics".to_owned()),
        (b'q', "Quit".to_owned()),
    ]);
    let default = if count == 0 && issues.is_empty() {
        choices.len() - 1
    } else {
        0
    };
    loop {
        match navigation::choose(dialog, "Next action", &choices, default)? {
            b'q' => return Ok(Action::Finish),
            b'a' => return Ok(Action::Collect),
            b'r' => return Ok(Action::Retry),
            b'i' => {
                dialog.heading("Scan issues")?;
                for entry in &issues {
                    let mut text = String::new();
                    write_folder_issue(&mut text, entry);
                    dialog.say(text.trim_end())?;
                }
                dialog.hint("Keep any --root or --project-root options when checking details.")?;
                dialog.hint("For another location, use --root TOOL:SCOPE:/absolute/path/to/skills. Kitrove will not change permissions or follow links.")?;
                match navigation::choose(
                    dialog,
                    "After checking the folder",
                    &[
                        (b'b', "Back".to_owned()),
                        (b'r', "Scan again".to_owned()),
                        (b'q', "Quit".to_owned()),
                    ],
                    0,
                )? {
                    b'r' => return Ok(Action::Retry),
                    b'q' => return Ok(Action::Finish),
                    _ => {}
                }
            }
            b'd' => {
                dialog.heading("Scan diagnostics")?;
                dialog.say(diagnostics(report).trim_end())?;
                dialog.hint(
                    "For the full report, run kitrove scan --verbose or kitrove scan --json.",
                )?;
            }
            choice => {
                if let Some((key, label, entries)) =
                    groups.iter().find(|(key, _, _)| choice == *key)
                    && browse_group(dialog, label, entries, *key == b'2', *key == b'1')?
                {
                    return Ok(Action::Collect);
                }
            }
        }
    }
}

fn browse_group(
    dialog: &mut Dialog<impl PromptInput, impl io::Write>,
    label: &str,
    entries: &[&ScanEntry],
    show_status: bool,
    can_collect: bool,
) -> Result<bool, CliError> {
    let mut start = 0;
    loop {
        let end = (start + PAGE_SIZE).min(entries.len());
        dialog.heading(&format!(
            "{label} · {}–{end} of {}",
            start + 1,
            entries.len()
        ))?;
        let mut rows = String::new();
        for entry in &entries[start..end] {
            write_entry(&mut rows, entry, show_status);
        }
        dialog.say(rows.trim_end())?;
        if can_collect {
            dialog.hint("These sources can be previewed. Existing collection names and blockers are checked next.")?;
        } else if show_status {
            dialog.hint("These skills need attention before they can be collected. View diagnostics for details.")?;
        }
        let mut choices = vec![(b'b', "Back".to_owned())];
        if end < entries.len() {
            choices.push((b'n', "Next page".to_owned()));
        }
        if start > 0 {
            choices.push((b'p', "Previous page".to_owned()));
        }
        if can_collect {
            choices.push((b'a', "Add skills to collection".to_owned()));
        }
        choices.push((b'q', "Quit".to_owned()));
        match navigation::choose(dialog, "Browse skills", &choices, 0)? {
            b'n' => start = end,
            b'p' => start -= PAGE_SIZE,
            b'a' => return Ok(true),
            b'q' => return Err(cancelled()),
            _ => return Ok(false),
        }
    }
}
