//! Read-only inventory navigation with an explicit handoff to guided collection.
use std::fmt::Write as _;
use std::io;

use kitrove_core::{PolicyRegistry, ScanClassification, ScanEntry, ScanReport};

use super::{Dialog, PromptInput, cancelled, collection, default_collection, initialization};
use crate::args::{CliError, ScanArgs};
use crate::scan::resolve_required_environment_root;
use crate::scan_display::{diagnostics, selectable, write_entry};

const PAGE_SIZE: usize = 12;

pub(crate) fn browse_scan(
    report: &ScanReport,
    selection: &ScanArgs,
    registry: &PolicyRegistry,
) -> Result<(), CliError> {
    let mut dialog = Dialog::terminal();
    let collect = match browse(&mut dialog, report) {
        Ok(collect) => collect,
        Err(error) if error.code == cancelled().code => false,
        Err(_) => return Err(terminal_error()),
    };
    if !collect {
        return dialog
            .say("No files changed.")
            .map_err(|_| terminal_error());
    }
    dialog.hint("Add copies to your Kitrove collection. Your tool files stay in place; apply and sync are separate.")?;
    let result = collect_scanned(&mut dialog, report, selection, registry);
    match result {
        Ok(()) => dialog.hint(
            "Collection step finished. Tool installation and sync require separate approvals.",
        ),
        Err(error) => {
            dialog.hint("Previously confirmed steps are retained. No later step ran.")?;
            if error.code == cancelled().code {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
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
) -> Result<bool, CliError> {
    let mut available = Vec::new();
    let mut review = Vec::new();
    let mut managed = Vec::new();
    for entry in &report.entries {
        if selectable(entry) {
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
        (b'2', "Needs review", review),
        (b'3', "Managed, unchanged", managed),
    ];
    dialog.heading("Kitrove inventory")?;
    dialog.hint(
        "Browsing makes no changes. Adding skills requires a collection preview and confirmation.",
    )?;
    let count = report.entries.len();
    let noun = if count == 1 { "skill" } else { "skills" };
    dialog.say(&format!("{count} {noun} in the inventory"))?;

    let mut menu = String::from("Explore the inventory");
    let mut keys = vec![b'd'];
    for (key, label, entries) in &groups {
        if !entries.is_empty() {
            keys.push(*key);
            write!(
                menu,
                "\n{}        {label} ({})",
                char::from(*key),
                entries.len()
            )
            .expect("string write");
        }
    }
    if can_collect {
        keys.push(b'a');
        menu.push_str("\na        Add to collection");
    }
    menu.push_str("\nd        Scan diagnostics\nEnter/q  Finish");

    loop {
        let answer = dialog.decision(&menu, &keys, true)?;
        match answer.as_bytes() {
            [] => return Ok(false),
            [b'a'] => return Ok(true),
            [b'd'] => {
                dialog.heading("Scan diagnostics")?;
                dialog.say(diagnostics(report).trim_end())?;
                dialog.hint("For the full report, run scan --verbose or scan --json.")?;
            }
            choice => {
                if let Some((key, label, entries)) =
                    groups.iter().find(|(key, _, _)| choice == [*key])
                    && browse_group(dialog, label, entries, *key == b'2', *key == b'1')?
                {
                    return Ok(true);
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
        }
        let mut menu = String::from("Browse skills");
        let mut keys = vec![b'b'];
        if end < entries.len() {
            menu.push_str("\nn        Next page");
            keys.push(b'n');
        }
        if start > 0 {
            menu.push_str("\np        Previous page");
            keys.push(b'p');
        }
        if can_collect {
            keys.push(b'a');
            menu.push_str("\na        Add to collection");
        }
        menu.push_str("\nEnter/b  Back\nq        Finish");
        match dialog.decision(&menu, &keys, true)?.as_str() {
            "n" => start = end,
            "p" => start -= PAGE_SIZE,
            "a" => return Ok(true),
            _ => return Ok(false),
        }
    }
}
