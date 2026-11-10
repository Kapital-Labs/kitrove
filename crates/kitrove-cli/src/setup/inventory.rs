//! Read-only navigation of the scan already captured by the CLI.
use std::fmt::Write as _;
use std::io;

use kitrove_core::{ScanClassification, ScanEntry, ScanReport};

use super::{Dialog, PromptInput, cancelled};
use crate::args::CliError;
use crate::scan_display::{diagnostics, selectable, write_entry};

const PAGE_SIZE: usize = 12;

pub(crate) fn browse_scan(report: &ScanReport) -> Result<(), CliError> {
    let mut dialog = Dialog::terminal();
    match browse(&mut dialog, report) {
        Ok(()) => {}
        Err(error) if error.code == cancelled().code => {}
        Err(_) => return Err(terminal_error()),
    }
    dialog
        .say(
            "No files changed. To collect skills, use kitrove configure for an existing collection or kitrove init for a new one.",
        )
        .map_err(|_| terminal_error())
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
) -> Result<(), CliError> {
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
    let groups = [
        (b'1', "Available to add", available),
        (b'2', "Needs review", review),
        (b'3', "Managed, unchanged", managed),
    ];
    dialog.heading("Kitrove inventory (read-only)")?;
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
    menu.push_str("\nd        Scan diagnostics\nEnter/q  Finish");

    loop {
        let answer = dialog.decision(&menu, &keys, true)?;
        match answer.as_bytes() {
            [] => return Ok(()),
            [b'd'] => {
                dialog.heading("Scan diagnostics")?;
                dialog.say(diagnostics(report).trim_end())?;
                dialog.hint("For the full report, run scan --verbose or scan --json.")?;
            }
            choice => {
                if let Some((key, label, entries)) =
                    groups.iter().find(|(key, _, _)| choice == [*key])
                {
                    browse_group(dialog, label, entries, *key == b'2')?;
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
) -> Result<(), CliError> {
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
        menu.push_str("\nEnter/b  Back\nq        Finish");
        match dialog.decision(&menu, &keys, true)?.as_str() {
            "n" => start = end,
            "p" => start -= PAGE_SIZE,
            _ => return Ok(()),
        }
    }
}
