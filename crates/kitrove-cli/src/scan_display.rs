//! Human presentation only. Observation identity and capture policy stay in core.
use std::collections::BTreeMap;
use std::fmt::Write as _;

use kitrove_core::{ScanClassification, ScanEntry, ScanReport};

use crate::args::CliError;

pub(crate) fn safe(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

pub(crate) fn name(entry: &ScanEntry) -> &str {
    entry
        .native_id
        .as_deref()
        .or(entry.source_relative_path.as_deref())
        .unwrap_or("(missing)")
}

pub(crate) fn selectable(entry: &ScanEntry) -> bool {
    entry.classification == ScanClassification::Unmanaged
        && entry.portable_hash.is_some()
        && entry.observation_id.is_some()
        && entry.shadowed_by.is_none()
}

pub(crate) fn resolve_skill_name(report: &ScanReport, selection: &str) -> Result<String, CliError> {
    // Exact identifiers for all existing capability types retain their old meaning.
    if selection
        .strip_prefix("observation-")
        .or_else(|| selection.strip_prefix("blake3:"))
        .is_some_and(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Ok(selection.to_owned());
    }
    let mut matches = report
        .entries
        .iter()
        .filter(|entry| name(entry) == selection);
    let first = matches.next().ok_or_else(|| {
        CliError::new(
            "adoption.name_missing",
            "no skill has that exact name; scan again or select an observation ID",
        )
    })?;
    if matches.next().is_some() {
        return Err(CliError::new(
            "adoption.name_ambiguous",
            "more than one skill has that name; narrow --harness/--scope/--root or use an observation ID from scan --verbose",
        ));
    }
    first
        .observation_id
        .as_ref()
        .map(|id| id.as_str().to_owned())
        .ok_or_else(|| {
            CliError::new(
                "adoption.name_unavailable",
                "the named skill has no current readable observation; inspect scan --verbose",
            )
        })
}

pub(crate) fn render(report: &ScanReport) -> String {
    let mut out = String::from("Kitrove inventory (read-only)\n\n");
    for entry in &report.entries {
        let state = if entry.shadowed_by.is_some() {
            "shadowed"
        } else {
            match entry.classification {
                ScanClassification::Unmanaged if selectable(entry) => "available to add",
                ScanClassification::Unmanaged => "needs portability review",
                ScanClassification::ManagedUnchanged => "managed, unchanged",
                ScanClassification::ManagedModified => "managed, locally changed",
                ScanClassification::MissingManaged => "managed, missing",
                ScanClassification::ConflictingDuplicate => "conflicting duplicate",
                ScanClassification::Unknown => "needs attention",
            }
        };
        writeln!(
            out,
            "  {}  [{} / {:?}]  {state}",
            safe(name(entry)),
            entry.harness.as_str(),
            entry.scope
        )
        .expect("string write");
        for finding in &entry.findings {
            writeln!(out, "    {}", description(finding.code)).expect("string write");
        }
    }
    writeln!(
        out,
        "\n{} skills observed; {} available to add. Destination compatibility is checked by plan.",
        report.entries.len(),
        report.entries.iter().filter(|e| selectable(e)).count()
    )
    .expect("string write");
    writeln!(out, "Other observations: {} commands, {} agents, {} extensions, {} instruction entries, {} MCP entries, {} related entries.", report.prompt_commands.len(), report.agents.len(), report.native_extensions.len(), report.instructions.len(), report.mcp_servers.len(), report.related.len()).expect("string write");
    let mut counts = BTreeMap::<&str, usize>::new();
    for finding in report
        .findings
        .iter()
        .chain(report.entries.iter().flat_map(|e| &e.findings))
        .chain(report.related.iter().flat_map(|e| &e.findings))
        .chain(report.instructions.iter().flat_map(|e| &e.findings))
        .chain(report.mcp_servers.iter().flat_map(|e| &e.findings))
        .chain(report.prompt_commands.iter().flat_map(|e| &e.findings))
        .chain(report.agents.iter().flat_map(|e| &e.findings))
        .chain(report.native_extensions.iter().flat_map(|e| &e.findings))
    {
        *counts.entry(finding.code).or_default() += 1;
    }
    if !counts.is_empty() {
        out.push_str("\nFindings (grouped):\n");
        for (code, count) in counts {
            let explanation = description(code);
            writeln!(out, "  {count} x {explanation}").expect("string write");
        }
    }
    out.push_str("\nNo files changed. Use scan --verbose or scan --json for full diagnostics.\nNext: kitrove init (new collection), or kitrove configure (existing collection).\nYou can also adopt a unique skill name: kitrove adopt NAME --harness TOOL\n");
    out
}

fn description(code: &str) -> &str {
    match code {
        "scan.discovery_unsafe_path" => {
            "linked or special entries skipped; existing links need not be removed"
        }
        "skill.frontmatter_invalid" => "skill metadata could not be read",
        "capture.file_size_limit" => "a source file exceeds the capture limit",
        "skill.credential_artifact" => {
            "possible credential-related artifact excluded; review locally"
        }
        "claude.version_unknown" => "Claude version unknown; conservative discovery policy used",
        "claude.portable_projection_unavailable" => "not portable in its current format",
        "mcp.portable_projection_blocked" => "MCP configuration cannot currently be imported",
        _ => code,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminal_controls_are_not_rendered() {
        assert_eq!(super::safe("name\n\u{1b}[31m"), "name\\n\\u{1b}[31m");
    }
}
