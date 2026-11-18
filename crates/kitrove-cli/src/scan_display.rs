//! Human presentation only. Observation identity and capture policy stay in core.
use std::collections::BTreeMap;
use std::fmt::Write as _;

use kitrove_adapter_api::{FindingSubject, RootTier};
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

/// A failed folder has no candidate identity; keep it out of human skill lists only.
pub(crate) fn folder_issue(entry: &ScanEntry) -> bool {
    entry.observation_id.is_none()
        && entry.native_id.is_none()
        && entry.source_relative_path.is_none()
        && entry.asset_id.is_none()
        && entry.receipt_id.is_none()
        && entry.findings.iter().any(|finding| {
            finding.code == "scan.root_unreadable"
                && matches!(finding.subject, FindingSubject::Root(_))
        })
}

pub(crate) fn write_folder_issue(out: &mut String, entry: &ScanEntry) {
    let scope = match entry.scope {
        kitrove_model::HarnessScope::User => "user",
        kitrove_model::HarnessScope::Project => "project",
    };
    let location = match entry.root_tier {
        Some(RootTier::Admin) => "administrator skills folder",
        Some(RootTier::System) => "bundled skills folder",
        Some(RootTier::Explicit) => "explicit skills folder",
        Some(RootTier::Compatibility) => "compatibility skills folder",
        _ => match entry.scope {
            kitrove_model::HarnessScope::User => "user skills folder",
            kitrove_model::HarnessScope::Project => "project skills folder",
        },
    };
    writeln!(
        out,
        "  {} / {location}: folder could not be scanned",
        entry.harness.as_str()
    )
    .expect("string write");
    if let Some(root) = &entry.logical_root {
        // These are compiled path hints, never resolved private absolute paths.
        let hint = match (entry.harness.as_str(), root.as_str()) {
            ("codex", "codex.admin.skills") => Some("/etc/codex/skills"),
            ("codex", "codex.user.skills") => Some("~/.agents/skills"),
            ("claude", "claude.user.skills") => Some("~/.claude/skills"),
            ("pi", "pi.user.native.skills") => Some("~/.pi/agent/skills"),
            ("pi", "pi.user.compatibility.skills") => Some("~/.agents/skills"),
            ("opencode", "opencode.user.native.skills") => Some("~/.config/opencode/skills"),
            ("opencode", "opencode.user.claude.skills") => Some("~/.claude/skills"),
            ("opencode", "opencode.user.agents.skills") => Some("~/.agents/skills"),
            _ => None,
        };
        match hint {
            Some(hint) => writeln!(out, "    Location: {hint}"),
            None => writeln!(out, "    Folder ID: {}", safe(root.as_str())),
        }
        .expect("string write");
    }
    out.push_str("    Kitrove could not safely read this skills folder.\n");
    out.push_str("    It may be unreadable or reached through a linked folder.\n");
    if matches!(entry.root_tier, Some(RootTier::Admin | RootTier::System)) {
        out.push_str(
            "    You can leave this optional folder alone and use other readable skills.\n",
        );
    } else {
        out.push_str(
            "    Inspect the location, then scan again; existing links need not be removed.\n",
        );
    }
    writeln!(
        out,
        "    Details: kitrove scan --harness {} --scope {scope} --verbose",
        entry.harness.as_str()
    )
    .expect("string write");
}

pub(crate) fn render(report: &ScanReport) -> String {
    let mut out = String::from("Kitrove inventory (read-only)\n\n");
    for entry in report.entries.iter().filter(|entry| !folder_issue(entry)) {
        write_entry(&mut out, entry, true);
    }
    writeln!(
        out,
        "\n{} skills listed; {} ready to preview. Existing collection names and adoption blockers are checked in the preview.",
        report.entries.iter().filter(|e| !folder_issue(e)).count(),
        report.entries.iter().filter(|e| selectable(e)).count()
    )
    .expect("string write");
    let issues: Vec<_> = report
        .entries
        .iter()
        .filter(|entry| folder_issue(entry))
        .collect();
    if !issues.is_empty() {
        writeln!(out, "\nScan issues ({})", issues.len()).expect("string write");
        for entry in issues {
            write_folder_issue(&mut out, entry);
        }
        out.push_str("The inventory is incomplete. Keep any --root or --project-root options when checking details.\n");
    }
    out.push_str(&diagnostics(report));
    out.push_str("\nNo files changed. Use scan --verbose or scan --json for full diagnostics.\nNext: kitrove init (new collection), or kitrove configure (existing collection).\nYou can also adopt a unique skill name: kitrove adopt NAME --harness TOOL\n");
    out
}

pub(crate) fn write_entry(out: &mut String, entry: &ScanEntry, show_status: bool) {
    write!(
        out,
        "  {}  [{} / {:?}]",
        safe(name(entry)),
        entry.harness.as_str(),
        entry.scope
    )
    .expect("string write");
    if show_status {
        write!(out, "  {}", entry_status(entry)).expect("string write");
    }
    out.push('\n');
    for finding in &entry.findings {
        writeln!(out, "    {}", description(finding.code)).expect("string write");
    }
}

fn entry_status(entry: &ScanEntry) -> &'static str {
    if entry.shadowed_by.is_some() {
        "shadowed"
    } else {
        match entry.classification {
            ScanClassification::Unmanaged if selectable(entry) => "ready to preview",
            ScanClassification::Unmanaged => "needs portability review",
            ScanClassification::ManagedUnchanged => "managed, unchanged",
            ScanClassification::ManagedModified => "managed, locally changed",
            ScanClassification::MissingManaged => "managed, missing",
            ScanClassification::ConflictingDuplicate => "conflicting duplicate",
            ScanClassification::Unknown => "needs attention",
        }
    }
}

pub(crate) fn diagnostics(report: &ScanReport) -> String {
    let mut out = format!(
        "Other observations: {} commands, {} agents, {} extensions, {} instruction entries, {} MCP entries, {} related entries.\n",
        report.prompt_commands.len(),
        report.agents.len(),
        report.native_extensions.len(),
        report.instructions.len(),
        report.mcp_servers.len(),
        report.related.len()
    );
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
    out
}

fn description(code: &str) -> &str {
    match code {
        "scan.root_unreadable" => "a skills folder could not be safely read; check Scan issues",
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
