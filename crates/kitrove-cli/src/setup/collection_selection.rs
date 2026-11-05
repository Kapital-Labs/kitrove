//! Selection of existing observations only; never equivalence or mutation authority.
use super::*;
use kitrove_core::ScanEntry;
use std::collections::BTreeMap;

pub(super) fn select(input: &str, candidates: &[&ScanEntry]) -> Option<Vec<usize>> {
    let Some(source) = input.strip_prefix("from ") else {
        return selection(input, candidates.len());
    };
    let (tool, exclusions) = source.split_once(',').unwrap_or((source, ""));
    let tool = tool.trim();
    if !candidates
        .iter()
        .any(|entry| entry.harness.as_str() == tool)
    {
        return None;
    }
    let included = if source.contains(',') {
        selection(&format!("all,{exclusions}"), candidates.len())?
    } else {
        (0..candidates.len()).collect()
    };
    Some(
        included
            .into_iter()
            .filter(|&i| candidates[i].harness.as_str() == tool)
            .collect(),
    )
}

pub(super) fn show_sources<R: BufRead, W: Write>(
    dialog: &mut Dialog<R, W>,
    candidates: &[&ScanEntry],
) -> Result<(), CliError> {
    let mut counts = BTreeMap::new();
    for entry in candidates {
        *counts.entry(entry.harness.as_str()).or_insert(0) += 1;
    }
    dialog.say(&format!(
        "Sources (observations, not unique skills): {}.",
        counts
            .iter()
            .map(|(tool, count)| format!("{tool}: {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))?;
    dialog.hint("The same name can appear through several tools. Use from TOOL (for example, from codex) to choose that tool's copies, not merge them. Add ,-3,-8 to exclude original inventory numbers.")
}

#[derive(Default)]
pub(super) struct Skipped {
    details: Vec<String>,
    reasons: BTreeMap<&'static str, usize>,
}

impl Skipped {
    pub(super) fn push(&mut self, reason: &'static str, detail: String) {
        self.details.push(detail);
        *self.reasons.entry(reason).or_default() += 1;
    }

    pub(super) fn summary<R: BufRead, W: Write>(
        &self,
        dialog: &mut Dialog<R, W>,
    ) -> Result<(), CliError> {
        for (reason, count) in &self.reasons {
            dialog.detail(&format!("{count}: {reason}"))?;
        }
        for detail in self.details.iter().take(20) {
            dialog.detail(detail)?;
        }
        if self.details.len() > 20 {
            dialog.hint("Showing the first 20 skipped items; d = all skipped-item details.")?;
        }
        Ok(())
    }

    pub(super) fn all<R: BufRead, W: Write>(
        &self,
        dialog: &mut Dialog<R, W>,
    ) -> Result<(), CliError> {
        for detail in &self.details {
            dialog.detail(detail)?;
        }
        Ok(())
    }
}
