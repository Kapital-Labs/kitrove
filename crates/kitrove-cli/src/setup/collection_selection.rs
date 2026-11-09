//! Selection of existing observations only; never equivalence or mutation authority.
use super::*;
use kitrove_core::ScanEntry;
use std::collections::BTreeMap;

pub(super) const AMBIGUOUS: &str =
    "same name in multiple selected sources; review individually to choose or rename";
pub(super) const OCCUPIED: &str = "collection name already in use; review individually to rename";

// Only narrow this selection. Original indices (including exclusions) stay bound
// to the displayed scan, and no harness is preferred or remembered.
pub(super) fn source_choices(
    candidates: &[&ScanEntry],
    selected: &[usize],
) -> Vec<(HarnessId, Vec<usize>)> {
    let mut names = BTreeMap::<_, BTreeSet<_>>::new();
    let mut tools = BTreeMap::<_, Vec<_>>::new();
    for &index in selected {
        let entry = candidates[index];
        names.entry(name(entry)).or_default().insert(&entry.harness);
        tools.entry(entry.harness.clone()).or_default().push(index);
    }
    if names.values().any(|harnesses| harnesses.len() > 1) {
        tools.into_iter().collect()
    } else {
        Vec::new()
    }
}

pub(super) fn source_prompt(choices: &[(HarnessId, Vec<usize>)]) -> String {
    let mut prompt = "Choose a tool's copies to preview\n".to_owned();
    for (index, (tool, indices)) in choices.iter().enumerate() {
        let count = indices.len();
        let unit = if count == 1 { "copy" } else { "copies" };
        prompt.push_str(&format!(
            "{}. {} ({count} selected {unit})\n",
            index + 1,
            tool.as_str()
        ));
    }
    prompt.push_str(concat!(
        "Enter/s       Choose different skills\n",
        "r             Review individually\n",
        "d             Show all skipped-item details\n",
        "n             Skip\n",
        "q             Quit",
    ));
    prompt
}

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
    pub(super) fn has_ambiguity(&self) -> bool {
        self.reasons.contains_key(AMBIGUOUS)
    }

    pub(super) fn push(&mut self, reason: &'static str, detail: String) {
        self.details.push(detail);
        *self.reasons.entry(reason).or_default() += 1;
    }

    pub(super) fn summary<R: BufRead, W: Write>(
        &self,
        dialog: &mut Dialog<R, W>,
    ) -> Result<(), CliError> {
        for (reason, count) in &self.reasons {
            let summary = match *reason {
                AMBIGUOUS => {
                    format!("{count} copies have the same name in multiple selected sources.")
                }
                OCCUPIED => format!(
                    "{count} copies: collection name already in use. Nothing will be overwritten."
                ),
                "excluded by selection" => format!("{count} copies excluded by your selection."),
                _ => format!("{count}: {reason}"),
            };
            dialog.detail(&summary)?;
        }
        if !self.details.is_empty() {
            dialog.hint(
                "Press d for skipped-item details. Existing collection items are not overwritten.",
            )?;
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
