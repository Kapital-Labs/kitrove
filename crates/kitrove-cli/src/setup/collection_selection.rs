//! Selection of existing observations only; never equivalence or mutation authority.
use super::*;
use kitrove_core::ScanEntry;
use std::collections::BTreeMap;

pub(super) const AMBIGUOUS: &str =
    "same name in multiple selected sources; review individually to choose or rename";

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

pub(super) fn show_sources<R: PromptInput, W: Write>(
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
    blockers: Vec<String>,
}

impl Skipped {
    pub(super) fn has_ambiguity(&self) -> bool {
        self.reasons.contains_key(AMBIGUOUS)
    }

    pub(super) fn push(&mut self, reason: &'static str, detail: String) {
        self.details.push(detail);
        *self.reasons.entry(reason).or_default() += 1;
    }

    pub(super) fn blocked(&mut self, detail: String) {
        self.push("blocked", format!("Blocked: {detail}"));
        self.blockers.push(detail);
    }

    pub(super) fn summary<R: PromptInput, W: Write>(
        &self,
        dialog: &mut Dialog<R, W>,
        selected: usize,
        names: usize,
        ready: usize,
    ) -> Result<(), CliError> {
        let name_word = if names == 1 {
            "skill name"
        } else {
            "skill names"
        };
        let copy_word = if selected == 1 {
            "source copy"
        } else {
            "source copies"
        };
        dialog.say(&format!(
            "\n{names} {name_word} · {selected} {copy_word} selected · {ready} ready to collect"
        ))?;
        for (reason, count) in &self.reasons {
            let summary = match *reason {
                super::collection_status::MATCHING
                | super::collection_status::DIFFERENT
                | super::collection_status::UNVERIFIED => {
                    format!("  {count}: {reason} (skipped; no overwrite)")
                }
                AMBIGUOUS => format!(
                    "  {count} copies share a name across the selected sources (choose one source)"
                ),
                "excluded by selection" | "blocked" => continue,
                _ => format!("  {count}: {reason}"),
            };
            dialog.say(&summary)?;
        }
        if !self.blockers.is_empty() {
            dialog.say(&format!("  {} blocked:", self.blockers.len()))?;
            for detail in self.blockers.iter().take(10) {
                dialog.say(&format!("    - {detail}"))?;
            }
            if self.blockers.len() > 10 {
                dialog.hint("Showing the first 10 blocked skills; d shows all details.")?;
            }
        }
        if self
            .reasons
            .contains_key(super::collection_status::UNVERIFIED)
        {
            dialog.hint(
                "Matching names do not prove matching contents. Nothing existing is overwritten.",
            )?;
        }
        if !self.details.is_empty() {
            dialog.hint("d shows all skipped-item details, including unselected copies.")?;
        }
        Ok(())
    }

    pub(super) fn all<R: PromptInput, W: Write>(
        &self,
        dialog: &mut Dialog<R, W>,
    ) -> Result<(), CliError> {
        for detail in &self.details {
            dialog.detail(detail)?;
        }
        Ok(())
    }
}
