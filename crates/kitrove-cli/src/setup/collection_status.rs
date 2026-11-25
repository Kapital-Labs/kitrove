//! Advisory content comparison. It never grants ownership, trust or mutation authority.
use super::*;
use kitrove_core::ScanEntry;
use kitrove_model::EnvironmentManifest;

pub(super) const MATCHING: &str = "already collected (exact native content matches)";
pub(super) const DIFFERENT: &str = "same name, different native content";
pub(super) const UNVERIFIED: &str = "same name; native content not compared";

pub(super) fn existing(
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    id: &AssetId,
    entry: &ScanEntry,
) -> &'static str {
    let Some(asset) = manifest.assets.get(id) else {
        return UNVERIFIED;
    };
    if !asset.native_variants.contains_key(&entry.harness) {
        return UNVERIFIED;
    }
    let Ok(object) = kitrove_core::load_native_skill_object(
        manifest,
        id,
        &entry.harness,
        root,
        CaptureLimits::default(),
    ) else {
        return UNVERIFIED;
    };
    let Some(observed) = &entry.exact_source_hash else {
        return UNVERIFIED;
    };
    let stored = kitrove_agent_skills::hash_skill_source(
        object.layout(),
        object.original_document_name(),
        object.tree(),
    );
    if &stored == observed {
        MATCHING
    } else {
        DIFFERENT
    }
}

pub(super) fn page<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    candidates: &[&ScanEntry],
    filter: &str,
    start: &mut usize,
    advance: bool,
) -> Result<(), CliError> {
    const PAGE_SIZE: usize = 10;
    let matches: Vec<_> = candidates
        .iter()
        .enumerate()
        .filter(|(_, entry)| name(entry).to_ascii_lowercase().contains(filter))
        .collect();
    if advance {
        *start = if *start + PAGE_SIZE < matches.len() {
            *start + PAGE_SIZE
        } else {
            0
        };
    }
    let end = (*start + PAGE_SIZE).min(matches.len());
    dialog.say(&format!(
        "Source copies · {}–{end} of {}",
        if matches.is_empty() { 0 } else { *start + 1 },
        matches.len()
    ))?;
    for &(index, entry) in &matches[*start..end] {
        dialog.say(&format!(
            "  {}. {} [{} / {:?}]",
            index + 1,
            safe(name(entry)),
            entry.harness.as_str(),
            entry.scope
        ))?;
    }
    dialog
        .hint("Use the original numbers to select skills. Type /name to filter or next to browse.")
}
