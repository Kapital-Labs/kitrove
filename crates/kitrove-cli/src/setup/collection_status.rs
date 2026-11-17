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

pub(super) fn grouped<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    candidates: &[&ScanEntry],
) -> Result<(), CliError> {
    let mut groups = std::collections::BTreeMap::<_, Vec<_>>::new();
    for (index, entry) in candidates.iter().enumerate() {
        groups.entry(name(entry)).or_default().push((index, *entry));
    }
    for (name, entries) in groups.into_iter().take(20) {
        let copies = if entries.len() == 1 {
            "source copy"
        } else {
            "source copies"
        };
        dialog.say(&format!("{} · {} {copies}", safe(name), entries.len()))?;
        for (index, entry) in entries.iter().take(8) {
            dialog.say(&format!(
                "  {}. {} [{:?}]",
                index + 1,
                entry.harness.as_str(),
                entry.scope
            ))?;
        }
        if entries.len() > 8 {
            dialog.hint("More copies are available under v; original numbers stay unchanged.")?;
        }
    }
    Ok(())
}
