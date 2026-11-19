//! Advisory checks use the same destination planner as the final confirmed batch.
use super::*;
use kitrove_model::{AssetKind, EnvironmentManifest};

pub(super) enum Readiness {
    Ready,
    Current,
    NeedsReview(CliError),
    AfterSelection,
}

impl Readiness {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Ready => "Ready to add / update",
            Self::Current => "Already current (managed)",
            Self::NeedsReview(error) if error.code == "apply.compatibility_blocked" => {
                "Not compatible with the selected tools"
            }
            Self::NeedsReview(error) if error.code == "apply.skill_trust_required" => {
                "Review scripts"
            }
            Self::NeedsReview(error) if error.code == "apply.destination_unmanaged" => {
                "Compare existing copy"
            }
            Self::NeedsReview(_) => "Needs attention",
            Self::AfterSelection => {
                "Checked after selection (may need tool-version or trust evidence)"
            }
        }
    }
}

pub(super) fn inspect(
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    id: &AssetId,
    args: &MaterializeArgs,
) -> Readiness {
    if manifest
        .assets
        .get(id)
        .is_none_or(|asset| asset.kind != AssetKind::Skill)
    {
        return Readiness::AfterSelection;
    }
    let one = MaterializeArgs {
        profile: None,
        assets: BTreeSet::from([id.clone()]),
        packs: BTreeSet::new(),
        targets: args.targets.clone(),
        scope: args.scope,
        project_root: args.project_root.clone(),
        version_binaries: Vec::new(),
        environment: Some(root.to_owned()),
        json: true,
    };
    match crate::materialize::run_plan(one) {
        Err(error) => Readiness::NeedsReview(error),
        Ok(plan) => match classify(&plan.output) {
            Ok(true) => Readiness::Ready,
            Ok(false) => Readiness::Current,
            Err(error) => Readiness::NeedsReview(error),
        },
    }
}

fn classify(encoded: &str) -> Result<bool, CliError> {
    let value: serde_json::Value = serde_json::from_str(encoded).map_err(|_| io_error())?;
    let items = value
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map_or_else(|| vec![&value], |items| items.iter().collect());
    if items.is_empty() {
        return Err(io_error());
    }
    let mut changes = false;
    for item in items {
        match item["disposition"].as_str() {
            Some("install" | "restore" | "managed_update") => changes = true,
            Some("no_op") => {}
            _ => {
                return Err(CliError::new(
                    "setup.plan_shape_invalid",
                    "the destination plan could not be summarized; use the full plan",
                ));
            }
        }
    }
    Ok(changes)
}

/// Compares exact rendered contents without granting trust, ownership or write authority.
pub(super) fn compare<R: PromptInput, W: Write>(
    dialog: &mut Dialog<R, W>,
    root: &std::path::Path,
    manifest: &EnvironmentManifest,
    id: &AssetId,
    args: &MaterializeArgs,
) -> Result<(), CliError> {
    if manifest
        .assets
        .get(id)
        .is_none_or(|asset| asset.kind != AssetKind::Skill)
    {
        return dialog
            .say("Compare supports ordinary skills. Select this item to see its full plan.");
    }
    let object =
        kitrove_core::load_portable_skill_object(manifest, id, root, CaptureLimits::default())
            .map_err(|error| CliError::new(error.code(), error.message()))?;
    let anchor =
        crate::scan::resolve_materialization_anchor(args.scope, args.project_root.as_deref())?;
    dialog.heading(&format!(
        "Compare existing copy: {} (read-only)",
        safe(id.as_str())
    ))?;
    for target in &args.targets {
        let policy = crate::adapters::target_policy(target, args.scope)?;
        let rendered = kitrove_core::render_portable_skill(&object, &policy)
            .map_err(|error| CliError::new(error.code(), error.message()))?;
        let destination =
            kitrove_core::resolve_target_destination(&anchor, &policy, rendered.package_name())
                .map_err(|error| CliError::new(error.code(), error.message()))?;
        dialog.say(&format!(
            "  {}: {}",
            target.as_str(),
            safe(destination.as_str())
        ))?;
        match kitrove_core::observe_skill_destination(std::path::Path::new(destination.as_str()), CaptureLimits::default()) {
            kitrove_core::DestinationObservation::Present { rendered_hash, .. } => {
                dialog.say(if &rendered_hash == rendered.rendered_hash() {
                    "Exact bundle contents match."
                } else {
                    "Different bundle contents. Review both copies before changing either one."
                })?;
                dialog.detail(&format!("  Collection render: {}\n  Existing copy:     {}", rendered.rendered_hash(), rendered_hash))?;
            }
            kitrove_core::DestinationObservation::Absent => dialog.say("No existing copy at this destination.")?,
            kitrove_core::DestinationObservation::Unsafe => dialog.warning("Existing bundle contents could not be verified. The destination is unsafe, unreadable or unsupported.")?,
        }
    }
    dialog.hint("Matching contents do not grant Kitrove ownership. Keep an unmanaged copy and leave this item out, or return to setup to choose another destination. Kitrove does not take over existing copies.")
}
