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
            Self::NeedsReview(_) => "Needs review",
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
