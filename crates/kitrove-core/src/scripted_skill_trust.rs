use crate::{
    ExecutableTrustDecision, ExecutableTrustError, ExecutableTrustPlan, ExecutableTrustStatus,
    ObjectStore, VerifiedSkillObjectCatalog, derive_manifest_revision,
};
use kitrove_agent_skills::{
    CaptureLimits, CapturedTree, FileMode, NativeSkillObject, StoredSkillTree,
    validate_scripted_skill_tree,
};
use kitrove_model::{
    AssetId, AssetKind, ContentClass, ContentHash, EnvironmentManifest, LocalState, TrustDecision,
};
use std::path::Path;

/// Full verified bundle retained as data. No file is interpreted or launched.
#[derive(Clone)]
pub struct ScriptedSkillBundle {
    portable: StoredSkillTree,
    native: std::collections::BTreeMap<kitrove_model::HarnessId, NativeSkillObject>,
}

/// Bounded file inventory for an explicit local review, without payload contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedSkillFile {
    pub component: String,
    pub path: String,
    pub mode: FileMode,
    pub bytes: usize,
    pub hash: ContentHash,
}

impl ScriptedSkillBundle {
    #[must_use]
    pub fn files(&self) -> Vec<ScriptedSkillFile> {
        let mut files = Vec::new();
        append_files(&mut files, "tool-ready files", self.portable.tree());
        for (harness, native) in &self.native {
            append_files(&mut files, &format!("{harness} original"), native.tree());
        }
        files
    }

    /// Returns exact stored bytes for an explicit inspection; never executes them.
    #[must_use]
    pub fn file_bytes(&self, index: usize) -> Option<&[u8]> {
        self.portable
            .tree()
            .files
            .values()
            .chain(
                self.native
                    .values()
                    .flat_map(|object| object.tree().files.values()),
            )
            .nth(index)
            .map(|file| file.bytes.as_slice())
    }

    fn validate(
        &self,
        manifest: &EnvironmentManifest,
        id: &AssetId,
    ) -> Result<(), ExecutableTrustError> {
        manifest.validate().map_err(|_| invalid())?;
        let asset = manifest.assets.get(id).ok_or_else(invalid)?;
        if asset.kind != AssetKind::Skill
            || asset.content_class != ContentClass::Executable
            || asset.portable.as_ref().map(|p| &p.object_hash) != Some(&self.portable.tree().hash)
            || asset.native_variants.len() != self.native.len()
            || asset.native_variants.iter().any(|(harness, native)| {
                self.native
                    .get(harness)
                    .is_none_or(|object| object.hash() != &native.object_hash)
            })
        {
            return Err(invalid());
        }
        let catalog =
            VerifiedSkillObjectCatalog::new([self.portable.clone()], self.native.values().cloned())
                .map_err(|_| invalid())?;
        crate::merge::validate_skill_snapshot_asset(asset, &catalog).map_err(|_| invalid())?;
        validate_scripted_skill_tree(self.portable.tree(), "SKILL.md")
            .map_err(|_| unsupported())?;
        for native in self.native.values() {
            validate_scripted_skill_tree(native.tree(), native.original_document_name())
                .map_err(|_| unsupported())?;
        }
        Ok(())
    }
}

fn append_files(output: &mut Vec<ScriptedSkillFile>, component: &str, tree: &CapturedTree) {
    output.extend(tree.files.iter().map(|(path, file)| ScriptedSkillFile {
        component: component.to_owned(),
        path: path.as_str().to_owned(),
        mode: file.mode,
        bytes: file.bytes.len(),
        hash: ContentHash::digest(&file.bytes),
    }));
}

/// Loads all manifest-authorized components for review without changing local decisions.
pub fn load_scripted_skill_bundle(
    manifest: &EnvironmentManifest,
    id: &AssetId,
    root: &Path,
    limits: CaptureLimits,
) -> Result<ScriptedSkillBundle, ExecutableTrustError> {
    let store = ObjectStore::open(root).map_err(|_| invalid())?;
    load_locked_bundle(manifest, id, &store, limits)
}

pub(crate) fn load_locked_bundle(
    manifest: &EnvironmentManifest,
    id: &AssetId,
    store: &ObjectStore,
    limits: CaptureLimits,
) -> Result<ScriptedSkillBundle, ExecutableTrustError> {
    manifest.validate().map_err(|_| invalid())?;
    let asset = manifest.assets.get(id).ok_or_else(invalid)?;
    if asset.kind != AssetKind::Skill || asset.native_variants.len() > 4 {
        return Err(invalid());
    }
    let portable = asset.portable.as_ref().ok_or_else(invalid)?;
    if portable.format != "agent-skills/v1"
        || asset
            .native_variants
            .values()
            .any(|n| n.format != "kitrove-native-skill-object/v1")
    {
        return Err(invalid());
    }
    let portable = store
        .load_portable(&portable.root, limits)
        .map_err(|_| invalid())?;
    let native = asset
        .native_variants
        .iter()
        .map(|(harness, variant)| {
            store
                .load_native(&variant.root, limits)
                .map(|object| (harness.clone(), object))
                .map_err(|_| invalid())
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    let bundle = ScriptedSkillBundle { portable, native };
    bundle.validate(manifest, id)?;
    Ok(bundle)
}

/// Plans a decision keyed by the entire asset revision, never just one helper file.
pub fn plan_scripted_skill_trust(
    manifest_text: &str,
    state_text: &str,
    id: &AssetId,
    bundle: &ScriptedSkillBundle,
    decision: ExecutableTrustDecision,
) -> Result<ExecutableTrustPlan, ExecutableTrustError> {
    let manifest = EnvironmentManifest::from_toml(manifest_text).map_err(|_| invalid())?;
    bundle.validate(&manifest, id)?;
    let revision = derive_manifest_revision(&manifest).map_err(|_| invalid())?;
    let state = LocalState::from_json(state_text).map_err(|_| invalid_state())?;
    crate::executable_trust::plan_trust_subject(
        id,
        &manifest.assets[id].content_hash,
        decision,
        revision,
        state,
        state_text,
    )
}

/// Reports only this machine's decision for this exact complete bundle.
pub fn inspect_scripted_skill_trust(
    manifest_text: &str,
    state_text: &str,
    id: &AssetId,
    bundle: &ScriptedSkillBundle,
) -> Result<ExecutableTrustStatus, ExecutableTrustError> {
    let manifest = EnvironmentManifest::from_toml(manifest_text).map_err(|_| invalid())?;
    bundle.validate(&manifest, id)?;
    let state = LocalState::from_json(state_text).map_err(|_| invalid_state())?;
    Ok(match state.trust.get(&manifest.assets[id].content_hash) {
        Some(TrustDecision::Trusted { .. }) => ExecutableTrustStatus::Trusted,
        Some(TrustDecision::Denied { .. }) => ExecutableTrustStatus::Denied,
        None => ExecutableTrustStatus::Unreviewed,
    })
}
fn invalid() -> ExecutableTrustError {
    ExecutableTrustError::new(
        "trust.skill_bundle_invalid",
        "the selected skill is not a complete verified executable bundle",
    )
}
fn unsupported() -> ExecutableTrustError {
    ExecutableTrustError::new(
        "trust.skill_bundle_unsupported",
        "compiled payloads and native lifecycle directives are not supported",
    )
}
fn invalid_state() -> ExecutableTrustError {
    ExecutableTrustError::new(
        "trust.local_state_invalid",
        "machine-local state authority is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adoption::tests::{capabilities, empty_manifest, make_candidate_with_files};
    use kitrove_agent_skills::CapturedFile;
    use kitrove_model::PortablePath;
    use std::collections::BTreeMap;
    fn bundle(bytes: &[u8]) -> (EnvironmentManifest, AssetId, ScriptedSkillBundle) {
        let candidate = make_candidate_with_files(
            FileMode::Regular,
            "review",
            0,
            BTreeMap::from([(
                PortablePath::parse("helper.py").unwrap(),
                CapturedFile {
                    mode: FileMode::Regular,
                    bytes: bytes.to_vec(),
                },
            )]),
        );
        let crate::AdoptionPlanOutcome::Ready(plan) =
            crate::plan_adoption(&candidate, None, &empty_manifest(), &capabilities()).unwrap()
        else {
            panic!("fixture should collect");
        };
        (
            plan.proposed_manifest().clone(),
            plan.asset().id.clone(),
            ScriptedSkillBundle {
                portable: plan.portable_object().clone(),
                native: BTreeMap::from([(
                    kitrove_model::HarnessId::Claude,
                    plan.native_object().clone(),
                )]),
            },
        )
    }
    fn state() -> LocalState {
        LocalState::from_json(r#"{"schema_version":1,"machine":{"id":"review-machine","enabled_targets":[],"harness_roots":{}},"bindings":{},"receipts":{},"pack_applications":{},"trust":{},"scans":[]}"#).unwrap()
    }
    #[test]
    fn approval_is_whole_bundle_local_and_changed_helper_invalidates_it() {
        let (manifest, id, bundle) = bundle(b"raise SystemExit('must never run')\n");
        let text = manifest.to_toml().unwrap();
        let empty = state().to_json().unwrap();
        let plan = plan_scripted_skill_trust(
            &text,
            &empty,
            &id,
            &bundle,
            ExecutableTrustDecision::Trusted,
        )
        .unwrap();
        assert_eq!(plan.object_hash(), &manifest.assets[&id].content_hash);
        assert_eq!(
            inspect_scripted_skill_trust(&text, &empty, &id, &bundle).unwrap(),
            ExecutableTrustStatus::Unreviewed
        );
        let approved = plan.proposed_local_state().to_json().unwrap();
        assert_eq!(
            inspect_scripted_skill_trust(&text, &approved, &id, &bundle).unwrap(),
            ExecutableTrustStatus::Trusted
        );
        let (new_manifest, _, changed) = self::bundle(b"raise SystemExit('changed helper')\n");
        assert_ne!(
            manifest.assets[&id].content_hash,
            new_manifest.assets[&id].content_hash
        );
        assert_eq!(
            inspect_scripted_skill_trust(
                &new_manifest.to_toml().unwrap(),
                &approved,
                &id,
                &changed
            )
            .unwrap(),
            ExecutableTrustStatus::Unreviewed
        );
        assert!(
            plan_scripted_skill_trust(
                &text,
                &empty,
                &id,
                &changed,
                ExecutableTrustDecision::Trusted
            )
            .is_err()
        );
        let denied = plan_scripted_skill_trust(
            &text,
            &approved,
            &id,
            &bundle,
            ExecutableTrustDecision::Denied,
        )
        .unwrap();
        assert_eq!(
            inspect_scripted_skill_trust(
                &text,
                &denied.proposed_local_state().to_json().unwrap(),
                &id,
                &bundle
            )
            .unwrap(),
            ExecutableTrustStatus::Denied
        );
        assert_eq!(
            manifest.to_toml().unwrap(),
            text,
            "local decisions never change portable authority"
        );
    }
}
