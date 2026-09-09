use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, ContentHash, EnvironmentManifest, Lockfile, Revision,
    SchemaVersion,
};

use crate::adoption::content_addressed_update_root;
use crate::whole_file_adoption::{self, UpdateDigestInput};
use crate::{
    LockStatus, McpAdoptionOutcome, McpDocumentObservation, TierOneMcpCapabilities,
    compare_lockfile, derive_lockfile, derive_manifest_revision, plan_mcp_adoption,
};

#[derive(Clone, Eq, PartialEq)]
pub struct McpUpdatePlan {
    observation: McpDocumentObservation,
    selected_entry_hash: ContentHash,
    expected_prior: ContentHash,
    prior_asset: Asset,
    asset: Asset,
    portable_object: StoredMcpServer,
    native_object: StoredNativeMcpEntry,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    observed_lock_text: String,
    base_manifest_hash: ContentHash,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl McpUpdatePlan {
    #[must_use]
    pub const fn observation(&self) -> &McpDocumentObservation {
        &self.observation
    }
    #[must_use]
    pub const fn selected_entry_hash(&self) -> &ContentHash {
        &self.selected_entry_hash
    }
    #[must_use]
    pub const fn expected_prior(&self) -> &ContentHash {
        &self.expected_prior
    }
    #[must_use]
    pub const fn prior_asset(&self) -> &Asset {
        &self.prior_asset
    }
    #[must_use]
    pub const fn asset(&self) -> &Asset {
        &self.asset
    }
    #[must_use]
    pub const fn portable_object(&self) -> &StoredMcpServer {
        &self.portable_object
    }
    #[must_use]
    pub const fn native_object(&self) -> &StoredNativeMcpEntry {
        &self.native_object
    }
    #[must_use]
    pub const fn proposed_manifest(&self) -> &EnvironmentManifest {
        &self.proposed_manifest
    }
    #[must_use]
    pub const fn proposed_lock(&self) -> &Lockfile {
        &self.proposed_lock
    }
    #[must_use]
    pub const fn base_manifest_hash(&self) -> &ContentHash {
        &self.base_manifest_hash
    }
    #[must_use]
    pub const fn base_manifest_revision(&self) -> &Revision {
        &self.base_manifest_revision
    }
    #[must_use]
    pub const fn proposed_manifest_revision(&self) -> &Revision {
        &self.proposed_manifest_revision
    }
    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }

    pub fn ensure_observation_fresh(
        &self,
        reread: &McpDocumentObservation,
    ) -> Result<(), McpUpdateError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(update_error("mcp_update.observation_stale"))
        }
    }

    pub fn ensure_portable_authority_fresh(
        &self,
        manifest_text: &str,
        manifest: &EnvironmentManifest,
        lock_text: Option<&str>,
    ) -> Result<(), McpUpdateError> {
        let revision = derive_manifest_revision(manifest)
            .map_err(|_| update_error("mcp_update.manifest_stale"))?;
        if ContentHash::digest(manifest_text.as_bytes()) != self.base_manifest_hash
            || revision != self.base_manifest_revision
            || manifest
                .assets
                .get(&self.asset.id)
                .map(|asset| &asset.content_hash)
                != Some(&self.expected_prior)
            || lock_text != Some(self.observed_lock_text.as_str())
            || compare_lockfile(manifest, lock_text).map(|comparison| comparison.status())
                != Ok(LockStatus::InSync)
        {
            return Err(update_error("mcp_update.manifest_stale"));
        }
        Ok(())
    }
}

impl Debug for McpUpdatePlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpUpdatePlan")
            .field("asset_id", &self.asset.id)
            .field("selected_entry_hash", &self.selected_entry_hash)
            .field("expected_prior", &self.expected_prior)
            .field("proposed_revision", &self.asset.content_hash)
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpUpdateError {
    code: &'static str,
    message: &'static str,
}

impl McpUpdateError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for McpUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpUpdateError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for McpUpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for McpUpdateError {}

/// Plans exact-prior replacement of one adopted MCP declaration without mutating state.
#[allow(clippy::too_many_arguments)]
pub fn plan_mcp_update(
    observation: &McpDocumentObservation,
    selected_entry_hash: &ContentHash,
    asset_id: &AssetId,
    expected_prior: &ContentHash,
    bearer_binding: Option<&BindingName>,
    manifest_text: &str,
    manifest: &EnvironmentManifest,
    lock_text: Option<&str>,
    capabilities: &TierOneMcpCapabilities,
) -> Result<McpUpdatePlan, McpUpdateError> {
    manifest
        .validate()
        .map_err(|_| update_error("mcp_update.manifest_invalid"))?;
    if EnvironmentManifest::from_toml(manifest_text).as_ref() != Ok(manifest) {
        return Err(update_error("mcp_update.manifest_invalid"));
    }
    let base_manifest_hash = ContentHash::digest(manifest_text.as_bytes());
    let base_manifest_revision = derive_manifest_revision(manifest)
        .map_err(|_| update_error("mcp_update.manifest_invalid"))?;
    let observed_lock_text = lock_text
        .filter(|text| {
            compare_lockfile(manifest, Some(text)).map(|comparison| comparison.status())
                == Ok(LockStatus::InSync)
        })
        .ok_or_else(|| update_error("mcp_update.lock_not_in_sync"))?
        .to_owned();
    let prior_asset = manifest
        .assets
        .get(asset_id)
        .filter(|asset| asset.kind == AssetKind::Mcp)
        .ok_or_else(|| update_error("mcp_update.asset_missing"))?;
    if &prior_asset.content_hash != expected_prior {
        return Err(update_error("mcp_update.expected_prior_mismatch"));
    }

    let empty = EnvironmentManifest {
        schema_version: SchemaVersion::V1,
        assets: BTreeMap::new(),
        packs: BTreeMap::new(),
        profiles: BTreeMap::new(),
        required_bindings: BTreeSet::new(),
    };
    let McpAdoptionOutcome::Ready(candidate) = plan_mcp_adoption(
        observation,
        selected_entry_hash,
        asset_id,
        bearer_binding,
        &empty,
        capabilities,
    )
    .map_err(|_| update_error("mcp_update.derivation_failed"))?
    else {
        return Err(update_error("mcp_update.content_blocked"));
    };
    let portable_object = candidate.portable_object().clone();
    let native_object = candidate.native_object().clone();
    if whole_file_adoption::same_adopted_authority(prior_asset, candidate.asset()) {
        return Err(update_error("mcp_update.revision_unchanged"));
    }
    let mut asset = candidate.asset().clone();
    let portable = asset
        .portable
        .as_mut()
        .ok_or_else(|| update_error("mcp_update.derivation_failed"))?;
    portable.root = content_addressed_update_root(asset_id, None, &portable.object_hash)
        .map_err(|_| update_error("mcp_update.object_path_invalid"))?;
    let native = asset
        .native_variants
        .get_mut(observation.harness())
        .ok_or_else(|| update_error("mcp_update.derivation_failed"))?;
    native.root =
        content_addressed_update_root(asset_id, Some(observation.harness()), &native.object_hash)
            .map_err(|_| update_error("mcp_update.object_path_invalid"))?;
    asset.refresh_content_hash();

    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .required_bindings
        .extend(asset.required_bindings.iter().cloned());
    proposed_manifest
        .assets
        .insert(asset_id.clone(), asset.clone());
    proposed_manifest
        .validate()
        .map_err(|_| update_error("mcp_update.proposed_manifest_invalid"))?;
    let proposed_lock = derive_lockfile(&proposed_manifest)
        .map_err(|_| update_error("mcp_update.proposed_lock_invalid"))?;
    let proposed_manifest_revision = derive_manifest_revision(&proposed_manifest)
        .map_err(|_| update_error("mcp_update.proposed_manifest_invalid"))?;
    let digest = whole_file_adoption::update_digest(UpdateDigestInput {
        domain: b"kitrove-mcp-update-plan-v1\0",
        observation_identity: selected_entry_hash,
        asset_id,
        expected_prior,
        asset: &asset,
        base_manifest_hash: &base_manifest_hash,
        base_revision: &base_manifest_revision,
        proposed_revision: &proposed_manifest_revision,
        observed_lock: &observed_lock_text,
        proposed_lock: &proposed_lock,
    })
    .map_err(|()| update_error("mcp_update.plan_digest_failed"))?;

    Ok(McpUpdatePlan {
        observation: observation.clone(),
        selected_entry_hash: selected_entry_hash.clone(),
        expected_prior: expected_prior.clone(),
        prior_asset: prior_asset.clone(),
        asset,
        portable_object,
        native_object,
        proposed_manifest,
        proposed_lock,
        observed_lock_text,
        base_manifest_hash,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })
}

fn update_error(code: &'static str) -> McpUpdateError {
    let message = match code {
        "mcp_update.manifest_invalid" => "MCP update planning requires a valid exact manifest",
        "mcp_update.lock_not_in_sync" => {
            "MCP update planning requires generated lock state in sync"
        }
        "mcp_update.asset_missing" => "the MCP asset does not exist",
        "mcp_update.expected_prior_mismatch" => "the expected prior MCP revision is stale",
        "mcp_update.content_blocked" => "the MCP update content requires review",
        "mcp_update.derivation_failed" => "the MCP update could not be derived",
        "mcp_update.revision_unchanged" => "the MCP update does not change stored content",
        "mcp_update.object_path_invalid" => "the MCP update object path is invalid",
        "mcp_update.proposed_manifest_invalid" => "the proposed MCP manifest is invalid",
        "mcp_update.proposed_lock_invalid" => "the proposed MCP lock is invalid",
        "mcp_update.plan_digest_failed" => "the MCP update plan digest could not be derived",
        "mcp_update.observation_stale" => "the MCP observation changed after planning",
        "mcp_update.manifest_stale" => "portable MCP authority changed after planning",
        _ => "MCP update planning failed",
    };
    McpUpdateError { code, message }
}

#[cfg(test)]
mod tests {
    use kitrove_model::HarnessId;

    use super::*;
    use crate::mcp_adoption::tests::{capabilities, empty_manifest, observe};

    fn adopted() -> (AssetId, EnvironmentManifest, String, String) {
        let asset_id = AssetId::parse("docs").unwrap();
        let observation = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://old.example.com/mcp"}}}"#,
        );
        let selected = observation.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        let McpAdoptionOutcome::Ready(plan) = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            unreachable!()
        };
        let manifest = plan.proposed_manifest().clone();
        let manifest_text = manifest.to_toml().unwrap();
        let lock_text = derive_lockfile(&manifest).unwrap().to_json().unwrap();
        (asset_id, manifest, manifest_text, lock_text)
    }

    #[test]
    fn plans_exact_prior_content_addressed_replacement() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let changed = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://new.example.com/mcp"}}}"#,
        );
        let selected = changed.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        let plan = plan_mcp_update(
            &changed,
            &selected,
            &asset_id,
            &expected,
            None,
            &manifest_text,
            &manifest,
            Some(&lock_text),
            &capabilities(),
        )
        .unwrap();

        assert_ne!(plan.asset().content_hash, expected);
        assert!(
            plan.asset()
                .portable
                .as_ref()
                .unwrap()
                .root
                .as_str()
                .contains("updates/portable/blake3-")
        );
        assert!(
            plan.asset().native_variants[&HarnessId::Claude]
                .root
                .as_str()
                .contains("updates/native/claude/blake3-")
        );
        assert!(plan.ensure_observation_fresh(&changed).is_ok());
        assert!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, Some(&lock_text))
                .is_ok()
        );
        assert!(!format!("{plan:?}").contains("new.example.com"));
    }

    #[test]
    fn stale_unchanged_and_nonportable_updates_fail_closed() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let unchanged = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://old.example.com/mcp"}}}"#,
        );
        let unchanged_hash = unchanged.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        assert_eq!(
            plan_mcp_update(
                &unchanged,
                &unchanged_hash,
                &asset_id,
                &expected,
                None,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities()
            )
            .unwrap_err()
            .code(),
            "mcp_update.revision_unchanged"
        );
        let blocked = observe(r#"{"mcpServers":{"docs":{"command":"npx"}}}"#);
        let blocked_hash = blocked.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        assert_eq!(
            plan_mcp_update(
                &blocked,
                &blocked_hash,
                &asset_id,
                &expected,
                None,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities()
            )
            .unwrap_err()
            .code(),
            "mcp_update.content_blocked"
        );
        let stale = ContentHash::digest(b"stale");
        assert_eq!(
            plan_mcp_update(
                &blocked,
                &blocked_hash,
                &asset_id,
                &stale,
                None,
                &manifest_text,
                &manifest,
                Some(&lock_text),
                &capabilities()
            )
            .unwrap_err()
            .code(),
            "mcp_update.expected_prior_mismatch"
        );
    }
}
