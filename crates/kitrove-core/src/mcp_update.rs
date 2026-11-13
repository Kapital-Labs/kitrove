use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_mcp::{StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, ContentHash, EnvironmentManifest, Lockfile, Revision,
};

use crate::whole_file_adoption::{self, UpdateFailure};
use crate::{
    McpAdoptionOutcome, McpDocumentObservation, TierOneMcpCapabilities, plan_mcp_adoption,
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
        if !whole_file_adoption::update_authority_is_current(
            manifest_text,
            manifest,
            lock_text,
            &self.asset.id,
            &self.expected_prior,
            &self.base_manifest_hash,
            &self.base_manifest_revision,
            &self.observed_lock_text,
        ) {
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
    let base = whole_file_adoption::update_base(
        AssetKind::Mcp,
        asset_id,
        expected_prior,
        manifest_text,
        manifest,
        lock_text,
    )
    .map_err(planning_error)?;
    let McpAdoptionOutcome::Ready(candidate) = plan_mcp_adoption(
        observation,
        selected_entry_hash,
        asset_id,
        bearer_binding,
        &whole_file_adoption::empty_manifest(),
        capabilities,
    )
    .map_err(|_| update_error("mcp_update.derivation_failed"))?
    else {
        return Err(update_error("mcp_update.content_blocked"));
    };
    let proposal = whole_file_adoption::propose_update(
        b"kitrove-mcp-update-plan-v1\0",
        selected_entry_hash,
        observation.harness(),
        asset_id,
        expected_prior,
        &base,
        candidate.asset(),
        manifest,
        true,
    )
    .map_err(planning_error)?;

    Ok(McpUpdatePlan {
        observation: observation.clone(),
        selected_entry_hash: selected_entry_hash.clone(),
        expected_prior: expected_prior.clone(),
        prior_asset: base.prior_asset,
        asset: proposal.asset,
        portable_object: candidate.portable_object().clone(),
        native_object: candidate.native_object().clone(),
        proposed_manifest: proposal.manifest,
        proposed_lock: proposal.lock,
        observed_lock_text: base.observed_lock_text,
        base_manifest_hash: base.manifest_hash,
        base_manifest_revision: base.manifest_revision,
        proposed_manifest_revision: proposal.manifest_revision,
        digest: proposal.digest,
    })
}

fn planning_error(failure: UpdateFailure) -> McpUpdateError {
    update_error(match failure {
        UpdateFailure::ManifestInvalid => "mcp_update.manifest_invalid",
        UpdateFailure::LockNotInSync => "mcp_update.lock_not_in_sync",
        UpdateFailure::AssetMissing => "mcp_update.asset_missing",
        UpdateFailure::ExpectedPriorMismatch => "mcp_update.expected_prior_mismatch",
        UpdateFailure::DerivationFailed => "mcp_update.derivation_failed",
        UpdateFailure::RevisionUnchanged => "mcp_update.revision_unchanged",
        UpdateFailure::ObjectPathInvalid => "mcp_update.object_path_invalid",
        UpdateFailure::ProposedManifestInvalid => "mcp_update.proposed_manifest_invalid",
        UpdateFailure::ProposedLockInvalid => "mcp_update.proposed_lock_invalid",
        UpdateFailure::PlanDigestFailed => "mcp_update.plan_digest_failed",
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
    use crate::derive_lockfile;
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

    #[test]
    fn update_failures_keep_their_exact_codes_messages_and_plan_identity() {
        let (asset_id, manifest, manifest_text, lock_text) = adopted();
        let expected = manifest.assets[&asset_id].content_hash.clone();
        let changed = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://new.example.com/mcp","headers":{"Authorization":"Bearer ${NATIVE_SECRET_TOKEN}"}}}}"#,
        );
        let selected = changed.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone();
        let binding = kitrove_model::BindingName::parse("company_mcp_token").unwrap();
        let plan_with = |id: &AssetId, text: &str, lock: Option<&str>| {
            plan_mcp_update(
                &changed,
                &selected,
                id,
                &expected,
                Some(&binding),
                text,
                &manifest,
                lock,
                &capabilities(),
            )
        };
        let failure = |id: &AssetId, text: &str, lock: Option<&str>| {
            plan_with(id, text, lock).unwrap_err().to_string()
        };
        let absent = AssetId::parse("absent").unwrap();

        assert_eq!(
            failure(&asset_id, "", Some(&lock_text)),
            "mcp_update.manifest_invalid: MCP update planning requires a valid exact manifest"
        );
        assert_eq!(
            failure(&asset_id, &manifest_text, None),
            "mcp_update.lock_not_in_sync: MCP update planning requires generated lock state in sync"
        );
        assert_eq!(
            failure(&asset_id, &manifest_text, Some("{}")),
            "mcp_update.lock_not_in_sync: MCP update planning requires generated lock state in sync"
        );
        assert_eq!(
            failure(&absent, &manifest_text, Some(&lock_text)),
            "mcp_update.asset_missing: the MCP asset does not exist"
        );
        // An invalid manifest is reported before a missing lock, and that before a missing asset.
        assert!(failure(&absent, "", None).starts_with("mcp_update.manifest_invalid"));
        assert!(failure(&absent, &manifest_text, None).starts_with("mcp_update.lock_not_in_sync"));

        let plan = plan_with(&asset_id, &manifest_text, Some(&lock_text)).unwrap();
        assert!(!manifest.required_bindings.contains(&binding));
        assert!(
            plan.proposed_manifest()
                .required_bindings
                .contains(&binding)
        );
        let other = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://other.example.com/mcp"}}}"#,
        );
        assert_eq!(
            plan.ensure_observation_fresh(&other)
                .unwrap_err()
                .to_string(),
            "mcp_update.observation_stale: the MCP observation changed after planning"
        );
        assert_eq!(
            plan.ensure_portable_authority_fresh(&manifest_text, &manifest, None)
                .unwrap_err()
                .to_string(),
            "mcp_update.manifest_stale: portable MCP authority changed after planning"
        );
        assert_eq!(
            format!("{:?}", plan_with(&asset_id, "", None).unwrap_err()),
            "McpUpdateError { code: \"mcp_update.manifest_invalid\" }"
        );
        assert_eq!(
            plan.digest().as_str(),
            "blake3:a2533ee026f6064dd219abcc52f8ae53a24473185cae5d68bdf4e0186da61e13"
        );
        assert_eq!(
            plan.asset().content_hash.as_str(),
            "blake3:3d4789c4abe597fa5112ec55027cd55de488865b2cdda042f92e638268f62cd2"
        );
        assert_eq!(
            plan.proposed_manifest_revision().as_str(),
            "manifest:blake3:b9480d94717d3364c9242cbaefb1e83f9642d710ebc406c185401d3ed614387e"
        );
        assert!(format!("{plan:?}").starts_with("McpUpdatePlan { asset_id: "));
    }
}
