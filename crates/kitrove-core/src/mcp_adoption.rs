use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use kitrove_adapter_api::{CapabilityMatrix, CapabilitySupport};
use kitrove_mcp::{McpPortability, McpServer, StoredMcpServer, StoredNativeMcpEntry};
use kitrove_model::{
    Asset, AssetId, AssetKind, BindingName, ContentHash, EnvironmentManifest, Fidelity,
    FidelityEvidence, FidelityResult, HarnessId, Lockfile, NativeVariant, PortableContent,
    PortablePath, Revision, Source,
};

use crate::adoption::{
    AdoptionDisposition, AdoptionRecoveryAction, CapabilityCatalogFailure, adoption_state,
    native_asset_root, portable_asset_root, tier_one_harnesses, validate_tier_one_capabilities,
};
use crate::whole_file_adoption::{self, BlockDigestInput};
use crate::{McpDocumentObservation, derive_lockfile, derive_manifest_revision};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TierOneMcpCapabilities {
    mcp: BTreeMap<HarnessId, CapabilitySupport>,
}

impl TierOneMcpCapabilities {
    pub fn new(matrices: BTreeMap<HarnessId, CapabilityMatrix>) -> Result<Self, McpAdoptionError> {
        let mcp = validate_tier_one_capabilities(&matrices, AssetKind::Mcp).map_err(|failure| {
            let (code, message) = match failure {
                CapabilityCatalogFailure::Incomplete => (
                    "mcp_adoption.incomplete_target_catalog",
                    "MCP adoption requires every tier-one capability matrix",
                ),
                CapabilityCatalogFailure::Missing => (
                    "mcp_adoption.capability_missing",
                    "a tier-one adapter does not declare MCP support",
                ),
                CapabilityCatalogFailure::Invalid => (
                    "mcp_adoption.capability_invalid",
                    "tier-one MCP support must be bounded and evidence-backed",
                ),
            };
            adoption_error(code, message)
        })?;
        let expected = [
            (HarnessId::Claude, Fidelity::Portable),
            (HarnessId::Codex, Fidelity::Adapted),
            (HarnessId::Pi, Fidelity::Unsupported),
            (HarnessId::OpenCode, Fidelity::Portable),
        ];
        if expected
            .iter()
            .any(|(harness, fidelity)| mcp[harness].result.fidelity() != *fidelity)
        {
            return Err(adoption_error(
                "mcp_adoption.capability_invalid",
                "tier-one MCP fidelity does not match the portable-v1 support contract",
            ));
        }
        Ok(Self { mcp })
    }

    fn mcp(&self, harness: &HarnessId) -> &CapabilitySupport {
        &self.mcp[harness]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpAdoptionBlockReason {
    EntryUnavailable,
    PortableProjectionUnavailable,
    BindingChoiceRequired,
    UnexpectedBindingChoice,
    AssetConflict,
}

impl McpAdoptionBlockReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EntryUnavailable => "entry_unavailable",
            Self::PortableProjectionUnavailable => "portable_projection_unavailable",
            Self::BindingChoiceRequired => "binding_choice_required",
            Self::UnexpectedBindingChoice => "unexpected_binding_choice",
            Self::AssetConflict => "asset_conflict",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpAdoptionBlock {
    asset_id: AssetId,
    exact_source_hash: ContentHash,
    reason: McpAdoptionBlockReason,
    digest: ContentHash,
}

impl McpAdoptionBlock {
    #[must_use]
    pub const fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }
    #[must_use]
    pub const fn exact_source_hash(&self) -> &ContentHash {
        &self.exact_source_hash
    }
    #[must_use]
    pub const fn reason(&self) -> McpAdoptionBlockReason {
        self.reason
    }
    #[must_use]
    pub const fn digest(&self) -> &ContentHash {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpAdoptionPlan {
    observation: McpDocumentObservation,
    selected_entry_hash: ContentHash,
    disposition: AdoptionDisposition,
    recovery_action: AdoptionRecoveryAction,
    asset: Asset,
    portable_object: StoredMcpServer,
    native_object: StoredNativeMcpEntry,
    proposed_manifest: EnvironmentManifest,
    proposed_lock: Lockfile,
    base_manifest_revision: Revision,
    proposed_manifest_revision: Revision,
    digest: ContentHash,
}

impl McpAdoptionPlan {
    #[must_use]
    pub const fn observation(&self) -> &McpDocumentObservation {
        &self.observation
    }
    #[must_use]
    pub const fn selected_entry_hash(&self) -> &ContentHash {
        &self.selected_entry_hash
    }
    #[must_use]
    pub const fn disposition(&self) -> AdoptionDisposition {
        self.disposition
    }
    #[must_use]
    pub const fn recovery_action(&self) -> AdoptionRecoveryAction {
        self.recovery_action
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
    ) -> Result<(), McpAdoptionError> {
        if &self.observation == reread {
            Ok(())
        } else {
            Err(adoption_error(
                "mcp_adoption.observation_stale",
                "the MCP document changed after planning",
            ))
        }
    }

    pub fn ensure_manifest_fresh(
        &self,
        reread: &EnvironmentManifest,
    ) -> Result<(), McpAdoptionError> {
        if manifest_revision(reread)? == self.base_manifest_revision {
            Ok(())
        } else {
            Err(adoption_error(
                "mcp_adoption.manifest_stale",
                "the authoritative manifest changed after planning",
            ))
        }
    }
}

impl Debug for McpAdoptionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAdoptionPlan")
            .field("asset_id", &self.asset.id)
            .field("origin_harness", &self.observation.harness())
            .field("exact_source_hash", &self.selected_entry_hash)
            .field("disposition", &self.disposition)
            .field("recovery_action", &self.recovery_action)
            .field("asset_revision", &self.asset.content_hash)
            .field("portable_object_hash", &self.portable_object.object_hash())
            .field("native_object_hash", &self.native_object.object_hash())
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpAdoptionOutcome {
    Ready(Box<McpAdoptionPlan>),
    Blocked(McpAdoptionBlock),
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpAdoptionError {
    code: &'static str,
    message: &'static str,
}

impl McpAdoptionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Debug for McpAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAdoptionError")
            .field("code", &self.code)
            .finish()
    }
}

impl Display for McpAdoptionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for McpAdoptionError {}

/// Plans adoption of one selected portable entry from a shared native MCP document.
pub fn plan_mcp_adoption(
    observation: &McpDocumentObservation,
    selected_entry_hash: &ContentHash,
    asset_id: &AssetId,
    bearer_binding: Option<&BindingName>,
    manifest: &EnvironmentManifest,
    capabilities: &TierOneMcpCapabilities,
) -> Result<McpAdoptionOutcome, McpAdoptionError> {
    manifest.validate().map_err(|_| invalid_manifest())?;
    let base_manifest_revision = manifest_revision(manifest)?;
    let Some(document) = observation.parsed() else {
        return Ok(blocked(
            selected_entry_hash,
            asset_id.clone(),
            McpAdoptionBlockReason::EntryUnavailable,
            &base_manifest_revision,
            None,
            None,
        ));
    };
    let Some(observed) = document
        .entries()
        .iter()
        .find(|entry| entry.exact_entry_hash() == selected_entry_hash)
    else {
        return Ok(blocked(
            selected_entry_hash,
            asset_id.clone(),
            McpAdoptionBlockReason::EntryUnavailable,
            &base_manifest_revision,
            None,
            None,
        ));
    };
    let McpPortability::Portable(projection) = observed.portability() else {
        return Ok(blocked(
            selected_entry_hash,
            asset_id.clone(),
            McpAdoptionBlockReason::PortableProjectionUnavailable,
            &base_manifest_revision,
            None,
            None,
        ));
    };
    let binding_required = projection.bearer_environment().is_some();
    if binding_required != bearer_binding.is_some() {
        let reason = if binding_required {
            McpAdoptionBlockReason::BindingChoiceRequired
        } else {
            McpAdoptionBlockReason::UnexpectedBindingChoice
        };
        return Ok(blocked(
            selected_entry_hash,
            asset_id.clone(),
            reason,
            &base_manifest_revision,
            None,
            None,
        ));
    }

    let server = McpServer::new(
        projection.name().clone(),
        projection.endpoint().clone(),
        bearer_binding.cloned(),
    )
    .map_err(|_| {
        adoption_error(
            "mcp_adoption.portable_object_invalid",
            "the MCP entry cannot form a portable object",
        )
    })?;
    let portable_object = StoredMcpServer::new(server);
    let native_object = StoredNativeMcpEntry::new(
        document.dialect(),
        document.exact_document_hash().clone(),
        observed,
    )
    .map_err(|_| {
        adoption_error(
            "mcp_adoption.native_object_invalid",
            "the exact MCP entry cannot form a native storage object",
        )
    })?;
    let provenance = kitrove_model::ComponentProvenance::new(
        Source::Harness {
            harness: observation.harness().clone(),
            origin: logical_origin(selected_entry_hash, observation)?,
        },
        Revision::parse(selected_entry_hash.as_str()).map_err(|_| invalid_path())?,
        selected_entry_hash.clone(),
        Some(observation.scope()),
    )
    .map_err(|_| {
        adoption_error(
            "mcp_adoption.provenance_invalid",
            "the MCP observation cannot form component provenance",
        )
    })?;
    let provenance_id = provenance.provenance_id();
    let required_bindings: BTreeSet<_> = bearer_binding
        .iter()
        .map(|binding| (*binding).clone())
        .collect();
    let mut asset = Asset {
        id: asset_id.clone(),
        kind: AssetKind::Mcp,
        content_hash: ContentHash::digest(b"pending-mcp-revision"),
        provenance: BTreeMap::from([(provenance_id.clone(), provenance)]),
        portable: Some(PortableContent {
            format: StoredMcpServer::format().to_owned(),
            root: portable_asset_root(asset_id).map_err(|_| invalid_path())?,
            object_hash: portable_object.object_hash().clone(),
            provenance: provenance_id.clone(),
        }),
        native_variants: BTreeMap::from([(
            observation.harness().clone(),
            NativeVariant {
                harness: observation.harness().clone(),
                format: StoredNativeMcpEntry::format().to_owned(),
                root: native_asset_root(asset_id, observation.harness())
                    .map_err(|_| invalid_path())?,
                object_hash: native_object.object_hash().clone(),
                content_class: observed.content_class(),
                provenance: provenance_id,
            },
        )]),
        compatibility: compatibility(
            observation.harness(),
            capabilities,
            portable_object.object_hash(),
            native_object.object_hash(),
        )?,
        content_class: observed.content_class(),
        required_bindings: required_bindings.clone(),
    };
    asset.refresh_content_hash();

    let existing_asset = manifest.assets.get(asset_id);
    let existing_pack = manifest.packs.get(asset_id);
    if existing_asset.is_some_and(|existing| existing != &asset) || existing_pack.is_some() {
        let conflicting_revision = existing_asset
            .map(|existing| &existing.content_hash)
            .or_else(|| existing_pack.map(|existing| &existing.content_hash));
        return Ok(blocked(
            selected_entry_hash,
            asset_id.clone(),
            McpAdoptionBlockReason::AssetConflict,
            &base_manifest_revision,
            Some(&asset.content_hash),
            conflicting_revision,
        ));
    }
    let (disposition, recovery_action) = adoption_state(existing_asset.is_some());
    let mut proposed_manifest = manifest.clone();
    proposed_manifest
        .required_bindings
        .extend(required_bindings);
    proposed_manifest
        .assets
        .insert(asset_id.clone(), asset.clone());
    proposed_manifest.validate().map_err(|_| {
        adoption_error(
            "mcp_adoption.proposed_manifest_invalid",
            "the proposed MCP manifest failed validation",
        )
    })?;
    let proposed_lock = derive_lockfile(&proposed_manifest).map_err(|_| {
        adoption_error(
            "mcp_adoption.proposed_lock_invalid",
            "the manifest-derived lockfile failed validation",
        )
    })?;
    let proposed_manifest_revision = manifest_revision(&proposed_manifest)?;
    let digest = whole_file_adoption::plan_digest(
        b"kitrove-mcp-adoption-plan-v1\0",
        selected_entry_hash,
        disposition,
        &asset,
        &base_manifest_revision,
        &proposed_manifest_revision,
        &proposed_lock,
    )
    .map_err(|()| {
        adoption_error(
            "mcp_adoption.plan_digest_failed",
            "the proposed lockfile cannot be encoded for the plan digest",
        )
    })?;

    Ok(McpAdoptionOutcome::Ready(Box::new(McpAdoptionPlan {
        observation: observation.clone(),
        selected_entry_hash: selected_entry_hash.clone(),
        disposition,
        recovery_action,
        asset,
        portable_object,
        native_object,
        proposed_manifest,
        proposed_lock,
        base_manifest_revision,
        proposed_manifest_revision,
        digest,
    })))
}

fn compatibility(
    origin: &HarnessId,
    capabilities: &TierOneMcpCapabilities,
    portable_hash: &ContentHash,
    native_hash: &ContentHash,
) -> Result<BTreeMap<HarnessId, FidelityResult>, McpAdoptionError> {
    tier_one_harnesses()
        .into_iter()
        .map(|harness| {
            let support = capabilities.mcp(&harness);
            let mut evidence = support.result.evidence().to_vec();
            let (fidelity, reasons) = if &harness == origin {
                evidence.push(FidelityEvidence::new(
                    "native.object_hash",
                    native_hash.as_str(),
                ));
                (Fidelity::Native, vec![])
            } else {
                if support.result.fidelity() != Fidelity::Unsupported {
                    evidence.push(FidelityEvidence::new(
                        "portable.object_hash",
                        portable_hash.as_str(),
                    ));
                }
                (support.result.fidelity(), support.result.reasons().to_vec())
            };
            FidelityResult::new(
                fidelity,
                reasons,
                evidence,
                vec![],
                support.result.adapter_version(),
                support.result.harness_version().map(str::to_owned),
            )
            .map(|result| (harness, result))
            .map_err(|_| {
                adoption_error(
                    "mcp_adoption.fidelity_invalid",
                    "the evidence-backed MCP fidelity result is invalid",
                )
            })
        })
        .collect()
}

fn logical_origin(
    selected_entry_hash: &ContentHash,
    observation: &McpDocumentObservation,
) -> Result<PortablePath, McpAdoptionError> {
    whole_file_adoption::observation_origin(
        selected_entry_hash,
        observation.harness(),
        observation.scope(),
        "mcp",
    )
    .map_err(|()| invalid_path())
}

fn invalid_path() -> McpAdoptionError {
    adoption_error(
        "mcp_adoption.portable_path_invalid",
        "the MCP observation cannot form a portable authority path",
    )
}

fn invalid_manifest() -> McpAdoptionError {
    adoption_error(
        "mcp_adoption.manifest_invalid",
        "the authoritative manifest is invalid",
    )
}

fn manifest_revision(manifest: &EnvironmentManifest) -> Result<Revision, McpAdoptionError> {
    derive_manifest_revision(manifest).map_err(|_| invalid_manifest())
}

fn blocked(
    observation_identity: &ContentHash,
    asset_id: AssetId,
    reason: McpAdoptionBlockReason,
    base_manifest_revision: &Revision,
    proposed_revision: Option<&ContentHash>,
    conflicting_revision: Option<&ContentHash>,
) -> McpAdoptionOutcome {
    let digest = whole_file_adoption::block_digest(BlockDigestInput {
        domain: b"kitrove-mcp-adoption-block-v1\0",
        observation_identity,
        asset_id: &asset_id,
        reason: reason.as_str(),
        base_manifest_revision,
        proposed_revision,
        conflicting_revision,
    });
    McpAdoptionOutcome::Blocked(McpAdoptionBlock {
        asset_id,
        exact_source_hash: observation_identity.clone(),
        reason,
        digest,
    })
}

const fn adoption_error(code: &'static str, message: &'static str) -> McpAdoptionError {
    McpAdoptionError { code, message }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;

    use kitrove_adapter_api::{McpTargetPolicy, PolicyLine, TargetAnchor};
    use kitrove_mcp::{McpParseLimits, NativeMcpDialect};
    use kitrove_model::{FidelityReason, HarnessScope, SchemaVersion};
    use tempfile::tempdir;

    use super::*;
    use crate::observe_mcp_document;

    fn capability(fidelity: Fidelity, version: &'static str) -> CapabilityMatrix {
        let evidence = vec![FidelityEvidence::new(
            "adapter.capability_matrix",
            "test adapter MCP contract",
        )];
        let result = if fidelity == Fidelity::Unsupported {
            FidelityResult::new(
                fidelity,
                vec![FidelityReason::new(
                    "mcp.unsupported",
                    "the target does not load a built-in MCP registry",
                )],
                evidence,
                vec![],
                version,
                None,
            )
        } else {
            FidelityResult::exact(fidelity, evidence, version, None)
        }
        .unwrap();
        CapabilityMatrix::empty().with_capability(AssetKind::Mcp, result, vec![])
    }

    pub(crate) fn capabilities() -> TierOneMcpCapabilities {
        TierOneMcpCapabilities::new(BTreeMap::from([
            (
                HarnessId::Claude,
                capability(Fidelity::Portable, "claude-mcp/1"),
            ),
            (
                HarnessId::Codex,
                capability(Fidelity::Adapted, "codex-mcp/1"),
            ),
            (HarnessId::Pi, capability(Fidelity::Unsupported, "pi-mcp/1")),
            (
                HarnessId::OpenCode,
                capability(Fidelity::Portable, "opencode-mcp/1"),
            ),
        ]))
        .unwrap()
    }

    pub(crate) fn empty_manifest() -> EnvironmentManifest {
        EnvironmentManifest {
            schema_version: SchemaVersion::V1,
            assets: BTreeMap::new(),
            packs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            required_bindings: BTreeSet::new(),
        }
    }

    pub(crate) fn observe(source: &str) -> McpDocumentObservation {
        let directory = tempdir().unwrap();
        let anchor = directory.path().canonicalize().unwrap();
        fs::write(anchor.join("claude.json"), source).unwrap();
        let policy = McpTargetPolicy::new(
            HarnessScope::User,
            PolicyLine::ClaudeCurrent,
            TargetAnchor::Scope,
            "claude.json",
            NativeMcpDialect::ClaudeCurrent,
            "claude-mcp/1",
            "fixture.claude.mcp",
        )
        .unwrap();
        observe_mcp_document(&anchor, &policy, McpParseLimits::default()).unwrap()
    }

    fn selected_hash(observation: &McpDocumentObservation) -> ContentHash {
        observation.parsed().unwrap().entries()[0]
            .exact_entry_hash()
            .clone()
    }

    #[test]
    fn plans_portable_mcp_with_native_origin_and_tier_one_fidelity() {
        let observation = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp"}}}"#,
        );
        let selected = selected_hash(&observation);
        let asset_id = AssetId::parse("company-docs").unwrap();
        let McpAdoptionOutcome::Ready(plan) = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            panic!("portable MCP entry should be adoptable")
        };

        assert_eq!(plan.asset().kind, AssetKind::Mcp);
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Claude].fidelity(),
            Fidelity::Native
        );
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Codex].fidelity(),
            Fidelity::Adapted
        );
        assert_eq!(
            plan.asset().compatibility[&HarnessId::Pi].fidelity(),
            Fidelity::Unsupported
        );
        assert_eq!(
            plan.asset().compatibility[&HarnessId::OpenCode].fidelity(),
            Fidelity::Portable
        );
        assert!(plan.asset().required_bindings.is_empty());
        plan.proposed_manifest().validate().unwrap();
        plan.proposed_lock().validate().unwrap();
        assert!(!format!("{plan:?}").contains("mcp.example.com"));
    }

    #[test]
    fn requires_a_logical_binding_without_copying_the_native_environment_name() {
        let observation = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${NATIVE_SECRET_TOKEN}"}}}}"#,
        );
        let selected = selected_hash(&observation);
        let asset_id = AssetId::parse("company-docs").unwrap();
        let outcome = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            McpAdoptionOutcome::Blocked(McpAdoptionBlock {
                reason: McpAdoptionBlockReason::BindingChoiceRequired,
                ..
            })
        ));

        let binding = BindingName::parse("company_mcp_token").unwrap();
        let McpAdoptionOutcome::Ready(plan) = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            Some(&binding),
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            panic!("a symbolic binding choice should unblock adoption")
        };
        assert_eq!(
            plan.asset().required_bindings,
            BTreeSet::from([binding.clone()])
        );
        assert!(
            plan.proposed_manifest()
                .required_bindings
                .contains(&binding)
        );
        let portable = plan.portable_object().to_json().unwrap();
        assert!(portable.contains("company_mcp_token"));
        assert!(!portable.contains("NATIVE_SECRET_TOKEN"));
    }

    #[test]
    fn blocks_nonportable_entries_and_conflicting_authority() {
        let blocked_observation =
            observe(r#"{"mcpServers":{"local":{"command":"npx","args":["server"]}}}"#);
        let blocked_hash = selected_hash(&blocked_observation);
        let asset_id = AssetId::parse("company-docs").unwrap();
        let outcome = plan_mcp_adoption(
            &blocked_observation,
            &blocked_hash,
            &asset_id,
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap();
        assert!(matches!(
            outcome,
            McpAdoptionOutcome::Blocked(McpAdoptionBlock {
                reason: McpAdoptionBlockReason::PortableProjectionUnavailable,
                ..
            })
        ));

        let observation = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://mcp.example.com/mcp"}}}"#,
        );
        let selected = selected_hash(&observation);
        let McpAdoptionOutcome::Ready(first) = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            None,
            &empty_manifest(),
            &capabilities(),
        )
        .unwrap() else {
            panic!("first adoption should be ready")
        };
        let repeated = plan_mcp_adoption(
            &observation,
            &selected,
            &asset_id,
            None,
            first.proposed_manifest(),
            &capabilities(),
        )
        .unwrap();
        assert!(matches!(
            repeated,
            McpAdoptionOutcome::Ready(plan)
                if plan.disposition() == AdoptionDisposition::Idempotent
        ));

        let changed = observe(
            r#"{"mcpServers":{"docs":{"type":"http","url":"https://other.example.com/mcp"}}}"#,
        );
        let changed_hash = selected_hash(&changed);
        let conflict = plan_mcp_adoption(
            &changed,
            &changed_hash,
            &asset_id,
            None,
            first.proposed_manifest(),
            &capabilities(),
        )
        .unwrap();
        assert!(matches!(
            conflict,
            McpAdoptionOutcome::Blocked(McpAdoptionBlock {
                reason: McpAdoptionBlockReason::AssetConflict,
                ..
            })
        ));
    }
}
